package usecase

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

type confirmFixture struct {
	useCase       *ConfirmRegistration
	users         *fakeRepository
	registrations *fakeRegistrations
	keys          *fakeKeys
	outbox        *fakeOutbox
	transactions  *fakeTransactions
	sessions      *loginSessions
	journal       *journal
	pending       *model.RegistrationRequest
}

func newConfirmFixture(t *testing.T) *confirmFixture {
	t.Helper()
	j := &journal{}
	token, _ := model.NewResetToken(resetTokenValue)
	email, _ := model.NewEmail("ana@example.com")
	name, _ := model.NewName("Ana Pérez")
	phone, _ := model.NewPhone("3001234567")
	address, _ := model.NewAddress("Calle 123 #45-67")
	f := &confirmFixture{
		users:         &fakeRepository{journal: j, taken: map[string]bool{}, byID: map[string]*model.User{}},
		registrations: newFakeRegistrations(j),
		keys:          &fakeKeys{journal: j, records: map[string]out.IdempotencyRecord{}},
		outbox:        &fakeOutbox{journal: j},
		transactions:  &fakeTransactions{journal: j},
		sessions:      &loginSessions{},
		journal:       j,
		pending:       model.NewRegistrationRequest("request-1", email, hashedPassword, name, phone, address, token, registeredAt.Add(-time.Hour)),
	}
	f.registrations.byToken[token.Hash()] = f.pending
	f.useCase = NewConfirmRegistration(ConfirmRegistrationPorts{
		Users: f.users, Registrations: f.registrations, Keys: f.keys, Outbox: f.outbox,
		IDs: &fakeIDs{next: []string{"user-1", "event-1"}}, Clock: fakeClock{}, Transactions: f.transactions,
		Tokens: loginTokens{}, Sessions: f.sessions,
	})
	return f
}

func confirmCommand() in.ConfirmRegistrationCommand {
	return in.ConfirmRegistrationCommand{IdempotencyKey: idempotencyKey, Token: resetTokenValue, UserAgent: "curl/8"}
}

func tokenHashOf(t *testing.T, raw string) string {
	t.Helper()
	token, err := model.NewResetToken(raw)
	if err != nil {
		t.Fatal(err)
	}
	return token.Hash()
}

func TestConfirmRegistrationCreatesTheClientTheKeyAndTheEventInOneTransactionThenOpensTheSession(t *testing.T) {
	f := newConfirmFixture(t)

	result, err := f.useCase.Confirm(context.Background(), confirmCommand())

	if err != nil || result.Replayed {
		t.Fatalf("Confirm() = %+v, %v; want a new account", result, err)
	}
	session := result.Session
	if session.AccessToken != accessSecret || session.RefreshToken != "opaque-refresh" || session.ExpiresIn != 3600 {
		t.Errorf("tokens = %q %q %d, want the issued ones and 3600 seconds", session.AccessToken, session.RefreshToken, session.ExpiresIn)
	}
	if session.User.ID != "user-1" || session.User.Email != "ana@example.com" || !reflect.DeepEqual(session.User.Roles, []string{"CLIENT"}) {
		t.Errorf("user = %+v, want the new CLIENT", session.User)
	}
	if len(f.users.saved) != 1 || f.users.saved[0].PasswordHash() != hashedPassword || f.users.saved[0].Phone().String() != "3001234567" {
		t.Fatalf("saved = %+v, want the account with the stored hash and contact data", f.users.saved)
	}
	wantKey := out.IdempotencyRecord{UserID: "user-1", RequestHash: tokenHashOf(t, resetTokenValue)}
	if got := f.keys.records[idempotencyKey]; got != wantKey {
		t.Errorf("stored key = %+v, want %+v", got, wantKey)
	}
	if len(f.registrations.used) != 1 || f.registrations.used[0].UsedAt() == nil {
		t.Error("the registration request was not marked as used")
	}
	wantSteps := []string{"begin", "find-key", "lock-token", "save", "save-key", "mark-used", "outbox", "commit"}
	if !reflect.DeepEqual(f.journal.steps, wantSteps) {
		t.Errorf("steps = %v, want %v", f.journal.steps, wantSteps)
	}
	wantEvent := model.UserRegistered{EventID: "event-1", OccurredAt: registeredAt, UserID: "user-1", Email: "ana@example.com", Roles: []string{"CLIENT"}}
	if len(f.outbox.events) != 1 || !reflect.DeepEqual(f.outbox.events[0], wantEvent) {
		t.Errorf("events = %+v, want [%+v]", f.outbox.events, wantEvent)
	}
	if want := (in.IssueRefreshTokenCommand{UserID: "user-1", UserAgent: "curl/8"}); len(f.sessions.commands) != 1 || f.sessions.commands[0] != want {
		t.Errorf("refresh token commands = %+v, want [%+v]", f.sessions.commands, want)
	}
}

func TestConfirmRegistrationBoundsTheUserAgentOfTheSession(t *testing.T) {
	f := newConfirmFixture(t)
	command := confirmCommand()
	command.UserAgent = strings.Repeat("a", 1000)

	if _, err := f.useCase.Confirm(context.Background(), command); err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	if got := len(f.sessions.commands[0].UserAgent); got >= 1000 {
		t.Errorf("user agent length = %d, want it bounded", got)
	}
}

func TestConfirmRegistrationRejectsInvalidInputWithoutTouchingAnything(t *testing.T) {
	for label, mutate := range map[string]func(*in.ConfirmRegistrationCommand){
		"key":   func(c *in.ConfirmRegistrationCommand) { c.IdempotencyKey = "short" },
		"token": func(c *in.ConfirmRegistrationCommand) { c.Token = "not-a-token" },
	} {
		t.Run(label, func(t *testing.T) {
			f := newConfirmFixture(t)
			command := confirmCommand()
			mutate(&command)

			if _, err := f.useCase.Confirm(context.Background(), command); err == nil || len(f.journal.steps) != 0 {
				t.Errorf("error = %v, steps = %v, want a validation error and nothing touched", err, f.journal.steps)
			}
		})
	}
}

func TestConfirmRegistrationRejectsAnUnknownExpiredOrUsedTokenAsOne(t *testing.T) {
	cases := map[string]func(*confirmFixture) in.ConfirmRegistrationCommand{
		"unknown": func(*confirmFixture) in.ConfirmRegistrationCommand {
			command := confirmCommand()
			command.Token = "3f2c1b7e-5a9d-4c1e-8b6f-0a1b2c3d4e60"
			return command
		},
		"used": func(f *confirmFixture) in.ConfirmRegistrationCommand {
			used := registeredAt.Add(-time.Minute)
			f.registrations.byToken[tokenHashOf(t, resetTokenValue)] = model.RestoreRegistrationRequest("request-1", f.pending.Email(), hashedPassword, f.pending.Name(), f.pending.Phone(), f.pending.Address(), f.pending.TokenHash(), f.pending.ExpiresAt(), &used)
			return confirmCommand()
		},
		"expired": func(f *confirmFixture) in.ConfirmRegistrationCommand {
			f.useCase.ports.Clock = clockAt{registeredAt.Add(model.RegistrationLifetime)}
			return confirmCommand()
		},
	}
	for label, prepare := range cases {
		t.Run(label, func(t *testing.T) {
			f := newConfirmFixture(t)
			command := prepare(f)

			_, err := f.useCase.Confirm(context.Background(), command)

			if !errors.Is(err, model.ErrRegistrationRejected) || len(f.users.saved) != 0 || len(f.outbox.events) != 0 || f.transactions.committed {
				t.Errorf("error = %v, saved = %d, events = %d, committed = %v; want ErrRegistrationRejected and nothing created", err, len(f.users.saved), len(f.outbox.events), f.transactions.committed)
			}
		})
	}
}

type clockAt struct{ now time.Time }

func (c clockAt) Now() time.Time { return c.now }

func TestConfirmRegistrationReplaysTheSameTokenWithoutCreatingAnythingOrTokens(t *testing.T) {
	f := newConfirmFixture(t)
	f.keys.records[idempotencyKey] = out.IdempotencyRecord{UserID: "user-1", RequestHash: tokenHashOf(t, resetTokenValue)}
	f.users.byID["user-1"] = storedUser(t, model.UserActive, model.RoleClient)

	result, err := f.useCase.Confirm(context.Background(), confirmCommand())

	if err != nil || !result.Replayed {
		t.Fatalf("Confirm() = %+v, %v; want a replay", result, err)
	}
	if result.Session.AccessToken != "" || len(f.sessions.commands) != 0 || len(f.users.saved) != 0 || len(f.outbox.events) != 0 {
		t.Errorf("session = %+v, want no tokens and nothing created", result.Session)
	}
	if result.Session.User.ID != "user-1" {
		t.Errorf("user = %+v, want the account of the first confirmation", result.Session.User)
	}
	if want := []string{"begin", "find-key", "find-user", "commit"}; !reflect.DeepEqual(f.journal.steps, want) {
		t.Errorf("steps = %v, want %v: the key is checked before the token", f.journal.steps, want)
	}
}

func TestConfirmRegistrationRejectsTheSameKeyWithAnotherToken(t *testing.T) {
	f := newConfirmFixture(t)
	f.keys.records[idempotencyKey] = out.IdempotencyRecord{UserID: "user-1", RequestHash: tokenHashOf(t, "3f2c1b7e-5a9d-4c1e-8b6f-0a1b2c3d4e60")}

	_, err := f.useCase.Confirm(context.Background(), confirmCommand())

	if !errors.Is(err, model.ErrIdempotencyKeyConflict) || len(f.users.saved) != 0 {
		t.Errorf("error = %v, saved = %d, want ErrIdempotencyKeyConflict and nothing created", err, len(f.users.saved))
	}
}

func TestConfirmRegistrationOfAnAddressTakenMeanwhileCreatesNothingAndKeepsTheTokenUnused(t *testing.T) {
	f := newConfirmFixture(t)
	f.users.taken["ana@example.com"] = true

	_, err := f.useCase.Confirm(context.Background(), confirmCommand())

	if !errors.Is(err, model.ErrEmailAlreadyRegistered) || len(f.users.saved) != 0 || f.transactions.committed {
		t.Errorf("error = %v, saved = %d, committed = %v; want ErrEmailAlreadyRegistered, nothing created", err, len(f.users.saved), f.transactions.committed)
	}
}

func TestConfirmRegistrationAnswersAsAReplayWhenAConcurrentRequestWinsTheKey(t *testing.T) {
	f := newConfirmFixture(t)
	f.keys.beforeSave = func() {
		f.keys.records[idempotencyKey] = out.IdempotencyRecord{UserID: "user-1", RequestHash: tokenHashOf(t, resetTokenValue)}
		f.users.byID["user-1"] = storedUser(t, model.UserActive, model.RoleClient)
	}

	result, err := f.useCase.Confirm(context.Background(), confirmCommand())

	if err != nil || !result.Replayed || len(f.sessions.commands) != 0 {
		t.Errorf("Confirm() = %+v, %v; want the replay of the winner without a session", result, err)
	}
}

func TestConfirmRegistrationRetriesOnlyOnce(t *testing.T) {
	f := newConfirmFixture(t)
	f.keys.saveErr = model.ErrIdempotencyKeyTaken

	_, err := f.useCase.Confirm(context.Background(), confirmCommand())

	if !errors.Is(err, model.ErrIdempotencyKeyTaken) {
		t.Fatalf("Confirm() error = %v, want the second failure returned", err)
	}
	if begins := countSteps(f.journal, "begin"); begins != 2 {
		t.Errorf("transactions = %d, want 2 (the attempt and one retry)", begins)
	}
}

func TestConfirmRegistrationRollsBackWhenAnOutboundPortFails(t *testing.T) {
	boom := errors.New("boom")
	cases := map[string]struct {
		fail  func(*confirmFixture)
		steps []string
	}{
		"key find":  {func(f *confirmFixture) { f.keys.findErr = boom }, []string{"begin", "find-key", "rollback"}},
		"lock":      {func(f *confirmFixture) { f.registrations.failAt["lock-token"] = boom }, []string{"begin", "find-key", "lock-token", "rollback"}},
		"existence": {func(f *confirmFixture) { f.users.existsErr = boom }, []string{"begin", "find-key", "lock-token", "rollback"}},
		"save":      {func(f *confirmFixture) { f.users.saveErr = boom }, []string{"begin", "find-key", "lock-token", "save", "rollback"}},
		"key save":  {func(f *confirmFixture) { f.keys.saveErr = boom }, []string{"begin", "find-key", "lock-token", "save", "save-key", "rollback"}},
		"mark used": {func(f *confirmFixture) { f.registrations.failAt["mark-used"] = boom }, []string{"begin", "find-key", "lock-token", "save", "save-key", "mark-used", "rollback"}},
		"outbox":    {func(f *confirmFixture) { f.outbox.err = boom }, []string{"begin", "find-key", "lock-token", "save", "save-key", "mark-used", "outbox", "rollback"}},
	}
	for label, c := range cases {
		t.Run(label, func(t *testing.T) {
			f := newConfirmFixture(t)
			c.fail(f)

			if _, err := f.useCase.Confirm(context.Background(), confirmCommand()); !errors.Is(err, boom) {
				t.Fatalf("Confirm() error = %v, want the port error", err)
			}
			if !reflect.DeepEqual(f.journal.steps, c.steps) || f.transactions.committed || len(f.sessions.commands) != 0 {
				t.Errorf("steps = %v committed = %v, want %v, no commit and no session", f.journal.steps, f.transactions.committed, c.steps)
			}
		})
	}
}

func TestConfirmRegistrationSurfacesSessionFailuresAfterTheCommit(t *testing.T) {
	boom := errors.New("boom")
	f := newConfirmFixture(t)
	f.sessions.err = boom

	_, err := f.useCase.Confirm(context.Background(), confirmCommand())

	if !errors.Is(err, boom) || !f.transactions.committed {
		t.Errorf("error = %v committed = %v, want the failure after the commit", err, f.transactions.committed)
	}
}
