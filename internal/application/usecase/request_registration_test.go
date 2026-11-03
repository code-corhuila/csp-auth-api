package usecase

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

type registrationFixture struct {
	useCase       *RequestRegistration
	users         *fakeRepository
	registrations *fakeRegistrations
	sender        *fakeRegistrationSender
	hasher        *fakeHasher
	transactions  *fakeTransactions
	journal       *journal
}

func newRegistrationFixture() *registrationFixture {
	j := &journal{}
	f := &registrationFixture{
		users:         &fakeRepository{journal: j, taken: map[string]bool{}, byID: map[string]*model.User{}},
		registrations: newFakeRegistrations(j),
		sender:        &fakeRegistrationSender{journal: j},
		hasher:        &fakeHasher{},
		transactions:  &fakeTransactions{journal: j},
		journal:       j,
	}
	f.useCase = NewRequestRegistration(RequestRegistrationPorts{
		Users: f.users, Registrations: f.registrations, Hasher: f.hasher, Tokens: &fakeResetTokens{journal: j}, Sender: f.sender,
		IDs: &fakeIDs{next: []string{"request-1", "request-2"}}, Clock: fakeClock{}, Transactions: f.transactions,
	})
	return f
}

func registrationCommand() in.RequestRegistrationCommand {
	return in.RequestRegistrationCommand{
		IdempotencyKey: idempotencyKey, Email: "Ana@Example.com", Password: "Secret123", Name: "Ana Pérez",
		Phone: "3001234567", Address: "Calle 123 #45-67",
	}
}

func registrationHashOf(t *testing.T, command in.RequestRegistrationCommand) string {
	t.Helper()
	email, err := model.NewEmail(command.Email)
	if err != nil {
		t.Fatal(err)
	}
	name, _ := model.NewName(command.Name)
	phone, _ := model.NewPhone(command.Phone)
	address, _ := model.NewAddress(command.Address)
	return model.RegistrationRequestHash(email, name, phone, address)
}

func countSteps(j *journal, step string) int {
	return len(slices.DeleteFunc(slices.Clone(j.steps), func(s string) bool { return s != step }))
}

func TestRequestRegistrationOfAFreeAddressStoresThePendingRegistrationAndSendsTheLinkAfterTheCommit(t *testing.T) {
	f := newRegistrationFixture()

	result, err := f.useCase.Request(context.Background(), registrationCommand())

	if err != nil || result.RequestID != "request-1" || result.Replayed {
		t.Fatalf("Request() = %+v, %v; want request-1, not replayed", result, err)
	}
	if got := f.registrations.added; len(got) != 1 || got[0].Request == nil || got[0].RequestHash != registrationHashOf(t, registrationCommand()) {
		t.Fatalf("stored = %+v, want the pending registration with the hash of the request", got)
	}
	pending := f.registrations.added[0].Request
	if pending.PasswordHash() != hashedPassword || pending.Email().String() != "ana@example.com" || pending.Name().String() != "Ana Pérez" {
		t.Errorf("pending = %q %q %q, want the bcrypt hash and the data of the request", pending.PasswordHash(), pending.Email(), pending.Name())
	}
	wantSteps := []string{"new-token", "begin", "find-key", "lock-email", "count", "supersede", "add", "commit", "send"}
	if !reflect.DeepEqual(f.journal.steps, wantSteps) {
		t.Errorf("steps = %v, want %v", f.journal.steps, wantSteps)
	}
	if want := []sentRegistrationMessage{{"confirmation", "ana@example.com", resetTokenValue}}; !reflect.DeepEqual(f.sender.sent, want) {
		t.Errorf("sent = %+v, want %+v", f.sender.sent, want)
	}
	if !reflect.DeepEqual(f.hasher.hashed, []string{"Secret123"}) {
		t.Errorf("hashed = %v, want the password hashed once", f.hasher.hashed)
	}
}

func TestRequestRegistrationOfAnAddressWithAnAccountCreatesNothingAndNotifiesItsOwner(t *testing.T) {
	f := newRegistrationFixture()
	f.users.taken["ana@example.com"] = true

	result, err := f.useCase.Request(context.Background(), registrationCommand())

	if err != nil || result.RequestID != "request-1" || result.Replayed {
		t.Fatalf("Request() = %+v, %v; want the same answer as for a free address", result, err)
	}
	if got := f.registrations.added; len(got) != 1 || got[0].Request != nil || f.registrations.superseds != 0 || len(f.users.saved) != 0 {
		t.Errorf("stored = %+v, superseded = %d, users = %d; want only the trace of the key", got, f.registrations.superseds, len(f.users.saved))
	}
	if want := []sentRegistrationMessage{{"notice", "ana@example.com", ""}}; !reflect.DeepEqual(f.sender.sent, want) {
		t.Errorf("sent = %+v, want the notice", f.sender.sent)
	}
}

func TestRequestRegistrationDoesTheSameWorkForAFreeAddressAndOneWithAnAccount(t *testing.T) {
	free := newRegistrationFixture()
	_, _ = free.useCase.Request(context.Background(), registrationCommand())
	taken := newRegistrationFixture()
	taken.users.taken["ana@example.com"] = true
	_, _ = taken.useCase.Request(context.Background(), registrationCommand())

	// The only step a free address adds is superseding the previous pending request, one statement before the insert.
	withoutSupersede := slices.DeleteFunc(slices.Clone(free.journal.steps), func(step string) bool { return step == "supersede" })
	if !reflect.DeepEqual(withoutSupersede, taken.journal.steps) || !reflect.DeepEqual(free.hasher.hashed, taken.hasher.hashed) {
		t.Errorf("free %v / taken %v: the password hash and the steps must match", free.journal.steps, taken.journal.steps)
	}
}

func TestRequestRegistrationOverTheLimitCreatesAndSendsNothingButAnswersTheSame(t *testing.T) {
	for label, taken := range map[string]bool{"free address": false, "address with an account": true} {
		t.Run(label, func(t *testing.T) {
			f := newRegistrationFixture()
			f.users.taken["ana@example.com"] = taken
			f.registrations.requested = model.MaxRegistrationRequests

			result, err := f.useCase.Request(context.Background(), registrationCommand())

			if err != nil || result.RequestID != "request-1" || result.Replayed {
				t.Fatalf("Request() = %+v, %v; want the same answer", result, err)
			}
			if got := f.registrations.added; len(got) != 1 || got[0].Request != nil || len(f.sender.sent) != 0 || f.registrations.superseds != 0 {
				t.Errorf("stored = %+v, sent = %v, superseded = %d; want only the trace of the key", got, f.sender.sent, f.registrations.superseds)
			}
			if want := (fakeClock{}).Now().Add(-model.RegistrationRequestWindow); !f.registrations.counted.Equal(want) {
				t.Errorf("counted since %v, want the last rolling hour %v", f.registrations.counted, want)
			}
		})
	}
}

func TestRequestRegistrationReplayOfTheSameRequestCreatesAndSendsNothing(t *testing.T) {
	f := newRegistrationFixture()
	f.registrations.byKey[idempotencyKey] = out.RegistrationRecord{ID: "first", RequestHash: registrationHashOf(t, registrationCommand())}
	command := registrationCommand()
	command.Email, command.Password = "ANA@example.com", "Another123"

	result, err := f.useCase.Request(context.Background(), command)

	if err != nil || result.RequestID != "first" || !result.Replayed {
		t.Fatalf("Request() = %+v, %v; want the first request, replayed", result, err)
	}
	if len(f.registrations.added) != 0 || len(f.sender.sent) != 0 || countSteps(f.journal, "lock-email") != 0 {
		t.Errorf("added = %v, sent = %v, steps = %v; want the key checked first and nothing else", f.registrations.added, f.sender.sent, f.journal.steps)
	}
}

func TestRequestRegistrationKeyUsedByAnotherRequestIsAConflictWhateverTheAccountIs(t *testing.T) {
	for label, taken := range map[string]bool{"free address": false, "address with an account": true} {
		t.Run(label, func(t *testing.T) {
			f := newRegistrationFixture()
			f.users.taken["ana@example.com"] = taken
			f.registrations.byKey[idempotencyKey] = out.RegistrationRecord{ID: "first", RequestHash: "another-request"}

			_, err := f.useCase.Request(context.Background(), registrationCommand())

			if !errors.Is(err, model.ErrIdempotencyKeyConflict) || len(f.sender.sent) != 0 {
				t.Errorf("error = %v, sent = %v, want the conflict and nothing sent", err, f.sender.sent)
			}
		})
	}
}

func TestRequestRegistrationLosingTheRaceOnTheKeyRetriesOnlyOnce(t *testing.T) {
	f := newRegistrationFixture()
	f.registrations.failAt["add"] = model.ErrIdempotencyKeyTaken

	_, err := f.useCase.Request(context.Background(), registrationCommand())

	if !errors.Is(err, model.ErrIdempotencyKeyTaken) || len(f.sender.sent) != 0 {
		t.Fatalf("error = %v, sent = %v, want the second failure and nothing sent", err, f.sender.sent)
	}
	if begins := countSteps(f.journal, "begin"); begins != 2 {
		t.Errorf("transactions = %d, want 2 (the attempt and one retry)", begins)
	}
}

func TestRequestRegistrationRejectsInvalidInputBeforeAnyWork(t *testing.T) {
	cases := map[string]func(*in.RequestRegistrationCommand){
		"key":      func(c *in.RequestRegistrationCommand) { c.IdempotencyKey = "short" },
		"email":    func(c *in.RequestRegistrationCommand) { c.Email = "not-an-email" },
		"password": func(c *in.RequestRegistrationCommand) { c.Password = "weak" },
		"name":     func(c *in.RequestRegistrationCommand) { c.Name = "" },
		"phone":    func(c *in.RequestRegistrationCommand) { c.Phone = "abc" },
	}
	for label, mutate := range cases {
		t.Run(label, func(t *testing.T) {
			f := newRegistrationFixture()
			command := registrationCommand()
			mutate(&command)

			if _, err := f.useCase.Request(context.Background(), command); err == nil {
				t.Fatal("Request() succeeded, want a validation error")
			}
			if len(f.journal.steps) != 0 || len(f.hasher.hashed) != 0 {
				t.Errorf("steps = %v, hashed = %v, want nothing touched", f.journal.steps, f.hasher.hashed)
			}
		})
	}
}

func TestRequestRegistrationSurfacesABusyHasherAndPortFailuresAndRollsBack(t *testing.T) {
	boom := errors.New("boom")
	cases := map[string]struct {
		fail  func(*registrationFixture)
		steps []string
	}{
		"busy hasher": {func(f *registrationFixture) { f.hasher.err = model.ErrPasswordHasherBusy }, nil},
		"key find":    {func(f *registrationFixture) { f.registrations.failAt["find-key"] = boom }, []string{"new-token", "begin", "find-key", "rollback"}},
		"lock":        {func(f *registrationFixture) { f.registrations.failAt["lock-email"] = boom }, []string{"new-token", "begin", "find-key", "lock-email", "rollback"}},
		"existence":   {func(f *registrationFixture) { f.users.existsErr = boom }, []string{"new-token", "begin", "find-key", "lock-email", "rollback"}},
		"count":       {func(f *registrationFixture) { f.registrations.failAt["count"] = boom }, []string{"new-token", "begin", "find-key", "lock-email", "count", "rollback"}},
		"supersede":   {func(f *registrationFixture) { f.registrations.failAt["supersede"] = boom }, []string{"new-token", "begin", "find-key", "lock-email", "count", "supersede", "rollback"}},
		"add":         {func(f *registrationFixture) { f.registrations.failAt["add"] = boom }, []string{"new-token", "begin", "find-key", "lock-email", "count", "supersede", "add", "rollback"}},
	}
	for label, c := range cases {
		t.Run(label, func(t *testing.T) {
			f := newRegistrationFixture()
			c.fail(f)

			_, err := f.useCase.Request(context.Background(), registrationCommand())

			if err == nil || len(f.sender.sent) != 0 || f.transactions.committed {
				t.Errorf("error = %v, sent = %v, committed = %v; want a failure, no commit and nothing sent", err, f.sender.sent, f.transactions.committed)
			}
			if label != "busy hasher" && !reflect.DeepEqual(f.journal.steps, c.steps) {
				t.Errorf("steps = %v, want %v", f.journal.steps, c.steps)
			}
		})
	}
}

func TestRequestRegistrationAnswersTheSameWhenTheSenderFails(t *testing.T) {
	for label, taken := range map[string]bool{"free address": false, "address with an account": true} {
		t.Run(label, func(t *testing.T) {
			f := newRegistrationFixture()
			f.users.taken["ana@example.com"] = taken
			f.sender.err = errors.New("smtp down")

			result, err := f.useCase.Request(context.Background(), registrationCommand())

			if err != nil || result.RequestID != "request-1" || !f.transactions.committed {
				t.Errorf("Request() = %+v, %v, committed = %v; want the same success after the commit", result, err, f.transactions.committed)
			}
		})
	}
}
