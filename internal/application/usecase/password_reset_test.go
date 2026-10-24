package usecase

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const (
	resetTokenValue = "3f2c1b7e-5a9d-4c1e-8b6f-0a1b2c3d4e5f"
	newPassword     = "NewSecret123"
)

type resetUsers struct {
	journal *journal
	user    *model.User
	err     error
}

func (u *resetUsers) ExistsByEmail(context.Context, model.Email) (bool, error) { return false, nil }
func (u *resetUsers) Save(context.Context, *model.User) error                  { return nil }
func (u *resetUsers) FindByID(context.Context, string) (*model.User, error) {
	return nil, model.ErrUserNotFound
}
func (u *resetUsers) FindByEmail(context.Context, model.Email) (*model.User, error) {
	u.journal.record("find-user")
	if u.err != nil {
		return nil, u.err
	}
	if u.user == nil {
		return nil, model.ErrUserNotFound
	}
	return u.user, nil
}

type fakeResets struct {
	journal        *journal
	requested      int
	requestedSince time.Time
	added          []*model.PasswordReset
	locked         *model.PasswordReset
	lockErr        error
	addErr         error
	lookupErr      error
	used           []*model.PasswordReset
}

func (r *fakeResets) LockRequestsOf(context.Context, string) error {
	r.journal.record("lock-requests")
	return r.lockErr
}

func (r *fakeResets) CountRequestsSince(_ context.Context, _ string, since time.Time) (int, error) {
	r.journal.record("count")
	r.requestedSince = since
	return r.requested, nil
}

func (r *fakeResets) SupersedePending(context.Context, string, time.Time) error {
	r.journal.record("supersede")
	return nil
}

func (r *fakeResets) Add(_ context.Context, reset *model.PasswordReset) error {
	r.journal.record("add")
	if r.addErr != nil {
		return r.addErr
	}
	r.added = append(r.added, reset)
	return nil
}

func (r *fakeResets) LockByTokenHash(_ context.Context, hash string) (*model.PasswordReset, error) {
	r.journal.record("lock-token")
	if r.lookupErr != nil {
		return nil, r.lookupErr
	}
	if r.locked == nil || r.locked.TokenHash() != hash {
		return nil, model.ErrPasswordResetRejected
	}
	return r.locked, nil
}

func (r *fakeResets) MarkUsed(_ context.Context, reset *model.PasswordReset) error {
	r.journal.record("mark-used")
	r.used = append(r.used, reset)
	return nil
}

type fakeResetTokens struct {
	journal *journal
	err     error
}

func (g *fakeResetTokens) NewToken() (model.ResetToken, error) {
	g.journal.record("new-token")
	token, _ := model.NewResetToken(resetTokenValue)
	return token, g.err
}

type fakeResetSender struct {
	journal    *journal
	deliveries []out.PasswordResetDelivery
	err        error
}

func (s *fakeResetSender) Send(_ context.Context, delivery out.PasswordResetDelivery) error {
	s.journal.record("send")
	s.deliveries = append(s.deliveries, delivery)
	return s.err
}

type resetHasher struct {
	journal *journal
	hashed  []string
	err     error
}

func (h *resetHasher) Hash(password model.Password) (string, error) {
	h.journal.record("hash")
	h.hashed = append(h.hashed, password.Reveal())
	return hashedPassword, h.err
}

func (h *resetHasher) Verify(string, string) bool { return false }

type fakePasswordUpdater struct {
	journal *journal
	userID  string
	hash    string
	err     error
}

func (p *fakePasswordUpdater) UpdatePasswordHash(_ context.Context, userID, hash string, _ time.Time) error {
	p.journal.record("update-password")
	p.userID, p.hash = userID, hash
	return p.err
}

type fakeRevoker struct {
	journal *journal
	userID  string
	err     error
}

func (r *fakeRevoker) RevokeAllActiveByUser(_ context.Context, userID string, _ time.Time) (int, error) {
	r.journal.record("revoke-sessions")
	r.userID = userID
	return 2, r.err
}

type requestResetFixture struct {
	useCase      *RequestPasswordReset
	users        *resetUsers
	resets       *fakeResets
	tokens       *fakeResetTokens
	sender       *fakeResetSender
	transactions *fakeTransactions
	journal      *journal
}

func newRequestResetFixture(user *model.User) *requestResetFixture {
	j := &journal{}
	f := &requestResetFixture{
		users:        &resetUsers{journal: j, user: user},
		resets:       &fakeResets{journal: j},
		tokens:       &fakeResetTokens{journal: j},
		sender:       &fakeResetSender{journal: j},
		transactions: &fakeTransactions{journal: j},
		journal:      j,
	}
	f.useCase = NewRequestPasswordReset(RequestPasswordResetPorts{
		Users: f.users, Resets: f.resets, Tokens: f.tokens, Sender: f.sender,
		IDs: &fakeIDs{next: []string{"reset-1"}}, Clock: fakeClock{}, Transactions: f.transactions,
	})
	return f
}

func resetRequest() in.RequestPasswordResetCommand {
	return in.RequestPasswordResetCommand{Email: " Ana@Example.com "}
}

func TestRequestResetStoresTheTokenInATransactionAndSendsItAfterTheCommit(t *testing.T) {
	f := newRequestResetFixture(storedUser(t, model.UserActive, model.RoleClient))

	err := f.useCase.RequestReset(context.Background(), resetRequest())

	if err != nil {
		t.Fatalf("RequestReset() error = %v", err)
	}
	wantSteps := []string{"find-user", "new-token", "begin", "lock-requests", "count", "supersede", "add", "commit", "send"}
	if !reflect.DeepEqual(f.journal.steps, wantSteps) {
		t.Errorf("steps = %v, want %v", f.journal.steps, wantSteps)
	}
	if len(f.resets.added) != 1 || f.resets.added[0].UserID() != "user-1" || f.resets.added[0].TokenHash() != model.HashOpaqueToken(resetTokenValue) {
		t.Fatalf("added = %+v, want the request of user-1 holding the digest of the token", f.resets.added)
	}
	if len(f.sender.deliveries) != 1 {
		t.Fatalf("deliveries = %d, want 1", len(f.sender.deliveries))
	}
	delivery := f.sender.deliveries[0]
	if delivery.UserID != "user-1" || delivery.Email.String() != "ana@example.com" || delivery.Token.Reveal() != resetTokenValue ||
		!delivery.ExpiresAt.Equal(registeredAt.Add(time.Hour)) {
		t.Errorf("delivery = %+v, want the account, its email, the token and the expiry", delivery)
	}
}

func TestRequestResetCountsTheRequestsOfTheLastRollingHour(t *testing.T) {
	f := newRequestResetFixture(storedUser(t, model.UserActive, model.RoleClient))
	f.resets.requested = 2

	err := f.useCase.RequestReset(context.Background(), resetRequest())

	if err != nil || !f.resets.requestedSince.Equal(registeredAt.Add(-time.Hour)) || len(f.sender.deliveries) != 1 {
		t.Errorf("error = %v, counted since %v, deliveries = %d, want nil, %v and a message for the third request",
			err, f.resets.requestedSince, len(f.sender.deliveries), registeredAt.Add(-time.Hour))
	}
}

func TestRequestResetAnswersTheSameAndSendsNothingWhenThereIsNothingToSend(t *testing.T) {
	cases := map[string]struct {
		user      func(*testing.T) *model.User
		requested int
		lockErr   error
		wantSteps []string
	}{
		"unknown email": {
			func(*testing.T) *model.User { return nil }, 0, nil,
			[]string{"find-user", "new-token"},
		},
		"locked account": {
			func(t *testing.T) *model.User { return storedUser(t, model.UserLocked, model.RoleClient) }, 0, nil,
			[]string{"find-user", "new-token"},
		},
		"fourth request in the hour": {
			func(t *testing.T) *model.User { return storedUser(t, model.UserActive, model.RoleClient) }, 3, nil,
			[]string{"find-user", "new-token", "begin", "lock-requests", "count", "commit"},
		},
		"account deleted meanwhile": {
			func(t *testing.T) *model.User { return storedUser(t, model.UserActive, model.RoleClient) }, 0, model.ErrUserNotFound,
			[]string{"find-user", "new-token", "begin", "lock-requests", "commit"},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newRequestResetFixture(c.user(t))
			f.resets.requested, f.resets.lockErr = c.requested, c.lockErr

			err := f.useCase.RequestReset(context.Background(), resetRequest())

			if err != nil {
				t.Fatalf("RequestReset() error = %v, want the same success as for a real account", err)
			}
			if !reflect.DeepEqual(f.journal.steps, c.wantSteps) {
				t.Errorf("steps = %v, want %v", f.journal.steps, c.wantSteps)
			}
			if len(f.resets.added) != 0 || len(f.sender.deliveries) != 0 {
				t.Errorf("added = %d, sent = %d, want nothing created and nothing sent", len(f.resets.added), len(f.sender.deliveries))
			}
		})
	}
}

func TestRequestResetRejectsAMalformedEmailBeforeAnyWork(t *testing.T) {
	f := newRequestResetFixture(nil)

	err := f.useCase.RequestReset(context.Background(), in.RequestPasswordResetCommand{Email: "nope"})

	if !errors.Is(err, model.ErrInvalidEmail) || len(f.journal.steps) != 0 {
		t.Errorf("error = %v, steps = %v, want ErrInvalidEmail and no work", err, f.journal.steps)
	}
}

func TestRequestResetKeepsTheAnswerWhenTheSenderFailsAndLogsNeitherTokenNorAddress(t *testing.T) {
	f := newRequestResetFixture(storedUser(t, model.UserActive, model.RoleClient))
	f.sender.err = errors.New("the queue is full")
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	err := f.useCase.RequestReset(context.Background(), resetRequest())

	if err != nil || !f.transactions.committed {
		t.Errorf("error = %v, committed = %v, want nil and the request kept", err, f.transactions.committed)
	}
	for _, text := range []string{"level=WARN", "user-1", "the queue is full"} {
		if !strings.Contains(logs.String(), text) {
			t.Errorf("log = %q, want a WARN with %q", logs.String(), text)
		}
	}
	for _, secret := range []string{resetTokenValue, model.HashOpaqueToken(resetTokenValue), "ana@example.com"} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("log = %q, leaks %q", logs.String(), secret)
		}
	}
}

func TestRequestResetFailuresOfTheServiceAreErrorsAndSendNothing(t *testing.T) {
	cases := map[string]func(*requestResetFixture){
		"lookup fails": func(f *requestResetFixture) { f.users.err = errors.New("database down") },
		"token fails":  func(f *requestResetFixture) { f.tokens.err = errors.New("no entropy") },
		"insert fails": func(f *requestResetFixture) { f.resets.addErr = errors.New("insert failed") },
		"lock fails":   func(f *requestResetFixture) { f.resets.lockErr = errors.New("lock failed") },
	}
	for name, arrange := range cases {
		t.Run(name, func(t *testing.T) {
			f := newRequestResetFixture(storedUser(t, model.UserActive, model.RoleClient))
			arrange(f)

			err := f.useCase.RequestReset(context.Background(), resetRequest())

			if err == nil || len(f.sender.deliveries) != 0 {
				t.Errorf("error = %v, sent = %d, want an error and nothing sent", err, len(f.sender.deliveries))
			}
		})
	}
}

type resetFixture struct {
	useCase      *ResetPassword
	resets       *fakeResets
	hasher       *resetHasher
	passwords    *fakePasswordUpdater
	sessions     *fakeRevoker
	transactions *fakeTransactions
	journal      *journal
}

func newResetFixture(t *testing.T) *resetFixture {
	t.Helper()
	j := &journal{}
	token, _ := model.NewResetToken(resetTokenValue)
	f := &resetFixture{
		resets:       &fakeResets{journal: j, locked: model.NewPasswordReset("reset-1", "user-1", token, registeredAt.Add(-10*time.Minute))},
		hasher:       &resetHasher{journal: j},
		passwords:    &fakePasswordUpdater{journal: j},
		sessions:     &fakeRevoker{journal: j},
		transactions: &fakeTransactions{journal: j},
		journal:      j,
	}
	f.useCase = NewResetPassword(ResetPasswordPorts{
		Resets: f.resets, Hasher: f.hasher, Passwords: f.passwords, Sessions: f.sessions,
		Clock: fakeClock{}, Transactions: f.transactions,
	})
	return f
}

func resetCommand() in.ResetPasswordCommand {
	return in.ResetPasswordCommand{Token: resetTokenValue, Password: newPassword}
}

func TestResetChangesThePasswordConsumesTheTokenAndRevokesTheSessionsInOneTransaction(t *testing.T) {
	f := newResetFixture(t)

	err := f.useCase.Reset(context.Background(), resetCommand())

	if err != nil {
		t.Fatalf("Reset() error = %v", err)
	}
	wantSteps := []string{"hash", "begin", "lock-token", "mark-used", "update-password", "revoke-sessions", "commit"}
	if !reflect.DeepEqual(f.journal.steps, wantSteps) {
		t.Errorf("steps = %v, want %v", f.journal.steps, wantSteps)
	}
	if !reflect.DeepEqual(f.hasher.hashed, []string{newPassword}) || f.passwords.userID != "user-1" || f.passwords.hash != hashedPassword || f.sessions.userID != "user-1" {
		t.Errorf("hashed = %v, updated %q with %q, revoked %q, want the new password stored for user-1 and its sessions revoked",
			f.hasher.hashed, f.passwords.userID, f.passwords.hash, f.sessions.userID)
	}
	if len(f.resets.used) != 1 || f.resets.used[0].UsedAt() == nil || !f.resets.used[0].UsedAt().Equal(registeredAt) {
		t.Errorf("used = %+v, want the request consumed at %v", f.resets.used, registeredAt)
	}
}

func TestResetValidatesTheTokenAndThePasswordBeforeAnyWork(t *testing.T) {
	cases := map[string]struct {
		command in.ResetPasswordCommand
		want    error
	}{
		"malformed token": {in.ResetPasswordCommand{Token: "abc", Password: newPassword}, model.ErrInvalidResetToken},
		"weak password":   {in.ResetPasswordCommand{Token: resetTokenValue, Password: "weak"}, model.ErrWeakPassword},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newResetFixture(t)

			err := f.useCase.Reset(context.Background(), c.command)

			if !errors.Is(err, c.want) || len(f.journal.steps) != 0 {
				t.Errorf("error = %v, steps = %v, want %v and no work: the token stays usable", err, f.journal.steps, c.want)
			}
		})
	}
}

func TestResetRejectsAnUnusableTokenWithTheSameErrorAndChangesNothing(t *testing.T) {
	token, _ := model.NewResetToken(resetTokenValue)
	usedAt := registeredAt.Add(-time.Minute)
	cases := map[string]func(*fakeResets){
		"unknown or superseded": func(r *fakeResets) { r.locked = nil },
		"expired": func(r *fakeResets) {
			r.locked = model.NewPasswordReset("reset-1", "user-1", token, registeredAt.Add(-2*time.Hour))
		},
		"already used": func(r *fakeResets) {
			r.locked = model.RestorePasswordReset("reset-1", "user-1", token.Hash(), registeredAt.Add(time.Minute), &usedAt)
		},
		"inactive account": func(r *fakeResets) { r.lookupErr = model.ErrPasswordResetRejected },
	}
	for name, arrange := range cases {
		t.Run(name, func(t *testing.T) {
			f := newResetFixture(t)
			arrange(f.resets)

			err := f.useCase.Reset(context.Background(), resetCommand())

			if !errors.Is(err, model.ErrPasswordResetRejected) {
				t.Fatalf("Reset() error = %v, want ErrPasswordResetRejected", err)
			}
			if strings.Contains(strings.Join(f.journal.steps, ","), "update-password") || len(f.resets.used) != 0 || f.transactions.committed {
				t.Errorf("steps = %v, used = %d, committed = %v, want nothing written", f.journal.steps, len(f.resets.used), f.transactions.committed)
			}
		})
	}
}

func TestResetFailuresRollBackEverything(t *testing.T) {
	cases := map[string]func(*resetFixture){
		"hashing fails":    func(f *resetFixture) { f.hasher.err = errors.New("bcrypt failed") },
		"update fails":     func(f *resetFixture) { f.passwords.err = errors.New("update failed") },
		"revocation fails": func(f *resetFixture) { f.sessions.err = errors.New("revoke failed") },
	}
	for name, arrange := range cases {
		t.Run(name, func(t *testing.T) {
			f := newResetFixture(t)
			arrange(f)

			err := f.useCase.Reset(context.Background(), resetCommand())

			if err == nil || f.transactions.committed {
				t.Errorf("error = %v, committed = %v, want an error and a rollback", err, f.transactions.committed)
			}
		})
	}
}
