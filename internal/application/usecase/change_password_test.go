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

// passwordAttempts is an in-memory out.PasswordChangeAttempts that applies the default policy like the real store.
type passwordAttempts struct {
	journal  *journal
	policy   model.LoginAttemptPolicy
	failures map[string]int
	locked   map[string]time.Duration
	err      error
	cleared  []string
}

func newPasswordAttempts(j *journal) *passwordAttempts {
	return &passwordAttempts{journal: j, policy: model.DefaultPasswordChangePolicy(), failures: map[string]int{}, locked: map[string]time.Duration{}}
}

func (a *passwordAttempts) Locked(_ context.Context, userID string) (time.Duration, error) {
	a.journal.record("check-lock")
	return a.locked[userID], a.err
}

func (a *passwordAttempts) RecordFailure(_ context.Context, userID string) error {
	a.journal.record("record-failure")
	if a.err != nil {
		return a.err
	}
	a.failures[userID]++
	if a.policy.Reached(a.failures[userID]) {
		a.locked[userID] = a.policy.Lock
	}
	return nil
}

func (a *passwordAttempts) Clear(_ context.Context, userID string) error {
	a.journal.record("clear")
	a.cleared = append(a.cleared, userID)
	delete(a.failures, userID)
	return a.err
}

type fakeHashLocker struct {
	journal *journal
	err     error
}

func (l *fakeHashLocker) LockPasswordHashOf(context.Context, string) (string, error) {
	l.journal.record("lock-hash")
	return currentHash, l.err
}

type changeFixture struct {
	useCase      *ChangePassword
	users        *profileUsers
	locker       *fakeHashLocker
	hasher       *resetHasher
	passwords    *fakePasswordUpdater
	revoker      *fakeRevoker
	attempts     *passwordAttempts
	refresh      *loginSessions
	tokens       loginTokens
	transactions *fakeTransactions
	journal      *journal
}

func newChangeFixture(t *testing.T) *changeFixture {
	t.Helper()
	j := &journal{}
	f := &changeFixture{
		users:        &profileUsers{journal: j, user: storedUser(t, model.UserActive, model.RoleClient)},
		locker:       &fakeHashLocker{journal: j},
		hasher:       &resetHasher{journal: j},
		passwords:    &fakePasswordUpdater{journal: j},
		revoker:      &fakeRevoker{journal: j},
		attempts:     newPasswordAttempts(j),
		refresh:      &loginSessions{},
		transactions: &fakeTransactions{journal: j},
		journal:      j,
	}
	f.build()
	return f
}

// build wires the use case again, after a test replaced one of the fakes.
func (f *changeFixture) build() {
	f.useCase = NewChangePassword(ChangePasswordPorts{
		Users: f.users, Hashes: f.locker, Passwords: f.passwords, Sessions: f.revoker, Hasher: f.hasher,
		Attempts: f.attempts, Tokens: f.tokens, Refresh: f.refresh, Clock: fakeClock{}, Transactions: f.transactions,
	})
}

func changeCommand(current, replacement string) in.ChangePasswordCommand {
	return in.ChangePasswordCommand{UserID: "user-1", CurrentPassword: current, NewPassword: replacement, UserAgent: "portal/1.0"}
}

func (f *changeFixture) change(current, replacement string) (in.LoginUserResult, error) {
	return f.useCase.Change(context.Background(), changeCommand(current, replacement))
}

func TestChangePasswordReplacesTheHashRevokesTheSessionsAndOpensANewOneInOneTransaction(t *testing.T) {
	f := newChangeFixture(t)

	session, err := f.change(currentPassword, newPassword)

	if err != nil {
		t.Fatalf("Change() error = %v", err)
	}
	wantSteps := []string{"check-lock", "begin", "lock-hash", "find-user", "verify", "verify", "hash", "update-password", "revoke-sessions", "commit", "clear"}
	if !reflect.DeepEqual(f.journal.steps, wantSteps) {
		t.Errorf("steps = %v, want %v", f.journal.steps, wantSteps)
	}
	if !reflect.DeepEqual(f.hasher.hashed, []string{newPassword}) || f.passwords.userID != "user-1" || f.passwords.hash != hashedPassword || f.revoker.userID != "user-1" {
		t.Errorf("hashed = %v, updated %q with %q, revoked %q, want the new password stored for user-1 and every session revoked",
			f.hasher.hashed, f.passwords.userID, f.passwords.hash, f.revoker.userID)
	}
	if session.AccessToken != accessSecret || session.RefreshToken != "opaque-refresh" || session.User.ID != "user-1" || len(f.refresh.commands) != 1 || f.refresh.commands[0].UserAgent != "portal/1.0" {
		t.Errorf("session = %+v, refresh commands = %+v, want a fresh session for the device that asked", session, f.refresh.commands)
	}
	if !reflect.DeepEqual(f.attempts.cleared, []string{"user-1"}) {
		t.Errorf("cleared = %v, want the failures of user-1 forgotten", f.attempts.cleared)
	}
}

func TestChangePasswordRejectsAWrongCurrentPasswordCountsItAndChangesNothing(t *testing.T) {
	f := newChangeFixture(t)

	_, err := f.change("WrongSecret1", newPassword)

	if !errors.Is(err, model.ErrWrongCurrentPassword) {
		t.Fatalf("Change() error = %v, want ErrWrongCurrentPassword", err)
	}
	wantSteps := []string{"check-lock", "begin", "lock-hash", "find-user", "verify", "rollback", "record-failure"}
	if !reflect.DeepEqual(f.journal.steps, wantSteps) {
		t.Errorf("steps = %v, want %v: the new password is not compared before the current one is proved", f.journal.steps, wantSteps)
	}
	if f.passwords.hash != "" || f.revoker.userID != "" || len(f.refresh.commands) != 0 || f.attempts.failures["user-1"] != 1 {
		t.Errorf("stored %q, revoked %q, sessions %d, failures %d, want nothing changed and one failure counted",
			f.passwords.hash, f.revoker.userID, len(f.refresh.commands), f.attempts.failures["user-1"])
	}
}

func TestChangePasswordRejectsTheCurrentPasswordAsTheNewOneWithoutCountingIt(t *testing.T) {
	f := newChangeFixture(t)

	_, err := f.change(currentPassword, currentPassword)

	if !errors.Is(err, model.ErrPasswordUnchanged) {
		t.Fatalf("Change() error = %v, want ErrPasswordUnchanged", err)
	}
	if f.passwords.hash != "" || f.revoker.userID != "" || f.transactions.committed || f.attempts.failures["user-1"] != 0 {
		t.Errorf("stored %q, revoked %q, committed = %v, failures = %d, want a rollback and no failure counted",
			f.passwords.hash, f.revoker.userID, f.transactions.committed, f.attempts.failures["user-1"])
	}
}

func TestChangePasswordValidatesBothPasswordsBeforeAnyWorkAndCountsNothing(t *testing.T) {
	cases := map[string]struct {
		current, replacement string
		want                 error
	}{
		"empty current":    {"", newPassword, model.ErrInvalidCurrentPassword},
		"current too long": {strings.Repeat("a", 73), newPassword, model.ErrInvalidCurrentPassword},
		"weak new":         {currentPassword, "weakpass", model.ErrWeakPassword},
		"new too long":     {currentPassword, "A1" + strings.Repeat("a", 71), model.ErrWeakPassword},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newChangeFixture(t)

			_, err := f.change(c.current, c.replacement)

			if !errors.Is(err, c.want) || len(f.journal.steps) != 0 {
				t.Errorf("Change() error = %v, steps = %v, want %v and no work at all", err, f.journal.steps, c.want)
			}
		})
	}
}

func TestChangePasswordRefusesALockedUserBeforeVerifyingEvenWithTheRightPassword(t *testing.T) {
	f := newChangeFixture(t)
	f.attempts.locked["user-1"] = 7 * time.Minute

	_, err := f.change(currentPassword, newPassword)

	var limited *model.PasswordChangeRateLimitedError
	if !errors.As(err, &limited) || limited.RetryAfter != 7*time.Minute {
		t.Fatalf("Change() error = %v, want a lock with 7m left", err)
	}
	if !reflect.DeepEqual(f.journal.steps, []string{"check-lock"}) {
		t.Errorf("steps = %v, want only the check of the lock: no transaction, no bcrypt", f.journal.steps)
	}
}

func TestChangePasswordLocksTheUserAfterFiveWrongPasswordsAndNoOneElse(t *testing.T) {
	f := newChangeFixture(t)
	for range 5 {
		if _, err := f.change("WrongSecret1", newPassword); !errors.Is(err, model.ErrWrongCurrentPassword) {
			t.Fatalf("failed attempt: error = %v, want ErrWrongCurrentPassword", err)
		}
	}

	_, sixth := f.change(currentPassword, newPassword)
	_, other := f.useCase.Change(context.Background(), in.ChangePasswordCommand{UserID: "user-2", CurrentPassword: "WrongSecret1", NewPassword: newPassword})

	var limited *model.PasswordChangeRateLimitedError
	if !errors.As(sixth, &limited) || limited.RetryAfter != 15*time.Minute {
		t.Errorf("sixth attempt: error = %v, want a lock with 15m left", sixth)
	}
	if errors.Is(other, model.ErrTooManyPasswordChangeAttempts) {
		t.Errorf("another user: error = %v, want it not to be locked", other)
	}
}

func TestChangePasswordGoesOnWhenTheLimitStoreFailsAndLogsNeitherPasswordNorUser(t *testing.T) {
	f := newChangeFixture(t)
	f.attempts.err = errors.New("redis: connection refused")
	logs := captureLoginLog(t)

	if _, err := f.change(currentPassword, newPassword); err != nil {
		t.Fatalf("Change() error = %v, want the change to go on without the limit", err)
	}

	for _, secret := range []string{currentPassword, newPassword, "user-1"} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("log %q must not contain %q", logs.String(), secret)
		}
	}
	if !strings.Contains(logs.String(), "level=WARN") {
		t.Errorf("log = %q, want a WARN about the limit", logs.String())
	}
}

func TestChangePasswordWritesNothingWhileTheLimitStoreIsPaused(t *testing.T) {
	f := newChangeFixture(t)
	f.attempts.err = out.ErrPasswordChangeAttemptsPaused
	logs := captureLoginLog(t)

	_, right := f.change(currentPassword, newPassword)
	_, wrong := f.change("WrongSecret1", newPassword)

	if right != nil || !errors.Is(wrong, model.ErrWrongCurrentPassword) || logs.Len() != 0 {
		t.Errorf("right = %v, wrong = %v, log = %q, want the change to go on, the credential failure and no log", right, wrong, logs)
	}
}

func TestChangePasswordRefusesAnAccountThatIsGoneOrLockedWithoutCountingIt(t *testing.T) {
	cases := map[string]struct {
		user *model.User
		want error
	}{
		"gone":   {nil, model.ErrUserNotFound},
		"locked": {storedUser(t, model.UserLocked, model.RoleClient), model.ErrUserLocked},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newChangeFixture(t)
			f.users.user = c.user

			_, err := f.change("WrongSecret1", newPassword)

			if !errors.Is(err, c.want) || f.attempts.failures["user-1"] != 0 || f.transactions.committed {
				t.Errorf("Change() error = %v, failures = %d, want %v, nothing counted and a rollback", err, f.attempts.failures["user-1"], c.want)
			}
		})
	}
}

func TestChangePasswordRollsBackEverythingWhenAStepFails(t *testing.T) {
	boom := errors.New("driver failure")
	cases := map[string]func(*changeFixture){
		"lock":         func(f *changeFixture) { f.locker.err = boom },
		"hash":         func(f *changeFixture) { f.hasher.err = boom },
		"update":       func(f *changeFixture) { f.passwords.err = boom },
		"revoke":       func(f *changeFixture) { f.revoker.err = boom },
		"access":       func(f *changeFixture) { f.tokens = loginTokens{err: boom}; f.build() },
		"refresh":      func(f *changeFixture) { f.refresh.err = boom; f.build() },
		"account gone": func(f *changeFixture) { f.locker.err = model.ErrUserNotFound },
	}
	for name, fail := range cases {
		t.Run(name, func(t *testing.T) {
			f := newChangeFixture(t)
			fail(f)

			_, err := f.change(currentPassword, newPassword)

			if err == nil || f.transactions.committed || len(f.attempts.cleared) != 0 || f.attempts.failures["user-1"] != 0 {
				t.Errorf("Change() error = %v, committed = %v, cleared = %v, failures = %d, want a rollback that counts nothing",
					err, f.transactions.committed, f.attempts.cleared, f.attempts.failures["user-1"])
			}
		})
	}
}
