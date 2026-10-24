//go:build integration

package persistence

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/security"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/system"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/application/usecase"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// countingAttempts is an out.PasswordChangeAttempts that only counts what the use case tells it.
type countingAttempts struct{ failures, cleared int }

func (a *countingAttempts) Locked(context.Context, string) (time.Duration, error) { return 0, nil }
func (a *countingAttempts) RecordFailure(context.Context, string) error           { a.failures++; return nil }
func (a *countingAttempts) Clear(context.Context, string) error                   { a.cleared++; return nil }

// unreachableAttempts is a limit store that cannot be reached.
type unreachableAttempts struct{ countingAttempts }

func (unreachableAttempts) Locked(context.Context, string) (time.Duration, error) {
	return 0, errors.New("redis: connection refused")
}
func (unreachableAttempts) RecordFailure(context.Context, string) error {
	return errors.New("redis: connection refused")
}
func (unreachableAttempts) Clear(context.Context, string) error {
	return errors.New("redis: connection refused")
}

type failingSessions struct{}

func (failingSessions) Issue(context.Context, in.IssueRefreshTokenCommand) (in.IssuedRefreshToken, error) {
	return in.IssuedRefreshToken{}, errors.New("the refresh token could not be stored")
}

func (f fixture) changePassword(attempts out.PasswordChangeAttempts, sessions in.IssueRefreshToken) *usecase.ChangePassword {
	return usecase.NewChangePassword(usecase.ChangePasswordPorts{
		Users: f.users, Hashes: f.users, Passwords: f.users, Sessions: NewRefreshTokenRepository(f.pool),
		Hasher: security.NewBcryptHasher(4), Attempts: attempts, Tokens: fixedTokens{}, Refresh: sessions,
		Clock: system.Clock{}, Transactions: f.transactions,
	})
}

func (f fixture) realSessions() in.IssueRefreshToken {
	return usecase.NewIssueRefreshToken(NewRefreshTokenRepository(f.pool), system.UUIDGenerator{}, system.Clock{}, 7*24*time.Hour)
}

// userWithPassword registers a user whose password is currentPassword and who has two open sessions.
func (f fixture) userWithPassword(t *testing.T, ctx context.Context) *model.User {
	t.Helper()
	user := f.registeredUser(t, ctx)
	current, _ := model.NewPassword(currentPassword)
	hash, err := security.NewBcryptHasher(4).Hash(current)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if err := f.users.UpdatePasswordHash(ctx, user.ID(), hash, time.Now()); err != nil {
		t.Fatalf("UpdatePasswordHash() error = %v", err)
	}
	f.openSessions(t, ctx, user.ID(), 2)
	return user
}

func changeFor(user *model.User, current, replacement string) in.ChangePasswordCommand {
	return in.ChangePasswordCommand{UserID: user.ID(), CurrentPassword: current, NewPassword: replacement, UserAgent: "integration"}
}

func TestChangePasswordReplacesTheHashRevokesEverySessionAndOpensOneInTheSameTransaction(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := f.userWithPassword(t, ctx)
	attempts := &countingAttempts{}

	session, err := f.changePassword(attempts, f.realSessions()).Change(ctx, changeFor(user, currentPassword, resetPassword))

	if err != nil {
		t.Fatalf("Change() error = %v", err)
	}
	if !security.NewBcryptHasher(4).Verify(f.passwordHash(t, ctx, user.ID()), resetPassword) {
		t.Error("the stored hash does not match the new password")
	}
	if active := f.activeSessions(t, ctx, user.ID()); active != 1 || session.RefreshToken == "" || session.AccessToken == "" {
		t.Errorf("active sessions = %d, session = %+v, want only the one just opened", active, session)
	}
	if attempts.cleared != 1 || attempts.failures != 0 {
		t.Errorf("cleared = %d, failures = %d, want the count forgotten once", attempts.cleared, attempts.failures)
	}
}

func TestChangePasswordWithAWrongOrUnchangedPasswordChangesNothing(t *testing.T) {
	cases := map[string]struct {
		current, replacement string
		want                 error
		failures             int
	}{
		"wrong current": {"Wrong12345", resetPassword, model.ErrWrongCurrentPassword, 1},
		"unchanged":     {currentPassword, currentPassword, model.ErrPasswordUnchanged, 0},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f, ctx := newFixture(t), context.Background()
			user := f.userWithPassword(t, ctx)
			before := f.passwordHash(t, ctx, user.ID())
			attempts := &countingAttempts{}

			_, err := f.changePassword(attempts, f.realSessions()).Change(ctx, changeFor(user, c.current, c.replacement))

			if !errors.Is(err, c.want) || f.passwordHash(t, ctx, user.ID()) != before || f.activeSessions(t, ctx, user.ID()) != 2 || attempts.failures != c.failures {
				t.Errorf("error = %v, failures = %d, active sessions = %d, want %v, %d failure(s), the hash and the 2 sessions untouched",
					err, attempts.failures, f.activeSessions(t, ctx, user.ID()), c.want, c.failures)
			}
		})
	}
}

func TestChangePasswordIsAllOrNothingWhenTheNewSessionCannotBeStored(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := f.userWithPassword(t, ctx)
	before := f.passwordHash(t, ctx, user.ID())
	attempts := &countingAttempts{}

	_, err := f.changePassword(attempts, failingSessions{}).Change(ctx, changeFor(user, currentPassword, resetPassword))

	if err == nil || f.passwordHash(t, ctx, user.ID()) != before || f.activeSessions(t, ctx, user.ID()) != 2 || attempts.failures+attempts.cleared != 0 {
		t.Errorf("error = %v, active sessions = %d, want a failure that left the hash and the 2 sessions as they were and counted nothing", err, f.activeSessions(t, ctx, user.ID()))
	}
}

func TestChangePasswordWritesNoEvent(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	reader := openPool(t, readerURLVariable)
	user := f.userWithPassword(t, ctx)
	var before, after int
	count := `SELECT count(*) FROM auth.outbox_event WHERE aggregate_id = $1`
	if err := reader.QueryRow(ctx, count, user.ID()).Scan(&before); err != nil {
		t.Fatalf("outbox query error = %v", err)
	}

	if _, err := f.changePassword(&countingAttempts{}, f.realSessions()).Change(ctx, changeFor(user, currentPassword, resetPassword)); err != nil {
		t.Fatalf("Change() error = %v", err)
	}

	if err := reader.QueryRow(ctx, count, user.ID()).Scan(&after); err != nil || after != before {
		t.Errorf("outbox events = %d (%v), want the %d of before: the change publishes nothing", after, err, before)
	}
}

func TestLockPasswordHashOfWaitsForTheTransactionThatHoldsTheAccount(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := f.userWithPassword(t, ctx)
	waiting := make(chan error, 1)

	err := f.transactions.WithinTransaction(ctx, func(ctx context.Context) error {
		if _, err := f.users.LockPasswordHashOf(ctx, user.ID()); err != nil {
			return err
		}
		go func() {
			waiting <- f.transactions.WithinTransaction(context.Background(), func(ctx context.Context) error {
				_, err := f.users.LockPasswordHashOf(ctx, user.ID())
				return err
			})
		}()
		select {
		case <-waiting:
			return errors.New("the second change took the account while the first transaction held it")
		case <-time.After(500 * time.Millisecond):
			return nil
		}
	})

	if err != nil {
		t.Fatalf("first transaction error = %v", err)
	}
	if err := <-waiting; err != nil {
		t.Errorf("second transaction error = %v, want it to go on once the first ended", err)
	}
}

func TestLockPasswordHashOfAnAccountThatDoesNotExistIsNotFound(t *testing.T) {
	f, ctx := newFixture(t), context.Background()

	err := f.transactions.WithinTransaction(ctx, func(ctx context.Context) error {
		_, err := f.users.LockPasswordHashOf(ctx, newUUID(t))
		return err
	})

	if !errors.Is(err, model.ErrUserNotFound) {
		t.Errorf("LockPasswordHashOf() error = %v, want ErrUserNotFound", err)
	}
}

func TestChangePasswordStillWorksWhenTheLimitStoreCannotBeReached(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := f.userWithPassword(t, ctx)

	_, err := f.changePassword(unreachableAttempts{}, f.realSessions()).Change(ctx, changeFor(user, currentPassword, resetPassword))

	if err != nil || !security.NewBcryptHasher(4).Verify(f.passwordHash(t, ctx, user.ID()), resetPassword) || f.activeSessions(t, ctx, user.ID()) != 1 {
		t.Errorf("error = %v, active sessions = %d, want the change to go on without the limit (fail open)", err, f.activeSessions(t, ctx, user.ID()))
	}
}
