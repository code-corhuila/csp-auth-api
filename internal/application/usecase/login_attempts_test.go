package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const clientAddress = "203.0.113.7"

// loginAttempts is an in-memory out.LoginAttempts that applies the default policy like the real store.
type loginAttempts struct {
	policy   model.LoginAttemptPolicy
	failures map[string]int
	locked   map[string]time.Duration
	err      error
	cleared  []string
}

func newLoginAttempts() *loginAttempts {
	return &loginAttempts{policy: model.DefaultLoginAttemptPolicy(), failures: map[string]int{}, locked: map[string]time.Duration{}}
}

func (a *loginAttempts) LockedFor(_ context.Context, client string) (time.Duration, error) {
	return a.locked[client], a.err
}

func (a *loginAttempts) RecordFailure(_ context.Context, client string) (model.LoginFailureOutcome, error) {
	if a.err != nil {
		return model.LoginFailureOutcome{}, a.err
	}
	a.failures[client]++
	outcome := model.LoginFailureOutcome{Attempts: a.failures[client]}
	if a.policy.Reached(a.failures[client]) {
		a.locked[client] = a.policy.Lock
		outcome.LockedFor = a.policy.Lock
	}
	return outcome, nil
}

func (a *loginAttempts) Clear(_ context.Context, client string) error {
	a.cleared = append(a.cleared, client)
	delete(a.failures, client)
	return a.err
}

func newLimitedLoginFixture(t *testing.T, attempts *loginAttempts) *loginFixture {
	f := newLoginFixture(storedUser(t, model.UserActive, model.RoleClient))
	f.useCase.attempts = attempts
	return f
}

func loginFrom(f *loginFixture, address, password string) error {
	_, err := f.useCase.Login(context.Background(), in.LoginUserCommand{Email: "ana@example.com", Password: password, ClientIP: address})
	return err
}

func TestLoginRejectsTheAttemptAfterTenFailuresEvenWithTheRightPassword(t *testing.T) {
	attempts := newLoginAttempts()
	f := newLimitedLoginFixture(t, attempts)
	for range 10 {
		if err := loginFrom(f, clientAddress, "Wrong1234"); !errors.Is(err, model.ErrInvalidCredentials) {
			t.Fatalf("failed attempt: error = %v, want ErrInvalidCredentials", err)
		}
	}
	checked := len(f.hasher.checked)

	err := loginFrom(f, clientAddress, rightPass)

	var limited *model.LoginRateLimitedError
	if !errors.As(err, &limited) || limited.RetryAfter != 5*time.Minute {
		t.Fatalf("error = %v, want a rate limit with 5m left", err)
	}
	if len(f.hasher.checked) != checked || len(f.sessions.commands) != 0 {
		t.Errorf("a locked client must not reach the password check or open a session")
	}
}

func TestLoginCountsEachClientAddressApart(t *testing.T) {
	attempts := newLoginAttempts()
	f := newLimitedLoginFixture(t, attempts)
	for range 10 {
		_ = loginFrom(f, clientAddress, "Wrong1234")
	}

	if err := loginFrom(f, "198.51.100.9", rightPass); err != nil {
		t.Errorf("another address: error = %v, want a normal login", err)
	}
}

func TestLoginWorksAgainOnceTheLockHasElapsed(t *testing.T) {
	attempts := newLoginAttempts()
	f := newLimitedLoginFixture(t, attempts)
	for range 10 {
		_ = loginFrom(f, clientAddress, "Wrong1234")
	}
	delete(attempts.locked, clientAddress)
	delete(attempts.failures, clientAddress)

	if err := loginFrom(f, clientAddress, rightPass); err != nil {
		t.Errorf("after the cooldown: error = %v, want a normal login", err)
	}
}

func TestLoginClearsTheFailuresOfTheClientOnSuccess(t *testing.T) {
	attempts := newLoginAttempts()
	f := newLimitedLoginFixture(t, attempts)
	_ = loginFrom(f, clientAddress, "Wrong1234")

	if err := loginFrom(f, clientAddress, rightPass); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	if len(attempts.cleared) != 1 || attempts.cleared[0] != clientAddress || attempts.failures[clientAddress] != 0 {
		t.Errorf("cleared = %v, failures = %v, want the client cleared", attempts.cleared, attempts.failures)
	}
}

func TestLoginCountsAnUnknownEmailAsAFailure(t *testing.T) {
	attempts := newLoginAttempts()
	f := newLimitedLoginFixture(t, attempts)
	f.users.user = nil

	_, err := f.useCase.Login(context.Background(), in.LoginUserCommand{Email: "ghost@example.com", Password: rightPass, ClientIP: clientAddress})

	if !errors.Is(err, model.ErrInvalidCredentials) || attempts.failures[clientAddress] != 1 {
		t.Errorf("error = %v, failures = %d, want a counted credential failure", err, attempts.failures[clientAddress])
	}
}

func TestLoginDoesNotCountALockedAccountOrAnInternalError(t *testing.T) {
	attempts := newLoginAttempts()
	locked := newLimitedLoginFixture(t, attempts)
	locked.users.user = storedUser(t, model.UserLocked, model.RoleClient)
	broken := newLimitedLoginFixture(t, attempts)
	broken.users.err = errors.New("boom")

	_ = loginFrom(locked, clientAddress, rightPass)
	_ = loginFrom(broken, clientAddress, rightPass)

	if attempts.failures[clientAddress] != 0 {
		t.Errorf("failures = %d, want 0: only wrong credentials count", attempts.failures[clientAddress])
	}
}

func TestLoginGoesOnWhenTheAttemptStoreFails(t *testing.T) {
	attempts := newLoginAttempts()
	attempts.err = errors.New("redis down")
	f := newLimitedLoginFixture(t, attempts)

	if err := loginFrom(f, clientAddress, rightPass); err != nil {
		t.Errorf("right password: error = %v, want the login to go on", err)
	}
	if err := loginFrom(f, clientAddress, "Wrong1234"); !errors.Is(err, model.ErrInvalidCredentials) {
		t.Errorf("wrong password: error = %v, want ErrInvalidCredentials, not the store failure", err)
	}
}

func TestLoginWithoutAClientAddressIsNotLimited(t *testing.T) {
	attempts := newLoginAttempts()
	f := newLimitedLoginFixture(t, attempts)

	for range 12 {
		_ = loginFrom(f, "", "Wrong1234")
	}

	if err := loginFrom(f, "", rightPass); err != nil || len(attempts.failures) != 0 {
		t.Errorf("error = %v, failures = %v, want an unlimited login and nothing counted", err, attempts.failures)
	}
}
