package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// lockAudit records the events that LoginUser hands to the audit port.
type lockAudit struct {
	events []model.LoginLocked
	err    error
}

func (a *lockAudit) RecordLoginLocked(_ context.Context, event model.LoginLocked) error {
	a.events = append(a.events, event)
	return a.err
}

func newAuditedLoginFixture(t *testing.T) (*loginFixture, *lockAudit) {
	audit := &lockAudit{}
	f := newLimitedLoginFixture(t, newLoginAttempts())
	f.useCase.audit = audit
	return f, audit
}

// The negative test of the story (HU-AUTH-005, STRIDE S): the 11th failed login from one address is rejected
// even with the valid password, and it does not reach the password check or open a session.
func TestAuthzLoginRejectsTheEleventhFailedAttemptFromTheSameAddressEvenWithValidCredentials(t *testing.T) {
	f := newLimitedLoginFixture(t, newLoginAttempts())
	for range 10 {
		if err := loginFrom(f, clientAddress, "Wrong1234"); !errors.Is(err, model.ErrInvalidCredentials) {
			t.Fatalf("failed attempt: error = %v, want ErrInvalidCredentials", err)
		}
	}
	checked := len(f.hasher.checked)

	err := loginFrom(f, clientAddress, rightPass)

	var limited *model.LoginRateLimitedError
	if !errors.As(err, &limited) || limited.RetryAfter <= 0 {
		t.Fatalf("11th attempt: error = %v, want a rate limit with Retry-After", err)
	}
	if len(f.hasher.checked) != checked || len(f.sessions.commands) != 0 {
		t.Errorf("the 11th attempt must not check the password or open a session")
	}
}

func TestLoginWritesOneAuditEventWhenAFailureLocksTheAddress(t *testing.T) {
	f, audit := newAuditedLoginFixture(t)

	for range 10 {
		_ = loginFrom(f, clientAddress, "Wrong1234")
	}

	if len(audit.events) != 1 {
		t.Fatalf("events = %d, want exactly one for the lock", len(audit.events))
	}
	if want := model.NewLoginLocked(clientAddress, 10, fakeClock{}.Now(), 5*time.Minute); audit.events[0] != want {
		t.Errorf("event = %+v, want %+v", audit.events[0], want)
	}
}

func TestLoginWritesNoAuditEventBeforeTheLockOrWhileTheAddressIsLocked(t *testing.T) {
	f, audit := newAuditedLoginFixture(t)

	for range 9 {
		_ = loginFrom(f, clientAddress, "Wrong1234")
	}
	if len(audit.events) != 0 {
		t.Fatalf("events = %d after 9 failures, want none", len(audit.events))
	}
	_ = loginFrom(f, clientAddress, "Wrong1234")
	for range 3 {
		_ = loginFrom(f, clientAddress, rightPass)
	}

	if len(audit.events) != 1 {
		t.Errorf("events = %d, want only the one of the failure that locked: a rejected attempt is not a new lock", len(audit.events))
	}
}

func TestLoginKeepsFailingWithTheSameErrorWhenTheAuditCannotBeWritten(t *testing.T) {
	f, audit := newAuditedLoginFixture(t)
	audit.err = errors.New("audit sink down")

	var last error
	for range 10 {
		last = loginFrom(f, clientAddress, "Wrong1234")
	}

	if !errors.Is(last, model.ErrInvalidCredentials) {
		t.Errorf("error = %v, want ErrInvalidCredentials: the audit never changes the answer", last)
	}
}

func TestLoginWritesNoAuditEventWhenTheLimitStoreIsDown(t *testing.T) {
	attempts := newLoginAttempts()
	attempts.err = errors.New("redis down")
	f := newLimitedLoginFixture(t, attempts)
	audit := &lockAudit{}
	f.useCase.audit = audit

	for range 12 {
		_, _ = f.useCase.Login(context.Background(), in.LoginUserCommand{Email: "ana@example.com", Password: "Wrong1234", ClientIP: clientAddress})
	}

	if len(audit.events) != 0 {
		t.Errorf("events = %d, want none: nothing was locked", len(audit.events))
	}
}
