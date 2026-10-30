package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// A saturated hasher (model.ErrPasswordHasherBusy) is not a wrong password: every route that hashes answers it as it is, so the
// HTTP adapter can say 503, and nothing is counted against the caller.

func TestLoginAnswersTheBusyHasherAndDoesNotCountItAsAFailedLogin(t *testing.T) {
	f, counter := newSlowdownFixture(t)
	f.hasher.err = model.ErrPasswordHasherBusy
	audit := &lockAudit{}
	f.useCase.audit = audit

	for range 25 {
		err := failFrom(f, clientAddress, "ana@example.com")
		if !errors.Is(err, model.ErrPasswordHasherBusy) || errors.Is(err, model.ErrInvalidCredentials) {
			t.Fatalf("error = %v, want the busy hasher and not bad credentials", err)
		}
	}

	attempts := f.useCase.attempts.(*loginAttempts)
	if attempts.failures[clientAddress] != 0 || len(counter.counts) != 0 || len(audit.events) != 0 {
		t.Errorf("address failures = %d, account counters = %d, lock events = %d; want nothing counted for a refusal",
			attempts.failures[clientAddress], len(counter.counts), len(audit.events))
	}
	if len(f.sessions.commands) != 0 {
		t.Error("a refused login must not open a session")
	}
}

func TestLoginOfAnEmailWithoutAccountAnswersTheBusyHasherToo(t *testing.T) {
	f, counter := newSlowdownFixture(t)
	f.users.user = nil
	f.hasher.err = model.ErrPasswordHasherBusy

	err := failFrom(f, clientAddress, "ghost@example.com")

	if !errors.Is(err, model.ErrPasswordHasherBusy) || len(counter.counts) != 0 {
		t.Errorf("error = %v, account counters = %d, want the busy hasher and nothing counted", err, len(counter.counts))
	}
}

func TestLoginOfAMalformedEmailAnswersTheBusyHasherToo(t *testing.T) {
	f, _ := newSlowdownFixture(t)
	f.hasher.err = model.ErrPasswordHasherBusy

	err := failFrom(f, clientAddress, "not-an-email")

	if !errors.Is(err, model.ErrPasswordHasherBusy) {
		t.Errorf("error = %v, want the busy hasher", err)
	}
}

func TestChangePasswordAnswersTheBusyHasherWithoutCountingAWrongPassword(t *testing.T) {
	f := newChangeFixture(t)
	f.hasher.verifyErr = model.ErrPasswordHasherBusy

	_, err := f.change(currentPassword, newPassword)

	if !errors.Is(err, model.ErrPasswordHasherBusy) {
		t.Fatalf("error = %v, want the busy hasher", err)
	}
	if len(f.attempts.failures) != 0 || f.passwords.userID != "" {
		t.Errorf("failures = %v, updated user %q; want nothing counted and nothing changed", f.attempts.failures, f.passwords.userID)
	}
}

func TestChangePasswordAnswersTheBusyHasherWhenItCannotHashTheNewPassword(t *testing.T) {
	f := newChangeFixture(t)
	f.hasher.err = model.ErrPasswordHasherBusy

	_, err := f.change(currentPassword, newPassword)

	if !errors.Is(err, model.ErrPasswordHasherBusy) || f.passwords.userID != "" {
		t.Errorf("error = %v, updated user %q; want the busy hasher and no update", err, f.passwords.userID)
	}
}

func TestResetPasswordAnswersTheBusyHasherAndChangesNothing(t *testing.T) {
	for name, set := range map[string]func(*resetHasher){
		"hash":   func(h *resetHasher) { h.err = model.ErrPasswordHasherBusy },
		"verify": func(h *resetHasher) { h.verifyErr = model.ErrPasswordHasherBusy },
	} {
		t.Run(name, func(t *testing.T) {
			f := newResetFixture(t)
			set(f.hasher)

			err := f.useCase.Reset(context.Background(), resetCommand())

			if !errors.Is(err, model.ErrPasswordHasherBusy) || f.passwords.userID != "" {
				t.Errorf("error = %v, updated user %q; want the busy hasher and no update", err, f.passwords.userID)
			}
		})
	}
}

func TestRegisterAnswersTheBusyHasherAndCreatesNothing(t *testing.T) {
	f := newFixture()
	f.hasher.err = model.ErrPasswordHasherBusy

	_, err := f.useCase.Register(context.Background(), validCommand())

	if !errors.Is(err, model.ErrPasswordHasherBusy) || len(f.sessions.commands) != 0 {
		t.Errorf("error = %v, sessions = %d, want the busy hasher and no session", err, len(f.sessions.commands))
	}
}
