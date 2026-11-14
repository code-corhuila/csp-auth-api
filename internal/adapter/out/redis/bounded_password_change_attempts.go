package redis

import (
	"context"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
)

// BoundedPasswordChangeAttempts decorates an out.PasswordChangeAttempts with the Circuit Breaker of ADR-048, as
// BoundedLoginAttempts does for the login: a Redis that fails or hangs costs a change of password one timeout at most, and
// the store is not called again until the pause has passed (out.ErrPasswordChangeAttemptsPaused).
type BoundedPasswordChangeAttempts struct {
	inner   out.PasswordChangeAttempts
	breaker *attemptsBreaker
}

var _ out.PasswordChangeAttempts = (*BoundedPasswordChangeAttempts)(nil)

// NewBoundedPasswordChangeAttempts wraps inner with the timeout of each call and the pause after a failure.
func NewBoundedPasswordChangeAttempts(inner out.PasswordChangeAttempts, timeout, pause time.Duration, clock out.Clock) *BoundedPasswordChangeAttempts {
	breaker := newAttemptsBreaker(timeout, pause, clock, out.ErrPasswordChangeAttemptsPaused,
		"password change limit paused after a Redis failure, the change goes on without it")
	return &BoundedPasswordChangeAttempts{inner: inner, breaker: breaker}
}

func (b *BoundedPasswordChangeAttempts) Locked(ctx context.Context, userID string) (time.Duration, error) {
	var remaining time.Duration
	err := b.breaker.call(ctx, func(bounded context.Context) (err error) {
		remaining, err = b.inner.Locked(bounded, userID)
		return err
	})
	return remaining, err
}

func (b *BoundedPasswordChangeAttempts) RecordFailure(ctx context.Context, userID string) error {
	return b.breaker.call(ctx, func(bounded context.Context) error { return b.inner.RecordFailure(bounded, userID) })
}

func (b *BoundedPasswordChangeAttempts) Clear(ctx context.Context, userID string) error {
	return b.breaker.call(ctx, func(bounded context.Context) error { return b.inner.Clear(bounded, userID) })
}
