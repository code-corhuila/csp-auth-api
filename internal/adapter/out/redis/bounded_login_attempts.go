package redis

import (
	"context"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
)

// BoundedLoginAttempts decorates an out.LoginAttempts so that a Redis that fails or hangs costs a login almost
// nothing (ADR-048, Circuit Breaker). Every call waits at most timeout; when one fails, the store is not called
// again until pause has passed and every call, the failing one included, answers out.ErrLoginAttemptsPaused. The first
// login of an outage therefore waits one timeout at most, and the next ones do not wait.
type BoundedLoginAttempts struct {
	inner   out.LoginAttempts
	breaker *attemptsBreaker
}

var _ out.LoginAttempts = (*BoundedLoginAttempts)(nil)

// NewBoundedLoginAttempts wraps inner with the timeout of each call and the pause after a failure.
func NewBoundedLoginAttempts(inner out.LoginAttempts, timeout, pause time.Duration, clock out.Clock) *BoundedLoginAttempts {
	breaker := newAttemptsBreaker(timeout, pause, clock, out.ErrLoginAttemptsPaused,
		"login attempt limit paused after a Redis failure, the login goes on without it")
	return &BoundedLoginAttempts{inner: inner, breaker: breaker}
}

func (b *BoundedLoginAttempts) LockedFor(ctx context.Context, clientAddress string) (time.Duration, error) {
	var remaining time.Duration
	err := b.breaker.call(ctx, func(bounded context.Context) (err error) {
		remaining, err = b.inner.LockedFor(bounded, clientAddress)
		return err
	})
	return remaining, err
}

func (b *BoundedLoginAttempts) RecordFailure(ctx context.Context, clientAddress string) error {
	return b.breaker.call(ctx, func(bounded context.Context) error { return b.inner.RecordFailure(bounded, clientAddress) })
}

func (b *BoundedLoginAttempts) Clear(ctx context.Context, clientAddress string) error {
	return b.breaker.call(ctx, func(bounded context.Context) error { return b.inner.Clear(bounded, clientAddress) })
}
