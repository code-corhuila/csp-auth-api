package redis

import (
	"context"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
)

// BoundedAccountLoginFailures decorates an out.AccountLoginFailures with the Circuit Breaker of ADR-048, as
// BoundedLoginAttempts does for the address counter: a Redis that fails or hangs costs a failed login one timeout at most, and
// the store is not called again until the pause has passed (out.ErrAccountLoginFailuresPaused).
type BoundedAccountLoginFailures struct {
	inner   out.AccountLoginFailures
	breaker *attemptsBreaker
}

var _ out.AccountLoginFailures = (*BoundedAccountLoginFailures)(nil)

// NewBoundedAccountLoginFailures wraps inner with the timeout of each call and the pause after a failure.
func NewBoundedAccountLoginFailures(inner out.AccountLoginFailures, timeout, pause time.Duration, clock out.Clock) *BoundedAccountLoginFailures {
	breaker := newAttemptsBreaker(timeout, pause, clock, out.ErrAccountLoginFailuresPaused,
		"account login failure counter paused after a Redis failure, failed logins are not slowed meanwhile")
	return &BoundedAccountLoginFailures{inner: inner, breaker: breaker}
}

func (b *BoundedAccountLoginFailures) Record(ctx context.Context, subject string) (int, error) {
	var count int
	err := b.breaker.call(ctx, func(bounded context.Context) (err error) {
		count, err = b.inner.Record(bounded, subject)
		return err
	})
	return count, err
}
