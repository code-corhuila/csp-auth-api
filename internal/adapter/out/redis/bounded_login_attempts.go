package redis

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
)

// BoundedLoginAttempts decorates an out.LoginAttempts so that a Redis that fails or hangs costs a login almost
// nothing (ADR-048, Circuit Breaker). Every call waits at most timeout; when one fails, the store is not called
// again until pause has passed and every call, the failing one included, answers out.ErrLoginAttemptsPaused. The first
// login of an outage therefore waits one timeout at most, and the next ones do not wait.
type BoundedLoginAttempts struct {
	inner   out.LoginAttempts
	timeout time.Duration
	pause   time.Duration
	clock   out.Clock

	mu          sync.Mutex
	pausedUntil time.Time
}

var _ out.LoginAttempts = (*BoundedLoginAttempts)(nil)

// NewBoundedLoginAttempts wraps inner with the timeout of each call and the pause after a failure.
func NewBoundedLoginAttempts(inner out.LoginAttempts, timeout, pause time.Duration, clock out.Clock) *BoundedLoginAttempts {
	return &BoundedLoginAttempts{inner: inner, timeout: timeout, pause: pause, clock: clock}
}

func (b *BoundedLoginAttempts) LockedFor(ctx context.Context, clientAddress string) (time.Duration, error) {
	var remaining time.Duration
	err := b.call(ctx, func(bounded context.Context) (err error) {
		remaining, err = b.inner.LockedFor(bounded, clientAddress)
		return err
	})
	return remaining, err
}

func (b *BoundedLoginAttempts) RecordFailure(ctx context.Context, clientAddress string) error {
	return b.call(ctx, func(bounded context.Context) error { return b.inner.RecordFailure(bounded, clientAddress) })
}

func (b *BoundedLoginAttempts) Clear(ctx context.Context, clientAddress string) error {
	return b.call(ctx, func(bounded context.Context) error { return b.inner.Clear(bounded, clientAddress) })
}

func (b *BoundedLoginAttempts) call(ctx context.Context, operation func(context.Context) error) error {
	if b.paused() {
		return out.ErrLoginAttemptsPaused
	}
	bounded, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	err := operation(bounded)
	// A client that went away says nothing about Redis: only a failure with the request still alive pauses. The call that
	// fails is answered as paused too, with its cause in the chain: the WARN of the pause is already written, so the use
	// case does not write a second one for it.
	if err != nil && ctx.Err() == nil {
		b.openPause(err)
		return fmt.Errorf("%w: %w", out.ErrLoginAttemptsPaused, err)
	}
	return err
}

func (b *BoundedLoginAttempts) paused() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.clock.Now().Before(b.pausedUntil)
}

// openPause starts a pause and writes its WARN, once: calls that were already running when the pause opened
// find it open and write nothing. The log never carries the client address.
func (b *BoundedLoginAttempts) openPause(cause error) {
	b.mu.Lock()
	now := b.clock.Now()
	if now.Before(b.pausedUntil) {
		b.mu.Unlock()
		return
	}
	b.pausedUntil = now.Add(b.pause)
	b.mu.Unlock()
	slog.Warn("login attempt limit paused after a Redis failure, the login goes on without it", "pause", b.pause.String(), "error", cause)
}
