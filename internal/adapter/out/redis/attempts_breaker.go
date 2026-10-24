package redis

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
)

// attemptsBreaker is the Circuit Breaker that the decorators of the attempt limits share (ADR-048). Every call waits at most
// timeout; when one fails, the store is not called again until pause has passed and every call, the failing one included,
// answers paused.
type attemptsBreaker struct {
	timeout time.Duration
	pause   time.Duration
	clock   out.Clock
	paused  error
	warning string

	mu          sync.Mutex
	pausedUntil time.Time
}

func newAttemptsBreaker(timeout, pause time.Duration, clock out.Clock, paused error, warning string) *attemptsBreaker {
	return &attemptsBreaker{timeout: timeout, pause: pause, clock: clock, paused: paused, warning: warning}
}

func (b *attemptsBreaker) call(ctx context.Context, operation func(context.Context) error) error {
	if b.isPaused() {
		return b.paused
	}
	bounded, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	err := operation(bounded)
	// A client that went away says nothing about Redis: only a failure with the request still alive pauses. The call that
	// fails is answered as paused too, with its cause in the chain: the WARN of the pause is already written, so the use
	// case does not write a second one for it.
	if err != nil && ctx.Err() == nil {
		b.openPause(err)
		return fmt.Errorf("%w: %w", b.paused, err)
	}
	return err
}

func (b *attemptsBreaker) isPaused() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.clock.Now().Before(b.pausedUntil)
}

// openPause starts a pause and writes its WARN, once: calls that were already running when the pause opened find it open and
// write nothing. The log never carries the subject of the limit.
func (b *attemptsBreaker) openPause(cause error) {
	b.mu.Lock()
	now := b.clock.Now()
	if now.Before(b.pausedUntil) {
		b.mu.Unlock()
		return
	}
	b.pausedUntil = now.Add(b.pause)
	b.mu.Unlock()
	slog.Warn(b.warning, "pause", b.pause.String(), "error", cause)
}
