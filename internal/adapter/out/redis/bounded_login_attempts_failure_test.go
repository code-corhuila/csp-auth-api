package redis

import (
	"context"
	"errors"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
)

// The call that fails is the one that opens the pause and writes its WARN, so its error already says "paused":
// the use case must not write a second WARN for it (one WARN per opened pause, ADR-048 D3). The cause stays in
// the chain for whoever wants to read it.
func TestTheFailingCallIsAnsweredAsPausedAndKeepsItsCause(t *testing.T) {
	down := errors.New("redis down")
	inner := &scriptedAttempts{err: down}
	bounded, _ := newBounded(inner)
	captureLog(t)

	err := bounded.RecordFailure(context.Background(), "203.0.113.7")

	if !errors.Is(err, out.ErrLoginAttemptsPaused) {
		t.Errorf("error = %v, want it to be ErrLoginAttemptsPaused so the use case stays silent", err)
	}
	if !errors.Is(err, down) {
		t.Errorf("error = %v, want the cause of the failure in the chain", err)
	}
}

func TestAFailureOfACancelledRequestIsNotAnsweredAsPaused(t *testing.T) {
	inner := &scriptedAttempts{block: true}
	bounded, _ := newBounded(inner)
	captureLog(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := bounded.Clear(ctx, "203.0.113.7")

	if errors.Is(err, out.ErrLoginAttemptsPaused) {
		t.Errorf("error = %v, want the plain cancellation: a client that went away does not pause the limiter", err)
	}
}
