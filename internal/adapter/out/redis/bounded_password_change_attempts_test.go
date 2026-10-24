package redis

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
)

const someUser = "9b2f4c1e-7d3a-4e58-8f60-2a1b3c4d5e6f"

// scriptedPasswordAttempts is an out.PasswordChangeAttempts that answers with what its embedded script says.
type scriptedPasswordAttempts struct{ scriptedAttempts }

func (s *scriptedPasswordAttempts) Locked(ctx context.Context, _ string) (time.Duration, error) {
	return s.locked, s.run(ctx)
}
func (s *scriptedPasswordAttempts) RecordFailure(ctx context.Context, _ string) error {
	return s.run(ctx)
}
func (s *scriptedPasswordAttempts) Clear(ctx context.Context, _ string) error { return s.run(ctx) }

func newBoundedPasswordChange(inner out.PasswordChangeAttempts) (*BoundedPasswordChangeAttempts, *steppedClock) {
	clock := &steppedClock{now: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	return NewBoundedPasswordChangeAttempts(inner, testTimeout, testPause, clock), clock
}

func TestWhileTheStoreAnswersThePasswordChangeDecoratorIsTransparent(t *testing.T) {
	inner := &scriptedPasswordAttempts{scriptedAttempts{locked: 90 * time.Second}}
	bounded, _ := newBoundedPasswordChange(inner)
	ctx := context.Background()

	if locked, err := bounded.Locked(ctx, someUser); err != nil || locked != 90*time.Second {
		t.Errorf("Locked() = %v, %v; want 90s, nil", locked, err)
	}
	if err := bounded.RecordFailure(ctx, someUser); err != nil {
		t.Errorf("RecordFailure() error = %v", err)
	}
	if err := bounded.Clear(ctx, someUser); err != nil {
		t.Errorf("Clear() error = %v", err)
	}
	if inner.callCount() != 3 {
		t.Errorf("calls = %d, want 3", inner.callCount())
	}
}

func TestAfterAFailureThePasswordChangeStoreIsPausedAndTheFailingCallKeepsItsCause(t *testing.T) {
	down := errors.New("redis down")
	inner := &scriptedPasswordAttempts{scriptedAttempts{err: down}}
	bounded, _ := newBoundedPasswordChange(inner)
	logs := captureLog(t)
	ctx := context.Background()

	first := bounded.RecordFailure(ctx, someUser)
	_, second := bounded.Locked(ctx, someUser)
	third := bounded.Clear(ctx, someUser)

	for name, err := range map[string]error{"first": first, "second": second, "third": third} {
		if !errors.Is(err, out.ErrPasswordChangeAttemptsPaused) {
			t.Errorf("%s call: error = %v, want ErrPasswordChangeAttemptsPaused", name, err)
		}
	}
	if !errors.Is(first, down) || errors.Is(second, down) {
		t.Errorf("first = %v, second = %v, want the cause only on the call that failed", first, second)
	}
	if inner.callCount() != 1 {
		t.Errorf("calls = %d, want only the first: the store is not called during the pause", inner.callCount())
	}
	if got := strings.Count(logs.String(), "level=WARN"); got != 1 || strings.Contains(logs.String(), someUser) {
		t.Errorf("log = %s, want one WARN per pause and no user id", logs)
	}
}

func TestThePasswordChangeStoreIsTriedAgainWhenThePauseEnds(t *testing.T) {
	inner := &scriptedPasswordAttempts{scriptedAttempts{err: errors.New("redis down")}}
	bounded, clock := newBoundedPasswordChange(inner)
	captureLog(t)
	ctx := context.Background()
	_ = bounded.RecordFailure(ctx, someUser)

	clock.now = clock.now.Add(testPause)
	inner.set(nil, false)

	if err := bounded.RecordFailure(ctx, someUser); err != nil {
		t.Errorf("after the pause: error = %v, want the store to answer again", err)
	}
}

func TestAPasswordChangeStoreThatDoesNotAnswerIsGivenUpOnAtTheTimeout(t *testing.T) {
	bounded, _ := newBoundedPasswordChange(&scriptedPasswordAttempts{scriptedAttempts{block: true}})
	captureLog(t)

	_, err := bounded.Locked(context.Background(), someUser)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want the deadline", err)
	}
}

func TestACancelledRequestDoesNotPauseThePasswordChangeStore(t *testing.T) {
	inner := &scriptedPasswordAttempts{scriptedAttempts{block: true}}
	bounded, _ := newBoundedPasswordChange(inner)
	captureLog(t)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	_ = bounded.Clear(cancelled, someUser)
	inner.set(nil, false)

	if err := bounded.Clear(context.Background(), someUser); err != nil {
		t.Errorf("error = %v, want the store to be working: a client that went away says nothing about Redis", err)
	}
}
