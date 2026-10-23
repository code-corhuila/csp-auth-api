package redis

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const (
	testTimeout = 50 * time.Millisecond
	testPause   = 10 * time.Second
)

type steppedClock struct{ now time.Time }

func (c *steppedClock) Now() time.Time { return c.now }

// scriptedAttempts is an out.LoginAttempts that counts its calls and answers with err, or blocks until the
// context ends when block is set (a Redis that does not answer).
type scriptedAttempts struct {
	mu     sync.Mutex
	calls  int
	err    error
	block  bool
	locked time.Duration
}

func (s *scriptedAttempts) run(ctx context.Context) error {
	s.mu.Lock()
	s.calls++
	err, block := s.err, s.block
	s.mu.Unlock()
	if block {
		<-ctx.Done()
		return ctx.Err()
	}
	return err
}

func (s *scriptedAttempts) LockedFor(ctx context.Context, _ string) (time.Duration, error) {
	return s.locked, s.run(ctx)
}
func (s *scriptedAttempts) RecordFailure(ctx context.Context, _ string) error { return s.run(ctx) }
func (s *scriptedAttempts) Clear(ctx context.Context, _ string) error         { return s.run(ctx) }

func (s *scriptedAttempts) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *scriptedAttempts) set(err error, block bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err, s.block = err, block
}

func newBounded(inner out.LoginAttempts) (*BoundedLoginAttempts, *steppedClock) {
	clock := &steppedClock{now: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)}
	return NewBoundedLoginAttempts(inner, testTimeout, testPause, clock), clock
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logs
}

func TestWhileTheStoreAnswersTheDecoratorIsTransparent(t *testing.T) {
	inner := &scriptedAttempts{locked: 90 * time.Second}
	bounded, _ := newBounded(inner)
	ctx := context.Background()

	if locked, err := bounded.LockedFor(ctx, "203.0.113.7"); err != nil || locked != 90*time.Second {
		t.Errorf("LockedFor() = %v, %v; want 90s, nil", locked, err)
	}
	if err := bounded.RecordFailure(ctx, "203.0.113.7"); err != nil {
		t.Errorf("RecordFailure() error = %v", err)
	}
	if err := bounded.Clear(ctx, "203.0.113.7"); err != nil {
		t.Errorf("Clear() error = %v", err)
	}
	if inner.callCount() != 3 {
		t.Errorf("calls = %d, want 3", inner.callCount())
	}
}

func TestAStoreThatDoesNotAnswerIsGivenUpOnAtTheTimeout(t *testing.T) {
	inner := &scriptedAttempts{block: true}
	bounded, _ := newBounded(inner)
	captureLog(t)

	started := time.Now()
	_, err := bounded.LockedFor(context.Background(), "203.0.113.7")

	// The store would block for ever: returning at all proves the bound. The margin is wide so that a loaded machine does not fail it.
	if elapsed := time.Since(started); elapsed > 20*time.Second {
		t.Errorf("LockedFor() took %v, want it to give up at the timeout %v", elapsed, testTimeout)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want the deadline", err)
	}
}

func TestAfterAFailureTheStoreIsNotCalledDuringThePause(t *testing.T) {
	down := errors.New("redis down")
	inner := &scriptedAttempts{err: down}
	bounded, _ := newBounded(inner)
	captureLog(t)
	ctx := context.Background()

	if _, err := bounded.LockedFor(ctx, "203.0.113.7"); !errors.Is(err, down) {
		t.Fatalf("first call: error = %v, want the failure of the store", err)
	}
	_, lockErr := bounded.LockedFor(ctx, "203.0.113.7")
	failErr := bounded.RecordFailure(ctx, "203.0.113.7")
	clearErr := bounded.Clear(ctx, "203.0.113.7")

	for name, err := range map[string]error{"LockedFor": lockErr, "RecordFailure": failErr, "Clear": clearErr} {
		if !errors.Is(err, out.ErrLoginAttemptsPaused) {
			t.Errorf("%s during the pause: error = %v, want ErrLoginAttemptsPaused", name, err)
		}
	}
	if inner.callCount() != 1 {
		t.Errorf("calls = %d, want only the first call: the store is not called during the pause", inner.callCount())
	}
}

func TestWhenThePauseEndsTheStoreIsTriedAgainAndTheLimitComesBack(t *testing.T) {
	inner := &scriptedAttempts{err: errors.New("redis down")}
	bounded, clock := newBounded(inner)
	captureLog(t)
	ctx := context.Background()
	_ = bounded.RecordFailure(ctx, "203.0.113.7")

	clock.now = clock.now.Add(testPause - time.Millisecond)
	if err := bounded.RecordFailure(ctx, "203.0.113.7"); !errors.Is(err, out.ErrLoginAttemptsPaused) {
		t.Errorf("just before the end: error = %v, want still paused", err)
	}
	clock.now = clock.now.Add(time.Millisecond)
	inner.set(nil, false)
	if err := bounded.RecordFailure(ctx, "203.0.113.7"); err != nil {
		t.Errorf("after the pause: error = %v, want the store to answer again", err)
	}
	if err := bounded.Clear(ctx, "203.0.113.7"); err != nil {
		t.Errorf("after recovery: error = %v, want no pause left", err)
	}
	if inner.callCount() != 3 {
		t.Errorf("calls = %d, want 3 (the failure, the retry and the clear)", inner.callCount())
	}
}

func TestAFailureAfterThePauseStartsANewPause(t *testing.T) {
	down := errors.New("redis down")
	inner := &scriptedAttempts{err: down}
	bounded, clock := newBounded(inner)
	captureLog(t)
	ctx := context.Background()
	_ = bounded.Clear(ctx, "203.0.113.7")
	clock.now = clock.now.Add(testPause)

	if err := bounded.Clear(ctx, "203.0.113.7"); !errors.Is(err, down) {
		t.Fatalf("retry: error = %v, want the failure of the store", err)
	}
	if err := bounded.Clear(ctx, "203.0.113.7"); !errors.Is(err, out.ErrLoginAttemptsPaused) {
		t.Errorf("after the second failure: error = %v, want paused again", err)
	}
}

func TestTheWarnIsWrittenOncePerOpenedPauseWithoutTheAddress(t *testing.T) {
	inner := &scriptedAttempts{err: errors.New("dial tcp: connection refused")}
	bounded, clock := newBounded(inner)
	logs := captureLog(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		_ = bounded.RecordFailure(ctx, "203.0.113.7")
	}
	if got := strings.Count(logs.String(), "level=WARN"); got != 1 {
		t.Fatalf("WARN lines = %d, want 1 for the whole pause:\n%s", got, logs.String())
	}
	if strings.Contains(logs.String(), "203.0.113.7") {
		t.Errorf("the log has the client address: %s", logs.String())
	}
	clock.now = clock.now.Add(testPause)
	_ = bounded.RecordFailure(ctx, "203.0.113.7")
	if got := strings.Count(logs.String(), "level=WARN"); got != 2 {
		t.Errorf("WARN lines = %d, want a second one for the second pause", got)
	}
}

func TestACancelledRequestDoesNotPauseTheLimiter(t *testing.T) {
	inner := &scriptedAttempts{block: true}
	bounded, _ := newBounded(inner)
	captureLog(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_ = bounded.Clear(ctx, "203.0.113.7")
	inner.set(nil, false)

	if err := bounded.Clear(context.Background(), "203.0.113.7"); err != nil {
		t.Errorf("error = %v, want the limiter to be working: a client that went away says nothing about Redis", err)
	}
}

// A listener that accepts and never answers is a Redis that hangs: the client of the platform would wait for
// APP_AUTH_REDIS_TIMEOUT (2s here), the limiter must give up at its own timeout.
func TestARedisThatHangsIsGivenUpOnAtTheLimiterTimeoutNotTheClientTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
	client, err := NewClient(ClientSettings{URL: "redis://" + listener.Addr().String() + "/0", Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	bounded := NewBoundedLoginAttempts(NewLoginAttempts(client, model.DefaultLoginAttemptPolicy()), 200*time.Millisecond, testPause, &steppedClock{now: time.Now()})
	captureLog(t)

	started := time.Now()
	_, firstErr := bounded.LockedFor(context.Background(), "203.0.113.7")
	first := time.Since(started)
	secondErr := bounded.RecordFailure(context.Background(), "203.0.113.7")

	if firstErr == nil || first >= 1900*time.Millisecond {
		t.Errorf("first call: %v in %v, want a failure at the limiter timeout (200ms) and not at the 2s of the client", firstErr, first)
	}
	if !errors.Is(secondErr, out.ErrLoginAttemptsPaused) {
		t.Errorf("second call: %v, want the pause", secondErr)
	}
}
