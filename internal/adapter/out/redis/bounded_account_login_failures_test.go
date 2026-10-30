package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
)

type scriptedAccountFailures struct {
	calls int
	block bool
	err   error
	count int
}

func (s *scriptedAccountFailures) Record(ctx context.Context, _ string) (int, error) {
	s.calls++
	if s.block {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	return s.count, s.err
}

func TestTheAccountCounterPassesTheCountOfARedisThatWorks(t *testing.T) {
	inner := &scriptedAccountFailures{count: 7}
	bounded := NewBoundedAccountLoginFailures(inner, testTimeout, testPause, &steppedClock{now: time.Now()})

	count, err := bounded.Record(context.Background(), "subject")

	if err != nil || count != 7 {
		t.Errorf("Record() = %d, %v; want 7, nil", count, err)
	}
}

func TestTheAccountCounterGivesUpAtOnceAfterAFailureAndStopsCallingRedisDuringThePause(t *testing.T) {
	inner := &scriptedAccountFailures{block: true}
	clock := &steppedClock{now: time.Now()}
	bounded := NewBoundedAccountLoginFailures(inner, testTimeout, testPause, clock)
	started := time.Now()

	_, first := bounded.Record(context.Background(), "subject")
	_, second := bounded.Record(context.Background(), "subject")

	if elapsed := time.Since(started); elapsed > 10*testTimeout {
		t.Errorf("two calls took %v, want about one timeout", elapsed)
	}
	if !errors.Is(first, out.ErrAccountLoginFailuresPaused) || !errors.Is(second, out.ErrAccountLoginFailuresPaused) || inner.calls != 1 {
		t.Errorf("errors = %v, %v, calls = %d; want both paused and one call to Redis", first, second, inner.calls)
	}
}

func TestTheAccountCounterTriesRedisAgainWhenThePauseEnds(t *testing.T) {
	inner := &scriptedAccountFailures{err: errors.New("redis down")}
	clock := &steppedClock{now: time.Now()}
	bounded := NewBoundedAccountLoginFailures(inner, testTimeout, testPause, clock)
	_, _ = bounded.Record(context.Background(), "subject")
	inner.err, inner.count = nil, 3
	clock.now = clock.now.Add(testPause + time.Second)

	count, err := bounded.Record(context.Background(), "subject")

	if err != nil || count != 3 {
		t.Errorf("Record() after the pause = %d, %v; want 3, nil", count, err)
	}
}
