//go:build integration

package redis

import (
	"context"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

func newClientAddress(t *testing.T) string {
	t.Helper()
	return "test-" + newJTI(t)
}

func policyOf(t *testing.T, maxAttempts int, window, lock time.Duration) model.LoginAttemptPolicy {
	t.Helper()
	policy, err := model.NewLoginAttemptPolicy(maxAttempts, window, lock)
	if err != nil {
		t.Fatalf("NewLoginAttemptPolicy() error = %v", err)
	}
	return policy
}

func TestTheClientIsLockedOnTheFailureThatReachesTheMaximum(t *testing.T) {
	client := openClient(t)
	store := NewLoginAttempts(client, policyOf(t, 3, time.Minute, 30*time.Second))
	ctx := context.Background()
	address := newClientAddress(t)

	for i := 1; i <= 2; i++ {
		if _, err := store.RecordFailure(ctx, address); err != nil {
			t.Fatalf("RecordFailure() #%d error = %v", i, err)
		}
		if locked, err := store.LockedFor(ctx, address); err != nil || locked != 0 {
			t.Fatalf("LockedFor() after %d failures = %v, %v; want 0, nil", i, locked, err)
		}
	}
	if _, err := store.RecordFailure(ctx, address); err != nil {
		t.Fatalf("RecordFailure() #3 error = %v", err)
	}

	locked, err := store.LockedFor(ctx, address)
	if err != nil || locked <= 29*time.Second || locked > 30*time.Second {
		t.Errorf("LockedFor() = %v, %v; want about 30s, nil", locked, err)
	}
	if found, _ := client.Exists(ctx, "attempts:"+address).Result(); found != 0 {
		t.Error("the counter must be dropped when the lock is written")
	}
}

func TestTheCounterLivesForTheWindowOnly(t *testing.T) {
	client := openClient(t)
	store := NewLoginAttempts(client, policyOf(t, 3, time.Second, time.Minute))
	ctx := context.Background()
	address := newClientAddress(t)

	if _, err := store.RecordFailure(ctx, address); err != nil {
		t.Fatalf("RecordFailure() error = %v", err)
	}
	ttl, err := client.TTL(ctx, "attempts:"+address).Result()
	if err != nil || ttl <= 0 || ttl > time.Second {
		t.Fatalf("counter ttl = %v, %v; want up to 1s", ttl, err)
	}
	time.Sleep(1200 * time.Millisecond)
	for i := 0; i < 2; i++ {
		if _, err := store.RecordFailure(ctx, address); err != nil {
			t.Fatalf("RecordFailure() error = %v", err)
		}
	}

	if locked, err := store.LockedFor(ctx, address); err != nil || locked != 0 {
		t.Errorf("LockedFor() = %v, %v; want 0: the first failure left the window", locked, err)
	}
}

func TestTheLockEndsWhenItsTimeHasPassed(t *testing.T) {
	store := NewLoginAttempts(openClient(t), policyOf(t, 1, time.Minute, time.Second))
	ctx := context.Background()
	address := newClientAddress(t)

	if _, err := store.RecordFailure(ctx, address); err != nil {
		t.Fatalf("RecordFailure() error = %v", err)
	}
	if locked, _ := store.LockedFor(ctx, address); locked <= 0 {
		t.Fatalf("LockedFor() = %v, want the client locked", locked)
	}
	time.Sleep(1200 * time.Millisecond)

	if locked, err := store.LockedFor(ctx, address); err != nil || locked != 0 {
		t.Errorf("LockedFor() after the lock time = %v, %v; want 0, nil", locked, err)
	}
}

func TestClearForgetsTheFailuresOfOneClientOnly(t *testing.T) {
	client := openClient(t)
	store := NewLoginAttempts(client, policyOf(t, 3, time.Minute, time.Minute))
	ctx := context.Background()
	mine, other := newClientAddress(t), newClientAddress(t)
	for _, address := range []string{mine, other} {
		if _, err := store.RecordFailure(ctx, address); err != nil {
			t.Fatalf("RecordFailure() error = %v", err)
		}
	}

	if err := store.Clear(ctx, mine); err != nil {
		t.Fatalf("Clear() error = %v", err)
	}

	if found, _ := client.Exists(ctx, "attempts:"+mine).Result(); found != 0 {
		t.Error("the counter of the cleared client still exists")
	}
	if found, _ := client.Exists(ctx, "attempts:"+other).Result(); found != 1 {
		t.Error("the counter of the other client must stay")
	}
}

func TestAnUnreachableRedisIsAnErrorOfTheLoginAttempts(t *testing.T) {
	client, err := NewClient(ClientSettings{URL: "redis://127.0.0.1:1/0", Timeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	store := NewLoginAttempts(client, model.DefaultLoginAttemptPolicy())
	ctx := context.Background()

	if _, err := store.LockedFor(ctx, "203.0.113.7"); err == nil {
		t.Error("LockedFor() error = nil, want an error")
	}
	if _, err := store.RecordFailure(ctx, "203.0.113.7"); err == nil {
		t.Error("RecordFailure() error = nil, want an error")
	}
	if err := store.Clear(ctx, "203.0.113.7"); err == nil {
		t.Error("Clear() error = nil, want an error")
	}
}
