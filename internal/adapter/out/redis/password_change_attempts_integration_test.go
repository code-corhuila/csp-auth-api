//go:build integration

package redis

import (
	"context"
	"testing"
	"time"
)

func TestTheUserIsLockedOnTheWrongPasswordThatReachesTheMaximumUnderItsOwnKeys(t *testing.T) {
	client := openClient(t)
	store := NewPasswordChangeAttempts(client, policyOf(t, 3, time.Minute, 30*time.Second))
	ctx := context.Background()
	userID := newClientAddress(t)

	for i := 1; i <= 2; i++ {
		if err := store.RecordFailure(ctx, userID); err != nil {
			t.Fatalf("RecordFailure() #%d error = %v", i, err)
		}
		if locked, err := store.Locked(ctx, userID); err != nil || locked != 0 {
			t.Fatalf("Locked() after %d failures = %v, %v; want 0, nil", i, locked, err)
		}
	}
	if found, _ := client.Exists(ctx, "attempts:pwd:"+userID).Result(); found != 1 {
		t.Error("the counter must live under attempts:pwd:{userId}")
	}
	if err := store.RecordFailure(ctx, userID); err != nil {
		t.Fatalf("RecordFailure() #3 error = %v", err)
	}

	locked, err := store.Locked(ctx, userID)
	if err != nil || locked <= 29*time.Second || locked > 30*time.Second {
		t.Errorf("Locked() = %v, %v; want about 30s, nil", locked, err)
	}
	if found, _ := client.Exists(ctx, "locked:pwd:"+userID).Result(); found != 1 {
		t.Error("the lock must live under locked:pwd:{userId}")
	}
	if found, _ := client.Exists(ctx, "attempts:pwd:"+userID).Result(); found != 0 {
		t.Error("the counter must be dropped when the lock is written")
	}
}

func TestThePasswordChangeKeysDoNotMeetTheLoginKeysOfTheSameSubject(t *testing.T) {
	client := openClient(t)
	passwords := NewPasswordChangeAttempts(client, policyOf(t, 1, time.Minute, time.Minute))
	logins := NewLoginAttempts(client, policyOf(t, 1, time.Minute, time.Minute))
	ctx := context.Background()
	subject := newClientAddress(t)

	if err := passwords.RecordFailure(ctx, subject); err != nil {
		t.Fatalf("RecordFailure() error = %v", err)
	}

	if locked, err := logins.LockedFor(ctx, subject); err != nil || locked != 0 {
		t.Errorf("LockedFor() = %v, %v; want 0: a wrong current password does not lock a login", locked, err)
	}
}

func TestClearForgetsTheWrongPasswordsOfOneUserOnly(t *testing.T) {
	client := openClient(t)
	store := NewPasswordChangeAttempts(client, policyOf(t, 3, time.Minute, time.Minute))
	ctx := context.Background()
	mine, other := newClientAddress(t), newClientAddress(t)
	for _, userID := range []string{mine, other} {
		if err := store.RecordFailure(ctx, userID); err != nil {
			t.Fatalf("RecordFailure() error = %v", err)
		}
	}

	if err := store.Clear(ctx, mine); err != nil {
		t.Fatalf("Clear() error = %v", err)
	}

	if found, _ := client.Exists(ctx, "attempts:pwd:"+mine).Result(); found != 0 {
		t.Error("the counter of the cleared user still exists")
	}
	if found, _ := client.Exists(ctx, "attempts:pwd:"+other).Result(); found != 1 {
		t.Error("the counter of the other user must stay")
	}
}

func TestTheLockOfAUserEndsWhenItsTimeHasPassed(t *testing.T) {
	store := NewPasswordChangeAttempts(openClient(t), policyOf(t, 1, time.Minute, time.Second))
	ctx := context.Background()
	userID := newClientAddress(t)
	if err := store.RecordFailure(ctx, userID); err != nil {
		t.Fatalf("RecordFailure() error = %v", err)
	}
	time.Sleep(1200 * time.Millisecond)

	if locked, err := store.Locked(ctx, userID); err != nil || locked != 0 {
		t.Errorf("Locked() after the lock time = %v, %v; want 0, nil", locked, err)
	}
}

func TestAnUnreachableRedisIsAnErrorOfThePasswordChangeAttempts(t *testing.T) {
	client, err := NewClient(ClientSettings{URL: "redis://127.0.0.1:1/0", Timeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	store := NewPasswordChangeAttempts(client, policyOf(t, 3, time.Minute, time.Minute))
	ctx := context.Background()

	if _, err := store.Locked(ctx, someUser); err == nil {
		t.Error("Locked() error = nil, want an error")
	}
	if err := store.RecordFailure(ctx, someUser); err == nil {
		t.Error("RecordFailure() error = nil, want an error")
	}
	if err := store.Clear(ctx, someUser); err == nil {
		t.Error("Clear() error = nil, want an error")
	}
}
