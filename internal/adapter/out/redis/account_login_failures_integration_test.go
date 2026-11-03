//go:build integration

package redis

import (
	"context"
	"testing"
	"time"
)

func TestTheAccountCounterCountsUnderItsOwnKeyAndExpiresWithTheWindow(t *testing.T) {
	client := openClient(t)
	store := NewAccountLoginFailures(client, 2*time.Second)
	ctx := context.Background()
	subject := newClientAddress(t)

	for want := 1; want <= 3; want++ {
		if count, err := store.Record(ctx, subject); err != nil || count != want {
			t.Fatalf("Record() #%d = %d, %v; want %d, nil", want, count, err, want)
		}
	}

	ttl, err := client.TTL(ctx, "attempts:account:"+subject).Result()
	if err != nil || ttl <= 0 || ttl > 2*time.Second {
		t.Errorf("counter ttl = %v, %v; want up to 2s: a counter without expiry would live for ever", ttl, err)
	}
	if found, _ := client.Exists(ctx, "attempts:"+subject).Result(); found != 0 {
		t.Error("the account counter must not use the key of an address")
	}
}

func TestTheAccountCounterStartsANewWindowWhenTheOldOneEnds(t *testing.T) {
	store := NewAccountLoginFailures(openClient(t), time.Second)
	ctx := context.Background()
	subject := newClientAddress(t)
	if _, err := store.Record(ctx, subject); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	time.Sleep(1200 * time.Millisecond)

	count, err := store.Record(ctx, subject)

	if err != nil || count != 1 {
		t.Errorf("Record() after the window = %d, %v; want 1, nil", count, err)
	}
}
