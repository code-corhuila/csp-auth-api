//go:build integration

package redis

import (
	"context"
	"testing"
	"time"
)

func TestEachFailureReportsItsCountAndOnlyTheOneThatReachesTheMaximumReportsTheLock(t *testing.T) {
	store := NewLoginAttempts(openClient(t), policyOf(t, 3, time.Minute, 30*time.Second))
	ctx := context.Background()
	address := newClientAddress(t)

	for want := 1; want <= 2; want++ {
		outcome, err := store.RecordFailure(ctx, address)
		if err != nil || outcome.Attempts != want || outcome.Locked() {
			t.Fatalf("failure #%d: outcome = %+v, error = %v; want %d attempts and no lock", want, outcome, err, want)
		}
	}
	outcome, err := store.RecordFailure(ctx, address)

	if err != nil || outcome.Attempts != 3 || outcome.LockedFor != 30*time.Second {
		t.Errorf("failure #3: outcome = %+v, error = %v; want 3 attempts and a 30s lock", outcome, err)
	}
}
