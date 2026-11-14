package model

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func TestLoginLockedKeepsTheHashOfTheAddressAndNotTheAddress(t *testing.T) {
	at := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

	event := NewLoginLocked("203.0.113.7", 10, at, 5*time.Minute)

	sum := sha256.Sum256([]byte("203.0.113.7"))
	if want := hex.EncodeToString(sum[:]); event.ClientHash != want {
		t.Errorf("ClientHash = %q, want the SHA-256 of the address %q", event.ClientHash, want)
	}
	if event.Attempts != 10 || !event.LockedAt.Equal(at) || event.LockFor != 5*time.Minute {
		t.Errorf("event = %+v, want 10 attempts, the lock time and the lock length", event)
	}
}

func TestLoginLockedGivesTheSameHashToTheSameAddressAndAnotherToAnotherAddress(t *testing.T) {
	at := time.Now()

	first := NewLoginLocked("203.0.113.7", 10, at, time.Minute)
	again := NewLoginLocked("203.0.113.7", 10, at, time.Minute)
	other := NewLoginLocked("198.51.100.9", 10, at, time.Minute)

	if first.ClientHash != again.ClientHash || first.ClientHash == other.ClientHash {
		t.Errorf("hashes = %q %q %q, want the first two equal and the third different", first.ClientHash, again.ClientHash, other.ClientHash)
	}
}

func TestLoginFailureOutcomeSaysWhetherTheFailureLockedTheClient(t *testing.T) {
	if (LoginFailureOutcome{Attempts: 3}).Locked() {
		t.Error("a failure that does not reach the policy must not report a lock")
	}
	if !(LoginFailureOutcome{Attempts: 10, LockedFor: time.Minute}).Locked() {
		t.Error("a failure that reaches the policy must report the lock")
	}
}
