package model

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// LoginFailureOutcome is what the store of the login attempt limit answers after counting one failed login: how many
// failures the client has in the window and, when this one reached the policy, how long the client is locked.
type LoginFailureOutcome struct {
	Attempts  int
	LockedFor time.Duration
}

// Locked reports whether the failure that was counted locked the client.
func (o LoginFailureOutcome) Locked() bool { return o.LockedFor > 0 }

// LoginLocked is the audit event raised when a failed login locks a client address (HU-AUTH-005). It carries the hash of
// the address, never the address, and no email or password, so that it can be reviewed and shared safely. The trace id
// of the request travels in the context of the audit port.
type LoginLocked struct {
	ClientHash string
	Attempts   int
	LockedAt   time.Time
	LockFor    time.Duration
}

// NewLoginLocked builds the event of the client address that reached attempts failures and is locked for lockFor.
func NewLoginLocked(client string, attempts int, lockedAt time.Time, lockFor time.Duration) LoginLocked {
	sum := sha256.Sum256([]byte(client))
	return LoginLocked{ClientHash: hex.EncodeToString(sum[:]), Attempts: attempts, LockedAt: lockedAt, LockFor: lockFor}
}
