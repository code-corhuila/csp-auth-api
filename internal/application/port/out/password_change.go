package out

import (
	"context"
	"errors"
	"time"
)

// ErrPasswordChangeAttemptsPaused is what a PasswordChangeAttempts answers while it is paused after a failure of its store
// (ADR-048): it is not called, it answers at once, and the use case goes on without logging it again.
var ErrPasswordChangeAttemptsPaused = errors.New("the password change limit is paused after a failure of its store")

// PasswordChangeAttempts counts the wrong current passwords of a user and holds the temporary lock of their change of
// password (HU-AUTH-007, ADR-051). The subject is the id of the user in the token, so the lock cannot be aimed at
// another account. An error means the store cannot be reached: the use case then lets the change go on.
type PasswordChangeAttempts interface {
	// Locked returns how long the change stays locked for the user, or zero when it is not locked.
	Locked(ctx context.Context, userID string) (time.Duration, error)
	// RecordFailure counts one wrong current password and locks the user when the policy is reached.
	RecordFailure(ctx context.Context, userID string) error
	// Clear forgets the wrong passwords of the user after a successful change.
	Clear(ctx context.Context, userID string) error
}

// PasswordHashLocker reads the stored hash of an account and keeps the account row locked until the transaction carried
// by the context ends, so two changes of the same account run one after the other.
type PasswordHashLocker interface {
	// LockPasswordHashOf returns the bcrypt hash of the active account userID, or model.ErrUserNotFound.
	LockPasswordHashOf(ctx context.Context, userID string) (string, error)
}
