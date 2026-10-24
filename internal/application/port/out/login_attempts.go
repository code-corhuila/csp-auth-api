package out

import (
	"context"
	"time"
)

// LoginAttempts counts the failed logins of a client address and holds its temporary lock
// (HU-AUTH-005). The client is the address the request came from; the store applies
// model.LoginAttemptPolicy. An error means the store cannot be reached: the use case then lets the
// login go on (the gateway keeps its per-IP limit).
type LoginAttempts interface {
	// LockedFor returns how long the client stays locked, or zero when it is not locked.
	LockedFor(ctx context.Context, client string) (time.Duration, error)
	// RecordFailure counts one failed login and locks the client when the policy is reached.
	RecordFailure(ctx context.Context, client string) error
	// Clear forgets the failures of the client after a successful login.
	Clear(ctx context.Context, client string) error
}
