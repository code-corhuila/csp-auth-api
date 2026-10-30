package out

import (
	"context"
	"errors"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// ErrLoginAttemptsPaused is what a LoginAttempts answers while it is paused after a failure of its store (ADR-048):
// it is not called, it answers at once, and the use case goes on without logging it again.
var ErrLoginAttemptsPaused = errors.New("the login attempt limit is paused after a failure of its store")

// LoginAttempts counts the failed logins of a client address and holds its temporary lock
// (HU-AUTH-005). The client is the address the request came from; the store applies
// model.LoginAttemptPolicy. An error means the store cannot be reached: the use case then lets the
// login go on (the gateway keeps its per-IP limit).
type LoginAttempts interface {
	// LockedFor returns how long the client stays locked, or zero when it is not locked.
	LockedFor(ctx context.Context, client string) (time.Duration, error)
	// RecordFailure counts one failed login and locks the client when the policy is reached. The outcome says how many
	// failures the client has and whether this one locked it.
	RecordFailure(ctx context.Context, client string) (model.LoginFailureOutcome, error)
	// Clear forgets the failures of the client after a successful login.
	Clear(ctx context.Context, client string) error
}
