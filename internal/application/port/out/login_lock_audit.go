package out

import (
	"context"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// LoginLockAudit records the lock of a client address so that it can be reviewed (HU-AUTH-005). Recording is a side effect of
// the login: an error is logged by the use case and never changes the answer of the login.
type LoginLockAudit interface {
	// RecordLoginLocked writes one event for one lock. The trace id of the request is read from ctx.
	RecordLoginLocked(ctx context.Context, event model.LoginLocked) error
}
