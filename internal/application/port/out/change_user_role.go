package out

import (
	"context"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// UserRoleRepository stores the roles of a user. Implementations take part in the transaction
// carried by the context.
type UserRoleRepository interface {
	// LockActiveAdmins locks the ADMIN assignments of the active users, so a concurrent revoke
	// waits for this transaction, and returns how many there are.
	LockActiveAdmins(ctx context.Context) (int, error)
	// SaveRole stores whether user holds role now; changedBy is the administrator who decided it.
	SaveRole(ctx context.Context, user *model.User, role model.Role, changedBy string) error
}

// UserRoleOutbox records UserRoleChanged in the auth outbox, in the transaction carried by the
// context (pattern Transactional Outbox, Norma 5.3.11).
type UserRoleOutbox interface {
	AppendRoleChanged(ctx context.Context, event model.UserRoleChanged) error
}
