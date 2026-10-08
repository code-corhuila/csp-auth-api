package out

import (
	"context"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// UserRepository stores users (pattern Repository). Implementations take part in the
// transaction carried by the context and report a duplicate email as model.ErrEmailAlreadyRegistered.
type UserRepository interface {
	ExistsByEmail(ctx context.Context, email model.Email) (bool, error)
	Save(ctx context.Context, user *model.User) error
}

// OutboxWriter records an event in the auth outbox table, in the transaction carried by the
// context; csp-worker relays it later (pattern Transactional Outbox, Norma 5.3.11).
type OutboxWriter interface {
	Append(ctx context.Context, event model.UserRegistered) error
}

// PasswordHasher turns a password into a bcrypt hash.
type PasswordHasher interface {
	Hash(password model.Password) (string, error)
}

// IDGenerator creates unique identifiers.
type IDGenerator interface {
	NewID() string
}

// Clock tells the current time, so use cases stay deterministic under test.
type Clock interface {
	Now() time.Time
}

// TransactionManager runs work atomically (pattern Unit of Work): it commits when work returns
// nil and rolls back otherwise. Repositories and the outbox join it through the context passed to work.
type TransactionManager interface {
	WithinTransaction(ctx context.Context, work func(ctx context.Context) error) error
}
