package out

import (
	"context"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// IdempotencyRecord is what a key remembers: the account its request created and a hash of that
// request, to tell a retry from a different request.
type IdempotencyRecord struct {
	UserID      string
	RequestHash string
}

// IdempotencyKeyRepository stores the keys of registrations (Norma 5.3.8). Implementations take
// part in the transaction carried by the context, so a key never exists without its account.
type IdempotencyKeyRepository interface {
	// Find returns the record of key and whether the key exists.
	Find(ctx context.Context, key model.IdempotencyKey) (IdempotencyRecord, bool, error)
	// Save stores the key for the account. A key that already exists is model.ErrIdempotencyKeyTaken,
	// which is how a concurrent request with the same key is detected.
	Save(ctx context.Context, key model.IdempotencyKey, record IdempotencyRecord) error
}
