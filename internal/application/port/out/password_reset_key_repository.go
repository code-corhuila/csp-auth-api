package out

import (
	"context"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// PasswordResetKeyRecord is what the key of a password reset request remembers: a hash of the request,
// to tell a retry from a request for another address, and the stored request it created. PasswordResetID
// is empty when the request created none (an unknown or inactive account, or a user over the limit),
// so every request that passes validation leaves the same trace.
type PasswordResetKeyRecord struct {
	RequestHash     string
	PasswordResetID string
}

// PasswordResetKeyRepository stores the keys of password reset requests (Norma 5.3.8, ADR-050).
// Implementations take part in the transaction carried by the context, so a key never exists without
// the request it created.
type PasswordResetKeyRepository interface {
	// Find returns the record of key and whether the key exists.
	Find(ctx context.Context, key model.IdempotencyKey) (PasswordResetKeyRecord, bool, error)
	// Save stores the key. A key that already exists is model.ErrIdempotencyKeyTaken, which is how a
	// concurrent request with the same key is detected.
	Save(ctx context.Context, key model.IdempotencyKey, record PasswordResetKeyRecord) error
}
