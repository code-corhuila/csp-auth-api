package out

import (
	"context"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// EmailChangeKeyRecord is what the key of an email change request remembers: a hash of the request, to
// tell a retry from another request, and the pending request it created.
type EmailChangeKeyRecord struct {
	RequestHash         string
	EmailVerificationID string
}

// EmailChangeKeyRepository stores the keys of email change requests (Norma 5.3.8, ADR-034).
// Implementations take part in the transaction carried by the context, so a key never exists without
// the request it created.
type EmailChangeKeyRepository interface {
	// Find returns the record of key and whether the key exists.
	Find(ctx context.Context, key model.IdempotencyKey) (EmailChangeKeyRecord, bool, error)
	// Save stores the key. A key that already exists is model.ErrIdempotencyKeyTaken, which is how a
	// concurrent request with the same key is detected.
	Save(ctx context.Context, key model.IdempotencyKey, record EmailChangeKeyRecord) error
}
