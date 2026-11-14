package out

import (
	"context"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// RegistrationRecord is what a registration request remembers under its Idempotency-Key: its id and a hash of the
// request, to tell a retry from another request that reuses the key. Request is the pending registration it created, nil
// when the request created none (the address has an account or is over its limit), so every request that passes
// validation leaves the same trace.
type RegistrationRecord struct {
	ID          string
	RequestHash string
	Request     *model.RegistrationRequest
}

// RegistrationRequestRepository stores the registration requests (pattern Repository, issue csp-docs#282). Implementations
// take part in the transaction carried by the context, so a key never exists without the request it stands for.
type RegistrationRequestRepository interface {
	// FindByKey returns the id and the request hash stored with key, and whether the key exists.
	FindByKey(ctx context.Context, key model.IdempotencyKey) (RegistrationRecord, bool, error)
	// LockEmail serializes the requests for an address until the transaction ends, so two concurrent ones are counted,
	// superseded and stored one after the other.
	LockEmail(ctx context.Context, email model.Email) error
	// CountRequestsSince counts the requests for the address made at or after since, those that created nothing included.
	CountRequestsSince(ctx context.Context, email model.Email, since time.Time) (int, error)
	// SupersedePending soft-deletes the pending request for the address, if any, at at.
	SupersedePending(ctx context.Context, email model.Email, at time.Time) error
	// Add stores the record under key at at. A key that already exists is model.ErrIdempotencyKeyTaken, which is how a
	// concurrent request with the same key is detected.
	Add(ctx context.Context, key model.IdempotencyKey, record RegistrationRecord, email model.Email, at time.Time) error
	// LockByTokenHash locks and returns the pending request with that digest. An unknown or superseded token is
	// model.ErrRegistrationRejected.
	LockByTokenHash(ctx context.Context, tokenHash string) (*model.RegistrationRequest, error)
	// MarkUsed stores the consumption of the request.
	MarkUsed(ctx context.Context, request *model.RegistrationRequest) error
}

// RegistrationConfirmation is what a RegistrationSender needs to get the confirmation link to the owner of the address.
type RegistrationConfirmation struct {
	Email     model.Email
	Token     model.ResetToken
	ExpiresAt time.Time
}

// RegistrationSender delivers the two messages of the registration (pattern Strategy: the composition root picks the
// adapter). Both are called after the commit and must not make the caller wait for the delivery. The token is a secret:
// it never goes to the outbox, an event or a log.
type RegistrationSender interface {
	// SendConfirmation mails the link to confirm the registration to a free address.
	SendConfirmation(ctx context.Context, confirmation RegistrationConfirmation) error
	// SendAccountNotice tells the owner of an address that has an account that someone tried to register with it.
	SendAccountNotice(ctx context.Context, email model.Email) error
}
