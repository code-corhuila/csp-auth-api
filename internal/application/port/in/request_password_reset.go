package in

import "context"

// RequestPasswordResetCommand asks for a link to choose a new password for Email, the raw address
// the use case validates. IdempotencyKey is the raw Idempotency-Key header, validated too.
type RequestPasswordResetCommand struct {
	IdempotencyKey string
	Email          string
}

// RequestPasswordReset is the first step of HU-AUTH-006 (ADR-050): a link is sent to the address of
// an active account. The answer never tells whether it was: an unknown address, an inactive account
// and a user over the limit of requests are all a success that sends nothing. A key already used by the
// same address is a replay, the same success that creates and sends nothing (Norma 5.3.8). Only a
// malformed address or key, model.ErrInvalidEmail and model.ErrInvalidIdempotencyKey, a key used for
// another address, model.ErrIdempotencyKeyConflict, and a failure of the service are errors.
type RequestPasswordReset interface {
	RequestReset(ctx context.Context, command RequestPasswordResetCommand) error
}
