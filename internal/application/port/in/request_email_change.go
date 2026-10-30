package in

import "context"

// RequestEmailChangeCommand asks to change the email of UserID, the account of the access token, to
// Email, the raw address the use case validates. IdempotencyKey is the raw Idempotency-Key header.
type RequestEmailChangeCommand struct {
	UserID         string
	Email          string
	IdempotencyKey string
}

// RequestEmailChange is the first step of HU-AUTH-004 (ADR-034): the user asks to change the email
// and a verification code is sent to the new address. Nothing changes in the account yet; the
// code is never returned. The key is stored with the request (Norma 5.3.8): the same key for the same
// address is a replay that creates and sends nothing and does not count towards the limit. Errors:
// model.ErrInvalidIdempotencyKey, model.ErrInvalidEmail, model.ErrEmailAlreadyRegistered,
// model.ErrIdempotencyKeyConflict (the key was used for another address or account) and
// model.ErrTooManyEmailChangeRequests, which arrives as a *model.EmailChangeRateLimitedError that
// carries the time left until the user can request again.
type RequestEmailChange interface {
	RequestChange(ctx context.Context, command RequestEmailChangeCommand) error
}
