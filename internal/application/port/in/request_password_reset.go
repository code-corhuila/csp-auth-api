package in

import "context"

// RequestPasswordResetCommand asks for a link to choose a new password for Email, the raw address
// the use case validates.
type RequestPasswordResetCommand struct {
	Email string
}

// RequestPasswordReset is the first step of HU-AUTH-006 (ADR-050): a link is sent to the address of
// an active account. The answer never tells whether it was: an unknown address, an inactive account
// and a user over the limit of requests are all a success that sends nothing. Only a malformed
// address, model.ErrInvalidEmail, and a failure of the service are errors.
type RequestPasswordReset interface {
	RequestReset(ctx context.Context, command RequestPasswordResetCommand) error
}
