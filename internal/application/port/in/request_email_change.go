package in

import "context"

// RequestEmailChangeCommand asks to change the email of UserID, the account of the access token, to
// Email, the raw address the use case validates.
type RequestEmailChangeCommand struct {
	UserID string
	Email  string
}

// RequestEmailChange is the first step of HU-AUTH-004 (ADR-034): the user asks to change the email
// and a verification code is sent to the new address. Nothing changes in the account yet; the
// code is never returned. Errors: model.ErrInvalidEmail, model.ErrEmailAlreadyRegistered and
// model.ErrTooManyEmailChangeRequests.
type RequestEmailChange interface {
	RequestChange(ctx context.Context, command RequestEmailChangeCommand) error
}
