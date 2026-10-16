package in

import "context"

// VerifyEmailChangeCommand confirms the pending change of UserID with VerificationCode, the raw code
// the use case validates.
type VerifyEmailChangeCommand struct {
	UserID           string
	VerificationCode string
}

// VerifyEmailChange is the second step of HU-AUTH-004 (ADR-034): the right code changes the email
// of the account and publishes UserEmailChanged. A malformed, unknown, expired, exhausted or wrong
// code is the one error model.ErrVerificationRejected. When another account took the address
// meanwhile the error is model.ErrEmailAlreadyRegistered and the request is no longer valid.
type VerifyEmailChange interface {
	VerifyChange(ctx context.Context, command VerifyEmailChangeCommand) error
}
