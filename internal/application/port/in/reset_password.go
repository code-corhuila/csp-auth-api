package in

import "context"

// ResetPasswordCommand chooses Password, as plain text, for the account that Token, the raw token of
// the link, was sent to.
type ResetPasswordCommand struct {
	Token    string
	Password string
}

// ResetPassword is the second step of HU-AUTH-006 (ADR-050): the token is consumed, the password is
// replaced and every refresh token of the user is revoked, all or nothing. Errors:
// model.ErrInvalidResetToken and model.ErrWeakPassword, which leave the token usable, and
// model.ErrPasswordResetRejected for an unknown, expired, used or superseded token and for an
// account that is no longer active.
type ResetPassword interface {
	Reset(ctx context.Context, command ResetPasswordCommand) error
}
