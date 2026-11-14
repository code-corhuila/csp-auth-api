package in

import "context"

// ChangePasswordCommand asks to replace the password of UserID, the account of the access token. Both passwords are plain
// text; UserAgent identifies the client that gets the new session and may be empty.
type ChangePasswordCommand struct {
	UserID          string
	CurrentPassword string
	NewPassword     string
	UserAgent       string
}

// ChangePassword is the change of password of HU-AUTH-007 (ADR-051): the user proves the current password, the hash is
// replaced and every refresh token of the user is revoked, all or nothing, and the device that asked gets a fresh
// session. Errors: model.ErrInvalidCurrentPassword and model.ErrWeakPassword, which are not counted against the limit;
// *model.PasswordChangeRateLimitedError while the user is locked, before the password is verified;
// model.ErrWrongCurrentPassword, which is counted; model.ErrPasswordUnchanged (the new password is the current one),
// which is not; model.ErrUserNotFound and model.ErrUserLocked for an account the token no longer identifies.
type ChangePassword interface {
	Change(ctx context.Context, command ChangePasswordCommand) (LoginUserResult, error)
}
