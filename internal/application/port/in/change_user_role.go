package in

import "context"

// ChangeUserRoleCommand asks to grant (Enabled) or revoke a role of UserID. ActingAdminID is the
// administrator who asks, taken from the token of the request; Role is the raw name the use case validates.
type ChangeUserRoleCommand struct {
	ActingAdminID string
	UserID        string
	Role          string
	Enabled       bool
}

// ChangeUserRole is the use case of HU-AUTH-003: an administrator grants or revokes the ADMIN role
// of a user. It returns the user after the change. Asking for the state the user already has is not
// an error and changes nothing. Errors: model.ErrUserNotFound, model.ErrUnknownRole,
// model.ErrRoleNotChangeable and model.ErrLastAdmin.
type ChangeUserRole interface {
	ChangeRole(ctx context.Context, command ChangeUserRoleCommand) (UserSummary, error)
}
