package in

import "context"

// UpdateProfileCommand edits the personal data of UserID, the account of the access token. A nil field was not sent and
// keeps its value.
type UpdateProfileCommand struct {
	UserID  string
	Name    *string
	Phone   *string
	Address *string
}

// UpdateProfile is the edition of the own profile of HU-AUTH-007 (ADR-051): the fields sent are written together and the
// profile after the change is returned. Errors: model.ErrEmptyProfileChange, and model.ErrInvalidName,
// model.ErrInvalidPhone and model.ErrInvalidAddress, joined when several fields are invalid, which change nothing;
// model.ErrUserNotFound and model.ErrUserLocked as in GetProfile.
type UpdateProfile interface {
	Update(ctx context.Context, command UpdateProfileCommand) (Profile, error)
}
