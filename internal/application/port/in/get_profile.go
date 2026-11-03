package in

import "context"

// Profile is the own profile of a user as HU-AUTH-007 shows it (ADR-051). Phone and Address are nil for an account
// created before they existed (ADR-024); they are returned only to their owner, never in UserSummary, a token or an event.
type Profile struct {
	ID      string
	Email   string
	Name    string
	Phone   *string
	Address *string
	Roles   []string
}

// GetProfile reads the profile of the account of the access token. Errors: model.ErrUserNotFound for an account that
// does not exist or was deleted, and model.ErrUserLocked for one that is locked: the token no longer identifies an
// active account.
type GetProfile interface {
	Get(ctx context.Context, userID string) (Profile, error)
}
