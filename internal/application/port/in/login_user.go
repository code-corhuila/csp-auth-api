package in

import "context"

// LoginUserCommand is what a client presents to authenticate. UserAgent identifies the client
// that asks for the session and may be empty.
type LoginUserCommand struct {
	Email     string
	Password  string
	UserAgent string
}

// UserSummary is the public projection of a user: no phone, no address, no password hash (ADR-024).
type UserSummary struct {
	ID          string
	Email       string
	Name        string
	Roles       []string
	Permissions []string
}

// LoginUserResult carries both credentials of a session. ExpiresIn is the lifetime of the access
// token in seconds; RefreshToken is the opaque value, which exists only in this result.
type LoginUserResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
	User         UserSummary
}

// LoginUser is the use case of HU-AUTH-002: a registered user authenticates and receives tokens.
type LoginUser interface {
	Login(ctx context.Context, command LoginUserCommand) (LoginUserResult, error)
}
