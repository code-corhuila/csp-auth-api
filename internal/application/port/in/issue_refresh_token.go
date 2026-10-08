package in

import (
	"context"
	"time"
)

// IssueRefreshTokenCommand names the user who gets a session and the client that asked for it.
type IssueRefreshTokenCommand struct {
	UserID    string
	UserAgent string
}

// IssuedRefreshToken carries the opaque value, which exists only in this result, and its expiry.
type IssuedRefreshToken struct {
	Token     string
	ExpiresAt time.Time
}

// IssueRefreshToken is the part of HU-AUTH-002 that creates the refresh token of a login.
type IssueRefreshToken interface {
	Issue(ctx context.Context, command IssueRefreshTokenCommand) (IssuedRefreshToken, error)
}
