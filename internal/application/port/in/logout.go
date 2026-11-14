package in

import (
	"context"
	"time"
)

// LogoutCommand identifies the session to end: the access token the caller presented (TokenID is its
// jti and ExpiresAt its expiration), the user it belongs to and what else to revoke.
type LogoutCommand struct {
	UserID    string
	TokenID   string
	ExpiresAt time.Time
	// RefreshToken is the opaque refresh token to revoke along with the access token; empty when the
	// client sends none. It is ignored when AllDevices is true, which revokes them all.
	RefreshToken string
	AllDevices   bool
}

// Logout is the use case of HU-AUTH-003 (Scenario 3, ADR-033) that ends a session: the refresh
// tokens are revoked in PostgreSQL and the access token is added to the list of revoked tokens.
type Logout interface {
	// Logout revokes the refresh tokens first and lists the access token after. A refresh token that
	// is unknown, not the user's or already revoked is not an error and revokes nothing.
	Logout(ctx context.Context, command LogoutCommand) error
}
