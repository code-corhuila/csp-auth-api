package out

import (
	"context"
	"time"
)

// UserSessionRevocations is the marker of the users whose access tokens were ended at once because
// they lost the ADMIN role (ADR-031, amendment 2026-10-24). A token is ended when it was issued at or
// before the instant of the marker.
type UserSessionRevocations interface {
	// RevokeUserSessions marks that the access tokens of userID issued at or before at are ended. The
	// marker lives as long as an access token can, and a later call overwrites it.
	RevokeUserSessions(ctx context.Context, userID string, at time.Time) error
	// UserSessionsRevokedAt returns the instant of the marker of userID, in whole seconds, and false
	// when there is none. An error means the marker cannot be consulted.
	UserSessionsRevokedAt(ctx context.Context, userID string) (at time.Time, found bool, err error)
}

// RevokedTokens is the list of the access tokens that a logout ended before they expired, keyed by
// their jti (ADR-028, ADR-033), together with the markers of the users whose sessions were ended.
// Only this service reads it, on its protected routes.
type RevokedTokens interface {
	UserSessionRevocations
	// Revoke lists the jti until ttl, the remaining life of the token, has passed. A ttl that is not
	// positive means the token has already expired and needs no entry.
	Revoke(ctx context.Context, jti string, ttl time.Duration) error
	// IsRevoked reports whether the jti is on the list. An error means the list cannot be consulted.
	IsRevoked(ctx context.Context, jti string) (bool, error)
}
