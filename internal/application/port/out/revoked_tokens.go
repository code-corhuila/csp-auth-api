package out

import (
	"context"
	"time"
)

// RevokedTokens is the list of the access tokens that a logout ended before they expired, keyed by
// their jti (ADR-028, ADR-033). Only this service reads it, on its protected routes.
type RevokedTokens interface {
	// Revoke lists the jti until ttl, the remaining life of the token, has passed. A ttl that is not
	// positive means the token has already expired and needs no entry.
	Revoke(ctx context.Context, jti string, ttl time.Duration) error
	// IsRevoked reports whether the jti is on the list. An error means the list cannot be consulted.
	IsRevoked(ctx context.Context, jti string) (bool, error)
}
