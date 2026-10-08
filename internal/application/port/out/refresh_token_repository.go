package out

import (
	"context"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// RefreshTokenRepository stores refresh tokens by the digest of their opaque value (pattern
// Repository). Implementations take part in the transaction carried by the context.
type RefreshTokenRepository interface {
	// Save stores a new token; a digest already in use is model.ErrRefreshTokenDuplicated.
	Save(ctx context.Context, token *model.RefreshToken) error
	// FindByHash returns the token with that digest, or model.ErrRefreshTokenNotFound.
	FindByHash(ctx context.Context, hash string) (*model.RefreshToken, error)
	// Revoke marks the token revoked at the given instant; an unknown id is model.ErrRefreshTokenNotFound.
	Revoke(ctx context.Context, id string, at time.Time) error
}
