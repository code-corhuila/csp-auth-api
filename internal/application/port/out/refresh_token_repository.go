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
	// RevokeByHash revokes, in one statement, the token with that digest if it is still active (not
	// revoked, not expired, not soft-deleted) and returns the id of its user. ok is false when no
	// active token has that digest, so of two concurrent callers exactly one gets ok.
	RevokeByHash(ctx context.Context, hash string, at time.Time) (userID string, ok bool, err error)
}
