package out

import (
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// IssuedAccessToken is a signed access token and the instant it stops being valid.
type IssuedAccessToken struct {
	Value     string
	ExpiresAt time.Time
}

// TokenIssuer signs access tokens (RS256) for the claims of a user. The private key never leaves it.
type TokenIssuer interface {
	IssueAccessToken(claims model.AccessClaims) (IssuedAccessToken, error)
}
