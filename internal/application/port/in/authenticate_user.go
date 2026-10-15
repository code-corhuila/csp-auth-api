package in

import (
	"context"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// AuthenticateUser identifies the caller of a protected operation that needs no permission beyond
// being signed in (Norma 5.3.7: each service validates the access token itself).
type AuthenticateUser interface {
	// AuthenticateUser takes the bearer token of the request and returns its claims. A missing or
	// invalid or revoked token is model.ErrAccessTokenInvalid. When the list of revoked tokens cannot
	// be consulted the error is model.ErrRevokedTokensUnavailable and the claims of the verified token
	// come with it; the callers that cannot prove the token was not revoked must refuse it.
	AuthenticateUser(ctx context.Context, bearerToken string) (model.AccessClaims, error)
}
