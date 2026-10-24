package out

import "github.com/code-corhuila/csp-auth-api/internal/domain/model"

// AccessTokenVerifier checks the access token of a user (Norma 5.3.7).
type AccessTokenVerifier interface {
	// VerifyAccessToken returns the claims of a valid RS256 access token issued by this service. Any
	// token that is not valid gives model.ErrAccessTokenInvalid.
	VerifyAccessToken(token string) (model.AccessClaims, error)
}
