package usecase

import (
	"context"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// AuthorizeUser implements in.AuthorizeUser: a protected operation accepts a valid access token
// whose permissions include the one the operation requires.
type AuthorizeUser struct {
	tokens out.AccessTokenVerifier
}

var _ in.AuthorizeUser = (*AuthorizeUser)(nil)

// NewAuthorizeUser wires the use case with the verifier of access tokens.
func NewAuthorizeUser(tokens out.AccessTokenVerifier) *AuthorizeUser {
	return &AuthorizeUser{tokens: tokens}
}

// AuthorizeUser verifies the token first and only then looks at its permissions, so a caller that
// is not authenticated never learns which permissions an operation needs.
func (a *AuthorizeUser) AuthorizeUser(_ context.Context, bearerToken, permission string) (string, error) {
	if bearerToken == "" {
		return "", model.ErrAccessTokenInvalid
	}
	claims, err := a.tokens.VerifyAccessToken(bearerToken)
	if err != nil {
		return "", err
	}
	if !claims.Allows(permission) {
		return "", model.ErrPermissionDenied
	}
	return claims.Subject, nil
}
