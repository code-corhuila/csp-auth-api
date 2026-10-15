package usecase

import (
	"context"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// AuthorizeUser implements in.AuthorizeUser and in.AuthenticateUser: a protected operation accepts a
// valid access token, and the ones that need a permission also require that the token holds it.
type AuthorizeUser struct {
	tokens out.AccessTokenVerifier
}

var (
	_ in.AuthorizeUser    = (*AuthorizeUser)(nil)
	_ in.AuthenticateUser = (*AuthorizeUser)(nil)
)

// NewAuthorizeUser wires the use case with the verifier of access tokens.
func NewAuthorizeUser(tokens out.AccessTokenVerifier) *AuthorizeUser {
	return &AuthorizeUser{tokens: tokens}
}

// AuthenticateUser verifies the token and returns its claims.
func (a *AuthorizeUser) AuthenticateUser(_ context.Context, bearerToken string) (model.AccessClaims, error) {
	if bearerToken == "" {
		return model.AccessClaims{}, model.ErrAccessTokenInvalid
	}
	return a.tokens.VerifyAccessToken(bearerToken)
}

// AuthorizeUser authenticates the token first and only then looks at its permissions, so a caller
// that is not authenticated never learns which permissions an operation needs.
func (a *AuthorizeUser) AuthorizeUser(ctx context.Context, bearerToken, permission string) (string, error) {
	claims, err := a.AuthenticateUser(ctx, bearerToken)
	if err != nil {
		return "", err
	}
	if !claims.Allows(permission) {
		return "", model.ErrPermissionDenied
	}
	return claims.Subject, nil
}
