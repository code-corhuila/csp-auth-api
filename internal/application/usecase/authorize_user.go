package usecase

import (
	"context"
	"fmt"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// AuthorizeUser implements in.AuthorizeUser and in.AuthenticateUser: a protected operation accepts a
// valid access token, and the ones that need a permission also require that the token holds it.
type AuthorizeUser struct {
	tokens  out.AccessTokenVerifier
	revoked out.RevokedTokens
}

var (
	_ in.AuthorizeUser    = (*AuthorizeUser)(nil)
	_ in.AuthenticateUser = (*AuthorizeUser)(nil)
)

// NewAuthorizeUser wires the use case with the verifier of access tokens and the list of the ones
// that a logout revoked.
func NewAuthorizeUser(tokens out.AccessTokenVerifier, revoked out.RevokedTokens) *AuthorizeUser {
	return &AuthorizeUser{tokens: tokens, revoked: revoked}
}

// AuthenticateUser verifies the token and then looks for its jti in the list of revoked tokens
// (ADR-033) and for the marker of its user (ADR-031, amendment 2026-10-24): a token issued at or
// before the instant of the marker, in whole seconds, belongs to a session that the removal of the
// ADMIN role ended, while one issued later belongs to a session opened afterwards. A revoked token is
// model.ErrAccessTokenInvalid, like any token that is not valid. When
// the list cannot be consulted the use case fails closed with model.ErrRevokedTokensUnavailable:
// it cannot prove that the token was not revoked. The token is only looked up once it is valid, so
// a forged one never reaches Redis. In that one case the claims of the verified token are returned
// with the error, for the logout, which goes on without the list (ADR-033).
func (a *AuthorizeUser) AuthenticateUser(ctx context.Context, bearerToken string) (model.AccessClaims, error) {
	if bearerToken == "" {
		return model.AccessClaims{}, model.ErrAccessTokenInvalid
	}
	claims, err := a.tokens.VerifyAccessToken(bearerToken)
	if err != nil {
		return model.AccessClaims{}, err
	}
	revoked, err := a.revoked.IsRevoked(ctx, claims.TokenID)
	if err != nil {
		return claims, fmt.Errorf("%w: %v", model.ErrRevokedTokensUnavailable, err)
	}
	if revoked {
		return model.AccessClaims{}, model.ErrAccessTokenInvalid
	}
	revokedAt, found, err := a.revoked.UserSessionsRevokedAt(ctx, claims.Subject)
	if err != nil {
		return claims, fmt.Errorf("%w: %v", model.ErrRevokedTokensUnavailable, err)
	}
	if found && claims.IssuedAt.Unix() <= revokedAt.Unix() {
		return model.AccessClaims{}, model.ErrAccessTokenInvalid
	}
	return claims, nil
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
