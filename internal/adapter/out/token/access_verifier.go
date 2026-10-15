package token

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// AccessTokenVerifier checks the access tokens that Issuer signs when a user presents one to this
// service (Norma 5.3.7). It implements out.AccessTokenVerifier with the public keys of the signing
// key of this service.
//
// Unlike the service credential, the token must carry the issuer and the audience the issuer sets,
// an expiration, a subject, an id (the jti a logout revokes) and known roles.
type AccessTokenVerifier struct {
	keys   []model.PublicKey
	parser *jwt.Parser
}

var _ out.AccessTokenVerifier = (*AccessTokenVerifier)(nil)

// NewAccessTokenVerifier creates a verifier of tokens signed with one of keys, judging expiration by clock.
func NewAccessTokenVerifier(keys []model.PublicKey, clock out.Clock) *AccessTokenVerifier {
	return &AccessTokenVerifier{
		keys: keys,
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
			jwt.WithExpirationRequired(),
			jwt.WithIssuer(issuerName),
			jwt.WithAudience(audience),
			jwt.WithTimeFunc(clock.Now),
		),
	}
}

// VerifyAccessToken returns the claims of a valid token. Whatever is wrong with the token is
// model.ErrAccessTokenInvalid.
func (v *AccessTokenVerifier) VerifyAccessToken(raw string) (model.AccessClaims, error) {
	claims := accessClaims{}
	if _, err := v.parser.ParseWithClaims(raw, &claims, keyFor(v.keys)); err != nil {
		return model.AccessClaims{}, fmt.Errorf("%w: %v", model.ErrAccessTokenInvalid, err)
	}
	if claims.Subject == "" {
		return model.AccessClaims{}, fmt.Errorf("%w: the token has no subject", model.ErrAccessTokenInvalid)
	}
	if claims.ID == "" {
		return model.AccessClaims{}, fmt.Errorf("%w: the token has no id", model.ErrAccessTokenInvalid)
	}
	roles := make([]model.Role, 0, len(claims.Roles))
	for _, name := range claims.Roles {
		role, err := model.ParseRole(name)
		if err != nil {
			return model.AccessClaims{}, fmt.Errorf("%w: %v", model.ErrAccessTokenInvalid, err)
		}
		roles = append(roles, role)
	}
	return model.AccessClaims{
		Subject:     claims.Subject,
		Roles:       roles,
		Permissions: claims.Permissions,
		TokenID:     claims.ID,
		ExpiresAt:   claims.ExpiresAt.Time,
	}, nil
}
