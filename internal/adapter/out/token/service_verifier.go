package token

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// ServiceTokenVerifier checks the RS256 tokens that other services present as their credential
// (ADR-020). It implements out.ServiceTokenVerifier with the public keys of the signing key of
// this service.
//
// A service credential is validated like any other token (signature, expiration and a subject) and
// must also carry the issuer csp-auth and the audience csp-internal (ADR-056). A token of a user,
// whose audience is csp-api, is therefore never a service credential.
type ServiceTokenVerifier struct {
	keys   []model.PublicKey
	parser *jwt.Parser
}

var _ out.ServiceTokenVerifier = (*ServiceTokenVerifier)(nil)

// NewServiceTokenVerifier creates a verifier of tokens signed with one of keys, judging
// expiration by clock.
func NewServiceTokenVerifier(keys []model.PublicKey, clock out.Clock) *ServiceTokenVerifier {
	return &ServiceTokenVerifier{
		keys: keys,
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
			jwt.WithExpirationRequired(),
			jwt.WithIssuer(issuerName),
			jwt.WithAudience(serviceAudience),
			jwt.WithTimeFunc(clock.Now),
		),
	}
}

// VerifyServiceToken returns the subject of a valid token. Whatever is wrong with the token is
// model.ErrServiceTokenInvalid.
func (v *ServiceTokenVerifier) VerifyServiceToken(raw string) (string, error) {
	claims := jwt.RegisteredClaims{}
	if _, err := v.parser.ParseWithClaims(raw, &claims, keyFor(v.keys)); err != nil {
		return "", fmt.Errorf("%w: %v", model.ErrServiceTokenInvalid, err)
	}
	if claims.Subject == "" {
		return "", fmt.Errorf("%w: the token has no subject", model.ErrServiceTokenInvalid)
	}
	return claims.Subject, nil
}

// keyFor returns the function that picks the verification key by the kid of the token. A token
// without kid, such as the ones of the development script, is checked against the only key there is.
func keyFor(keys []model.PublicKey) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			if len(keys) == 1 {
				return keys[0].Key, nil
			}
			return nil, fmt.Errorf("the token has no kid and %d keys are published", len(keys))
		}
		for _, key := range keys {
			if key.KeyID == kid {
				return key.Key, nil
			}
		}
		return nil, errors.New("the kid of the token is unknown")
	}
}
