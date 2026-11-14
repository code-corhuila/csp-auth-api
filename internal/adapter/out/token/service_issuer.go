package token

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// serviceAudience is the audience of the credentials of the services (07-api/authentication.md).
const serviceAudience = "csp-internal"

// IssueServiceToken signs the credential of one service (ADR-052) with the key of the access
// tokens: sub, iss, aud, iat, exp and a unique jti, and the kid of the key in the header. It carries
// no roles or permissions: the API that receives it decides by the sub.
func (i *Issuer) IssueServiceToken(request model.ServiceTokenRequest) (model.IssuedServiceToken, error) {
	now := i.clock.Now()
	expiresAt := now.Add(request.Lifetime)
	tokenID := i.ids.NewID()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Subject:   request.Subject,
		Issuer:    issuerName,
		Audience:  jwt.ClaimStrings{serviceAudience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		ID:        tokenID,
	})
	token.Header["kid"] = i.keyID
	signed, err := token.SignedString(i.key)
	if err != nil {
		return model.IssuedServiceToken{}, fmt.Errorf("sign service token: %w", err)
	}
	return model.IssuedServiceToken{Value: signed, TokenID: tokenID, ExpiresAt: expiresAt}, nil
}
