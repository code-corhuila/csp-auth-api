package token

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// Registered claims fixed by the auth-service contract (AccessTokenClaims).
const (
	issuerName = "csp-auth"
	audience   = "csp-api"
)

// The contract declares aud as a string, while the library writes a single audience as an array.
func init() {
	jwt.MarshalSingleStringAsArray = false
}

// Issuer signs access tokens with one RSA key. It implements out.TokenIssuer and in.PublicKeys.
type Issuer struct {
	key   *rsa.PrivateKey
	keyID string
	ttl   time.Duration
	clock out.Clock
	ids   out.IDGenerator
}

// NewIssuer builds an Issuer. The key must have at least MinKeyBits; ttl is the access token lifetime.
func NewIssuer(key *rsa.PrivateKey, ttl time.Duration, clock out.Clock, ids out.IDGenerator) (*Issuer, error) {
	if key == nil || key.N.BitLen() < MinKeyBits {
		return nil, fmt.Errorf("the signing key must be RSA of at least %d bits", MinKeyBits)
	}
	if ttl <= 0 {
		return nil, errors.New("the access token lifetime must be positive")
	}
	return &Issuer{key: key, keyID: thumbprint(&key.PublicKey), ttl: ttl, clock: clock, ids: ids}, nil
}

type accessClaims struct {
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	jwt.RegisteredClaims
}

// IssueAccessToken signs an RS256 token whose claims are the contract's AccessTokenClaims plus a
// unique jti, the key the Redis blacklist uses to revoke it.
func (i *Issuer) IssueAccessToken(claims model.AccessClaims) (out.IssuedAccessToken, error) {
	now := i.clock.Now()
	expiresAt := now.Add(i.ttl)
	roles := make([]string, len(claims.Roles))
	for n, role := range claims.Roles {
		roles[n] = role.String()
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims{
		Roles:       roles,
		Permissions: claims.Permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   claims.Subject,
			Issuer:    issuerName,
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			ID:        i.ids.NewID(),
		},
	})
	token.Header["kid"] = i.keyID
	signed, err := token.SignedString(i.key)
	if err != nil {
		return out.IssuedAccessToken{}, fmt.Errorf("sign access token: %w", err)
	}
	return out.IssuedAccessToken{Value: signed, ExpiresAt: expiresAt}, nil
}

// PublicKeys returns the verification key of the signing key.
func (i *Issuer) PublicKeys() []model.PublicKey {
	return []model.PublicKey{{KeyID: i.keyID, Key: &i.key.PublicKey}}
}
