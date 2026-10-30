package token

import (
	"crypto/rsa"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

func newAccessVerifier(keys ...*rsa.PrivateKey) *AccessTokenVerifier {
	published := make([]model.PublicKey, 0, len(keys))
	for _, key := range keys {
		published = append(published, model.PublicKey{KeyID: thumbprint(&key.PublicKey), Key: &key.PublicKey})
	}
	return NewAccessTokenVerifier(published, fixedClock{verifiedAt})
}

func accessTokenClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"sub": "550e8400-e29b-41d4-a716-446655440000", "iss": "csp-auth", "aud": "csp-api",
		"jti": "jti-7", "iat": verifiedAt.Unix(), "exp": verifiedAt.Add(time.Hour).Unix(),
		"roles": []string{"ADMIN"}, "permissions": []string{"user:role:update"},
	}
}

func TestAccessVerifierReturnsTheClaimsOfATokenOfTheIssuer(t *testing.T) {
	key := generateKey(t, 2048)
	issued, err := newIssuer(t, key, verifiedAt).IssueAccessToken(adminClaims(t))
	if err != nil {
		t.Fatalf("IssueAccessToken() error = %v", err)
	}

	claims, err := newAccessVerifier(key).VerifyAccessToken(issued.Value)

	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	want := adminClaims(t)
	want.TokenID, want.ExpiresAt = "jti-1", verifiedAt.Add(time.Hour)
	if !claims.ExpiresAt.Equal(want.ExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", claims.ExpiresAt, want.ExpiresAt)
	}
	if !claims.IssuedAt.Equal(verifiedAt) {
		t.Errorf("IssuedAt = %v, want %v: the iat of the token, which the user revocation rule compares", claims.IssuedAt, verifiedAt)
	}
	claims.ExpiresAt, claims.IssuedAt = want.ExpiresAt, want.IssuedAt
	if !reflect.DeepEqual(claims, want) {
		t.Errorf("claims = %+v, want %+v", claims, want)
	}
	if !claims.Allows("user:role:update") || claims.Allows("unknown:permission") {
		t.Errorf("Allows() does not follow the permissions %v", claims.Permissions)
	}
}

func TestAccessVerifierRejectsEveryTokenThatTheIssuerWouldNotHaveSigned(t *testing.T) {
	key, other := generateKey(t, 2048), generateKey(t, 2048)
	with := func(name string, value any) jwt.MapClaims {
		claims := accessTokenClaims()
		if value == nil {
			delete(claims, name)
		} else {
			claims[name] = value
		}
		return claims
	}
	cases := map[string]string{
		"empty":                   "",
		"not a token":             "not-a-jwt",
		"signed by another key":   serviceToken(t, other, jwt.SigningMethodRS256, accessTokenClaims(), ""),
		"unknown kid":             serviceToken(t, key, jwt.SigningMethodRS256, accessTokenClaims(), "unknown"),
		"expired":                 serviceToken(t, key, jwt.SigningMethodRS256, with("exp", verifiedAt.Add(-time.Second).Unix()), ""),
		"without exp":             serviceToken(t, key, jwt.SigningMethodRS256, with("exp", nil), ""),
		"without iat":             serviceToken(t, key, jwt.SigningMethodRS256, with("iat", nil), ""),
		"without jti":             serviceToken(t, key, jwt.SigningMethodRS256, with("jti", nil), ""),
		"without sub":             serviceToken(t, key, jwt.SigningMethodRS256, with("sub", nil), ""),
		"another issuer":          serviceToken(t, key, jwt.SigningMethodRS256, with("iss", "someone-else"), ""),
		"without issuer":          serviceToken(t, key, jwt.SigningMethodRS256, with("iss", nil), ""),
		"another audience":        serviceToken(t, key, jwt.SigningMethodRS256, with("aud", "other-api"), ""),
		"without audience":        serviceToken(t, key, jwt.SigningMethodRS256, with("aud", nil), ""),
		"an unknown role":         serviceToken(t, key, jwt.SigningMethodRS256, with("roles", []string{"SUPERUSER"}), ""),
		"signed with RS512":       serviceToken(t, key, jwt.SigningMethodRS512, accessTokenClaims(), ""),
		"alg none":                signedNone(t, accessTokenClaims()),
		"HS256 with a shared key": signedHMAC(t, accessTokenClaims()),
	}
	for name, signed := range cases {
		claims, err := newAccessVerifier(key).VerifyAccessToken(signed)
		if !errors.Is(err, model.ErrAccessTokenInvalid) || claims.Subject != "" {
			t.Errorf("%s: claims = %+v, error = %v, want ErrAccessTokenInvalid", name, claims, err)
		}
	}
}

func TestAccessVerifierAcceptsATokenWithTheAudienceAsAnArray(t *testing.T) {
	key := generateKey(t, 2048)
	claims := accessTokenClaims()
	claims["aud"] = []string{"csp-api"}

	if _, err := newAccessVerifier(key).VerifyAccessToken(serviceToken(t, key, jwt.SigningMethodRS256, claims, "")); err != nil {
		t.Errorf("error = %v, want nil", err)
	}
}
