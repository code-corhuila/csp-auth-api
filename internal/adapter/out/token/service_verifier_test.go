package token

import (
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

var verifiedAt = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

// serviceToken signs claims with key the way csp-infra-postgres/scripts/dev-token.sh does: RS256,
// no kid, and only the claims the caller gives.
func serviceToken(t *testing.T, key *rsa.PrivateKey, method jwt.SigningMethod, claims jwt.MapClaims, kid string) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	return signed
}

func newVerifier(keys ...*rsa.PrivateKey) *ServiceTokenVerifier {
	published := make([]model.PublicKey, 0, len(keys))
	for _, key := range keys {
		published = append(published, model.PublicKey{KeyID: thumbprint(&key.PublicKey), Key: &key.PublicKey})
	}
	return NewServiceTokenVerifier(published, fixedClock{verifiedAt})
}

func validClaims() jwt.MapClaims {
	return jwt.MapClaims{"sub": "csp-worker", "iat": verifiedAt.Unix(), "exp": verifiedAt.Add(time.Minute).Unix()}
}

func TestVerifierReturnsTheSubjectOfATokenSignedByTheServiceKey(t *testing.T) {
	key := generateKey(t, 2048)
	cases := map[string]string{
		"without kid, as dev-token.sh signs it": serviceToken(t, key, jwt.SigningMethodRS256, validClaims(), ""),
		"with the kid of the key":               serviceToken(t, key, jwt.SigningMethodRS256, validClaims(), thumbprint(&key.PublicKey)),
	}
	for name, signed := range cases {
		subject, err := newVerifier(key).VerifyServiceToken(signed)
		if err != nil || subject != "csp-worker" {
			t.Errorf("%s: subject = %q, error = %v, want csp-worker and no error", name, subject, err)
		}
	}
}

func TestVerifierAcceptsAnAccessTokenOfTheIssuerAndLeavesAuthorizationToTheUseCase(t *testing.T) {
	key := generateKey(t, 2048)
	issued, err := newIssuer(t, key, verifiedAt).IssueAccessToken(adminClaims(t))
	if err != nil {
		t.Fatalf("IssueAccessToken() error = %v", err)
	}

	subject, err := newVerifier(key).VerifyServiceToken(issued.Value)

	if err != nil || subject != "550e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("subject = %q, error = %v, want the user id", subject, err)
	}
}

func TestVerifierRejectsEveryTokenThatIsNotAValidServiceCredential(t *testing.T) {
	key, other := generateKey(t, 2048), generateKey(t, 2048)
	withoutExp := validClaims()
	delete(withoutExp, "exp")
	withoutSub := validClaims()
	delete(withoutSub, "sub")
	emptySub := validClaims()
	emptySub["sub"] = ""
	expired := validClaims()
	expired["exp"] = verifiedAt.Add(-time.Second).Unix()
	cases := map[string]string{
		"empty":                   "",
		"not a token":             "not-a-jwt",
		"signed by another key":   serviceToken(t, other, jwt.SigningMethodRS256, validClaims(), ""),
		"unknown kid":             serviceToken(t, key, jwt.SigningMethodRS256, validClaims(), "unknown"),
		"expired":                 serviceToken(t, key, jwt.SigningMethodRS256, expired, ""),
		"without exp":             serviceToken(t, key, jwt.SigningMethodRS256, withoutExp, ""),
		"without sub":             serviceToken(t, key, jwt.SigningMethodRS256, withoutSub, ""),
		"with an empty sub":       serviceToken(t, key, jwt.SigningMethodRS256, emptySub, ""),
		"signed with RS512":       serviceToken(t, key, jwt.SigningMethodRS512, validClaims(), ""),
		"alg none":                signedNone(t, validClaims()),
		"HS256 with a shared key": signedHMAC(t, validClaims()),
	}
	for name, signed := range cases {
		subject, err := newVerifier(key).VerifyServiceToken(signed)
		if !errors.Is(err, model.ErrServiceTokenInvalid) || subject != "" {
			t.Errorf("%s: subject = %q, error = %v, want ErrServiceTokenInvalid", name, subject, err)
		}
	}
}

func TestVerifierWithSeveralKeysNeedsTheKidToPickOne(t *testing.T) {
	first, second := generateKey(t, 2048), generateKey(t, 2048)
	verifier := newVerifier(first, second)

	if subject, err := verifier.VerifyServiceToken(serviceToken(t, second, jwt.SigningMethodRS256, validClaims(), thumbprint(&second.PublicKey))); err != nil || subject != "csp-worker" {
		t.Errorf("with kid: subject = %q, error = %v, want csp-worker", subject, err)
	}
	if _, err := verifier.VerifyServiceToken(serviceToken(t, second, jwt.SigningMethodRS256, validClaims(), "")); !errors.Is(err, model.ErrServiceTokenInvalid) {
		t.Errorf("without kid: error = %v, want ErrServiceTokenInvalid", err)
	}
}

func signedNone(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign with alg none: %v", err)
	}
	return signed
}

func signedHMAC(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("shared-secret"))
	if err != nil {
		t.Fatalf("sign with HS256: %v", err)
	}
	return signed
}
