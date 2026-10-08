package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

type sequenceIDs struct{ next int }

func (s *sequenceIDs) NewID() string {
	s.next++
	return "jti-" + string(rune('0'+s.next))
}

func generateKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return key
}

func newIssuer(t *testing.T, key *rsa.PrivateKey, at time.Time) *Issuer {
	t.Helper()
	issuer, err := NewIssuer(key, time.Hour, fixedClock{at}, &sequenceIDs{})
	if err != nil {
		t.Fatalf("NewIssuer() error = %v", err)
	}
	return issuer
}

func adminClaims(t *testing.T) model.AccessClaims {
	t.Helper()
	claims, err := model.NewAccessClaims("550e8400-e29b-41d4-a716-446655440000", []model.Role{model.RoleAdmin})
	if err != nil {
		t.Fatalf("NewAccessClaims() error = %v", err)
	}
	return claims
}

// verificationKey rebuilds the public key from the JWK members n and e, as a consuming service does.
func verificationKey(t *testing.T, key model.PublicKey) *rsa.PublicKey {
	t.Helper()
	n, err := base64.RawURLEncoding.DecodeString(modulus(key.Key))
	if err != nil {
		t.Fatalf("decode n: %v", err)
	}
	e, err := base64.RawURLEncoding.DecodeString(exponent(key.Key))
	if err != nil {
		t.Fatalf("decode e: %v", err)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
}

func TestIssuedTokenVerifiesWithTheKeyRebuiltFromTheJWK(t *testing.T) {
	at := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	issuer := newIssuer(t, generateKey(t, 2048), at)

	issued, err := issuer.IssueAccessToken(adminClaims(t))
	if err != nil {
		t.Fatalf("IssueAccessToken() error = %v", err)
	}
	if !issued.ExpiresAt.Equal(at.Add(time.Hour)) {
		t.Errorf("ExpiresAt = %v, want one hour after issue", issued.ExpiresAt)
	}

	published := issuer.PublicKeys()
	parsed := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(issued.Value, parsed, func(*jwt.Token) (any, error) {
		return verificationKey(t, published[0]), nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithTimeFunc(func() time.Time { return at }),
		jwt.WithIssuer("csp-auth"), jwt.WithAudience("csp-api"), jwt.WithExpirationRequired())
	if err != nil {
		t.Fatalf("token does not verify: %v", err)
	}
	if token.Header["kid"] != published[0].KeyID || token.Header["alg"] != "RS256" {
		t.Errorf("header = %v, want kid %q and alg RS256", token.Header, published[0].KeyID)
	}

	adminPermissions := adminClaims(t).Permissions
	want := jwt.MapClaims{
		"sub": "550e8400-e29b-41d4-a716-446655440000", "iss": "csp-auth", "aud": "csp-api",
		"iat": float64(at.Unix()), "exp": float64(at.Add(time.Hour).Unix()), "jti": "jti-1",
		"roles": []any{"ADMIN"}, "permissions": toAny(adminPermissions),
	}
	if !reflect.DeepEqual(parsed, want) {
		t.Errorf("claims = %v, want %v", parsed, want)
	}
}

func toAny(values []string) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}

func TestEachTokenHasItsOwnJTI(t *testing.T) {
	issuer := newIssuer(t, generateKey(t, 2048), time.Now())
	first, _ := issuer.IssueAccessToken(adminClaims(t))
	second, _ := issuer.IssueAccessToken(adminClaims(t))
	jti := func(raw string) string {
		claims := jwt.MapClaims{}
		_, _, err := jwt.NewParser().ParseUnverified(raw, claims)
		if err != nil {
			t.Fatalf("ParseUnverified() error = %v", err)
		}
		return claims["jti"].(string)
	}
	if jti(first.Value) == jti(second.Value) {
		t.Error("two tokens share the same jti")
	}
}

func TestTokensSignedWithAnotherAlgorithmAreNotAccepted(t *testing.T) {
	key := generateKey(t, 2048)
	issuer := newIssuer(t, key, time.Now())
	issued, _ := issuer.IssueAccessToken(adminClaims(t))
	if header := strings.Split(issued.Value, ".")[0]; decodeSegment(t, header) != `{"alg":"RS256","kid":"`+issuer.PublicKeys()[0].KeyID+`","typ":"JWT"}` {
		t.Errorf("header = %s, want RS256 with kid and no other algorithm", decodeSegment(t, header))
	}

	for name, method := range map[string]jwt.SigningMethod{"HS256": jwt.SigningMethodHS256, "none": jwt.SigningMethodNone} {
		var secret any = []byte("shared-secret")
		if name == "none" {
			secret = jwt.UnsafeAllowNoneSignatureType
		}
		forged, err := jwt.NewWithClaims(method, jwt.MapClaims{"sub": "x"}).SignedString(secret)
		if err != nil {
			t.Fatalf("%s forge error = %v", name, err)
		}
		_, err = jwt.Parse(forged, func(*jwt.Token) (any, error) { return &key.PublicKey, nil }, jwt.WithValidMethods([]string{"RS256"}))
		if err == nil {
			t.Errorf("%s token was accepted by an RS256-only verifier", name)
		}
	}
}

func decodeSegment(t *testing.T, segment string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("decode segment: %v", err)
	}
	return string(raw)
}

func TestKeyIDIsTheRFC7638Thumbprint(t *testing.T) {
	// Key and thumbprint from RFC 7638, section 3.1.
	n := "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	nBytes, _ := base64.RawURLEncoding.DecodeString(n)
	key := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: 65537}
	if got, want := thumbprint(key), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"; got != want {
		t.Errorf("thumbprint = %q, want %q", got, want)
	}
}

func TestNewIssuerRefusesWeakKeysAndBadLifetimes(t *testing.T) {
	if _, err := NewIssuer(generateKey(t, 1024), time.Hour, fixedClock{}, &sequenceIDs{}); err == nil {
		t.Error("a 1024-bit key was accepted")
	}
	if _, err := NewIssuer(generateKey(t, 2048), 0, fixedClock{}, &sequenceIDs{}); err == nil {
		t.Error("a zero lifetime was accepted")
	}
}

func encodePEM(t *testing.T, key *rsa.PrivateKey, pkcs8 bool) string {
	t.Helper()
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	if pkcs8 {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
		}
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	}
	return string(pem.EncodeToMemory(block))
}

func TestLoadPrivateKeyAcceptsExactlyOneSource(t *testing.T) {
	key := generateKey(t, 2048)
	pkcs1, pkcs8 := encodePEM(t, key, false), encodePEM(t, key, true)
	file := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(file, []byte(pkcs8), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	valid := map[string][2]string{
		"pkcs1 contents":            {pkcs1, ""},
		"pkcs8 contents":            {pkcs8, ""},
		"contents with literal \\n": {strings.ReplaceAll(pkcs1, "\n", `\n`), ""},
		"file":                      {"", file},
	}
	for name, source := range valid {
		got, err := LoadPrivateKey(source[0], source[1])
		if err != nil || !got.Equal(key) {
			t.Errorf("%s: LoadPrivateKey() = %v, %v; want the key", name, got != nil, err)
		}
	}

	invalid := map[string][2]string{
		"both sources":    {pkcs1, file},
		"no source":       {"", ""},
		"missing file":    {"", filepath.Join(t.TempDir(), "absent.pem")},
		"not pem":         {"not a key", ""},
		"not a key":       {string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("junk")})), ""},
		"under 2048 bits": {encodePEM(t, generateKey(t, 1024), false), ""},
	}
	for name, source := range invalid {
		if _, err := LoadPrivateKey(source[0], source[1]); err == nil {
			t.Errorf("%s: LoadPrivateKey() error = nil, want a clear error", name)
		}
	}
}
