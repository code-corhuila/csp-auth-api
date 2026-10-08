package httpapi

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

type fixedKeys []model.PublicKey

func (k fixedKeys) PublicKeys() []model.PublicKey { return k }

func TestJWKSPublishesEveryKeyAsContractJsonWebKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	handler := NewHandler(WithPublicKeys(fixedKeys{{KeyID: "kid-1", Key: &key.PublicKey}}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/jwks", nil))

	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status = %d, content type = %q, want 200 application/json", rec.Code, rec.Header().Get("Content-Type"))
	}
	var body struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if len(body.Keys) != 1 {
		t.Fatalf("keys = %d, want 1 (minItems 1)", len(body.Keys))
	}
	jwk := body.Keys[0]
	for field, want := range map[string]string{"kty": "RSA", "kid": "kid-1", "alg": "RS256", "use": "sig"} {
		if jwk[field] != want {
			t.Errorf("%s = %q, want %q", field, jwk[field], want)
		}
	}
	if len(jwk) != 6 {
		t.Errorf("members = %v, want exactly kty, kid, alg, use, n, e", jwk)
	}
	n, errN := base64.RawURLEncoding.DecodeString(jwk["n"])
	e, errE := base64.RawURLEncoding.DecodeString(jwk["e"])
	if errN != nil || errE != nil || new(big.Int).SetBytes(n).Cmp(key.N) != 0 || new(big.Int).SetBytes(e).Int64() != int64(key.E) {
		t.Errorf("n and e do not encode the public key in unpadded base64url")
	}
}

func TestJWKSIsAbsentWithoutKeys(t *testing.T) {
	if rec := get(t, "/api/v1/auth/jwks"); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when no key source is injected", rec.Code)
	}
}
