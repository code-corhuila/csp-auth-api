//go:build integration

package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// The test sends to a user-protected route (GET /me) through the real handler stack the tokens that a
// forged or stale caller would present, and checks that each is 401 UNAUTHORIZED with the common error
// envelope, a traceId and WWW-Authenticate: Bearer (Norma 5.3.7 and Annex C). Every forged token carries
// the claims of a real, valid one, so only the signature, the algorithm or the lifetime is wrong.
func TestUserProtectedRouteRejectsEveryInvalidTokenOverHTTP(t *testing.T) {
	databaseURL, redisURL := os.Getenv("AUTH_TEST_DATABASE_URL"), os.Getenv("AUTH_TEST_REDIS_URL")
	if databaseURL == "" || redisURL == "" {
		t.Skip("AUTH_TEST_DATABASE_URL and AUTH_TEST_REDIS_URL are not set: the test needs PostgreSQL with the csp-auth-db migrations and the Redis of csp-infra-redis")
	}
	cfg := testConfig(t)
	cfg.DatabaseURL = databaseURL
	cfg.RedisURL = redisURL
	cfg.BcryptRounds = 4
	cfg.JWTPrivateKey = generatedKeyPEM(t)
	server := startLogoutServer(t, cfg)
	key := mustKey(t, cfg.JWTPrivateKey)
	_, userID, valid, _ := signUpUser(t, server.URL, "e2e-token-checks")
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyDER})

	claims := func(lifetime time.Duration) jwt.MapClaims {
		now := time.Now()
		return jwt.MapClaims{
			"iss": "csp-auth", "aud": "csp-api", "sub": userID, "jti": "forged-token-id",
			"iat": now.Unix(), "exp": now.Add(lifetime).Unix(),
			"roles": []string{"ADMIN"}, "permissions": []string{"user:role:update"},
		}
	}
	sign := func(method jwt.SigningMethod, secret any, claims jwt.MapClaims) string {
		t.Helper()
		signed, err := jwt.NewWithClaims(method, claims).SignedString(secret)
		if err != nil {
			t.Fatalf("sign the %s token: %v", method.Alg(), err)
		}
		return signed
	}

	t.Run("the control token of the same user is accepted", func(t *testing.T) {
		response := callWithBearer(t, server.URL, valid)
		if response.status != http.StatusOK || response.body["id"] != userID {
			t.Errorf("status = %d, body = %v, want 200 and the profile of the user", response.status, response.body)
		}
	})

	cases := map[string]string{
		"no token":                         "",
		"malformed, not a JWT":             "not-a-token",
		"malformed, three empty segments":  "..",
		"malformed, header is not base64":  "%%%.%%%.%%%",
		"alg none":                         sign(jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, claims(time.Hour)),
		"HS256 with the PEM public key":    sign(jwt.SigningMethodHS256, publicKeyPEM, claims(time.Hour)),
		"HS256 with the DER public key":    sign(jwt.SigningMethodHS256, publicKeyDER, claims(time.Hour)),
		"expired":                          sign(jwt.SigningMethodRS256, key, claims(-time.Minute)),
		"signed with another key":          sign(jwt.SigningMethodRS256, mustKey(t, generatedKeyPEM(t)), claims(time.Hour)),
		"valid token with a damaged tail":  valid[:len(valid)-6] + "AAAAAA",
		"valid payload, signature removed": valid[:len(valid)-len(lastSegment(valid))],
	}
	for name, bearer := range cases {
		t.Run(name+" is 401 with the common envelope", func(t *testing.T) {
			response := callWithBearer(t, server.URL, bearer)

			if response.status != http.StatusUnauthorized || response.body["error"] != "UNAUTHORIZED" {
				t.Fatalf("status = %d, body = %v, want 401 UNAUTHORIZED", response.status, response.body)
			}
			if message, _ := response.body["message"].(string); message == "" {
				t.Errorf("body = %v, want a message", response.body)
			}
			if traceID, _ := response.body["traceId"].(string); traceID == "" {
				t.Errorf("body = %v, want a traceId", response.body)
			}
			if got := response.header.Get("WWW-Authenticate"); got != "Bearer" {
				t.Errorf("WWW-Authenticate = %q, want Bearer", got)
			}
			if got := response.header.Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", got)
			}
			if got := response.header.Get("X-Correlation-Id"); got == "" || got != response.body["traceId"] {
				t.Errorf("X-Correlation-Id = %q, want the traceId of the body", got)
			}
		})
	}
}

type tokenCheckResponse struct {
	status int
	header http.Header
	body   map[string]any
}

func callWithBearer(t *testing.T, baseURL, bearer string) tokenCheckResponse {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, baseURL+profilePath, nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("GET %s error = %v", profilePath, err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode the response (status %d, body %q): %v", response.StatusCode, raw, err)
	}
	return tokenCheckResponse{status: response.StatusCode, header: response.Header, body: payload}
}

func lastSegment(token string) string {
	for i := len(token) - 1; i >= 0; i-- {
		if token[i] == '.' {
			return token[i+1:]
		}
	}
	return token
}
