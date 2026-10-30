//go:build integration

package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/persistence"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/system"
)

// The test serves the real handler (real adapters, real database, generated RSA key) and calls
// POST /register over HTTP. It needs a PostgreSQL with the csp-auth-db migrations applied and is
// skipped without AUTH_TEST_DATABASE_URL (login auth_app). auth_writer cannot delete users, so
// every run registers fresh random emails and keys.
func TestRegisterEndToEndAgainstTheDatabase(t *testing.T) {
	url := os.Getenv("AUTH_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AUTH_TEST_DATABASE_URL is not set: the end-to-end test needs a PostgreSQL with the csp-auth-db migrations")
	}
	cfg := testConfig(t)
	cfg.DatabaseURL = url
	cfg.BcryptRounds = 4
	cfg.JWTPrivateKey = generatedKeyPEM(t)
	handler, closeDatabase, err := newHandler(context.Background(), discardLogger(), cfg, persistence.NewPool)
	if err != nil {
		t.Fatalf("newHandler() error = %v", err)
	}
	t.Cleanup(closeDatabase)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	ids := system.UUIDGenerator{}
	email := "e2e-" + ids.NewID() + "@example.com"
	body := fmt.Sprintf(`{"email":%q,"password":"Str0ng-Passw0rd!","name":"Ada Lovelace","phone":"+573001234567","address":"Calle 1 # 2-3"}`, email)
	key := ids.NewID()

	t.Run("creates the account and answers 201 with tokens that /jwks verifies", func(t *testing.T) {
		status, payload := register(t, server.URL, key, body)
		if status != http.StatusCreated {
			t.Fatalf("status = %d, want 201; body = %v", status, payload)
		}
		access, _ := payload["accessToken"].(string)
		refresh, _ := payload["refreshToken"].(string)
		if access == "" || refresh == "" {
			t.Fatalf("tokens = %q / %q, want both", access, refresh)
		}
		verifyWithJWKS(t, server.URL, access)
	})

	t.Run("repeating the same request answers 200 without tokens", func(t *testing.T) {
		status, payload := register(t, server.URL, key, body)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body = %v", status, payload)
		}
		if _, present := payload["accessToken"]; present {
			t.Error("a replay must not carry tokens")
		}
		if payload["email"] != email {
			t.Errorf("email = %v, want %s", payload["email"], email)
		}
	})

	t.Run("the same key with another body answers 409 IDEMPOTENCY_KEY_CONFLICT", func(t *testing.T) {
		other := strings.Replace(body, "Ada Lovelace", "Grace Hopper", 1)
		status, payload := register(t, server.URL, key, other)
		if status != http.StatusConflict || payload["error"] != "IDEMPOTENCY_KEY_CONFLICT" {
			t.Errorf("status = %d, body = %v, want 409 IDEMPOTENCY_KEY_CONFLICT", status, payload)
		}
	})

	t.Run("a new key with the same email answers 409 EMAIL_ALREADY_REGISTERED", func(t *testing.T) {
		status, payload := register(t, server.URL, ids.NewID(), body)
		if status != http.StatusConflict || payload["error"] != "EMAIL_ALREADY_REGISTERED" {
			t.Errorf("status = %d, body = %v, want 409 EMAIL_ALREADY_REGISTERED", status, payload)
		}
	})

	t.Run("an invalid body answers 400 with details", func(t *testing.T) {
		status, payload := register(t, server.URL, ids.NewID(), `{"email":"not-an-email","password":"short"}`)
		details, _ := payload["details"].([]any)
		if status != http.StatusBadRequest || payload["error"] != "VALIDATION_ERROR" || len(details) == 0 {
			t.Errorf("status = %d, body = %v, want 400 VALIDATION_ERROR with details", status, payload)
		}
	})
}

func register(t *testing.T, baseURL, idempotencyKey, body string) (int, map[string]any) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+registerPath, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", idempotencyKey)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("POST %s error = %v", registerPath, err)
	}
	defer response.Body.Close()
	var payload map[string]any
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode the response (status %d): %v", response.StatusCode, err)
	}
	return response.StatusCode, payload
}

// verifyWithJWKS checks the signature of the access token with the key published at /jwks, the
// way another service would.
func verifyWithJWKS(t *testing.T, baseURL, accessToken string) {
	t.Helper()
	response, err := http.Get(baseURL + "/api/v1/auth/jwks")
	if err != nil {
		t.Fatalf("GET /jwks error = %v", err)
	}
	defer response.Body.Close()
	var set struct {
		Keys []struct{ Kid, N, E string } `json:"keys"`
	}
	if err := json.NewDecoder(response.Body).Decode(&set); err != nil || len(set.Keys) != 1 {
		t.Fatalf("jwks = %+v, error = %v, want one key", set, err)
	}
	n, errN := base64.RawURLEncoding.DecodeString(set.Keys[0].N)
	e, errE := base64.RawURLEncoding.DecodeString(set.Keys[0].E)
	if errN != nil || errE != nil {
		t.Fatalf("jwks key is not base64url: %v %v", errN, errE)
	}
	public := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	parsed, err := jwt.Parse(accessToken, func(*jwt.Token) (any, error) { return public, nil }, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !parsed.Valid {
		t.Fatalf("the access token does not verify against /jwks: %v", err)
	}
	if parsed.Header["kid"] != set.Keys[0].Kid {
		t.Errorf("token kid = %v, want %s", parsed.Header["kid"], set.Keys[0].Kid)
	}
}
