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
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/persistence"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/system"
)

// The test serves the real handler (real adapters, real database, generated RSA key, an in-process relay that stands for
// the local mail catcher) and calls POST /register and POST /register/confirm over HTTP. It needs a PostgreSQL with the
// csp-auth-db migrations applied and is skipped without AUTH_TEST_DATABASE_URL (login auth_app). auth_writer cannot delete
// users, so every run registers fresh random emails and keys.
func TestRegisterEndToEndAgainstTheDatabase(t *testing.T) {
	url := os.Getenv("AUTH_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AUTH_TEST_DATABASE_URL is not set: the end-to-end test needs a PostgreSQL with the csp-auth-db migrations")
	}
	ctx := context.Background()
	cfg := testConfig(t)
	cfg.DatabaseURL = url
	cfg.BcryptRounds = 4
	cfg.JWTPrivateKey = generatedKeyPEM(t)
	relay := useRegistrationRelay(t, &cfg)
	handler, closeDatabase, err := newHandler(ctx, discardLogger(), cfg, persistence.NewPool)
	if err != nil {
		t.Fatalf("newHandler() error = %v", err)
	}
	t.Cleanup(closeDatabase)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	conn := connect(t, ctx, url)
	count := func(query string, args ...any) int {
		t.Helper()
		var n int
		if err := conn.QueryRow(ctx, query, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		return n
	}

	ids := system.UUIDGenerator{}
	email := "e2e-" + ids.NewID() + "@example.com"
	body := fmt.Sprintf(`{"email":%q,"password":"Str0ng-Passw0rd!","name":"Ada Lovelace","phone":"+573001234567","address":"Calle 1 # 2-3"}`, email)
	key := ids.NewID()
	var firstID string
	var firstShape []string

	t.Run("a free email answers 201 with the id of the request and creates no account", func(t *testing.T) {
		status, payload := register(t, server.URL, key, body)
		if status != http.StatusCreated {
			t.Fatalf("status = %d, want 201; body = %v", status, payload)
		}
		firstID, _ = payload["id"].(string)
		firstShape = shapeOf(payload)
		if firstID == "" || len(payload) != 1 {
			t.Fatalf("body = %v, want only the id", payload)
		}
		if n := count(`SELECT count(*) FROM auth.app_user WHERE email = $1`, email); n != 0 {
			t.Errorf("accounts = %d, want none before the confirmation", n)
		}
		if n := count(`SELECT count(*) FROM auth.registration_request WHERE email = $1 AND token_hash IS NOT NULL`, email); n != 1 {
			t.Errorf("pending registrations = %d, want 1", n)
		}
	})

	t.Run("the person cannot sign in before confirming", func(t *testing.T) {
		response, err := http.Post(server.URL+"/api/v1/auth/login", "application/json", strings.NewReader(fmt.Sprintf(`{"email":%q,"password":"Str0ng-Passw0rd!"}`, email)))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Errorf("login status = %d, want 401: the password of an unconfirmed registration opens nothing", response.StatusCode)
		}
	})

	t.Run("repeating the same request answers 200 with the same id and sends nothing more", func(t *testing.T) {
		status, payload := register(t, server.URL, key, body)
		if status != http.StatusOK || payload["id"] != firstID {
			t.Fatalf("status = %d, body = %v, want 200 and the first id", status, payload)
		}
	})

	t.Run("the same key with another body answers 409 IDEMPOTENCY_KEY_CONFLICT", func(t *testing.T) {
		other := strings.Replace(body, "Ada Lovelace", "Grace Hopper", 1)
		status, payload := register(t, server.URL, key, other)
		if status != http.StatusConflict || payload["error"] != "IDEMPOTENCY_KEY_CONFLICT" {
			t.Errorf("status = %d, body = %v, want 409 IDEMPOTENCY_KEY_CONFLICT", status, payload)
		}
	})

	var tokens map[string]any
	t.Run("the link of the message creates the account and answers 201 with tokens that /jwks verifies", func(t *testing.T) {
		token := relay.tokenFor(t, email)
		status, payload := confirmRegistration(t, server.URL, key, token)
		if status != http.StatusCreated {
			t.Fatalf("status = %d, want 201; body = %v", status, payload)
		}
		tokens = payload
		access, _ := payload["accessToken"].(string)
		if refresh, _ := payload["refreshToken"].(string); access == "" || refresh == "" {
			t.Fatalf("tokens = %q / %q, want both", access, refresh)
		}
		verifyWithJWKS(t, server.URL, access)
		if n := count(`SELECT count(*) FROM auth.app_user WHERE email = $1`, email); n != 1 {
			t.Errorf("accounts = %d, want 1 after the confirmation", n)
		}
		if reader := os.Getenv("AUTH_TEST_OUTBOX_READER_URL"); reader != "" {
			var events int
			user, _ := payload["user"].(map[string]any)
			if err := connect(t, ctx, reader).QueryRow(ctx, `SELECT count(*) FROM auth.outbox_event WHERE event_type = 'UserRegistered' AND aggregate_id::text = $1`, user["id"]).Scan(&events); err != nil || events != 1 {
				t.Errorf("UserRegistered events = %d (%v), want 1: published by the confirmation only", events, err)
			}
		}
	})

	t.Run("confirming again with the same key answers 200 without tokens", func(t *testing.T) {
		status, payload := confirmRegistration(t, server.URL, key, relay.tokenFor(t, email))
		if status != http.StatusOK || payload["email"] != email {
			t.Fatalf("status = %d, body = %v, want 200 with the account", status, payload)
		}
		if _, present := payload["accessToken"]; present {
			t.Error("a replay must not carry tokens")
		}
		_ = tokens
	})

	t.Run("a used token with a new key answers 401 INVALID_TOKEN", func(t *testing.T) {
		status, payload := confirmRegistration(t, server.URL, ids.NewID(), relay.tokenFor(t, email))
		if status != http.StatusUnauthorized || payload["error"] != "INVALID_TOKEN" {
			t.Errorf("status = %d, body = %v, want 401 INVALID_TOKEN", status, payload)
		}
	})

	t.Run("an email that already has an account gets the same answer and its owner gets a notice", func(t *testing.T) {
		before := count(`SELECT count(*) FROM auth.app_user`)
		status, payload := register(t, server.URL, ids.NewID(), body)
		if status != http.StatusCreated || len(payload) != 1 || payload["id"] == "" || payload["id"] == firstID {
			t.Fatalf("status = %d, body = %v, want 201 with the id of a new request", status, payload)
		}
		if got := shapeOf(payload); !reflect.DeepEqual(got, firstShape) {
			t.Errorf("shape = %v, want %v: the same as for a free email", got, firstShape)
		}
		notice := relay.waitForMessageMatching(t, email, regexp.MustCompile(`ya tienes una`))
		if tokenInMessage.MatchString(notice) {
			t.Errorf("message to the owner = %q, want the notice without a link", notice)
		}
		if after := count(`SELECT count(*) FROM auth.app_user`); after != before {
			t.Errorf("accounts = %d, want %d: nothing is created", after, before)
		}
		if n := count(`SELECT count(*) FROM auth.registration_request WHERE email = $1 AND token_hash IS NOT NULL AND used_at IS NULL`, email); n != 0 {
			t.Errorf("pending registrations = %d, want none for an email with an account", n)
		}
	})

	t.Run("a fourth request for one address in an hour answers the same and sends nothing", func(t *testing.T) {
		limited := "e2e-limit-" + ids.NewID() + "@example.com"
		limitedBody := strings.Replace(body, email, limited, 1)
		for range 3 {
			if status, _ := register(t, server.URL, ids.NewID(), limitedBody); status != http.StatusCreated {
				t.Fatalf("status = %d, want 201", status)
			}
		}
		status, payload := register(t, server.URL, ids.NewID(), limitedBody)
		if status != http.StatusCreated || len(payload) != 1 {
			t.Errorf("status = %d, body = %v, want the same 201", status, payload)
		}
		if n := count(`SELECT count(*) FROM auth.registration_request WHERE email = $1`, limited); n != 4 {
			t.Errorf("requests = %d, want 4 recorded", n)
		}
		if n := count(`SELECT count(*) FROM auth.registration_request WHERE email = $1 AND token_hash IS NOT NULL AND used_at IS NULL AND deleted_at IS NULL`, limited); n != 1 {
			t.Errorf("pending = %d, want 1: each request supersedes the previous one and the fourth created nothing", n)
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

func shapeOf(payload map[string]any) []string {
	keys := make([]string, 0, len(payload))
	for name := range payload {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	return keys
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
