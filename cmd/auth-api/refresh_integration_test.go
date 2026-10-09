//go:build integration

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/persistence"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/system"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// The test registers and logs in through the real handler and then rotates the refresh token
// over HTTP, with the same requirements as TestLoginEndToEndAgainstTheDatabase. Expiry is set
// directly in the database, because the time to live is fixed by configuration.
func TestRefreshEndToEndAgainstTheDatabase(t *testing.T) {
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
	email := "e2e-refresh-" + ids.NewID() + "@example.com"
	signUp := fmt.Sprintf(`{"email":%q,"password":%q,"name":"Ada Lovelace","phone":"+573001234567","address":"Calle 1 # 2-3"}`, email, e2ePassword)
	if status, payload := register(t, server.URL, ids.NewID(), signUp); status != http.StatusCreated {
		t.Fatalf("register status = %d, want 201; body = %v", status, payload)
	}
	_, _, session := login(t, server.URL, fmt.Sprintf(`{"email":%q,"password":%q}`, email, e2ePassword))
	first, _ := session["refreshToken"].(string)
	if first == "" {
		t.Fatalf("login gave no refresh token: %v", session)
	}

	status, header, renewed := refresh(t, server.URL, first)
	if status != http.StatusOK {
		t.Fatalf("refresh status = %d, want 200; body = %v", status, renewed)
	}
	if header.Get("Cache-Control") != "no-store" || header.Get("Pragma") != "no-cache" {
		t.Errorf("cache headers = %v, want no-store / no-cache", header)
	}
	second, _ := renewed["refreshToken"].(string)
	access, _ := renewed["accessToken"].(string)
	if second == "" || second == first || access == "" {
		t.Fatalf("tokens = %q / %q, want a new pair", second, access)
	}
	verifyWithJWKS(t, server.URL, access)
	assertAccessClaims(t, access, renewed)
	assertRefreshTokenStoredHashed(t, url, second)

	t.Run("the spent token now answers 401 INVALID_REFRESH_TOKEN and the reuse revokes the new one", func(t *testing.T) {
		status, _, payload := refresh(t, server.URL, first)
		if status != http.StatusUnauthorized || payload["error"] != "INVALID_REFRESH_TOKEN" {
			t.Errorf("status = %d, body = %v, want 401 INVALID_REFRESH_TOKEN", status, payload)
		}
		if status, _, _ := refresh(t, server.URL, second); status != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401: reusing a spent token revokes the sessions of the user", status)
		}
	})

	t.Run("a new token rotates again", func(t *testing.T) {
		_, _, again := login(t, server.URL, fmt.Sprintf(`{"email":%q,"password":%q}`, email, e2ePassword))
		token, _ := again["refreshToken"].(string)
		if status, _, payload := refresh(t, server.URL, token); status != http.StatusOK {
			t.Errorf("status = %d, want 200; body = %v", status, payload)
		}
	})

	t.Run("an expired token, an unknown token and a missing token", func(t *testing.T) {
		_, _, again := login(t, server.URL, fmt.Sprintf(`{"email":%q,"password":%q}`, email, e2ePassword))
		token, _ := again["refreshToken"].(string)
		conn := connect(t, context.Background(), url)
		if _, err := conn.Exec(context.Background(), `UPDATE auth.refresh_token SET expires_at = NOW() - INTERVAL '1 second' WHERE token_hash = $1`, model.HashOpaqueToken(token)); err != nil {
			t.Fatalf("expire the token: %v", err)
		}
		expiredStatus, _, expired := refresh(t, server.URL, token)
		unknownStatus, _, unknown := refresh(t, server.URL, ids.NewID())
		if expiredStatus != http.StatusUnauthorized || unknownStatus != http.StatusUnauthorized {
			t.Fatalf("statuses = %d / %d, want 401 for each", expiredStatus, unknownStatus)
		}
		delete(expired, "traceId")
		delete(unknown, "traceId")
		if fmt.Sprint(expired) != fmt.Sprint(unknown) {
			t.Errorf("bodies differ: %v / %v", expired, unknown)
		}
		if status, _, payload := refresh(t, server.URL, ""); status != http.StatusBadRequest || payload["error"] != "VALIDATION_ERROR" {
			t.Errorf("status = %d, body = %v, want 400 VALIDATION_ERROR", status, payload)
		}
	})

	t.Run("a locked account answers 423", func(t *testing.T) {
		_, _, again := login(t, server.URL, fmt.Sprintf(`{"email":%q,"password":%q}`, email, e2ePassword))
		token, _ := again["refreshToken"].(string)
		lockAccount(t, url, email)
		if status, _, payload := refresh(t, server.URL, token); status != http.StatusLocked || payload["error"] != "ACCOUNT_LOCKED" {
			t.Errorf("status = %d, body = %v, want 423 ACCOUNT_LOCKED", status, payload)
		}
	})
}

func refresh(t *testing.T, baseURL, refreshToken string) (int, http.Header, map[string]any) {
	t.Helper()
	body := fmt.Sprintf(`{"refreshToken":%q}`, refreshToken)
	response, err := http.Post(baseURL+refreshPath, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s error = %v", refreshPath, err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode the response (status %d): %v", response.StatusCode, err)
	}
	return response.StatusCode, response.Header, payload
}
