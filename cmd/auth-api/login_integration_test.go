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
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/persistence"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/system"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const (
	e2ePassword      = "Str0ng-Passw0rd!"
	e2eWrongPassword = "Wr0ng-Passw0rd!"
)

// The test registers a user through the real handler and then calls POST /login over HTTP, with
// the same requirements as TestRegisterEndToEndAgainstTheDatabase. The lock is set directly in
// the database, because no use case locks accounts yet.
func TestLoginEndToEndAgainstTheDatabase(t *testing.T) {
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
	email := "e2e-login-" + ids.NewID() + "@example.com"
	signUp := fmt.Sprintf(`{"email":%q,"password":%q,"name":"Ada Lovelace","phone":"+573001234567","address":"Calle 1 # 2-3"}`, email, e2ePassword)
	if status, payload := register(t, server.URL, ids.NewID(), signUp); status != http.StatusCreated {
		t.Fatalf("register status = %d, want 201; body = %v", status, payload)
	}
	credentials := func(email, password string) string {
		return fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)
	}

	t.Run("the right password answers 200 with tokens that /jwks verifies", func(t *testing.T) {
		status, header, payload := login(t, server.URL, credentials(email, e2ePassword))
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body = %v", status, payload)
		}
		if header.Get("Cache-Control") != "no-store" || header.Get("Pragma") != "no-cache" {
			t.Errorf("cache headers = %v, want no-store / no-cache", header)
		}
		access, _ := payload["accessToken"].(string)
		refresh, _ := payload["refreshToken"].(string)
		if access == "" || refresh == "" {
			t.Fatalf("tokens = %q / %q, want both", access, refresh)
		}
		verifyWithJWKS(t, server.URL, access)
		assertAccessClaims(t, access, payload)
		assertRefreshTokenStoredHashed(t, url, refresh)
	})

	t.Run("a wrong password, an unknown email and a malformed email answer 401 with the identical body", func(t *testing.T) {
		wrongStatus, _, wrong := login(t, server.URL, credentials(email, e2eWrongPassword))
		unknownStatus, _, unknown := login(t, server.URL, credentials("nobody-"+ids.NewID()+"@example.com", e2ePassword))
		malformedStatus, _, malformed := login(t, server.URL, credentials("not-an-email", e2ePassword))
		if wrongStatus != http.StatusUnauthorized || unknownStatus != http.StatusUnauthorized || malformedStatus != http.StatusUnauthorized {
			t.Fatalf("statuses = %d / %d / %d, want 401 for each", wrongStatus, unknownStatus, malformedStatus)
		}
		for _, payload := range []map[string]any{wrong, unknown, malformed} {
			delete(payload, "traceId")
		}
		if fmt.Sprint(wrong) != fmt.Sprint(unknown) || fmt.Sprint(wrong) != fmt.Sprint(malformed) {
			t.Errorf("bodies differ: %v / %v / %v", wrong, unknown, malformed)
		}
		if wrong["error"] != "INVALID_CREDENTIALS" {
			t.Errorf("error = %v, want INVALID_CREDENTIALS", wrong["error"])
		}
	})

	t.Run("a missing password answers 400 VALIDATION_ERROR", func(t *testing.T) {
		status, _, payload := login(t, server.URL, fmt.Sprintf(`{"email":%q}`, email))
		if status != http.StatusBadRequest || payload["error"] != "VALIDATION_ERROR" {
			t.Errorf("status = %d, body = %v, want 400 VALIDATION_ERROR", status, payload)
		}
	})

	t.Run("a locked account answers 423 with the right password and 401 with a wrong one", func(t *testing.T) {
		lockAccount(t, url, email)
		status, _, payload := login(t, server.URL, credentials(email, e2ePassword))
		if status != http.StatusLocked || payload["error"] != "ACCOUNT_LOCKED" {
			t.Errorf("status = %d, body = %v, want 423 ACCOUNT_LOCKED", status, payload)
		}
		status, _, payload = login(t, server.URL, credentials(email, e2eWrongPassword))
		if status != http.StatusUnauthorized {
			t.Errorf("status = %d, body = %v, want 401: the lock must not be revealed without the password", status, payload)
		}
	})
}

func login(t *testing.T, baseURL, body string) (int, http.Header, map[string]any) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+loginPath, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("POST %s error = %v", loginPath, err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode the response (status %d): %v", response.StatusCode, err)
	}
	return response.StatusCode, response.Header, payload
}

// assertAccessClaims reads the claims of a token already verified with /jwks and compares them
// with the user of the response.
func assertAccessClaims(t *testing.T, accessToken string, payload map[string]any) {
	t.Helper()
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(accessToken, claims); err != nil {
		t.Fatalf("parse the access token: %v", err)
	}
	user, _ := payload["user"].(map[string]any)
	if claims["sub"] == "" || claims["sub"] != user["id"] {
		t.Errorf("sub = %v, want the user id %v", claims["sub"], user["id"])
	}
	roles, _ := claims["roles"].([]any)
	permissions, _ := claims["permissions"].([]any)
	if len(roles) == 0 || fmt.Sprint(roles) != fmt.Sprint(user["roles"]) || fmt.Sprint(permissions) != fmt.Sprint(user["permissions"]) {
		t.Errorf("roles/permissions = %v / %v, want those of the user %v", roles, permissions, user)
	}
	expiresAt, err := claims.GetExpirationTime()
	if err != nil || expiresAt == nil || !expiresAt.After(time.Now()) {
		t.Errorf("exp = %v, error = %v, want a future expiration", expiresAt, err)
	}
}

// assertRefreshTokenStoredHashed checks that the database holds the digest of the opaque value
// returned to the client, and never the value itself.
func assertRefreshTokenStoredHashed(t *testing.T, databaseURL, refreshToken string) {
	t.Helper()
	ctx := context.Background()
	conn := connect(t, ctx, databaseURL)
	var hashed, raw int
	err := conn.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE token_hash = $1), count(*) FILTER (WHERE token_hash = $2) FROM auth.refresh_token`,
		model.HashOpaqueToken(refreshToken), refreshToken).Scan(&hashed, &raw)
	if err != nil {
		t.Fatalf("count the refresh tokens: %v", err)
	}
	if hashed != 1 || raw != 0 {
		t.Errorf("rows with the digest = %d, rows with the raw value = %d, want 1 and 0", hashed, raw)
	}
}

func lockAccount(t *testing.T, databaseURL, email string) {
	t.Helper()
	ctx := context.Background()
	conn := connect(t, ctx, databaseURL)
	tag, err := conn.Exec(ctx, `UPDATE auth.app_user SET status = 'LOCKED' WHERE email = $1`, email)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("lock the account: rows = %d, error = %v", tag.RowsAffected(), err)
	}
}

func connect(t *testing.T, ctx context.Context, databaseURL string) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect to the test database: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })
	return conn
}
