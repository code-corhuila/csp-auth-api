//go:build integration

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/persistence"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/system"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// The test spends a refresh token and presents it again over HTTP (ADR-029): inside the grace
// window nothing else is revoked; after it every active token of that user is, the revocation is
// committed although the request fails, and the answer is the same as for an unknown token.
func TestRefreshTokenReuseEndToEndAgainstTheDatabase(t *testing.T) {
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
	email := "e2e-reuse-" + ids.NewID() + "@example.com"
	signUp := fmt.Sprintf(`{"email":%q,"password":%q,"name":"Ada Lovelace","phone":"+573001234567","address":"Calle 1 # 2-3"}`, email, e2ePassword)
	if status, payload := register(t, server.URL, ids.NewID(), signUp); status != http.StatusCreated {
		t.Fatalf("register status = %d, want 201; body = %v", status, payload)
	}
	signIn := func() string {
		_, _, session := login(t, server.URL, fmt.Sprintf(`{"email":%q,"password":%q}`, email, e2ePassword))
		token, _ := session["refreshToken"].(string)
		return token
	}
	spent, otherDevice := signIn(), signIn()
	status, _, renewed := refresh(t, server.URL, spent)
	if status != http.StatusOK {
		t.Fatalf("first refresh status = %d, want 200; body = %v", status, renewed)
	}
	current, _ := renewed["refreshToken"].(string)
	activeBeforeReuse := activeTokens(t, url, email)

	t.Run("inside the grace window the reuse revokes nothing else", func(t *testing.T) {
		if status, _, payload := refresh(t, server.URL, spent); status != http.StatusUnauthorized || payload["error"] != "INVALID_REFRESH_TOKEN" {
			t.Fatalf("status = %d, body = %v, want 401 INVALID_REFRESH_TOKEN", status, payload)
		}
		if got := activeTokens(t, url, email); got != activeBeforeReuse {
			t.Errorf("active tokens = %d, want the %d there were before the reuse", got, activeBeforeReuse)
		}
	})

	t.Run("after the grace window the reuse revokes every active token of the user and answers like an unknown token", func(t *testing.T) {
		conn := connect(t, context.Background(), url)
		if _, err := conn.Exec(context.Background(), `UPDATE auth.refresh_token SET revoked_at = NOW() - INTERVAL '1 minute' WHERE token_hash = $1`, model.HashOpaqueToken(spent)); err != nil {
			t.Fatalf("age the revocation: %v", err)
		}

		reusedStatus, reusedHeader, reused := refresh(t, server.URL, spent)
		unknownStatus, unknownHeader, unknown := refresh(t, server.URL, ids.NewID())

		if reusedStatus != http.StatusUnauthorized || unknownStatus != http.StatusUnauthorized {
			t.Fatalf("statuses = %d / %d, want 401 for each", reusedStatus, unknownStatus)
		}
		delete(reused, "traceId")
		delete(unknown, "traceId")
		if fmt.Sprint(reused) != fmt.Sprint(unknown) || reused["error"] != "INVALID_REFRESH_TOKEN" {
			t.Errorf("bodies differ: %v / %v", reused, unknown)
		}
		if reusedHeader.Get("Cache-Control") != unknownHeader.Get("Cache-Control") {
			t.Errorf("headers differ: %v / %v", reusedHeader, unknownHeader)
		}
		if activeTokens(t, url, email) != 0 {
			t.Errorf("active tokens = %d, want 0: the revocation must be committed although the request failed", activeTokens(t, url, email))
		}
		for name, token := range map[string]string{"current": current, "other device": otherDevice} {
			if status, _, _ := refresh(t, server.URL, token); status != http.StatusUnauthorized {
				t.Errorf("%s token: status = %d, want 401", name, status)
			}
		}
	})
}

func activeTokens(t *testing.T, databaseURL, email string) int {
	t.Helper()
	var count int
	err := connect(t, context.Background(), databaseURL).QueryRow(context.Background(),
		`SELECT count(*) FROM auth.refresh_token r JOIN auth.app_user u ON u.id = r.user_id
		 WHERE u.email = $1 AND r.revoked_at IS NULL AND r.expires_at > NOW()`, email).Scan(&count)
	if err != nil {
		t.Fatalf("count the active tokens: %v", err)
	}
	return count
}
