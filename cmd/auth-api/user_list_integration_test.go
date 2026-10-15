//go:build integration

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/persistence"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/system"
)

// The test lists users over HTTP with real access tokens: only an administrator may, the email
// prefix is case-insensitive, and the items carry the roles and never the permissions (ADR-031).
func TestListUsersEndToEndAgainstTheDatabase(t *testing.T) {
	databaseURL := os.Getenv("AUTH_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("AUTH_TEST_DATABASE_URL is not set: the end-to-end test needs a PostgreSQL with the csp-auth-db migrations")
	}
	ctx := context.Background()
	cfg := testConfig(t)
	cfg.DatabaseURL = databaseURL
	cfg.BcryptRounds = 4
	cfg.JWTPrivateKey = generatedKeyPEM(t)
	handler, closeDatabase, err := newHandler(ctx, discardLogger(), cfg, persistence.NewPool)
	if err != nil {
		t.Fatalf("newHandler() error = %v", err)
	}
	t.Cleanup(closeDatabase)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	ids := system.UUIDGenerator{}
	prefix := "e2e-list-" + strings.ReplaceAll(ids.NewID(), "-", "")[:12]
	signUp := func(suffix string) (email, id, access string) {
		email = prefix + suffix + "@example.com"
		body := fmt.Sprintf(`{"email":%q,"password":%q,"name":"Ada Lovelace","phone":"+573001234567","address":"Calle 1 # 2-3"}`, email, e2ePassword)
		status, payload := register(t, server.URL, ids.NewID(), body)
		if status != http.StatusCreated {
			t.Fatalf("register status = %d, want 201; body = %v", status, payload)
		}
		user, _ := payload["user"].(map[string]any)
		id, _ = user["id"].(string)
		access, _ = payload["accessToken"].(string)
		return email, id, access
	}
	adminEmail, adminID, _ := signUp("-a")
	_, targetID, clientToken := signUp("-b")
	conn := lockAdministrators(t, ctx, databaseURL)
	if _, err := conn.Exec(ctx, `INSERT INTO auth.user_role (user_id, role_id) SELECT $1, id FROM auth.role WHERE name = 'ADMIN'`, adminID); err != nil {
		t.Fatalf("seed the administrator: %v", err)
	}
	_, _, signedIn := login(t, server.URL, fmt.Sprintf(`{"email":%q,"password":%q}`, adminEmail, e2ePassword))
	adminToken, _ := signedIn["accessToken"].(string)

	if status, _ := listUsers(t, server.URL, "", "?email="+prefix); status != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", status)
	}
	if status, _ := listUsers(t, server.URL, clientToken, "?email="+prefix); status != http.StatusForbidden {
		t.Errorf("client token: status = %d, want 403", status)
	}

	status, payload := listUsers(t, server.URL, adminToken, "?limit=1&email="+url.QueryEscape(strings.ToUpper(prefix)))
	data, _ := payload["data"].([]any)
	meta, _ := payload["meta"].(map[string]any)
	if status != http.StatusOK || len(data) != 1 || meta["total"] != float64(2) || meta["totalPages"] != float64(2) || meta["limit"] != float64(1) {
		t.Fatalf("status = %d, body = %v, want 200, one item of two users and two pages", status, payload)
	}
	first, _ := data[0].(map[string]any)
	if first["id"] != adminID || first["email"] != adminEmail {
		t.Errorf("first item = %v, want the administrator (email order)", first)
	}
	if _, leaked := first["permissions"]; leaked {
		t.Errorf("first item = %v, want no permissions", first)
	}
	if roles, _ := first["roles"].([]any); len(roles) != 2 {
		t.Errorf("roles = %v, want ADMIN and CLIENT", first["roles"])
	}

	if _, payload := listUsers(t, server.URL, adminToken, "?page=2&limit=1&email="+prefix); fmt.Sprint(payload["data"]) == "[]" || !strings.Contains(fmt.Sprint(payload["data"]), targetID) {
		t.Errorf("page 2 = %v, want the second user %s", payload, targetID)
	}
	if status, payload := listUsers(t, server.URL, adminToken, "?email="); status != http.StatusBadRequest || payload["error"] != "VALIDATION_ERROR" {
		t.Errorf("empty prefix: status = %d, body = %v, want 400 VALIDATION_ERROR", status, payload)
	}
}

func listUsers(t *testing.T, baseURL, bearer, query string) (int, map[string]any) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/auth/users"+query, nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("GET users error = %v", err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode the response (status %d): %v", response.StatusCode, err)
	}
	return response.StatusCode, payload
}
