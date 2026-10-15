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
	"slices"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/persistence"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/system"
)

// adminLockKey serializes the tests that count or retire the administrators of the shared test
// database; the persistence tests take the same advisory lock.
const adminLockKey = 3013

// The test changes roles over HTTP the way the administrator portal does, with real access tokens:
// the guard answers 401 and 403, the last administrator is protected, a grant reaches the target at
// its next login and refresh, and a repeated request changes nothing (ADR-031).
func TestChangeUserRoleEndToEndAgainstTheDatabase(t *testing.T) {
	url := os.Getenv("AUTH_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AUTH_TEST_DATABASE_URL is not set: the end-to-end test needs a PostgreSQL with the csp-auth-db migrations")
	}
	ctx := context.Background()
	lock := connect(t, ctx, url)
	if _, err := lock.Exec(ctx, `SELECT pg_advisory_lock($1)`, adminLockKey); err != nil {
		t.Fatalf("take the administrators lock: %v", err)
	}
	t.Cleanup(func() { _, _ = lock.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, adminLockKey) })

	cfg := testConfig(t)
	cfg.DatabaseURL = url
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
	signUp := func(name string) (email, id, access, refreshToken string) {
		email = name + "-" + ids.NewID() + "@example.com"
		body := fmt.Sprintf(`{"email":%q,"password":%q,"name":"Ada Lovelace","phone":"+573001234567","address":"Calle 1 # 2-3"}`, email, e2ePassword)
		status, payload := register(t, server.URL, ids.NewID(), body)
		if status != http.StatusCreated {
			t.Fatalf("register status = %d, want 201; body = %v", status, payload)
		}
		user, _ := payload["user"].(map[string]any)
		id, _ = user["id"].(string)
		access, _ = payload["accessToken"].(string)
		refreshToken, _ = payload["refreshToken"].(string)
		return email, id, access, refreshToken
	}
	adminEmail, adminID, _, _ := signUp("e2e-admin")
	targetEmail, targetID, clientToken, targetRefresh := signUp("e2e-target")
	if _, err := lock.Exec(ctx,
		`INSERT INTO auth.user_role (user_id, role_id) SELECT $1, id FROM auth.role WHERE name = 'ADMIN'`, adminID); err != nil {
		t.Fatalf("seed the administrator: %v", err)
	}
	if _, err := lock.Exec(ctx,
		`UPDATE auth.user_role SET deleted_at = NOW() WHERE deleted_at IS NULL AND user_id <> $1
		   AND role_id = (SELECT id FROM auth.role WHERE name = 'ADMIN')`, adminID); err != nil {
		t.Fatalf("retire the other administrators: %v", err)
	}
	_, _, adminLogin := login(t, server.URL, fmt.Sprintf(`{"email":%q,"password":%q}`, adminEmail, e2ePassword))
	adminToken, _ := adminLogin["accessToken"].(string)
	if !slices.Contains(rolesOf(t, adminToken), "ADMIN") {
		t.Fatalf("the administrator token has roles %v, want ADMIN", rolesOf(t, adminToken))
	}
	grant, revoke := `{"role":"ADMIN","enabled":true}`, `{"role":"ADMIN","enabled":false}`

	t.Run("a missing token is 401 and a CLIENT token is 403", func(t *testing.T) {
		if status, payload := patchRole(t, server.URL, "", targetID, grant); status != http.StatusUnauthorized || payload["error"] != "UNAUTHORIZED" {
			t.Errorf("no token: status = %d, body = %v, want 401 UNAUTHORIZED", status, payload)
		}
		if status, payload := patchRole(t, server.URL, clientToken, targetID, grant); status != http.StatusForbidden || payload["error"] != "FORBIDDEN" {
			t.Errorf("client token: status = %d, body = %v, want 403 FORBIDDEN", status, payload)
		}
	})

	t.Run("an invalid id or body is 400 and an unknown user is 404", func(t *testing.T) {
		if status, payload := patchRole(t, server.URL, adminToken, "not-a-uuid", grant); status != http.StatusBadRequest || payload["error"] != "VALIDATION_ERROR" {
			t.Errorf("invalid id: status = %d, body = %v, want 400 VALIDATION_ERROR", status, payload)
		}
		if status, payload := patchRole(t, server.URL, adminToken, targetID, `{"role":"CLIENT","enabled":true}`); status != http.StatusBadRequest || payload["error"] != "VALIDATION_ERROR" {
			t.Errorf("CLIENT role: status = %d, body = %v, want 400 VALIDATION_ERROR", status, payload)
		}
		if status, payload := patchRole(t, server.URL, adminToken, ids.NewID(), grant); status != http.StatusNotFound || payload["error"] != "NOT_FOUND" {
			t.Errorf("unknown user: status = %d, body = %v, want 404 NOT_FOUND", status, payload)
		}
	})

	t.Run("the only administrator cannot revoke itself", func(t *testing.T) {
		if status, payload := patchRole(t, server.URL, adminToken, adminID, revoke); status != http.StatusConflict || payload["error"] != "LAST_ADMIN" {
			t.Errorf("status = %d, body = %v, want 409 LAST_ADMIN", status, payload)
		}
	})

	t.Run("revoking the only role of a user is 409 USER_WITHOUT_ROLES, and LAST_ADMIN wins when both apply", func(t *testing.T) {
		_, soloID, _, _ := signUp("e2e-solo")
		if _, err := lock.Exec(ctx, `UPDATE auth.user_role SET deleted_at = NOW() WHERE user_id = $1 AND role_id = (SELECT id FROM auth.role WHERE name = 'CLIENT')`, soloID); err != nil {
			t.Fatalf("drop CLIENT: %v", err)
		}
		if _, err := lock.Exec(ctx, `INSERT INTO auth.user_role (user_id, role_id) SELECT $1, id FROM auth.role WHERE name = 'ADMIN'`, soloID); err != nil {
			t.Fatalf("seed the ADMIN-only user: %v", err)
		}
		if status, payload := patchRole(t, server.URL, adminToken, soloID, revoke); status != http.StatusConflict || payload["error"] != "USER_WITHOUT_ROLES" {
			t.Errorf("status = %d, body = %v, want 409 USER_WITHOUT_ROLES", status, payload)
		}
		retire := `UPDATE auth.user_role SET deleted_at = NOW() WHERE user_id = $1 AND role_id = (SELECT id FROM auth.role WHERE name = 'ADMIN')`
		if _, err := lock.Exec(ctx, retire, adminID); err != nil {
			t.Fatalf("retire the first administrator: %v", err)
		}
		if status, payload := patchRole(t, server.URL, adminToken, soloID, revoke); status != http.StatusConflict || payload["error"] != "LAST_ADMIN" {
			t.Errorf("status = %d, body = %v, want 409 LAST_ADMIN when both rules apply", status, payload)
		}
		if _, err := lock.Exec(ctx, retire, soloID); err != nil {
			t.Fatalf("retire the ADMIN-only user: %v", err)
		}
		if _, err := lock.Exec(ctx, `UPDATE auth.user_role SET deleted_at = NULL WHERE user_id = $1 AND role_id = (SELECT id FROM auth.role WHERE name = 'ADMIN')`, adminID); err != nil {
			t.Fatalf("restore the first administrator: %v", err)
		}
	})

	t.Run("a grant answers the user, reaches the target at its next login and refresh, and repeating it changes nothing", func(t *testing.T) {
		status, payload := patchRole(t, server.URL, adminToken, targetID, grant)
		if status != http.StatusOK || !slices.Contains(toStrings(payload["roles"]), "ADMIN") {
			t.Fatalf("status = %d, body = %v, want 200 with ADMIN", status, payload)
		}
		if again, _ := patchRole(t, server.URL, adminToken, targetID, grant); again != http.StatusOK {
			t.Errorf("repeated grant: status = %d, want 200", again)
		}
		if status, _ := patchRole(t, server.URL, clientToken, targetID, revoke); status != http.StatusForbidden {
			t.Errorf("the token issued before the grant: status = %d, want 403 (it keeps its roles until it expires)", status)
		}
		if _, _, signedIn := login(t, server.URL, fmt.Sprintf(`{"email":%q,"password":%q}`, targetEmail, e2ePassword)); !slices.Contains(rolesOf(t, fmt.Sprint(signedIn["accessToken"])), "ADMIN") {
			t.Errorf("login after the grant: roles = %v, want ADMIN", signedIn)
		}
		refreshed, _, renewed := refresh(t, server.URL, targetRefresh)
		if refreshed != http.StatusOK || !slices.Contains(rolesOf(t, fmt.Sprint(renewed["accessToken"])), "ADMIN") {
			t.Errorf("refresh: status = %d, body = %v, want a token with ADMIN", refreshed, renewed)
		}
	})

	t.Run("with two administrators one may revoke the other, and the revoked one loses ADMIN at its next login", func(t *testing.T) {
		if status, payload := patchRole(t, server.URL, adminToken, targetID, revoke); status != http.StatusOK || slices.Contains(toStrings(payload["roles"]), "ADMIN") {
			t.Fatalf("status = %d, body = %v, want 200 without ADMIN", status, payload)
		}
		if status, payload := patchRole(t, server.URL, adminToken, targetID, revoke); status != http.StatusOK {
			t.Errorf("repeated revoke: status = %d, body = %v, want 200", status, payload)
		}
		if _, _, signedIn := login(t, server.URL, fmt.Sprintf(`{"email":%q,"password":%q}`, targetEmail, e2ePassword)); slices.Contains(rolesOf(t, fmt.Sprint(signedIn["accessToken"])), "ADMIN") {
			t.Errorf("login after the revoke: roles = %v, want no ADMIN", signedIn)
		}
	})
}

func patchRole(t *testing.T, baseURL, bearer, userID, body string) (int, map[string]any) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPatch, baseURL+"/api/v1/auth/users/"+userID+"/role", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "e2e-role-"+userID)
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("PATCH role error = %v", err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode the response (status %d): %v", response.StatusCode, err)
	}
	return response.StatusCode, payload
}

// rolesOf reads the roles claim of a token that the test already trusts.
func rolesOf(t *testing.T, accessToken string) []string {
	t.Helper()
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(accessToken, claims); err != nil {
		t.Fatalf("parse the access token: %v", err)
	}
	return toStrings(claims["roles"])
}

func toStrings(value any) []string {
	items, _ := value.([]any)
	names := make([]string, 0, len(items))
	for _, item := range items {
		names = append(names, fmt.Sprint(item))
	}
	return names
}
