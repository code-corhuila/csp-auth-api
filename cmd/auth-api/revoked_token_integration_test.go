//go:build integration

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

// The test checks the revoked token list on the protected routes over HTTP with real tokens
// (ADR-033): after a logout the same access token is 401 on logout, GET /users and PATCH
// /users/{userId}/role, even though it would have been accepted before; a CLIENT token that was logged
// out is 401, not 403; with Redis down the routes fail closed with 500; without a Redis URL they
// work without the check.
func TestRevokedAccessTokenIsRejectedOnTheProtectedRoutesEndToEnd(t *testing.T) {
	databaseURL, redisURL := os.Getenv("AUTH_TEST_DATABASE_URL"), os.Getenv("AUTH_TEST_REDIS_URL")
	if databaseURL == "" || redisURL == "" {
		t.Skip("AUTH_TEST_DATABASE_URL and AUTH_TEST_REDIS_URL are not set: the end-to-end test needs PostgreSQL with the csp-auth-db migrations and the Redis of csp-infra-redis")
	}
	ctx := context.Background()
	lock := lockAdministrators(t, ctx, databaseURL)
	cfg := testConfig(t)
	cfg.DatabaseURL = databaseURL
	cfg.RedisURL = redisURL
	cfg.BcryptRounds = 4
	cfg.JWTPrivateKey = generatedKeyPEM(t)
	server := startLogoutServer(t, cfg)
	withoutRedis := cfg
	withoutRedis.RedisURL = ""
	unconfiguredServer := startLogoutServer(t, withoutRedis)
	redisDown := cfg
	redisDown.RedisURL = "redis://auth_app:unused@127.0.0.1:1/0"
	redisDown.RedisTimeout = 300 * time.Millisecond
	downServer := startLogoutServer(t, redisDown)

	adminEmail, adminID, _, _ := signUpUser(t, server.URL, "e2e-revoked-admin")
	_, clientID, clientToken, _ := signUpUser(t, server.URL, "e2e-revoked-client")
	if _, err := lock.Exec(ctx, `INSERT INTO auth.user_role (user_id, role_id) SELECT $1, id FROM auth.role WHERE name = 'ADMIN'`, adminID); err != nil {
		t.Fatalf("seed the administrator: %v", err)
	}
	signInAdmin := func() string {
		status, _, payload := login(t, server.URL, fmt.Sprintf(`{"email":%q,"password":%q}`, adminEmail, e2ePassword))
		token, _ := payload["accessToken"].(string)
		if status != http.StatusOK || token == "" {
			t.Fatalf("login of the administrator: status = %d, body = %v", status, payload)
		}
		return token
	}
	const noChange = `{"role":"ADMIN","enabled":false}`
	listAdmins := func(url, token string) int {
		status, _ := listUsers(t, url, token, "?email=e2e-revoked-admin")
		return status
	}
	changeRole := func(url, token string) int {
		status, _ := patchRole(t, url, token, clientID, noChange)
		return status
	}

	adminToken := signInAdmin()
	t.Run("before the logout the administrator token is accepted", func(t *testing.T) {
		if status := listAdmins(server.URL, adminToken); status != http.StatusOK {
			t.Errorf("GET /users: status = %d, want 200", status)
		}
		if status := changeRole(server.URL, adminToken); status != http.StatusOK {
			t.Errorf("PATCH role: status = %d, want 200", status)
		}
	})

	t.Run("after the logout the same token is 401 on logout, GET /users and PATCH role", func(t *testing.T) {
		if status := logout(t, server.URL, adminToken, ""); status != http.StatusNoContent {
			t.Fatalf("logout: status = %d, want 204", status)
		}

		if status := logout(t, server.URL, adminToken, `{"allDevices":true}`); status != http.StatusUnauthorized {
			t.Errorf("second logout: status = %d, want 401", status)
		}
		if status := listAdmins(server.URL, adminToken); status != http.StatusUnauthorized {
			t.Errorf("GET /users: status = %d, want 401", status)
		}
		if status := changeRole(server.URL, adminToken); status != http.StatusUnauthorized {
			t.Errorf("PATCH role: status = %d, want 401", status)
		}
	})

	t.Run("a new token of the same user is accepted", func(t *testing.T) {
		if status := listAdmins(server.URL, signInAdmin()); status != http.StatusOK {
			t.Errorf("GET /users with a new token: status = %d, want 200", status)
		}
	})

	t.Run("a CLIENT token is 403 before its logout and 401 after it", func(t *testing.T) {
		if status := listAdmins(server.URL, clientToken); status != http.StatusForbidden {
			t.Fatalf("GET /users before: status = %d, want 403", status)
		}
		if status := logout(t, server.URL, clientToken, ""); status != http.StatusNoContent {
			t.Fatalf("logout: status = %d, want 204", status)
		}
		if status := listAdmins(server.URL, clientToken); status != http.StatusUnauthorized {
			t.Errorf("GET /users after: status = %d, want 401 (a revoked token is not authenticated, so it is not judged for permissions)", status)
		}
	})

	t.Run("with Redis down the protected routes fail closed with 500 and a forged token is still 401", func(t *testing.T) {
		token := signInAdmin()

		for name, status := range map[string]int{
			"GET /users":  listAdmins(downServer.URL, token),
			"PATCH role":  changeRole(downServer.URL, token),
			"POST logout": logout(t, downServer.URL, token, ""),
		} {
			if status != http.StatusInternalServerError {
				t.Errorf("%s: status = %d, want 500", name, status)
			}
		}
		if status := listAdmins(downServer.URL, "not-a-token"); status != http.StatusUnauthorized {
			t.Errorf("forged token: status = %d, want 401 without consulting Redis", status)
		}
		if status := listAdmins(server.URL, token); status != http.StatusOK {
			t.Errorf("the same token with Redis up: status = %d, want 200 (the failed logout revoked nothing)", status)
		}
	})

	t.Run("without a Redis URL the routes work without the check and logout is not enabled", func(t *testing.T) {
		token := signInAdmin()

		if status := listAdmins(unconfiguredServer.URL, token); status != http.StatusOK {
			t.Errorf("GET /users: status = %d, want 200", status)
		}
		if status := logout(t, unconfiguredServer.URL, token, ""); status != http.StatusNotFound {
			t.Errorf("POST /logout: status = %d, want 404", status)
		}
	})
}
