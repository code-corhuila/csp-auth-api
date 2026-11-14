//go:build integration

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/redis"
)

// The test checks over HTTP, with real tokens, PostgreSQL and the Redis of the auth_app user, that
// removing ADMIN ends the sessions of the user (ADR-031, amendment 2026-10-24): the access token that
// was issued before is 401 on every route that reads the revoked list, every refresh token is 401, the
// marker blacklist:user:{userId} holds the instant with a life of at most one hour, and a login after the
// revocation gives a session with only CLIENT that is accepted. A grant, a repeated revoke and the
// other users end nothing.
func TestRemovingAdminEndsTheSessionsOfTheUserEndToEnd(t *testing.T) {
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
	client, err := redis.NewClient(redis.ClientSettings{URL: redisURL, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("redis.NewClient() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	grant, revoke := `{"role":"ADMIN","enabled":true}`, `{"role":"ADMIN","enabled":false}`
	seedAdmin := func(userID string) {
		if _, err := lock.Exec(ctx, `INSERT INTO auth.user_role (user_id, role_id) SELECT $1, id FROM auth.role WHERE name = 'ADMIN'`, userID); err != nil {
			t.Fatalf("seed the administrator: %v", err)
		}
	}
	signIn := func(email string) (access, refreshToken string) {
		status, _, payload := login(t, server.URL, fmt.Sprintf(`{"email":%q,"password":%q}`, email, e2ePassword))
		access, _ = payload["accessToken"].(string)
		refreshToken, _ = payload["refreshToken"].(string)
		if status != http.StatusOK || access == "" {
			t.Fatalf("login: status = %d, body = %v", status, payload)
		}
		return access, refreshToken
	}
	// A token issued in the second of the revocation is rejected on purpose (inside one second the order
	// cannot be told), so a session that must survive is opened in a later second.
	waitForTheNextSecond := func() { time.Sleep(1100 * time.Millisecond) }

	emailA, idA, _, _ := signUpUser(t, server.URL, "e2e-ends-a")
	emailB, idB, _, _ := signUpUser(t, server.URL, "e2e-ends-b")
	_, idC, tokenC, refreshC := signUpUser(t, server.URL, "e2e-ends-c")
	seedAdmin(idA)
	seedAdmin(idB)
	tokenA1, refreshA1 := signIn(emailA)
	tokenA2, refreshA2 := signIn(emailA)
	tokenB, _ := signIn(emailB)
	listAs := func(token string) int {
		status, _ := listUsers(t, server.URL, token, "?email=e2e-ends")
		return status
	}
	if listAs(tokenA1) != http.StatusOK || listAs(tokenA2) != http.StatusOK || listAs(tokenB) != http.StatusOK {
		t.Fatal("the administrators must be accepted before the revocation")
	}

	t.Run("a grant ends no session and does not write a marker", func(t *testing.T) {
		if status, payload := patchRole(t, server.URL, tokenB, idC, grant); status != http.StatusOK {
			t.Fatalf("grant: status = %d, body = %v, want 200", status, payload)
		}
		if exists, _ := client.Exists(ctx, "blacklist:user:"+idC).Result(); exists != 0 {
			t.Error("a grant wrote the marker of the user")
		}
		status, _, renewed := refresh(t, server.URL, refreshC)
		if status != http.StatusOK {
			t.Fatalf("refresh after the grant: status = %d, want 200", status)
		}
		refreshC, _ = renewed["refreshToken"].(string)
	})

	t.Run("revoking ADMIN of A ends every access token and refresh token of A", func(t *testing.T) {
		before := time.Now().Unix()
		if status, payload := patchRole(t, server.URL, tokenB, idA, revoke); status != http.StatusOK || slices.Contains(toStrings(payload["roles"]), "ADMIN") {
			t.Fatalf("revoke: status = %d, body = %v, want 200 without ADMIN", status, payload)
		}

		for name, token := range map[string]string{"first token": tokenA1, "second token": tokenA2} {
			if status := listAs(token); status != http.StatusUnauthorized {
				t.Errorf("%s on GET /users: status = %d, want 401", name, status)
			}
			if status, _ := patchRole(t, server.URL, token, idC, grant); status != http.StatusUnauthorized {
				t.Errorf("%s on PATCH role: status = %d, want 401", name, status)
			}
			if status := logout(t, server.URL, token, ""); status != http.StatusUnauthorized {
				t.Errorf("%s on POST /logout: status = %d, want 401", name, status)
			}
		}
		for name, token := range map[string]string{"first": refreshA1, "second": refreshA2} {
			if status, _, payload := refresh(t, server.URL, token); status != http.StatusUnauthorized || payload["error"] != "INVALID_REFRESH_TOKEN" {
				t.Errorf("%s refresh token: status = %d, body = %v, want 401 INVALID_REFRESH_TOKEN", name, status, payload)
			}
		}
		raw, err := client.Get(ctx, "blacklist:user:"+idA).Result()
		instant, _ := strconv.ParseInt(raw, 10, 64)
		if err != nil || instant < before || instant > time.Now().Unix() {
			t.Errorf("marker = %q, %v; want the epoch second of the revocation", raw, err)
		}
		if ttl, err := client.TTL(ctx, "blacklist:user:"+idA).Result(); err != nil || ttl <= 0 || ttl > time.Hour {
			t.Errorf("marker ttl = %v, %v; want at most 3600 s", ttl, err)
		}
	})

	t.Run("the other users are not affected", func(t *testing.T) {
		if status := listAs(tokenB); status != http.StatusOK {
			t.Errorf("administrator B: status = %d, want 200", status)
		}
		if status := listAs(tokenC); status != http.StatusForbidden {
			t.Errorf("client C: status = %d, want 403 and not 401", status)
		}
		if status, _, _ := refresh(t, server.URL, refreshC); status != http.StatusOK {
			t.Errorf("refresh of C: status = %d, want 200", status)
		}
	})

	t.Run("a login after the revocation gives a session with only CLIENT that is accepted", func(t *testing.T) {
		waitForTheNextSecond()

		token, refreshToken := signIn(emailA)

		if roles := rolesOf(t, token); !slices.Equal(roles, []string{"CLIENT"}) {
			t.Errorf("roles = %v, want only CLIENT", roles)
		}
		if status := listAs(token); status != http.StatusForbidden {
			t.Errorf("GET /users with the new token: status = %d, want 403 (accepted, without the permission)", status)
		}
		if status, _, _ := refresh(t, server.URL, refreshToken); status != http.StatusOK {
			t.Errorf("refresh of the new session: status = %d, want 200", status)
		}
		if status := listAs(tokenA1); status != http.StatusUnauthorized {
			t.Errorf("the old token: status = %d, want 401 while the marker lives", status)
		}
	})

	t.Run("revoking again a role that is not held changes nothing and ends no session", func(t *testing.T) {
		waitForTheNextSecond()
		token, _ := signIn(emailA)
		before, err := client.Get(ctx, "blacklist:user:"+idA).Result()
		if err != nil {
			t.Fatal(err)
		}

		if status, payload := patchRole(t, server.URL, tokenB, idA, revoke); status != http.StatusOK {
			t.Fatalf("repeated revoke: status = %d, body = %v, want 200", status, payload)
		}

		if after, _ := client.Get(ctx, "blacklist:user:"+idA).Result(); after != before {
			t.Errorf("marker = %q, want it unchanged (%q)", after, before)
		}
		if status := listAs(token); status != http.StatusForbidden {
			t.Errorf("session opened after the first revocation: status = %d, want 403 and not 401", status)
		}
	})

	t.Run("an administrator who revokes their own ADMIN gets 200 and the next call is 401", func(t *testing.T) {
		if status, payload := patchRole(t, server.URL, tokenB, idA, grant); status != http.StatusOK {
			t.Fatalf("grant to A: status = %d, body = %v, want 200", status, payload)
		}
		waitForTheNextSecond()
		token, refreshToken := signIn(emailA)
		if status := listAs(token); status != http.StatusOK {
			t.Fatalf("A with ADMIN again: status = %d, want 200", status)
		}

		if status, payload := patchRole(t, server.URL, token, idA, revoke); status != http.StatusOK {
			t.Fatalf("self revoke: status = %d, body = %v, want 200", status, payload)
		}

		if status := listAs(token); status != http.StatusUnauthorized {
			t.Errorf("next call with the same token: status = %d, want 401", status)
		}
		if status, _, _ := refresh(t, server.URL, refreshToken); status != http.StatusUnauthorized {
			t.Errorf("refresh: status = %d, want 401", status)
		}
		if status := listAs(tokenB); status != http.StatusOK {
			t.Errorf("administrator B: status = %d, want 200", status)
		}
	})

	t.Run("a refused revoke ends nothing", func(t *testing.T) {
		if _, err := lock.Exec(ctx, `UPDATE auth.user_role SET deleted_at = NOW() WHERE deleted_at IS NULL AND user_id <> $1
		   AND role_id = (SELECT id FROM auth.role WHERE name = 'ADMIN')`, idB); err != nil {
			t.Fatalf("retire the other administrators: %v", err)
		}
		waitForTheNextSecond()
		token, refreshToken := signIn(emailB)
		before, _ := client.Get(ctx, "blacklist:user:"+idB).Result()

		if status, payload := patchRole(t, server.URL, token, idB, revoke); status != http.StatusConflict || payload["error"] != "LAST_ADMIN" {
			t.Fatalf("status = %d, body = %v, want 409 LAST_ADMIN", status, payload)
		}

		if status := listAs(token); status != http.StatusOK {
			t.Errorf("token after LAST_ADMIN: status = %d, want 200", status)
		}
		if status, _, _ := refresh(t, server.URL, refreshToken); status != http.StatusOK {
			t.Errorf("refresh after LAST_ADMIN: status = %d, want 200", status)
		}
		if after, _ := client.Get(ctx, "blacklist:user:"+idB).Result(); after != before {
			t.Errorf("marker = %q, want it unchanged (%q)", after, before)
		}
	})
}
