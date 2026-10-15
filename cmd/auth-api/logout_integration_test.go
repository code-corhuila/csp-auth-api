//go:build integration

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	goredis "github.com/redis/go-redis/v9"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/persistence"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/redis"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/system"
	"github.com/code-corhuila/csp-auth-api/internal/config"
)

const logoutPath = "/api/v1/auth/logout"

// The test signs out over HTTP with real access and refresh tokens, a PostgreSQL with the csp-auth-db
// migrations and the Redis 7 of csp-infra-redis with the ACL of auth_app (ADR-033): the refresh
// tokens are revoked in PostgreSQL, the jti of the access token is listed with a ttl of its
// remaining life, a token of another user is never revoked, and with Redis down the call answers
// 500 although the refresh token stays revoked.
func TestLogoutEndToEndAgainstTheDatabaseAndRedis(t *testing.T) {
	databaseURL, redisURL := os.Getenv("AUTH_TEST_DATABASE_URL"), os.Getenv("AUTH_TEST_REDIS_URL")
	if databaseURL == "" || redisURL == "" {
		t.Skip("AUTH_TEST_DATABASE_URL and AUTH_TEST_REDIS_URL are not set: the end-to-end test needs PostgreSQL with the csp-auth-db migrations and the Redis of csp-infra-redis")
	}
	cfg := testConfig(t)
	cfg.DatabaseURL = databaseURL
	cfg.RedisURL = redisURL
	cfg.BcryptRounds = 4
	cfg.JWTPrivateKey = generatedKeyPEM(t)
	server := startLogoutServer(t, cfg)
	checker, err := redis.NewClient(redis.ClientSettings{URL: redisURL, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("redis.NewClient() error = %v", err)
	}
	t.Cleanup(func() { _ = checker.Close() })
	signUp := func(name string) (email, access, refreshToken string) {
		email, _, access, refreshToken = signUpUser(t, server.URL, name)
		return email, access, refreshToken
	}
	signIn := func(email string) (access, refreshToken string) {
		status, _, payload := login(t, server.URL, fmt.Sprintf(`{"email":%q,"password":%q}`, email, e2ePassword))
		if status != http.StatusOK {
			t.Fatalf("login status = %d, want 200; body = %v", status, payload)
		}
		access, _ = payload["accessToken"].(string)
		refreshToken, _ = payload["refreshToken"].(string)
		return access, refreshToken
	}
	email, firstAccess, firstRefresh := signUp("e2e-logout")
	_, _, otherRefresh := signUp("e2e-other")

	t.Run("a missing or forged access token is 401", func(t *testing.T) {
		for name, bearer := range map[string]string{"no token": "", "forged": "not-a-token"} {
			if status := logout(t, server.URL, bearer, ""); status != http.StatusUnauthorized {
				t.Errorf("%s: status = %d, want 401", name, status)
			}
		}
	})

	t.Run("it revokes the presented refresh token only, lists the access token and leaves other sessions alone", func(t *testing.T) {
		secondAccess, secondRefresh := signIn(email)

		if status := logout(t, server.URL, firstAccess, fmt.Sprintf(`{"refreshToken":%q}`, firstRefresh)); status != http.StatusNoContent {
			t.Fatalf("logout status = %d, want 204", status)
		}

		if status, _, payload := refresh(t, server.URL, firstRefresh); status != http.StatusUnauthorized || payload["error"] != "INVALID_REFRESH_TOKEN" {
			t.Errorf("the revoked refresh token: status = %d, body = %v, want 401 INVALID_REFRESH_TOKEN", status, payload)
		}
		assertListedForItsRemainingLife(t, checker, firstAccess)
		if status, _, _ := refresh(t, server.URL, secondRefresh); status != http.StatusOK {
			t.Errorf("the refresh token of the other session: status = %d, want 200", status)
		}
		if listed(t, checker, secondAccess) {
			t.Error("the access token of the other session was listed")
		}
	})

	t.Run("a refresh token of another user, an unknown one and one already revoked do not fail the call and revoke nothing", func(t *testing.T) {
		for name, presented := range map[string]string{"another user's": otherRefresh, "unknown": "never-issued", "already revoked": firstRefresh} {
			access, _ := signIn(email) // a logged out access token is 401, so each call needs its own
			if status := logout(t, server.URL, access, fmt.Sprintf(`{"refreshToken":%q}`, presented)); status != http.StatusNoContent {
				t.Errorf("%s: status = %d, want 204", name, status)
			}
		}
		status, _, renewed := refresh(t, server.URL, otherRefresh)
		if status != http.StatusOK {
			t.Fatalf("the refresh token of the other user: status = %d, want 200 (it must not be revoked)", status)
		}
		otherRefresh, _ = renewed["refreshToken"].(string)
	})

	t.Run("allDevices revokes every refresh token of the user and the token of another user passed in the body is not revoked", func(t *testing.T) {
		_, thirdRefresh := signIn(email)
		fourthAccess, fourthRefresh := signIn(email)

		body := fmt.Sprintf(`{"allDevices":true,"refreshToken":%q}`, otherRefresh)
		if status := logout(t, server.URL, fourthAccess, body); status != http.StatusNoContent {
			t.Fatalf("logout status = %d, want 204", status)
		}

		for name, token := range map[string]string{"third": thirdRefresh, "fourth": fourthRefresh} {
			if status, _, _ := refresh(t, server.URL, token); status != http.StatusUnauthorized {
				t.Errorf("%s refresh token: status = %d, want 401", name, status)
			}
		}
		if status, _, _ := refresh(t, server.URL, otherRefresh); status != http.StatusOK {
			t.Errorf("the refresh token of another user: status = %d, want 200", status)
		}
	})

	t.Run("a body that cannot be read is 400 and revokes nothing", func(t *testing.T) {
		access, refreshToken := signIn(email)

		if status := logout(t, server.URL, access, `{"refreshToken":`); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
		if status, _, _ := refresh(t, server.URL, refreshToken); status != http.StatusOK {
			t.Errorf("the refresh token after the rejected call: status = %d, want 200", status)
		}
	})

	t.Run("with Redis down the call is 500 but the refresh token is revoked, and a retry once Redis is back is 204", func(t *testing.T) {
		access, refreshToken := signIn(email)
		down := cfg
		down.RedisURL = "redis://auth_app:unused@127.0.0.1:1/0"
		down.RedisTimeout = 300 * time.Millisecond
		downServer := startLogoutServer(t, down)

		if status := logout(t, downServer.URL, access, fmt.Sprintf(`{"refreshToken":%q}`, refreshToken)); status != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", status)
		}

		if status, _, payload := refresh(t, server.URL, refreshToken); status != http.StatusUnauthorized || payload["error"] != "INVALID_REFRESH_TOKEN" {
			t.Errorf("the refresh token after the failed call: status = %d, body = %v, want 401 INVALID_REFRESH_TOKEN", status, payload)
		}
		if listed(t, checker, access) {
			t.Error("the access token was listed although Redis was down")
		}
		if status := logout(t, server.URL, access, ""); status != http.StatusNoContent {
			t.Errorf("retry once Redis is back: status = %d, want 204", status)
		}
		assertListedForItsRemainingLife(t, checker, access)
	})
}

// signUpUser registers a user with a unique email and returns the email, the id and the session.
func signUpUser(t *testing.T, baseURL, name string) (email, id, access, refreshToken string) {
	t.Helper()
	ids := system.UUIDGenerator{}
	email = name + "-" + ids.NewID() + "@example.com"
	body := fmt.Sprintf(`{"email":%q,"password":%q,"name":"Ada Lovelace","phone":"+573001234567","address":"Calle 1 # 2-3"}`, email, e2ePassword)
	status, payload := register(t, baseURL, ids.NewID(), body)
	if status != http.StatusCreated {
		t.Fatalf("register status = %d, want 201; body = %v", status, payload)
	}
	user, _ := payload["user"].(map[string]any)
	id, _ = user["id"].(string)
	access, _ = payload["accessToken"].(string)
	refreshToken, _ = payload["refreshToken"].(string)
	return email, id, access, refreshToken
}

func startLogoutServer(t *testing.T, cfg config.Config) *httptest.Server {
	t.Helper()
	handler, closeAll, err := newHandler(context.Background(), discardLogger(), cfg, persistence.NewPool)
	if err != nil {
		t.Fatalf("newHandler() error = %v", err)
	}
	t.Cleanup(closeAll)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func logout(t *testing.T, baseURL, bearer, body string) int {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+logoutPath, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("POST %s error = %v", logoutPath, err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode
}

func jtiOf(t *testing.T, accessToken string) string {
	t.Helper()
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(accessToken, claims); err != nil {
		t.Fatalf("parse the access token: %v", err)
	}
	jti, _ := claims["jti"].(string)
	return jti
}

func listed(t *testing.T, checker *goredis.Client, accessToken string) bool {
	t.Helper()
	found, err := checker.Exists(context.Background(), "blacklist:"+jtiOf(t, accessToken)).Result()
	if err != nil {
		t.Fatalf("EXISTS error = %v", err)
	}
	return found > 0
}

// assertListedForItsRemainingLife checks the key blacklist:{jti} and that it lives no longer than the token.
func assertListedForItsRemainingLife(t *testing.T, checker *goredis.Client, accessToken string) {
	t.Helper()
	key := "blacklist:" + jtiOf(t, accessToken)
	ttl, err := checker.TTL(context.Background(), key).Result()
	if err != nil {
		t.Fatalf("TTL error = %v", err)
	}
	if ttl <= 0 || ttl > time.Hour {
		t.Errorf("ttl of %s = %v, want between 0 and 1h (the remaining life of the access token)", key, ttl)
	}
}
