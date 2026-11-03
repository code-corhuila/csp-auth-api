//go:build integration

package main

import (
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

// Criterion 3 of code-corhuila/csp-docs#280 (STRIDE S), end to end against PostgreSQL with the csp-auth-db migrations and the Redis of
// csp-infra-redis: 25 failed logins for one email, each from a different address, so the address lock never acts; the 26th answer
// takes at least one second, and the account is not locked: the right password still opens a session.
func TestAuthzLoginSlowsTheAnswersOfOneEmailAfterTwentyFailuresFromDifferentAddresses(t *testing.T) {
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
	email, _, _, _ := signUpUser(t, server.URL, "e2e-slow")
	wrong := fmt.Sprintf(`{"email":%q,"password":"Wrong-1234"}`, email)
	right := fmt.Sprintf(`{"email":%q,"password":%q}`, email, e2ePassword)

	for i := 1; i <= 25; i++ {
		started := time.Now()
		status, _, _ := loginFromAddress(t, server.URL, newTestAddress(), wrong)
		if status != http.StatusUnauthorized {
			t.Fatalf("failed login %d: status = %d, want 401", i, status)
		}
		if i <= 20 && time.Since(started) >= time.Second {
			t.Fatalf("failed login %d took %v, only the ones after the 20th are slowed", i, time.Since(started))
		}
	}

	started := time.Now()
	status, _, payload := loginFromAddress(t, server.URL, newTestAddress(), wrong)
	elapsed := time.Since(started)

	if status != http.StatusUnauthorized || payload["error"] != "INVALID_CREDENTIALS" {
		t.Errorf("26th failure: status = %d, body = %v, want the usual 401", status, payload)
	}
	if elapsed < time.Second {
		t.Errorf("26th failure answered in %v, want at least 1s", elapsed)
	}
	if status, _, payload := loginFromAddress(t, server.URL, newTestAddress(), right); status != http.StatusOK {
		t.Errorf("right password after 26 failures: status = %d, body = %v, want 200: the account is slowed, not locked", status, payload)
	}
}
