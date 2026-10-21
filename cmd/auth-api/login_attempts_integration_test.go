//go:build integration

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The test logs in over HTTP against a PostgreSQL with the csp-auth-db migrations and the Redis 7 of
// csp-infra-redis with the ACL of auth_app (HU-AUTH-005). The limit is 3 failures and a 2-second lock
// so the cooldown can be waited for; the address that counts is the last entry of X-Forwarded-For,
// like behind the gateway, so every subtest uses its own address.
func TestLoginAttemptLimitEndToEndAgainstTheDatabaseAndRedis(t *testing.T) {
	databaseURL, redisURL := os.Getenv("AUTH_TEST_DATABASE_URL"), os.Getenv("AUTH_TEST_REDIS_URL")
	if databaseURL == "" || redisURL == "" {
		t.Skip("AUTH_TEST_DATABASE_URL and AUTH_TEST_REDIS_URL are not set: the end-to-end test needs PostgreSQL with the csp-auth-db migrations and the Redis of csp-infra-redis")
	}
	cfg := testConfig(t)
	cfg.DatabaseURL = databaseURL
	cfg.RedisURL = redisURL
	cfg.BcryptRounds = 4
	cfg.JWTPrivateKey = generatedKeyPEM(t)
	cfg.LoginMaxAttempts, cfg.LoginWindow, cfg.LoginLock = 3, time.Minute, 2*time.Second
	server := startLogoutServer(t, cfg)
	email, _, _, _ := signUpUser(t, server.URL, "e2e-limit")
	right := fmt.Sprintf(`{"email":%q,"password":%q}`, email, e2ePassword)
	wrong := fmt.Sprintf(`{"email":%q,"password":"Wrong-1234"}`, email)
	failTimes := func(t *testing.T, address string, times int) {
		t.Helper()
		for i := 1; i <= times; i++ {
			if status, _, _ := loginFromAddress(t, server.URL, address, wrong); status != http.StatusUnauthorized {
				t.Fatalf("failed attempt %d: status = %d, want 401", i, status)
			}
		}
	}

	t.Run("the attempt after the maximum is 429 even with the right password, and Retry-After says how long", func(t *testing.T) {
		address := newTestAddress()
		failTimes(t, address, 3)

		status, header, payload := loginFromAddress(t, server.URL, address, right)

		if status != http.StatusTooManyRequests || payload["error"] != "RATE_LIMITED" {
			t.Fatalf("status = %d, body = %v, want 429 RATE_LIMITED", status, payload)
		}
		if seconds, err := strconv.Atoi(header.Get("Retry-After")); err != nil || seconds < 1 || seconds > 2 {
			t.Errorf("Retry-After = %q, want 1 or 2 seconds", header.Get("Retry-After"))
		}
	})

	t.Run("another address is not affected", func(t *testing.T) {
		failTimes(t, newTestAddress(), 3)

		if status, _, payload := loginFromAddress(t, server.URL, newTestAddress(), right); status != http.StatusOK {
			t.Errorf("status = %d, body = %v, want 200", status, payload)
		}
	})

	t.Run("after the cooldown the right credentials authenticate normally", func(t *testing.T) {
		address := newTestAddress()
		failTimes(t, address, 3)
		time.Sleep(2300 * time.Millisecond)

		if status, _, payload := loginFromAddress(t, server.URL, address, right); status != http.StatusOK {
			t.Errorf("status = %d, body = %v, want 200", status, payload)
		}
	})

	t.Run("a successful login clears the failures", func(t *testing.T) {
		address := newTestAddress()
		failTimes(t, address, 2)
		if status, _, _ := loginFromAddress(t, server.URL, address, right); status != http.StatusOK {
			t.Fatalf("right credentials: status = %d, want 200", status)
		}

		failTimes(t, address, 2)

		if status, _, _ := loginFromAddress(t, server.URL, address, right); status != http.StatusOK {
			t.Errorf("status = %d, want 200: the failures before the success must not count", status)
		}
	})

	t.Run("an address forged at the start of X-Forwarded-For does not escape the limit", func(t *testing.T) {
		address := newTestAddress()
		for i := 1; i <= 3; i++ {
			forged := fmt.Sprintf("9.9.9.%d, %s", i, address)
			if status, _, _ := loginFromAddress(t, server.URL, forged, wrong); status != http.StatusUnauthorized {
				t.Fatalf("failed attempt %d: status = %d, want 401", i, status)
			}
		}

		if status, _, _ := loginFromAddress(t, server.URL, "9.9.9.200, "+address, right); status != http.StatusTooManyRequests {
			t.Errorf("status = %d, want 429", status)
		}
	})

	t.Run("with Redis down the login goes on and is not limited", func(t *testing.T) {
		down := cfg
		down.RedisURL = "redis://auth_app:unused@127.0.0.1:1/0"
		down.RedisTimeout = 300 * time.Millisecond
		downServer := startLogoutServer(t, down)
		address := newTestAddress()
		for i := 1; i <= 4; i++ {
			if status, _, _ := loginFromAddress(t, downServer.URL, address, wrong); status != http.StatusUnauthorized {
				t.Fatalf("failed attempt %d: status = %d, want 401", i, status)
			}
		}

		if status, _, payload := loginFromAddress(t, downServer.URL, address, right); status != http.StatusOK {
			t.Errorf("status = %d, body = %v, want 200", status, payload)
		}
	})
}

var testAddressCounter = time.Now().UnixNano() % 1_000_000

// newTestAddress is an address of the documentation range that no other test or earlier run uses.
func newTestAddress() string {
	testAddressCounter++
	return fmt.Sprintf("198.51.%d.%d", (testAddressCounter/250)%250, testAddressCounter%250+1)
}

func loginFromAddress(t *testing.T, baseURL, forwardedFor, body string) (int, http.Header, map[string]any) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+loginPath, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Forwarded-For", forwardedFor)
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
