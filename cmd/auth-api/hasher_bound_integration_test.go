//go:build integration

package main

import (
	"fmt"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"
)

type loginOutcome struct {
	status     int
	retryAfter string
	code       any
	elapsed    time.Duration
}

// Criterion 2 of code-corhuila/csp-docs#281 (STRIDE D), end to end against PostgreSQL and Redis: with one hash slot and a real
// bcrypt cost, a burst of logins is answered, the ones that find no slot get 503 SERVICE_UNAVAILABLE with Retry-After in well
// under 200 ms plus the queue timeout, and the refusals count as nothing against the address or the account.
func TestAuthzLoginAnswers503WhenTheBoundOnConcurrentHashesIsFull(t *testing.T) {
	databaseURL, redisURL := os.Getenv("AUTH_TEST_DATABASE_URL"), os.Getenv("AUTH_TEST_REDIS_URL")
	if databaseURL == "" || redisURL == "" {
		t.Skip("AUTH_TEST_DATABASE_URL and AUTH_TEST_REDIS_URL are not set: the end-to-end test needs PostgreSQL with the csp-auth-db migrations and the Redis of csp-infra-redis")
	}
	cfg := testConfig(t)
	cfg.DatabaseURL = databaseURL
	cfg.RedisURL = redisURL
	cfg.BcryptRounds = 12
	cfg.BcryptMaxConcurrent = 1
	cfg.BcryptQueueTimeout = 20 * time.Millisecond
	cfg.LoginMaxConcurrency = 16
	cfg.JWTPrivateKey = generatedKeyPEM(t)
	server := startLogoutServer(t, cfg)
	email, _, _, _ := signUpUser(t, server.URL, "e2e-bound")
	wrong := fmt.Sprintf(`{"email":%q,"password":"Wrong-1234"}`, email)

	const burst = 8
	outcomes := make([]loginOutcome, burst)
	var wg sync.WaitGroup
	for i := range burst {
		wg.Add(1)
		address := newTestAddress()
		go func() {
			defer wg.Done()
			started := time.Now()
			status, header, payload := loginFromAddress(t, server.URL, address, wrong)
			outcomes[i] = loginOutcome{status: status, retryAfter: header.Get("Retry-After"), code: payload["error"], elapsed: time.Since(started)}
		}()
	}
	wg.Wait()

	refused, answered := 0, 0
	for i, o := range outcomes {
		switch o.status {
		case http.StatusServiceUnavailable:
			refused++
			if o.code != "SERVICE_UNAVAILABLE" || o.retryAfter != "1" {
				t.Errorf("refusal %d: code = %v, Retry-After = %q, want SERVICE_UNAVAILABLE and 1", i, o.code, o.retryAfter)
			}
			if o.elapsed >= 200*time.Millisecond+cfg.BcryptQueueTimeout {
				t.Errorf("refusal %d took %v, want it in under 200 ms", i, o.elapsed)
			}
		case http.StatusUnauthorized:
			answered++
		default:
			t.Errorf("login %d: status = %d, want 401 or 503", i, o.status)
		}
	}
	if refused == 0 || answered == 0 {
		t.Fatalf("refused = %d, answered = %d; want some of both with one hash slot", refused, answered)
	}

	right := fmt.Sprintf(`{"email":%q,"password":%q}`, email, e2ePassword)
	if status, _, payload := loginFromAddress(t, server.URL, newTestAddress(), right); status != http.StatusOK {
		t.Errorf("right password after the burst: status = %d, body = %v, want 200: a refusal is not a failed login", status, payload)
	}
}
