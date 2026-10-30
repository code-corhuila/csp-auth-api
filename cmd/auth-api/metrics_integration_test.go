//go:build integration

package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

// Criterion 4 of code-corhuila/csp-docs#281 needs the metrics of the credential routes: this logs in and registers over HTTP against
// PostgreSQL and Redis, and reads what Prometheus would scrape.
func TestTheScrapeShowsTheCredentialRoutesWithTheirOutcomesAndNoPersonalData(t *testing.T) {
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
	email, _, _, _ := signUpUser(t, server.URL, "e2e-metrics")
	wrong := fmt.Sprintf(`{"email":%q,"password":"Wrong-1234"}`, email)
	right := fmt.Sprintf(`{"email":%q,"password":%q}`, email, e2ePassword)
	loginFromAddress(t, server.URL, newTestAddress(), wrong)
	loginFromAddress(t, server.URL, newTestAddress(), right)

	response, err := http.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics error = %v", err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	body := string(raw)

	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics status = %d, want 200", response.StatusCode)
	}
	for _, want := range []string{
		`auth_http_requests_total{route="/api/v1/auth/register",method="POST",outcome="success"}`,
		`auth_http_requests_total{route="/api/v1/auth/login",method="POST",outcome="client_error"} 1`,
		`auth_http_requests_total{route="/api/v1/auth/login",method="POST",outcome="success"} 1`,
		`auth_http_request_duration_seconds_count{route="/api/v1/auth/login",method="POST"} 2`,
		`auth_http_request_duration_seconds_bucket{route="/api/v1/auth/login",method="POST",le="+Inf"} 2`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the scrape misses %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, email) || strings.Contains(body, e2ePassword) || strings.Contains(body, "198.51.") {
		t.Error("the scrape carries an email, a password or an address: the labels must be route, method and outcome only")
	}
}
