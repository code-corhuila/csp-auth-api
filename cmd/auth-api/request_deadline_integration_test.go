//go:build integration

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/persistence"
)

// With a pool of one connection that is held, a request waits for a connection until its deadline
// (APP_AUTH_HTTP_REQUEST_TIMEOUT) and then answers 503 SERVICE_UNAVAILABLE instead of queueing until the client leaves.
func TestARequestWaitingForAPoolConnectionEndsAtItsDeadlineWith503(t *testing.T) {
	url := os.Getenv("AUTH_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AUTH_TEST_DATABASE_URL is not set: the end-to-end test needs a PostgreSQL with the csp-auth-db migrations")
	}
	cfg := testConfig(t)
	cfg.DatabaseURL = url
	cfg.DatabaseMaxConnections, cfg.DatabaseMinConnections = 1, 0
	cfg.RegisterMaxConcurrency, cfg.LoginMaxConcurrency = 1, 1
	cfg.RequestTimeout = 300 * time.Millisecond
	cfg.BcryptRounds = 4
	cfg.JWTPrivateKey = generatedKeyPEM(t)
	var pool *pgxpool.Pool
	open := func(ctx context.Context, settings persistence.PoolSettings) (*pgxpool.Pool, error) {
		var err error
		pool, err = persistence.NewPool(ctx, settings)
		return pool, err
	}
	handler, closeDatabase, err := newHandler(context.Background(), discardLogger(), cfg, open)
	if err != nil {
		t.Fatalf("newHandler() error = %v", err)
	}
	t.Cleanup(closeDatabase)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	held, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("hold the only connection: %v", err)
	}
	body := `{"email":"nobody@example.com","password":"` + e2ePassword + `"}`

	started := time.Now()
	status, header, payload := login(t, server.URL, body)
	elapsed := time.Since(started)

	if status != http.StatusServiceUnavailable || payload["error"] != "SERVICE_UNAVAILABLE" || header.Get("Retry-After") != "1" {
		t.Fatalf("status = %d, Retry-After = %q, body = %v, want 503 SERVICE_UNAVAILABLE with Retry-After 1", status, header.Get("Retry-After"), payload)
	}
	if elapsed < cfg.RequestTimeout || elapsed > 3*time.Second {
		t.Errorf("the request took %s, want it to end at its %s deadline", elapsed, cfg.RequestTimeout)
	}

	held.Release()
	if status, _, payload = login(t, server.URL, body); status != http.StatusUnauthorized {
		t.Errorf("after the connection was freed: status = %d, body = %v, want 401 (unknown user)", status, payload)
	}
}
