//go:build integration

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/persistence"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/redis"
	"github.com/code-corhuila/csp-auth-api/internal/config"
)

// cancelOnRevocation makes the browser leave the page at the worst moment: when the sign out reaches the
// UPDATE of the refresh tokens it cancels the client request and waits until the server has noticed.
type cancelOnRevocation struct {
	mu            sync.Mutex
	cancelClient  context.CancelFunc
	cancelledOnce bool
}

func (c *cancelOnRevocation) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancelledOnce || !strings.Contains(data.SQL, "UPDATE auth.refresh_token SET revoked_at") {
		return ctx
	}
	c.cancelledOnce = true
	c.cancelClient()
	select { // the server cancels the context of a request whose connection is closed
	case <-ctx.Done():
	case <-time.After(time.Second):
	}
	return ctx
}

func (c *cancelOnRevocation) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// The sign out is the last thing a browser does before it navigates away, so the request is cancelled
// while the tokens are being revoked. ADR-033: the session still ends, the refresh token is revoked and
// the access token is listed.
func TestLogoutEndsTheSessionWhenTheClientCancelsTheRequest(t *testing.T) {
	databaseURL, redisURL := os.Getenv("AUTH_TEST_DATABASE_URL"), os.Getenv("AUTH_TEST_REDIS_URL")
	if databaseURL == "" || redisURL == "" {
		t.Skip("AUTH_TEST_DATABASE_URL and AUTH_TEST_REDIS_URL are not set: the test needs PostgreSQL with the csp-auth-db migrations and the Redis of csp-infra-redis")
	}
	cfg := testConfig(t)
	cfg.DatabaseURL = databaseURL
	cfg.RedisURL = redisURL
	cfg.BcryptRounds = 4
	cfg.JWTPrivateKey = generatedKeyPEM(t)
	server := startLogoutServer(t, cfg)
	_, _, access, refreshToken := signUpUser(t, server.URL, "e2e-cancel")
	checker, err := redis.NewClient(redis.ClientSettings{URL: redisURL, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("redis.NewClient() error = %v", err)
	}
	t.Cleanup(func() { _ = checker.Close() })

	clientCtx, cancelClient := context.WithCancel(context.Background())
	defer cancelClient()
	tracer := &cancelOnRevocation{cancelClient: cancelClient}
	cancelling := startTracedServer(t, cfg, tracer)

	body := fmt.Sprintf(`{"refreshToken":%q}`, refreshToken)
	request, err := http.NewRequestWithContext(clientCtx, http.MethodPost, cancelling.URL+logoutPath, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+access)
	if response, err := http.DefaultClient.Do(request); err == nil {
		_ = response.Body.Close()
		t.Fatal("the client request was not cancelled, so the test proves nothing")
	}

	deadline := time.Now().Add(5 * time.Second)
	for !listed(t, checker, access) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if !listed(t, checker, access) {
		t.Error("the access token was not listed after the client cancelled the request")
	}
	if status, _, payload := refresh(t, server.URL, refreshToken); status != http.StatusUnauthorized || payload["error"] != "INVALID_REFRESH_TOKEN" {
		t.Errorf("the refresh token after the cancelled sign out: status = %d, body = %v, want 401 INVALID_REFRESH_TOKEN", status, payload)
	}
}

// startTracedServer starts the service with a pgx tracer on its pool, to act at a precise statement.
func startTracedServer(t *testing.T, cfg config.Config, tracer pgx.QueryTracer) *httptest.Server {
	t.Helper()
	handler, closeAll, err := newHandler(context.Background(), discardLogger(), cfg, func(ctx context.Context, settings persistence.PoolSettings) (*pgxpool.Pool, error) {
		poolCfg, err := pgxpool.ParseConfig(settings.URL)
		if err != nil {
			return nil, err
		}
		poolCfg.ConnConfig.Tracer = tracer
		return pgxpool.NewWithConfig(ctx, poolCfg)
	})
	if err != nil {
		t.Fatalf("newHandler() error = %v", err)
	}
	t.Cleanup(closeAll)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}
