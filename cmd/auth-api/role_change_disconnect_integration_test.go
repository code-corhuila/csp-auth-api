//go:build integration

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/redis"
)

// cancelAfterCommit makes the client leave right after the transaction of the first request commits, which
// is the moment between the commit and the write of the marker in Redis.
type cancelAfterCommit struct {
	cancelClient context.CancelFunc
	done         bool
}

func (c *cancelAfterCommit) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	return ctx
}

func (c *cancelAfterCommit) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	if c.done || data.CommandTag.String() != "COMMIT" {
		return
	}
	c.done = true
	c.cancelClient()
	select { // the server cancels the context of a request whose connection is closed
	case <-ctx.Done():
	case <-time.After(time.Second):
	}
}

// Removing ADMIN commits and then writes the marker that ends the access tokens already issued (ADR-031).
// If the client leaves between the two the role is lost, so the marker must still be written.
func TestRemovingAdminWritesTheMarkerWhenTheClientCancelsTheRequest(t *testing.T) {
	databaseURL, redisURL := os.Getenv("AUTH_TEST_DATABASE_URL"), os.Getenv("AUTH_TEST_REDIS_URL")
	if databaseURL == "" || redisURL == "" {
		t.Skip("AUTH_TEST_DATABASE_URL and AUTH_TEST_REDIS_URL are not set: the test needs PostgreSQL with the csp-auth-db migrations and the Redis of csp-infra-redis")
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
	emailA, idA, _, _ := signUpUser(t, server.URL, "e2e-cancel-role-a")
	emailB, idB, _, _ := signUpUser(t, server.URL, "e2e-cancel-role-b")
	for _, id := range []string{idA, idB} {
		if _, err := lock.Exec(ctx, `INSERT INTO auth.user_role (user_id, role_id) SELECT $1, id FROM auth.role WHERE name = 'ADMIN'`, id); err != nil {
			t.Fatalf("seed the administrator: %v", err)
		}
	}
	signIn := func(email string) string {
		status, _, payload := login(t, server.URL, fmt.Sprintf(`{"email":%q,"password":%q}`, email, e2ePassword))
		access, _ := payload["accessToken"].(string)
		if status != http.StatusOK || access == "" {
			t.Fatalf("login: status = %d, body = %v", status, payload)
		}
		return access
	}
	tokenA, tokenB := signIn(emailA), signIn(emailB)
	if status, _ := listUsers(t, server.URL, tokenA, "?email=e2e-cancel-role"); status != http.StatusOK {
		t.Fatalf("the administrator before the revocation: status = %d, want 200", status)
	}

	clientCtx, cancelClient := context.WithCancel(ctx)
	defer cancelClient()
	cancelling := startTracedServer(t, cfg, &cancelAfterCommit{cancelClient: cancelClient})
	request, err := http.NewRequestWithContext(clientCtx, http.MethodPatch, cancelling.URL+"/api/v1/auth/users/"+idA+"/role", strings.NewReader(`{"role":"ADMIN","enabled":false}`))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "e2e-role-cancel")
	request.Header.Set("Authorization", "Bearer "+tokenB)
	if response, err := http.DefaultClient.Do(request); err == nil {
		_ = response.Body.Close()
		t.Fatal("the client request was not cancelled, so the test proves nothing")
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if exists, _ := client.Exists(ctx, "blacklist:user:"+idA).Result(); exists > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if exists, _ := client.Exists(ctx, "blacklist:user:"+idA).Result(); exists == 0 {
		t.Error("the marker of the user was not written after the client cancelled the request")
	}
	if status, _ := listUsers(t, server.URL, tokenA, "?email=e2e-cancel-role"); status != http.StatusUnauthorized {
		t.Errorf("the old access token on GET /users: status = %d, want 401", status)
	}
}
