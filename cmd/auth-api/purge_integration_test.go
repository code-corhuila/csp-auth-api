//go:build integration

package main

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/persistence"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/system"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/token"
)

// purgeLockKey is the advisory lock that the purge tests of every package take: a purge deletes
// any old row of the shared test database.
const purgeLockKey = 3012

const day = 24 * time.Hour

// The test calls the purge over HTTP the way csp-worker does, with a service token signed by the
// key of the service, and checks the answers of the contract (401, 403, 200 and 400), that old
// rows go in bounded batches, and that a registration repeated with a purged Idempotency-Key
// answers 409 EMAIL_ALREADY_REGISTERED (ADR-030).
func TestPurgeEndToEndAgainstTheDatabase(t *testing.T) {
	url := os.Getenv("AUTH_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AUTH_TEST_DATABASE_URL is not set: the end-to-end test needs a PostgreSQL with the csp-auth-db migrations")
	}
	ctx := context.Background()
	lock := connect(t, ctx, url)
	if _, err := lock.Exec(ctx, `SELECT pg_advisory_lock($1)`, purgeLockKey); err != nil {
		t.Fatalf("take the purge lock: %v", err)
	}
	t.Cleanup(func() { _, _ = lock.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, purgeLockKey) })

	cfg := testConfig(t)
	cfg.DatabaseURL = url
	cfg.BcryptRounds = 4
	cfg.JWTPrivateKey = generatedKeyPEM(t)
	cfg.ServiceSubjects = []string{"csp-worker"}
	handler, closeDatabase, err := newHandler(ctx, discardLogger(), cfg, persistence.NewPool)
	if err != nil {
		t.Fatalf("newHandler() error = %v", err)
	}
	t.Cleanup(closeDatabase)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	key, err := token.ParsePrivateKey(cfg.JWTPrivateKey)
	if err != nil {
		t.Fatalf("ParsePrivateKey() error = %v", err)
	}
	workerToken := signServiceToken(t, key, "csp-worker", time.Minute)

	t.Run("a missing, invalid, expired or foreign token is 401 and a valid token of another subject is 403", func(t *testing.T) {
		cases := map[string]struct {
			bearer string
			want   int
			code   string
		}{
			"no token":      {"", http.StatusUnauthorized, "UNAUTHORIZED"},
			"garbage":       {"not-a-token", http.StatusUnauthorized, "UNAUTHORIZED"},
			"expired":       {signServiceToken(t, key, "csp-worker", -time.Minute), http.StatusUnauthorized, "UNAUTHORIZED"},
			"another key":   {signServiceToken(t, mustKey(t, generatedKeyPEM(t)), "csp-worker", time.Minute), http.StatusUnauthorized, "UNAUTHORIZED"},
			"other subject": {signServiceToken(t, key, "booking-service", time.Minute), http.StatusForbidden, "FORBIDDEN"},
		}
		for name, c := range cases {
			status, payload := purgeCall(t, server.URL, c.bearer, `{}`)
			if status != c.want || payload["error"] != c.code {
				t.Errorf("%s: status = %d, body = %v, want %d %s", name, status, payload, c.want, c.code)
			}
		}
	})

	t.Run("an access token of a user is 401: its audience is csp-api, not csp-internal", func(t *testing.T) {
		ids := system.UUIDGenerator{}
		email := "e2e-purge-user-" + ids.NewID() + "@example.com"
		signUp := fmt.Sprintf(`{"email":%q,"password":%q,"name":"Ada Lovelace","phone":"+573001234567","address":"Calle 1 # 2-3"}`, email, e2ePassword)
		_, payload := register(t, server.URL, ids.NewID(), signUp)
		access, _ := payload["accessToken"].(string)
		if status, body := purgeCall(t, server.URL, access, `{}`); status != http.StatusUnauthorized || body["error"] != "UNAUTHORIZED" {
			t.Errorf("status = %d, body = %v, want 401 UNAUTHORIZED", status, body)
		}
	})

	t.Run("a batch size outside 1 to 500 is 400", func(t *testing.T) {
		for _, body := range []string{`{"batchSize":0}`, `{"batchSize":501}`, `{"batchSize":"many"}`} {
			if status, payload := purgeCall(t, server.URL, workerToken, body); status != http.StatusBadRequest || payload["error"] != "VALIDATION_ERROR" {
				t.Errorf("%s: status = %d, body = %v, want 400 VALIDATION_ERROR", body, status, payload)
			}
		}
	})

	// The worker calls until hasMore is false: that empties the tables of old rows left by others.
	drainPurge(t, server.URL, workerToken)

	ids := system.UUIDGenerator{}
	email := "e2e-purge-" + ids.NewID() + "@example.com"
	signUp := fmt.Sprintf(`{"email":%q,"password":%q,"name":"Ada Lovelace","phone":"+573001234567","address":"Calle 1 # 2-3"}`, email, e2ePassword)
	idempotencyKey := ids.NewID()
	status, registered := register(t, server.URL, idempotencyKey, signUp)
	if status != http.StatusCreated {
		t.Fatalf("register status = %d, want 201; body = %v", status, registered)
	}
	user, _ := registered["user"].(map[string]any)
	userID, _ := user["id"].(string)
	conn := connect(t, ctx, url)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := conn.Exec(ctx, query, args...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	for range 2 {
		exec(`INSERT INTO auth.outbox_event (id, aggregate_type, aggregate_id, event_type, payload, created_at)
			VALUES ($1, 'User', $2, 'UserRegistered', '{}', NOW() - INTERVAL '31 days')`, ids.NewID(), ids.NewID())
	}
	exec(`UPDATE auth.refresh_token SET expires_at = NOW() - INTERVAL '31 days' WHERE user_id = $1`, userID)
	verificationID := ids.NewID()
	exec(`INSERT INTO auth.email_verification (id, user_id, verification_code, expires_at, new_email)
		VALUES ($1, $2, '123456', NOW() - INTERVAL '8 days', 'purge-target@example.com')`, verificationID, userID)
	var requestHash string
	if err := conn.QueryRow(ctx, `SELECT request_hash FROM auth.idempotency_key WHERE key = $1`, idempotencyKey).Scan(&requestHash); err != nil {
		t.Fatalf("read the idempotency key: %v", err)
	}
	exec(`DELETE FROM auth.idempotency_key WHERE key = $1`, idempotencyKey)
	exec(`INSERT INTO auth.idempotency_key (key, user_id, request_hash, created_at) VALUES ($1, $2, $3, NOW() - INTERVAL '8 days')`, idempotencyKey, userID, requestHash)
	if status, _ := register(t, server.URL, idempotencyKey, signUp); status != http.StatusOK {
		t.Fatalf("replay before the purge: status = %d, want 200", status)
	}

	t.Run("a call deletes at most batchSize rows and says whether more is left", func(t *testing.T) {
		status, first := purgeCall(t, server.URL, workerToken, `{"batchSize":2}`)
		if status != http.StatusOK || first["processedCount"] != float64(2) || first["hasMore"] != true {
			t.Fatalf("first call: status = %d, body = %v, want 200, 2 and hasMore true", status, first)
		}
		status, second := purgeCall(t, server.URL, workerToken, `{"batchSize":500}`)
		if status != http.StatusOK || second["hasMore"] != false {
			t.Fatalf("second call: status = %d, body = %v, want 200 and hasMore false", status, second)
		}
		if got := second["processedCount"].(float64); got < 3 {
			t.Errorf("second call processedCount = %v, want the refresh token, the key and the email verification at least", got)
		}
		var left bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM auth.email_verification WHERE id = $1)`, verificationID).Scan(&left); err != nil || left {
			t.Errorf("the email verification expired 8 days ago is still there (%v, error %v)", left, err)
		}
		if status, again := purgeCall(t, server.URL, workerToken, ``); status != http.StatusOK || again["processedCount"] != float64(0) || again["hasMore"] != false {
			t.Errorf("third call without a body: status = %d, body = %v, want nothing to do", status, again)
		}
	})

	t.Run("the purged key no longer replays: the same registration is 409 EMAIL_ALREADY_REGISTERED", func(t *testing.T) {
		status, payload := register(t, server.URL, idempotencyKey, signUp)
		if status != http.StatusConflict || payload["error"] != "EMAIL_ALREADY_REGISTERED" {
			t.Errorf("status = %d, body = %v, want 409 EMAIL_ALREADY_REGISTERED", status, payload)
		}
	})
}

func mustKey(t *testing.T, pemText string) *rsa.PrivateKey {
	t.Helper()
	key, err := token.ParsePrivateKey(pemText)
	if err != nil {
		t.Fatalf("ParsePrivateKey() error = %v", err)
	}
	return key
}

func signServiceToken(t *testing.T, key *rsa.PrivateKey, subject string, lifetime time.Duration) string {
	t.Helper()
	now := time.Now()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": subject, "iss": "csp-auth", "aud": "csp-internal", "iat": now.Unix(), "exp": now.Add(lifetime).Unix(),
	}).SignedString(key)
	if err != nil {
		t.Fatalf("sign the service token: %v", err)
	}
	return signed
}

func purgeCall(t *testing.T, baseURL, bearer, body string) (int, map[string]any) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+purgePath, strings.NewReader(body))
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
		t.Fatalf("POST %s error = %v", purgePath, err)
	}
	defer response.Body.Close()
	var payload map[string]any
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode the response (status %d): %v", response.StatusCode, err)
	}
	return response.StatusCode, payload
}

func drainPurge(t *testing.T, baseURL, bearer string) {
	t.Helper()
	for {
		status, payload := purgeCall(t, baseURL, bearer, `{"batchSize":500}`)
		if status != http.StatusOK {
			t.Fatalf("drain: status = %d, body = %v", status, payload)
		}
		if payload["hasMore"] == false {
			return
		}
	}
}
