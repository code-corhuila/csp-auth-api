//go:build integration

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/persistence"
)

// With a slow SMTP relay the email change requests hold a connection and the lock of the account for as long
// as the relay takes (ADR-034). The bulkhead admits MaxConcurrency of them; the extra ones are refused with
// 429 and Retry-After 1 after a short wait, and the login, the write timeout and the pool are not affected.
func TestEmailChangeBulkheadKeepsTheServiceResponsiveWithASlowRelay(t *testing.T) {
	databaseURL := os.Getenv("AUTH_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("AUTH_TEST_DATABASE_URL is not set: the end-to-end test needs a PostgreSQL with the csp-auth-db migrations")
	}
	const (
		admitted     = 4
		extra        = 10
		relayDelay   = 1500 * time.Millisecond
		writeTimeout = 5 * time.Second
	)
	cfg := testConfig(t)
	cfg.DatabaseURL = databaseURL
	cfg.DatabaseMaxConnections, cfg.DatabaseMinConnections = admitted+2, 1
	cfg.BcryptRounds = 4
	cfg.JWTPrivateKey = generatedKeyPEM(t)
	cfg.EmailChangeMaxConcurrency, cfg.EmailChangeQueueTimeout = admitted, 200*time.Millisecond
	relay := startFakeSMTP(t)
	relay.configure(&cfg)
	relay.delay = relayDelay
	cfg.SMTPTimeout = 4 * time.Second
	handler, closeAll, err := newHandler(context.Background(), discardLogger(), cfg, persistence.NewPool)
	if err != nil {
		t.Fatalf("newHandler() error = %v", err)
	}
	t.Cleanup(closeAll)
	server := httptest.NewUnstartedServer(handler)
	server.Config.WriteTimeout = writeTimeout
	server.Start()
	t.Cleanup(server.Close)

	type account struct{ email, id, access string }
	accounts := make([]account, admitted+extra)
	for i := range accounts {
		accounts[i].email, accounts[i].id, accounts[i].access, _ = signUpUser(t, server.URL, "e2e-bulkhead")
	}
	type outcome struct {
		status     int
		retryAfter string
		took       time.Duration
	}
	outcomes := make([]outcome, len(accounts))
	var wg sync.WaitGroup
	for i := range accounts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			started := time.Now()
			status, header, _ := requestChange(t, server.URL, accounts[i].access, fmt.Sprintf("e2e-bulkhead-%d-%s@example.com", i, accounts[i].id))
			outcomes[i] = outcome{status, header.Get("Retry-After"), time.Since(started)}
		}()
	}

	time.Sleep(400 * time.Millisecond) // the admitted requests are now inside the relay and the others were refused
	for i := 0; i < 5; i++ {
		started := time.Now()
		status, _, _ := login(t, server.URL, fmt.Sprintf(`{"email":%q,"password":%q}`, accounts[0].email, e2ePassword))
		if took := time.Since(started); status != http.StatusOK || took > time.Second {
			t.Errorf("login #%d during the stall: status = %d after %v, want 200 in under 1s", i+1, status, took)
		}
	}
	wg.Wait()

	var accepted, refused int
	for i, o := range outcomes {
		switch o.status {
		case http.StatusAccepted:
			accepted++
			if o.took >= writeTimeout {
				t.Errorf("request %d took %v, want less than the write timeout %v", i, o.took, writeTimeout)
			}
		case http.StatusTooManyRequests:
			refused++
			if seconds, err := strconv.Atoi(o.retryAfter); err != nil || seconds != 1 {
				t.Errorf("request %d: Retry-After = %q, want 1", i, o.retryAfter)
			}
			if o.took > time.Second {
				t.Errorf("request %d was refused after %v, want a quick 429 (under 1s)", i, o.took)
			}
		default:
			t.Errorf("request %d: status = %d, want 202 or 429", i, o.status)
		}
	}
	if accepted != admitted || refused != extra {
		t.Errorf("accepted = %d, refused = %d, want %d and %d", accepted, refused, admitted, extra)
	}
}
