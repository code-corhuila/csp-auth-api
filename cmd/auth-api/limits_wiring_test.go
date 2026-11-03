package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/persistence"
	"github.com/code-corhuila/csp-auth-api/internal/config"
)

func TestNewHandlerRefusesRegisterAndLoginWithoutABulkhead(t *testing.T) {
	for name, concurrency := range map[string]func(*config.Config) *int{
		"register": func(cfg *config.Config) *int { return &cfg.RegisterMaxConcurrency },
		"login":    func(cfg *config.Config) *int { return &cfg.LoginMaxConcurrency },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig(t)
			cfg.JWTPrivateKey = generatedKeyPEM(t)
			cfg.DatabaseURL = "postgres://user:secret@127.0.0.1:1/db"
			*concurrency(&cfg) = 0
			var settings persistence.PoolSettings
			var opened int

			if _, _, err := newHandler(context.Background(), discardLogger(), cfg, lazyPool(&settings, &opened)); err == nil {
				t.Error("newHandler() error = nil, want the route not to start without a limit")
			}
		})
	}
}

func TestNewHandlerGivesEveryRequestTheBodyLimitOfTheConfiguration(t *testing.T) {
	cfg := testConfig(t)
	cfg.JWTPrivateKey = generatedKeyPEM(t)
	cfg.DatabaseURL = "postgres://user:secret@127.0.0.1:1/db"
	cfg.MaxBodyBytes = 32
	var settings persistence.PoolSettings
	var opened int
	handler, closeDatabase, err := newHandler(context.Background(), discardLogger(), cfg, lazyPool(&settings, &opened))
	if err != nil {
		t.Fatalf("newHandler() error = %v", err)
	}
	t.Cleanup(closeDatabase)
	request, _ := http.NewRequest(http.MethodPost, loginPath, strings.NewReader(`{"email":"`+strings.Repeat("a", 64)+`"}`))
	request.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, request)

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "must be at most 32 bytes") {
		t.Errorf("status = %d, body = %s, want 400 at the configured 32 bytes", rec.Code, rec.Body.String())
	}
}

func TestServeAppliesTheMaximumHeaderBytes(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := testConfig(t)
	cfg.MaxHeaderBytes = 1024
	go func() { _ = serve(ctx, discardLogger(), cfg, listener) }()
	url := "http://" + listener.Addr().String() + "/api/v1/auth/health"
	statusWith := func(headerBytes int) int {
		request, _ := http.NewRequest(http.MethodGet, url, nil)
		request.Header.Set("X-Padding", strings.Repeat("a", headerBytes))
		client := &http.Client{Timeout: 5 * time.Second}
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("GET %s error = %v", url, err)
		}
		response.Body.Close()
		return response.StatusCode
	}

	if small, large := statusWith(100), statusWith(16384); small != http.StatusOK || large != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("statuses = %d (small header) and %d (large header), want 200 and 431", small, large)
	}
}
