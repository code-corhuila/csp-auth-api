package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/config"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func lookupFrom(env map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := env[key]
		return value, ok
	}
}

func testConfig(t *testing.T) config.Config {
	t.Helper()
	cfg, err := config.Load(lookupFrom(nil))
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	return cfg
}

func TestRunRejectsInvalidConfiguration(t *testing.T) {
	err := run(context.Background(), discardLogger(), lookupFrom(map[string]string{"PORT": "not-a-number"}))
	if err == nil {
		t.Fatal("run() error = nil, want a configuration error")
	}
}

func TestServeAnswersHealthAndStopsOnCancel(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	cfg := testConfig(t)
	go func() { done <- serve(ctx, discardLogger(), cfg, listener) }()

	url := "http://" + listener.Addr().String() + "/api/v1/auth/health"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s error = %v", url, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET %s status = %d, want 200", url, resp.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve() error = %v, want nil after a graceful shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve() did not return after the context was cancelled")
	}
}

func TestRunFailsWhenThePortIsTaken(t *testing.T) {
	taken, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer taken.Close()
	port := taken.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = run(ctx, discardLogger(), lookupFrom(map[string]string{"PORT": strconv.Itoa(port)}))

	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "listen" {
		t.Fatalf("run() error = %v, want a listen error", err)
	}
}

func TestNewHandlerPublishesJWKSOnlyWhenAKeyIsConfigured(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))

	statusOf := func(cfg config.Config) int {
		handler, err := newHandler(cfg)
		if err != nil {
			t.Fatalf("newHandler() error = %v", err)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/jwks", nil))
		return rec.Code
	}
	if got := statusOf(testConfig(t)); got != http.StatusNotFound {
		t.Errorf("without a key: status = %d, want 404", got)
	}
	withKey := testConfig(t)
	withKey.JWTPrivateKey = keyPEM
	if got := statusOf(withKey); got != http.StatusOK {
		t.Errorf("with a key: status = %d, want 200", got)
	}
}

func TestNewHandlerFailsFastOnAnInvalidKey(t *testing.T) {
	cfg := testConfig(t)
	cfg.JWTPrivateKey = "not a key"
	if _, err := newHandler(cfg); err == nil {
		t.Error("newHandler() error = nil, want a key error")
	}
}
