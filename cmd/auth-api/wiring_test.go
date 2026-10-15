package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/persistence"
	"github.com/code-corhuila/csp-auth-api/internal/config"
)

const (
	registerPath = "/api/v1/auth/register"
	loginPath    = "/api/v1/auth/login"
	refreshPath  = "/api/v1/auth/refresh"
)

// lazyPool returns a pool that has not connected: enough to wire the use case without a database.
func lazyPool(settings *persistence.PoolSettings, opened *int) poolOpener {
	return func(ctx context.Context, got persistence.PoolSettings) (*pgxpool.Pool, error) {
		*opened++
		*settings = got
		return pgxpool.New(ctx, "postgres://user:secret@127.0.0.1:1/db")
	}
}

func registerStatus(t *testing.T, cfg config.Config, open poolOpener) (int, func()) {
	t.Helper()
	return postEmptyJSON(t, registerPath, cfg, open)
}

func loginStatus(t *testing.T, cfg config.Config, open poolOpener) (int, func()) {
	t.Helper()
	return postEmptyJSON(t, loginPath, cfg, open)
}

func refreshStatus(t *testing.T, cfg config.Config, open poolOpener) (int, func()) {
	t.Helper()
	return postEmptyJSON(t, refreshPath, cfg, open)
}

func postEmptyJSON(t *testing.T, path string, cfg config.Config, open poolOpener) (int, func()) {
	t.Helper()
	handler, closeDatabase, err := newHandler(context.Background(), discardLogger(), cfg, open)
	if err != nil {
		t.Fatalf("newHandler() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
	request.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, request)
	return rec.Code, closeDatabase
}

func TestNewHandlerRegisterLoginAndRefreshRouteDecisionTable(t *testing.T) {
	withKey := testConfig(t)
	withKey.JWTPrivateKey = generatedKeyPEM(t)
	withDatabase := withKey
	withDatabase.DatabaseURL = "postgres://user:secret@127.0.0.1:1/db"
	withDatabase.DatabaseMaxConnections = 7
	withDatabase.DatabaseMinConnections = 1

	var settings persistence.PoolSettings
	var opened int

	if got, _ := registerStatus(t, testConfig(t), lazyPool(&settings, &opened)); got != http.StatusNotFound {
		t.Errorf("no database, no key: status = %d, want 404", got)
	}
	if got, _ := registerStatus(t, withKey, lazyPool(&settings, &opened)); got != http.StatusNotFound {
		t.Errorf("key without database: status = %d, want 404", got)
	}
	if got, _ := loginStatus(t, testConfig(t), lazyPool(&settings, &opened)); got != http.StatusNotFound {
		t.Errorf("login, no database, no key: status = %d, want 404", got)
	}
	if got, _ := loginStatus(t, withKey, lazyPool(&settings, &opened)); got != http.StatusNotFound {
		t.Errorf("login, key without database: status = %d, want 404", got)
	}
	if got, _ := refreshStatus(t, testConfig(t), lazyPool(&settings, &opened)); got != http.StatusNotFound {
		t.Errorf("refresh, no database, no key: status = %d, want 404", got)
	}
	if got, _ := refreshStatus(t, withKey, lazyPool(&settings, &opened)); got != http.StatusNotFound {
		t.Errorf("refresh, key without database: status = %d, want 404", got)
	}
	if opened != 0 {
		t.Fatalf("the pool was opened %d times without a database URL", opened)
	}

	got, closeDatabase := registerStatus(t, withDatabase, lazyPool(&settings, &opened))
	defer closeDatabase()
	if got != http.StatusBadRequest {
		t.Errorf("database and key: status = %d, want 400 (the route exists and validates the request)", got)
	}
	if opened != 1 || settings.URL != withDatabase.DatabaseURL || settings.MaxConnections != 7 || settings.MinConnections != 1 {
		t.Errorf("pool opened %d times with %+v, want once with the configured limits", opened, settings)
	}

	gotLogin, closeLoginDatabase := loginStatus(t, withDatabase, lazyPool(&settings, &opened))
	defer closeLoginDatabase()
	if gotLogin != http.StatusBadRequest {
		t.Errorf("login, database and key: status = %d, want 400 (the route exists and validates the request)", gotLogin)
	}

	gotRefresh, closeRefreshDatabase := refreshStatus(t, withDatabase, lazyPool(&settings, &opened))
	defer closeRefreshDatabase()
	if gotRefresh != http.StatusBadRequest {
		t.Errorf("refresh, database and key: status = %d, want 400 (the route exists and validates the request)", gotRefresh)
	}
}

func TestNewHandlerFailsFastWhenTheDatabaseHasNoSigningKey(t *testing.T) {
	cfg := testConfig(t)
	cfg.DatabaseURL = "postgres://user:secret@127.0.0.1:1/db"
	var opened int
	var settings persistence.PoolSettings

	_, _, err := newHandler(context.Background(), discardLogger(), cfg, lazyPool(&settings, &opened))

	if err == nil || !strings.Contains(err.Error(), "signing key") {
		t.Fatalf("newHandler() error = %v, want a signing key error", err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Errorf("the error leaks the database URL: %v", err)
	}
	if opened != 0 {
		t.Error("the pool was opened although the service cannot start")
	}
}

func TestNewHandlerFailsFastWhenThePoolCannotBeOpened(t *testing.T) {
	cfg := testConfig(t)
	cfg.JWTPrivateKey = generatedKeyPEM(t)
	cfg.DatabaseURL = "postgres://user:secret@127.0.0.1:1/db"
	failing := func(context.Context, persistence.PoolSettings) (*pgxpool.Pool, error) {
		return nil, errors.New("ping postgres: refused")
	}

	if _, _, err := newHandler(context.Background(), discardLogger(), cfg, failing); err == nil {
		t.Fatal("newHandler() error = nil, want the pool error")
	}
}

func TestNewHandlerDoesNotLogTheDatabaseURLOrTheKey(t *testing.T) {
	cfg := testConfig(t)
	cfg.JWTPrivateKey = generatedKeyPEM(t)
	cfg.DatabaseURL = "postgres://user:secret@127.0.0.1:1/db"
	var logs strings.Builder
	logger := slogTo(&logs)
	var settings persistence.PoolSettings
	var opened int

	_, closeDatabase, err := newHandler(context.Background(), logger, cfg, lazyPool(&settings, &opened))
	if err != nil {
		t.Fatalf("newHandler() error = %v", err)
	}
	defer closeDatabase()

	for _, announcement := range []string{"register route enabled", "login route enabled", "refresh route enabled"} {
		if !strings.Contains(logs.String(), announcement) {
			t.Errorf("log = %q, want %q", logs.String(), announcement)
		}
	}
	if strings.Contains(logs.String(), "secret") || strings.Contains(logs.String(), "PRIVATE KEY") {
		t.Errorf("log leaks a secret: %q", logs.String())
	}
}
