package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/persistence"
	"github.com/code-corhuila/csp-auth-api/internal/config"
)

const (
	registerPath = "/api/v1/auth/register"
	loginPath    = "/api/v1/auth/login"
	refreshPath  = "/api/v1/auth/refresh"
	purgePath    = "/api/v1/auth/internal/maintenance/purge"
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

func purgeStatus(t *testing.T, cfg config.Config, open poolOpener) (int, func()) {
	t.Helper()
	return postEmptyJSON(t, purgePath, cfg, open)
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
	if got, _ := purgeStatus(t, testConfig(t), lazyPool(&settings, &opened)); got != http.StatusNotFound {
		t.Errorf("purge, no database, no key: status = %d, want 404", got)
	}
	if got, _ := purgeStatus(t, withKey, lazyPool(&settings, &opened)); got != http.StatusNotFound {
		t.Errorf("purge, key without database: status = %d, want 404", got)
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

	gotPurge, closePurgeDatabase := purgeStatus(t, withDatabase, lazyPool(&settings, &opened))
	defer closePurgeDatabase()
	if gotPurge != http.StatusUnauthorized {
		t.Errorf("purge, database and key: status = %d, want 401 (the route exists and asks for a service token)", gotPurge)
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

func TestNewHandlerServesTheUserRoleRouteOnlyWithTheDatabase(t *testing.T) {
	withKey := testConfig(t)
	withKey.JWTPrivateKey = generatedKeyPEM(t)
	withDatabase := withKey
	withDatabase.DatabaseURL = "postgres://user:secret@127.0.0.1:1/db"
	var settings persistence.PoolSettings
	var opened int

	for name, c := range map[string]struct {
		cfg  config.Config
		want int
	}{
		"key without database":       {withKey, http.StatusNotFound},
		"database and key, no token": {withDatabase, http.StatusUnauthorized},
	} {
		handler, closeDatabase, err := newHandler(context.Background(), discardLogger(), c.cfg, lazyPool(&settings, &opened))
		if err != nil {
			t.Fatalf("%s: newHandler() error = %v", name, err)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPatch, "/api/v1/auth/users/3f2a9c1e-5b7d-4e08-9a41-6c2d8e0f1a23/role", strings.NewReader("{}")))
		closeDatabase()
		if rec.Code != c.want {
			t.Errorf("%s: status = %d, want %d", name, rec.Code, c.want)
		}
	}
}

func TestNewHandlerServesTheUserListRouteOnlyWithTheDatabase(t *testing.T) {
	withKey := testConfig(t)
	withKey.JWTPrivateKey = generatedKeyPEM(t)
	withDatabase := withKey
	withDatabase.DatabaseURL = "postgres://user:secret@127.0.0.1:1/db"
	var settings persistence.PoolSettings
	var opened int

	for name, c := range map[string]struct {
		cfg  config.Config
		want int
	}{
		"key without database":       {withKey, http.StatusNotFound},
		"database and key, no token": {withDatabase, http.StatusUnauthorized},
	} {
		handler, closeDatabase, err := newHandler(context.Background(), discardLogger(), c.cfg, lazyPool(&settings, &opened))
		if err != nil {
			t.Fatalf("%s: newHandler() error = %v", name, err)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/users?email=ada", nil))
		closeDatabase()
		if rec.Code != c.want {
			t.Errorf("%s: status = %d, want %d", name, rec.Code, c.want)
		}
	}
}

func TestNewHandlerEnablesLogoutOnlyWithTheDatabaseTheKeyAndRedis(t *testing.T) {
	const logoutPath = "/api/v1/auth/logout"
	withDatabase := testConfig(t)
	withDatabase.JWTPrivateKey = generatedKeyPEM(t)
	withDatabase.DatabaseURL = "postgres://user:secret@127.0.0.1:1/db"
	withRedis := withDatabase
	withRedis.RedisURL = "redis://auth_app:secret@127.0.0.1:1/0"
	withRedis.RedisTimeout = time.Second
	var settings persistence.PoolSettings
	var opened int

	got, closeWithoutRedis := postEmptyJSON(t, logoutPath, withDatabase, lazyPool(&settings, &opened))
	defer closeWithoutRedis()
	if got != http.StatusNotFound {
		t.Errorf("no Redis URL: status = %d, want 404", got)
	}
	got, closeWithRedis := postEmptyJSON(t, logoutPath, withRedis, lazyPool(&settings, &opened))
	defer closeWithRedis()
	if got != http.StatusUnauthorized {
		t.Errorf("Redis URL: status = %d, want 401 (the route exists and asks for an access token)", got)
	}
	withoutKey := testConfig(t)
	withoutKey.RedisURL = withRedis.RedisURL
	if got, _ := postEmptyJSON(t, logoutPath, withoutKey, lazyPool(&settings, &opened)); got != http.StatusNotFound {
		t.Errorf("Redis URL without database and key: status = %d, want 404", got)
	}
}

func TestNewHandlerFailsFastOnAnInvalidRedisURLWithoutRevealingIt(t *testing.T) {
	cfg := testConfig(t)
	cfg.JWTPrivateKey = generatedKeyPEM(t)
	cfg.DatabaseURL = "postgres://user:secret@127.0.0.1:1/db"
	cfg.RedisURL = "http://auth_app:topsecret@redis"
	var settings persistence.PoolSettings
	var opened int

	_, _, err := newHandler(context.Background(), discardLogger(), cfg, lazyPool(&settings, &opened))

	if err == nil || strings.Contains(err.Error(), "topsecret") {
		t.Errorf("error = %v, want an error that does not show the password", err)
	}
}

func TestOpenRevokedTokensWorksWithoutCheckWhenRedisIsNotConfigured(t *testing.T) {
	var logs strings.Builder

	state, closeList, err := openRedisState(slogTo(&logs), testConfig(t))
	defer closeList()

	if err != nil {
		t.Fatalf("openRedisState() error = %v", err)
	}
	if revoked, err := state.revoked.IsRevoked(context.Background(), "any-jti"); revoked || err != nil {
		t.Errorf("IsRevoked() = %v, %v, want false and no error", revoked, err)
	}
	if !strings.Contains(logs.String(), "APP_AUTH_REDIS_URL is not set") {
		t.Errorf("log = %q, want a line that says the check is off", logs.String())
	}
}

func TestNewHandlerServesTheEmailChangeRoutesOnlyWithTheDatabaseAndAnSMTPHost(t *testing.T) {
	withKey := testConfig(t)
	withKey.JWTPrivateKey = generatedKeyPEM(t)
	withDatabase := withKey
	withDatabase.DatabaseURL = "postgres://user:secret@127.0.0.1:1/db"
	withHost := withDatabase
	withHost.SMTPHost, withHost.SMTPFrom = "mailpit", "no-reply@cinesync.local"
	keyAndHost := withKey
	keyAndHost.SMTPHost, keyAndHost.SMTPFrom = withHost.SMTPHost, withHost.SMTPFrom
	var settings persistence.PoolSettings
	var opened int

	for name, c := range map[string]struct {
		cfg     config.Config
		want    int
		logLine string
	}{
		"key without database":                  {withKey, http.StatusNotFound, ""},
		"key and host without database":         {keyAndHost, http.StatusNotFound, ""},
		"database and key, no SMTP host":        {withDatabase, http.StatusNotFound, "APP_AUTH_SMTP_HOST is not set: the email change is not enabled"},
		"database, key and SMTP host, no token": {withHost, http.StatusUnauthorized, "email change routes enabled"},
	} {
		for _, route := range []struct{ method, path string }{
			{http.MethodPatch, "/api/v1/auth/me/email"},
			{http.MethodPost, "/api/v1/auth/me/email/verify"},
		} {
			var logs strings.Builder
			handler, closeDatabase, err := newHandler(context.Background(), slogTo(&logs), c.cfg, lazyPool(&settings, &opened))
			if err != nil {
				t.Fatalf("%s: newHandler() error = %v", name, err)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(route.method, route.path, strings.NewReader("{}")))
			closeDatabase()
			if rec.Code != c.want {
				t.Errorf("%s %s %s: status = %d, want %d", name, route.method, route.path, rec.Code, c.want)
			}
			if !strings.Contains(logs.String(), c.logLine) || strings.Count(logs.String(), "email change") > 1 {
				t.Errorf("%s: log = %q, want exactly one email change line containing %q", name, logs.String(), c.logLine)
			}
		}
	}
}

func TestOpenRedisStateLimitsTheLoginOnlyWhenRedisIsConfigured(t *testing.T) {
	without := testConfig(t)
	with := without
	with.RedisURL = "redis://auth_app:secret@127.0.0.1:1/0"
	with.LoginMaxAttempts, with.LoginWindow, with.LoginLock = 10, 5*time.Minute, 5*time.Minute

	off, closeOff, err := openRedisState(discardLogger(), without)
	defer closeOff()
	if _, noop := off.attempts.(noLoginAttempts); err != nil || !noop {
		t.Errorf("without Redis: attempts = %T, err = %v, want the no-op store", off.attempts, err)
	}
	on, closeOn, err := openRedisState(discardLogger(), with)
	defer closeOn()
	if _, noop := on.attempts.(noLoginAttempts); err != nil || noop {
		t.Errorf("with Redis: attempts = %T, err = %v, want the Redis store", on.attempts, err)
	}
}

func TestOpenRedisStateRejectsAnInvalidLoginAttemptLimit(t *testing.T) {
	cfg := testConfig(t)
	cfg.RedisURL = "redis://auth_app:secret@127.0.0.1:1/0"
	cfg.LoginMaxAttempts = 0

	if _, _, err := openRedisState(discardLogger(), cfg); err == nil {
		t.Error("openRedisState() error = nil, want the policy without attempts to be refused")
	}
}
