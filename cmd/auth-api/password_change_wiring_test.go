package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/persistence"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/redis"
	"github.com/code-corhuila/csp-auth-api/internal/config"
)

const passwordChangePath = "/api/v1/auth/me/password"

func TestNewHandlerServesThePasswordChangeRouteOnlyWithTheDatabase(t *testing.T) {
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
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, passwordChangePath, strings.NewReader("{}")))
		closeDatabase()
		if rec.Code != c.want {
			t.Errorf("%s: status = %d, want %d", name, rec.Code, c.want)
		}
	}
}

func TestNewHandlerRefusesAPasswordChangeWithoutABulkhead(t *testing.T) {
	cfg := testConfig(t)
	cfg.JWTPrivateKey = generatedKeyPEM(t)
	cfg.DatabaseURL = "postgres://user:secret@127.0.0.1:1/db"
	cfg.PasswordChangeMaxConcurrency = 0
	var settings persistence.PoolSettings
	var opened int

	_, _, err := newHandler(context.Background(), discardLogger(), cfg, lazyPool(&settings, &opened))

	if err == nil {
		t.Error("newHandler() error = nil, want the password change not to start without a limit")
	}
}

func TestOpenRedisStateLimitsAndBoundsThePasswordChangeOnlyWhenRedisIsConfigured(t *testing.T) {
	without := testConfig(t)
	with := without
	with.RedisURL = "redis://auth_app:secret@127.0.0.1:1/0"

	off, closeOff, err := openRedisState(discardLogger(), without)
	defer closeOff()
	if _, noop := off.passwordChanges.(noPasswordChangeAttempts); err != nil || !noop {
		t.Errorf("without Redis: passwordChanges = %T, err = %v, want the no-op store", off.passwordChanges, err)
	}
	on, closeOn, err := openRedisState(discardLogger(), with)
	defer closeOn()
	if _, bounded := on.passwordChanges.(*redis.BoundedPasswordChangeAttempts); err != nil || !bounded {
		t.Errorf("with Redis: passwordChanges = %T, err = %v, want the Redis store bounded by its timeout and pause (ADR-048)", on.passwordChanges, err)
	}
}

func TestOpenRedisStateRejectsAnInvalidPasswordChangeLimit(t *testing.T) {
	cfg := testConfig(t)
	cfg.RedisURL = "redis://auth_app:secret@127.0.0.1:1/0"
	cfg.PasswordChangeMaxAttempts = 0

	if _, _, err := openRedisState(discardLogger(), cfg); err == nil {
		t.Error("openRedisState() error = nil, want the policy without attempts to be refused")
	}
}
