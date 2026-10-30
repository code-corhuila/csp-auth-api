package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/persistence"
	"github.com/code-corhuila/csp-auth-api/internal/config"
)

const profilePath = "/api/v1/auth/me"

func TestNewHandlerServesTheOwnProfileRoutesOnlyWithTheDatabase(t *testing.T) {
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
		for _, method := range []string{http.MethodGet, http.MethodPatch} {
			handler, closeDatabase, err := newHandler(context.Background(), discardLogger(), c.cfg, lazyPool(&settings, &opened))
			if err != nil {
				t.Fatalf("%s: newHandler() error = %v", name, err)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(method, profilePath, strings.NewReader("{}")))
			closeDatabase()
			if rec.Code != c.want {
				t.Errorf("%s, %s: status = %d, want %d", name, method, rec.Code, c.want)
			}
		}
	}
}
