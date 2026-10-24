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

const (
	forgotPasswordPath = "/api/v1/auth/forgot-password"
	resetPasswordPath  = "/api/v1/auth/reset-password"
)

func TestNewHandlerServesThePasswordResetRoutesOnlyWithTheDatabaseTheSMTPHostAndTheLink(t *testing.T) {
	withKey := testConfig(t)
	withKey.JWTPrivateKey = generatedKeyPEM(t)
	withDatabase := withKey
	withDatabase.DatabaseURL = "postgres://user:secret@127.0.0.1:1/db"
	withHost := withDatabase
	withHost.SMTPHost, withHost.SMTPFrom = "mailpit", "no-reply@cinesync.local"
	withLink := withHost
	withLink.PasswordResetURL = "https://portal.cinesync.local/reset-password"
	keyAndLink := withKey
	keyAndLink.SMTPHost, keyAndLink.SMTPFrom, keyAndLink.PasswordResetURL = withLink.SMTPHost, withLink.SMTPFrom, withLink.PasswordResetURL
	var settings persistence.PoolSettings
	var opened int

	for name, c := range map[string]struct {
		cfg        config.Config
		wantStatus int
		wantBody   string
		logLine    string
	}{
		"key and link without database":    {keyAndLink, http.StatusNotFound, "404 page not found", ""},
		"database and key, no SMTP host":   {withDatabase, http.StatusNotFound, `"error":"NOT_FOUND"`, "APP_AUTH_SMTP_HOST is not set: the password reset is not enabled"},
		"database, SMTP host, no link":     {withHost, http.StatusNotFound, `"error":"NOT_FOUND"`, "APP_AUTH_PASSWORD_RESET_URL is not set: the password reset is not enabled"},
		"database, SMTP host and the link": {withLink, http.StatusBadRequest, `"error":"VALIDATION_ERROR"`, "password reset routes enabled"},
	} {
		for _, path := range []string{forgotPasswordPath, resetPasswordPath} {
			var logs strings.Builder
			handler, closeAll, err := newHandler(context.Background(), slogTo(&logs), c.cfg, lazyPool(&settings, &opened))
			if err != nil {
				t.Fatalf("%s: newHandler() error = %v", name, err)
			}
			rec := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
			request.Header.Set("Content-Type", "application/json")
			handler.ServeHTTP(rec, request)
			closeAll()
			if rec.Code != c.wantStatus || !strings.Contains(rec.Body.String(), c.wantBody) {
				t.Errorf("%s %s: status = %d, body = %s, want %d with %s", name, path, rec.Code, rec.Body, c.wantStatus, c.wantBody)
			}
			if !strings.Contains(logs.String(), c.logLine) || strings.Count(logs.String(), "password reset") > 1 {
				t.Errorf("%s: log = %q, want exactly one password reset line containing %q", name, logs.String(), c.logLine)
			}
		}
	}
}

func TestNewHandlerRefusesAPasswordResetWithoutABulkhead(t *testing.T) {
	cfg := testConfig(t)
	cfg.JWTPrivateKey = generatedKeyPEM(t)
	cfg.DatabaseURL = "postgres://user:secret@127.0.0.1:1/db"
	cfg.SMTPHost, cfg.SMTPFrom = "mailpit", "no-reply@cinesync.local"
	cfg.PasswordResetURL = "https://portal.cinesync.local/reset-password"
	cfg.PasswordResetMaxConcurrency = 0
	var settings persistence.PoolSettings
	var opened int

	_, _, err := newHandler(context.Background(), discardLogger(), cfg, lazyPool(&settings, &opened))

	if err == nil {
		t.Error("newHandler() error = nil, want the password reset not to start without a limit")
	}
}
