package config

import (
	"testing"
	"time"
)

func TestLoadReadsTheRequestLimits(t *testing.T) {
	cfg, err := Load(lookupFrom(nil))
	if err != nil || cfg.RequestTimeout != 10*time.Second || cfg.DetachedDeadline != 10*time.Second || cfg.MaxHeaderBytes != 65536 ||
		cfg.MaxBodyBytes != 1048576 || cfg.PasswordResetMaxBodyBytes != 4096 {
		t.Fatalf("default: timeout = %v, detached = %v, header = %d, body = %d, reset body = %d, err = %v; want 10s, 10s, 65536, 1048576 and 4096",
			cfg.RequestTimeout, cfg.DetachedDeadline, cfg.MaxHeaderBytes, cfg.MaxBodyBytes, cfg.PasswordResetMaxBodyBytes, err)
	}
	cfg, err = Load(lookupFrom(map[string]string{
		"APP_AUTH_HTTP_REQUEST_TIMEOUT":          "2s",
		"APP_AUTH_DETACHED_DEADLINE":             "30s",
		"APP_AUTH_HTTP_MAX_HEADER_BYTES":         "8192",
		"APP_AUTH_MAX_BODY_BYTES":                "2048",
		"APP_AUTH_PASSWORD_RESET_MAX_BODY_BYTES": "512",
	}))
	if err != nil || cfg.RequestTimeout != 2*time.Second || cfg.DetachedDeadline != 30*time.Second || cfg.MaxHeaderBytes != 8192 ||
		cfg.MaxBodyBytes != 2048 || cfg.PasswordResetMaxBodyBytes != 512 {
		t.Fatalf("cfg = %+v, err = %v; want the five settings read", cfg, err)
	}
}

func TestLoadRejectsAnInvalidRequestLimit(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"request timeout zero":                {"APP_AUTH_HTTP_REQUEST_TIMEOUT": "0s"},
		"request timeout negative":            {"APP_AUTH_HTTP_REQUEST_TIMEOUT": "-1s"},
		"request timeout not a duration":      {"APP_AUTH_HTTP_REQUEST_TIMEOUT": "10"},
		"request timeout above the maximum":   {"APP_AUTH_HTTP_REQUEST_TIMEOUT": "61s"},
		"detached deadline not positive":      {"APP_AUTH_DETACHED_DEADLINE": "0s"},
		"detached deadline above the maximum": {"APP_AUTH_DETACHED_DEADLINE": "2m"},
		"header bytes zero":                   {"APP_AUTH_HTTP_MAX_HEADER_BYTES": "0"},
		"header bytes not a number":           {"APP_AUTH_HTTP_MAX_HEADER_BYTES": "big"},
		"header bytes above the maximum":      {"APP_AUTH_HTTP_MAX_HEADER_BYTES": "1048577"},
		"body bytes zero":                     {"APP_AUTH_MAX_BODY_BYTES": "0"},
		"body bytes above the maximum":        {"APP_AUTH_MAX_BODY_BYTES": "16777217"},
		"reset body bytes negative":           {"APP_AUTH_PASSWORD_RESET_MAX_BODY_BYTES": "-1"},
		"reset body bytes above the body":     {"APP_AUTH_MAX_BODY_BYTES": "1024", "APP_AUTH_PASSWORD_RESET_MAX_BODY_BYTES": "2048"},
	} {
		if _, err := Load(lookupFrom(env)); err == nil {
			t.Errorf("%s: Load() error = nil", name)
		}
	}
}

func TestLoadReadsTheRegisterAndLoginBulkheads(t *testing.T) {
	cfg, err := Load(lookupFrom(nil))
	if err != nil || cfg.RegisterMaxConcurrency != 8 || cfg.LoginMaxConcurrency != 8 {
		t.Fatalf("default: register = %d, login = %d, err = %v; want 8 for both", cfg.RegisterMaxConcurrency, cfg.LoginMaxConcurrency, err)
	}
	cfg, err = Load(lookupFrom(map[string]string{
		"APP_AUTH_REGISTER_MAX_CONCURRENCY": "2",
		"APP_AUTH_LOGIN_MAX_CONCURRENCY":    "3",
	}))
	if err != nil || cfg.RegisterMaxConcurrency != 2 || cfg.LoginMaxConcurrency != 3 {
		t.Fatalf("cfg = %+v, err = %v; want the two settings read", cfg, err)
	}
}

func TestLoadRejectsAnInvalidRegisterOrLoginBulkhead(t *testing.T) {
	database := map[string]string{"APP_AUTH_DATABASE_URL": "postgres://user:secret@127.0.0.1:1/db"}
	for name, env := range map[string]map[string]string{
		"register concurrency zero":         {"APP_AUTH_REGISTER_MAX_CONCURRENCY": "0"},
		"register concurrency not a number": {"APP_AUTH_REGISTER_MAX_CONCURRENCY": "many"},
		"register concurrency at the pool":  {"APP_AUTH_REGISTER_MAX_CONCURRENCY": "10"},
		"login concurrency zero":            {"APP_AUTH_LOGIN_MAX_CONCURRENCY": "0"},
		"login concurrency not a number":    {"APP_AUTH_LOGIN_MAX_CONCURRENCY": "many"},
		"login concurrency at the pool":     {"APP_AUTH_LOGIN_MAX_CONCURRENCY": "10"},
		"default concurrency, tiny pool":    {"APP_AUTH_DATABASE_MAX_CONNECTIONS": "8", "APP_AUTH_DATABASE_MIN_CONNECTIONS": "1", "APP_AUTH_PASSWORD_CHANGE_MAX_CONCURRENCY": "1"},
	} {
		merged := map[string]string{}
		for k, v := range database {
			merged[k] = v
		}
		for k, v := range env {
			merged[k] = v
		}
		if _, err := Load(lookupFrom(merged)); err == nil {
			t.Errorf("%s: Load() error = nil", name)
		}
	}
}

func TestLoadDoesNotRelateTheRegisterAndLoginBulkheadsToThePoolWithoutADatabase(t *testing.T) {
	env := map[string]string{"APP_AUTH_DATABASE_MAX_CONNECTIONS": "2", "APP_AUTH_DATABASE_MIN_CONNECTIONS": "1", "APP_AUTH_PASSWORD_CHANGE_MAX_CONCURRENCY": "1"}
	if _, err := Load(lookupFrom(env)); err != nil {
		t.Fatalf("Load() error = %v, want none without a database", err)
	}
}
