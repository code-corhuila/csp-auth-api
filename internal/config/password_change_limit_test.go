package config

import (
	"testing"
	"time"
)

func TestLoadReadsThePasswordChangeSettings(t *testing.T) {
	cfg, err := Load(lookupFrom(nil))
	if err != nil || cfg.PasswordChangeMaxAttempts != 5 || cfg.PasswordChangeWindow != 15*time.Minute || cfg.PasswordChangeLock != 15*time.Minute ||
		cfg.PasswordChangeMaxConcurrency != 4 || cfg.PasswordChangeQueueTimeout != time.Second {
		t.Fatalf("default: attempts = %d, window = %v, lock = %v, concurrency = %d, wait = %v, err = %v; want 5, 15m, 15m, 4 and 1s",
			cfg.PasswordChangeMaxAttempts, cfg.PasswordChangeWindow, cfg.PasswordChangeLock, cfg.PasswordChangeMaxConcurrency, cfg.PasswordChangeQueueTimeout, err)
	}
	cfg, err = Load(lookupFrom(map[string]string{
		"APP_AUTH_PASSWORD_CHANGE_MAX_ATTEMPTS":    "3",
		"APP_AUTH_PASSWORD_CHANGE_WINDOW":          "10m",
		"APP_AUTH_PASSWORD_CHANGE_LOCK":            "20m",
		"APP_AUTH_PASSWORD_CHANGE_MAX_CONCURRENCY": "2",
		"APP_AUTH_PASSWORD_CHANGE_QUEUE_TIMEOUT":   "250ms",
	}))
	if err != nil || cfg.PasswordChangeMaxAttempts != 3 || cfg.PasswordChangeWindow != 10*time.Minute || cfg.PasswordChangeLock != 20*time.Minute ||
		cfg.PasswordChangeMaxConcurrency != 2 || cfg.PasswordChangeQueueTimeout != 250*time.Millisecond {
		t.Fatalf("cfg = %+v, err = %v; want the five settings read", cfg, err)
	}
}

func TestLoadRejectsAnInvalidPasswordChangeSetting(t *testing.T) {
	database := map[string]string{"APP_AUTH_DATABASE_URL": "postgres://user:secret@127.0.0.1:1/db"}
	for name, env := range map[string]map[string]string{
		"attempts zero":                   {"APP_AUTH_PASSWORD_CHANGE_MAX_ATTEMPTS": "0"},
		"attempts above the maximum":      {"APP_AUTH_PASSWORD_CHANGE_MAX_ATTEMPTS": "101"},
		"attempts not a number":           {"APP_AUTH_PASSWORD_CHANGE_MAX_ATTEMPTS": "many"},
		"window not positive":             {"APP_AUTH_PASSWORD_CHANGE_WINDOW": "0s"},
		"window not a duration":           {"APP_AUTH_PASSWORD_CHANGE_WINDOW": "15"},
		"lock not positive":               {"APP_AUTH_PASSWORD_CHANGE_LOCK": "-1m"},
		"lock not a duration":             {"APP_AUTH_PASSWORD_CHANGE_LOCK": "soon"},
		"concurrency zero":                {"APP_AUTH_PASSWORD_CHANGE_MAX_CONCURRENCY": "0"},
		"concurrency not a number":        {"APP_AUTH_PASSWORD_CHANGE_MAX_CONCURRENCY": "many"},
		"concurrency equal to the pool":   {"APP_AUTH_PASSWORD_CHANGE_MAX_CONCURRENCY": "10"},
		"default concurrency, tiny pool":  {"APP_AUTH_DATABASE_MAX_CONNECTIONS": "4", "APP_AUTH_DATABASE_MIN_CONNECTIONS": "1"},
		"queue timeout not positive":      {"APP_AUTH_PASSWORD_CHANGE_QUEUE_TIMEOUT": "0s"},
		"queue timeout not a duration":    {"APP_AUTH_PASSWORD_CHANGE_QUEUE_TIMEOUT": "1"},
		"queue timeout above the maximum": {"APP_AUTH_PASSWORD_CHANGE_QUEUE_TIMEOUT": "6s"},
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

func TestLoadDoesNotRelateThePasswordChangeBulkheadToThePoolWithoutADatabase(t *testing.T) {
	env := map[string]string{"APP_AUTH_DATABASE_MAX_CONNECTIONS": "2", "APP_AUTH_DATABASE_MIN_CONNECTIONS": "1"}

	if _, err := Load(lookupFrom(env)); err != nil {
		t.Errorf("Load() without a database URL and a pool of 2 error = %v, want none: the route is not enabled", err)
	}
}
