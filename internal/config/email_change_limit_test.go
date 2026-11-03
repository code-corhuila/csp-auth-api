package config

import (
	"testing"
	"time"
)

func TestLoadReadsTheEmailChangeBulkhead(t *testing.T) {
	cfg, err := Load(lookupFrom(nil))
	if err != nil || cfg.EmailChangeMaxConcurrency != 4 || cfg.EmailChangeQueueTimeout != time.Second {
		t.Fatalf("default: concurrency = %d, wait = %v, err = %v; want 4 and 1s", cfg.EmailChangeMaxConcurrency, cfg.EmailChangeQueueTimeout, err)
	}
	cfg, err = Load(lookupFrom(map[string]string{
		"APP_AUTH_EMAIL_CHANGE_MAX_CONCURRENCY": "2",
		"APP_AUTH_EMAIL_CHANGE_QUEUE_TIMEOUT":   "250ms",
	}))
	if err != nil || cfg.EmailChangeMaxConcurrency != 2 || cfg.EmailChangeQueueTimeout != 250*time.Millisecond {
		t.Fatalf("cfg = %+v, err = %v; want 2 and 250ms", cfg, err)
	}
}

func TestLoadRejectsAnInvalidEmailChangeBulkhead(t *testing.T) {
	smtp := map[string]string{"APP_AUTH_SMTP_HOST": "smtp.example.com", "APP_AUTH_SMTP_FROM": "no-reply@example.com"}
	for name, env := range map[string]map[string]string{
		"concurrency zero":                {"APP_AUTH_EMAIL_CHANGE_MAX_CONCURRENCY": "0"},
		"concurrency negative":            {"APP_AUTH_EMAIL_CHANGE_MAX_CONCURRENCY": "-1"},
		"concurrency not a number":        {"APP_AUTH_EMAIL_CHANGE_MAX_CONCURRENCY": "many"},
		"concurrency equal to the pool":   {"APP_AUTH_EMAIL_CHANGE_MAX_CONCURRENCY": "10"},
		"concurrency above the pool":      {"APP_AUTH_EMAIL_CHANGE_MAX_CONCURRENCY": "4", "APP_AUTH_DATABASE_MAX_CONNECTIONS": "3", "APP_AUTH_DATABASE_MIN_CONNECTIONS": "1"},
		"default concurrency, tiny pool":  {"APP_AUTH_DATABASE_MAX_CONNECTIONS": "2", "APP_AUTH_DATABASE_MIN_CONNECTIONS": "1"},
		"queue timeout not positive":      {"APP_AUTH_EMAIL_CHANGE_QUEUE_TIMEOUT": "0s"},
		"queue timeout not a duration":    {"APP_AUTH_EMAIL_CHANGE_QUEUE_TIMEOUT": "1"},
		"queue timeout above the maximum": {"APP_AUTH_EMAIL_CHANGE_QUEUE_TIMEOUT": "6s"},
	} {
		merged := map[string]string{}
		for k, v := range smtp {
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

func TestLoadDoesNotRelateTheBulkheadToThePoolWhileTheEmailChangeIsOff(t *testing.T) {
	env := map[string]string{"APP_AUTH_DATABASE_MAX_CONNECTIONS": "2", "APP_AUTH_DATABASE_MIN_CONNECTIONS": "1"}

	if _, err := Load(lookupFrom(env)); err != nil {
		t.Errorf("Load() without an SMTP host and a pool of 2 error = %v, want none: the email change is not enabled", err)
	}
}
