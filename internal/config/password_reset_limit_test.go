package config

import (
	"testing"
	"time"
)

func TestLoadReadsThePasswordResetSettings(t *testing.T) {
	cfg, err := Load(lookupFrom(nil))
	if err != nil || cfg.PasswordResetURL != "" || cfg.PasswordResetMaxConcurrency != 4 || cfg.PasswordResetQueueTimeout != time.Second {
		t.Fatalf("default: url = %q, concurrency = %d, wait = %v, err = %v; want no url, 4 and 1s",
			cfg.PasswordResetURL, cfg.PasswordResetMaxConcurrency, cfg.PasswordResetQueueTimeout, err)
	}
	cfg, err = Load(lookupFrom(map[string]string{
		"APP_AUTH_PASSWORD_RESET_URL":             "https://portal.cinesync.local/reset-password",
		"APP_AUTH_PASSWORD_RESET_MAX_CONCURRENCY": "2",
		"APP_AUTH_PASSWORD_RESET_QUEUE_TIMEOUT":   "250ms",
	}))
	if err != nil || cfg.PasswordResetURL != "https://portal.cinesync.local/reset-password" || cfg.PasswordResetMaxConcurrency != 2 || cfg.PasswordResetQueueTimeout != 250*time.Millisecond {
		t.Fatalf("cfg = %+v, err = %v; want the three settings read", cfg, err)
	}
}

func TestLoadRejectsAnInvalidPasswordResetSetting(t *testing.T) {
	smtp := map[string]string{"APP_AUTH_SMTP_HOST": "smtp.example.com", "APP_AUTH_SMTP_FROM": "no-reply@example.com"}
	for name, env := range map[string]map[string]string{
		"concurrency zero":                {"APP_AUTH_PASSWORD_RESET_MAX_CONCURRENCY": "0"},
		"concurrency negative":            {"APP_AUTH_PASSWORD_RESET_MAX_CONCURRENCY": "-1"},
		"concurrency not a number":        {"APP_AUTH_PASSWORD_RESET_MAX_CONCURRENCY": "many"},
		"concurrency equal to the pool":   {"APP_AUTH_PASSWORD_RESET_MAX_CONCURRENCY": "10"},
		"default concurrency, tiny pool":  {"APP_AUTH_DATABASE_MAX_CONNECTIONS": "2", "APP_AUTH_DATABASE_MIN_CONNECTIONS": "1", "APP_AUTH_EMAIL_CHANGE_MAX_CONCURRENCY": "1"},
		"queue timeout not positive":      {"APP_AUTH_PASSWORD_RESET_QUEUE_TIMEOUT": "0s"},
		"queue timeout not a duration":    {"APP_AUTH_PASSWORD_RESET_QUEUE_TIMEOUT": "1"},
		"queue timeout above the maximum": {"APP_AUTH_PASSWORD_RESET_QUEUE_TIMEOUT": "6s"},
		"url without a scheme":            {"APP_AUTH_PASSWORD_RESET_URL": "portal.cinesync.local/reset-password"},
		"url that is not http":            {"APP_AUTH_PASSWORD_RESET_URL": "ftp://portal.cinesync.local/reset-password"},
		"url without a host":              {"APP_AUTH_PASSWORD_RESET_URL": "https:///reset-password"},
		"url with a fragment":             {"APP_AUTH_PASSWORD_RESET_URL": "https://portal.cinesync.local/reset-password#top"},
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

func TestLoadDoesNotRelateThePasswordResetBulkheadToThePoolWhileTheSMTPRelayIsOff(t *testing.T) {
	env := map[string]string{"APP_AUTH_DATABASE_MAX_CONNECTIONS": "2", "APP_AUTH_DATABASE_MIN_CONNECTIONS": "1"}

	if _, err := Load(lookupFrom(env)); err != nil {
		t.Errorf("Load() without an SMTP host and a pool of 2 error = %v, want none: the password reset is not enabled", err)
	}
}
