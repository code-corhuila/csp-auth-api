package config

import (
	"testing"
	"time"
)

func TestLoadReadsTheLoginAccountSlowdown(t *testing.T) {
	cfg, err := Load(lookupFrom(nil))
	if err != nil || cfg.LoginAccountSlowAfter != 20 || cfg.LoginAccountWindow != time.Hour || cfg.LoginAccountDelay != time.Second {
		t.Fatalf("default: %d failures, %v window, %v delay, err = %v; want 20, 1h and 1s", cfg.LoginAccountSlowAfter, cfg.LoginAccountWindow, cfg.LoginAccountDelay, err)
	}
	cfg, err = Load(lookupFrom(map[string]string{
		"APP_AUTH_LOGIN_ACCOUNT_SLOW_AFTER": "5",
		"APP_AUTH_LOGIN_ACCOUNT_WINDOW":     "30m",
		"APP_AUTH_LOGIN_ACCOUNT_DELAY":      "5s",
	}))
	if err != nil || cfg.LoginAccountSlowAfter != 5 || cfg.LoginAccountWindow != 30*time.Minute || cfg.LoginAccountDelay != 5*time.Second {
		t.Fatalf("%d failures, %v window, %v delay, err = %v; want 5, 30m and 5s", cfg.LoginAccountSlowAfter, cfg.LoginAccountWindow, cfg.LoginAccountDelay, err)
	}
}

func TestLoadRejectsAnInvalidLoginAccountSlowdown(t *testing.T) {
	invalid := map[string][]string{
		"APP_AUTH_LOGIN_ACCOUNT_SLOW_AFTER": {"0", "-1", "twenty", "1.5", "1001"},
		"APP_AUTH_LOGIN_ACCOUNT_WINDOW":     {"0", "-1m", "soon", "60", "25h"},
		"APP_AUTH_LOGIN_ACCOUNT_DELAY":      {"0", "-1s", "soon", "1", "5001ms", "1m"},
	}
	for key, values := range invalid {
		for _, value := range values {
			if _, err := Load(lookupFrom(map[string]string{key: value})); err == nil {
				t.Errorf("%s=%s: Load() error = nil", key, value)
			}
		}
	}
}
