package config

import (
	"testing"
	"time"
)

func TestLoadReadsTheLoginAttemptLimit(t *testing.T) {
	cfg, err := Load(lookupFrom(nil))
	if err != nil || cfg.LoginMaxAttempts != 10 || cfg.LoginWindow != 5*time.Minute || cfg.LoginLock != 5*time.Minute {
		t.Fatalf("default: %d attempts, %v window, %v lock, err = %v; want 10, 5m and 5m", cfg.LoginMaxAttempts, cfg.LoginWindow, cfg.LoginLock, err)
	}
	cfg, err = Load(lookupFrom(map[string]string{
		"APP_AUTH_LOGIN_MAX_ATTEMPTS": "3",
		"APP_AUTH_LOGIN_WINDOW":       "90s",
		"APP_AUTH_LOGIN_LOCK":         "10m",
	}))
	if err != nil || cfg.LoginMaxAttempts != 3 || cfg.LoginWindow != 90*time.Second || cfg.LoginLock != 10*time.Minute {
		t.Fatalf("%d attempts, %v window, %v lock, err = %v; want 3, 90s and 10m", cfg.LoginMaxAttempts, cfg.LoginWindow, cfg.LoginLock, err)
	}
}

func TestLoadRejectsAnInvalidLoginAttemptLimit(t *testing.T) {
	invalid := map[string][]string{
		"APP_AUTH_LOGIN_MAX_ATTEMPTS": {"0", "-1", "ten", "1.5", "1001"},
		"APP_AUTH_LOGIN_WINDOW":       {"0", "-1m", "soon", "5"},
		"APP_AUTH_LOGIN_LOCK":         {"0", "-1m", "soon", "5"},
	}
	for key, values := range invalid {
		for _, value := range values {
			if _, err := Load(lookupFrom(map[string]string{key: value})); err == nil {
				t.Errorf("%s=%s: Load() error = nil", key, value)
			}
		}
	}
}
