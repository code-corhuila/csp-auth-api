package config

import (
	"testing"
	"time"
)

func TestLoadReadsTheLoginLimiterTimeoutAndPause(t *testing.T) {
	cfg, err := Load(lookupFrom(nil))
	if err != nil || cfg.LoginLimitTimeout != 300*time.Millisecond || cfg.LoginLimitPause != 10*time.Second {
		t.Fatalf("default: %v timeout, %v pause, err = %v; want 300ms and 10s", cfg.LoginLimitTimeout, cfg.LoginLimitPause, err)
	}
	cfg, err = Load(lookupFrom(map[string]string{
		"APP_AUTH_LOGIN_LIMIT_TIMEOUT": "5s",
		"APP_AUTH_LOGIN_LIMIT_PAUSE":   "5m",
	}))
	if err != nil || cfg.LoginLimitTimeout != 5*time.Second || cfg.LoginLimitPause != 5*time.Minute {
		t.Fatalf("%v timeout, %v pause, err = %v; want the upper bounds 5s and 5m", cfg.LoginLimitTimeout, cfg.LoginLimitPause, err)
	}
}

func TestLoadRejectsAnInvalidLoginLimiterTimeoutOrPause(t *testing.T) {
	invalid := map[string][]string{
		"APP_AUTH_LOGIN_LIMIT_TIMEOUT": {"0", "-1s", "soon", "300", "5001ms", "1m"},
		"APP_AUTH_LOGIN_LIMIT_PAUSE":   {"0", "-1s", "soon", "10", "5m1s", "1h"},
	}
	for key, values := range invalid {
		for _, value := range values {
			if _, err := Load(lookupFrom(map[string]string{key: value})); err == nil {
				t.Errorf("%s=%s: Load() error = nil", key, value)
			}
		}
	}
}
