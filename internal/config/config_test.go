package config

import (
	"testing"
	"time"
)

func lookupFrom(values map[string]string) Lookup {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func TestLoadUsesDefaultsWhenNothingIsSet(t *testing.T) {
	cfg, err := Load(lookupFrom(nil))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Port != 8081 {
		t.Errorf("Port = %d, want 8081", cfg.Port)
	}
	if cfg.ReadHeaderTimeout != 5*time.Second || cfg.ShutdownTimeout != 15*time.Second {
		t.Errorf("unexpected default timeouts: %+v", cfg)
	}
}

func TestLoadReadsOverrides(t *testing.T) {
	cfg, err := Load(lookupFrom(map[string]string{
		"PORT":                           "9000",
		"APP_AUTH_HTTP_WRITE_TIMEOUT":    "30s",
		"APP_AUTH_HTTP_IDLE_TIMEOUT":     "2m",
		"APP_AUTH_HTTP_READ_TIMEOUT":     "",
		"APP_AUTH_HTTP_SHUTDOWN_TIMEOUT": "1s",
	}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Port != 9000 || cfg.WriteTimeout != 30*time.Second || cfg.IdleTimeout != 2*time.Minute {
		t.Errorf("overrides not applied: %+v", cfg)
	}
	if cfg.ReadTimeout != 10*time.Second {
		t.Errorf("empty value must keep the default, got %v", cfg.ReadTimeout)
	}
}

func TestLoadRejectsInvalidValues(t *testing.T) {
	cases := map[string]map[string]string{
		"port not a number":     {"PORT": "abc"},
		"port out of range":     {"PORT": "70000"},
		"duration malformed":    {"APP_AUTH_HTTP_READ_TIMEOUT": "soon"},
		"duration not positive": {"APP_AUTH_HTTP_IDLE_TIMEOUT": "0s"},
	}
	for name, values := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(lookupFrom(values)); err == nil {
				t.Fatal("Load() error = nil, want an error")
			}
		})
	}
}
