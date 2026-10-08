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

func TestLoadUsesDatabaseAndBcryptDefaults(t *testing.T) {
	cfg, err := Load(lookupFrom(nil))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.DatabaseURL != "" || cfg.DatabaseMaxConnections != 10 || cfg.DatabaseMinConnections != 2 {
		t.Errorf("unexpected pool defaults: %+v", cfg)
	}
	if cfg.DatabaseConnectTimeout != 5*time.Second || cfg.DatabaseQueryTimeout != 5*time.Second {
		t.Errorf("unexpected database timeouts: %+v", cfg)
	}
	if cfg.BcryptRounds != 12 {
		t.Errorf("BcryptRounds = %d, want 12", cfg.BcryptRounds)
	}
}

func TestLoadReadsDatabaseAndBcryptOverrides(t *testing.T) {
	cfg, err := Load(lookupFrom(map[string]string{
		"APP_AUTH_DATABASE_URL":             "postgresql://u:p@db:5432/csp",
		"APP_AUTH_DATABASE_MAX_CONNECTIONS": "20",
		"APP_AUTH_DATABASE_MIN_CONNECTIONS": "5",
		"APP_AUTH_DATABASE_CONNECT_TIMEOUT": "3s",
		"APP_AUTH_DATABASE_QUERY_TIMEOUT":   "8s",
		"APP_AUTH_BCRYPT_ROUNDS":            "10",
	}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.DatabaseURL != "postgresql://u:p@db:5432/csp" || cfg.DatabaseMaxConnections != 20 || cfg.DatabaseMinConnections != 5 {
		t.Errorf("pool overrides not applied: %+v", cfg)
	}
	if cfg.DatabaseConnectTimeout != 3*time.Second || cfg.DatabaseQueryTimeout != 8*time.Second || cfg.BcryptRounds != 10 {
		t.Errorf("overrides not applied: %+v", cfg)
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
		"port not a number":            {"PORT": "abc"},
		"port out of range":            {"PORT": "70000"},
		"duration malformed":           {"APP_AUTH_HTTP_READ_TIMEOUT": "soon"},
		"duration not positive":        {"APP_AUTH_HTTP_IDLE_TIMEOUT": "0s"},
		"max connections not a number": {"APP_AUTH_DATABASE_MAX_CONNECTIONS": "many"},
		"max connections zero":         {"APP_AUTH_DATABASE_MAX_CONNECTIONS": "0"},
		"min above max":                {"APP_AUTH_DATABASE_MIN_CONNECTIONS": "11"},
		"min negative":                 {"APP_AUTH_DATABASE_MIN_CONNECTIONS": "-1"},
		"connect timeout malformed":    {"APP_AUTH_DATABASE_CONNECT_TIMEOUT": "soon"},
		"query timeout not positive":   {"APP_AUTH_DATABASE_QUERY_TIMEOUT": "0s"},
		"bcrypt rounds not a number":   {"APP_AUTH_BCRYPT_ROUNDS": "strong"},
		"bcrypt rounds too low":        {"APP_AUTH_BCRYPT_ROUNDS": "3"},
		"bcrypt rounds too high":       {"APP_AUTH_BCRYPT_ROUNDS": "32"},
	}
	for name, values := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(lookupFrom(values)); err == nil {
				t.Fatal("Load() error = nil, want an error")
			}
		})
	}
}

func TestLoadReadsTheTokenSettings(t *testing.T) {
	cfg, err := Load(lookupFrom(nil))
	if err != nil || cfg.AccessTokenTTL != time.Hour || cfg.JWTPrivateKey != "" || cfg.JWTPrivateKeyFile != "" {
		t.Fatalf("defaults: cfg = %+v, err = %v; want 1h and no key", cfg, err)
	}
	cfg, err = Load(lookupFrom(map[string]string{
		"APP_AUTH_JWT_PRIVATE_KEY_FILE": "/run/secrets/jwt.pem",
		"APP_AUTH_JWT_EXPIRY":           "30m",
	}))
	if err != nil || cfg.JWTPrivateKeyFile != "/run/secrets/jwt.pem" || cfg.AccessTokenTTL != 30*time.Minute {
		t.Fatalf("cfg = %+v, err = %v", cfg, err)
	}
}

func TestLoadRejectsAnAccessTokenLifetimeOverOneHour(t *testing.T) {
	for _, value := range []string{"61m", "soon", "0s"} {
		if _, err := Load(lookupFrom(map[string]string{"APP_AUTH_JWT_EXPIRY": value})); err == nil {
			t.Errorf("APP_AUTH_JWT_EXPIRY=%s: Load() error = nil", value)
		}
	}
}
