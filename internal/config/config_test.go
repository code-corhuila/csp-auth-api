package config

import (
	"reflect"
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
		"APP_AUTH_JWT_EXPIRY":           "1800",
	}))
	if err != nil || cfg.JWTPrivateKeyFile != "/run/secrets/jwt.pem" || cfg.AccessTokenTTL != 30*time.Minute {
		t.Fatalf("cfg = %+v, err = %v", cfg, err)
	}
}

func TestLoadReadsTheRefreshTokenLifetime(t *testing.T) {
	cfg, err := Load(lookupFrom(nil))
	if err != nil || cfg.RefreshTokenTTL != 168*time.Hour {
		t.Fatalf("default: cfg.RefreshTokenTTL = %v, err = %v; want 168h", cfg.RefreshTokenTTL, err)
	}
	cfg, err = Load(lookupFrom(map[string]string{"APP_AUTH_REFRESH_TOKEN_EXPIRY": "86400"}))
	if err != nil || cfg.RefreshTokenTTL != 24*time.Hour {
		t.Fatalf("cfg.RefreshTokenTTL = %v, err = %v; want 24h", cfg.RefreshTokenTTL, err)
	}
}

func TestLoadRejectsAnInvalidRefreshTokenLifetime(t *testing.T) {
	for _, value := range []string{"0", "-1", "168h", "a week", "1.5"} {
		if _, err := Load(lookupFrom(map[string]string{"APP_AUTH_REFRESH_TOKEN_EXPIRY": value})); err == nil {
			t.Errorf("APP_AUTH_REFRESH_TOKEN_EXPIRY=%s: Load() error = nil", value)
		}
	}
}

func TestLoadRejectsAnAccessTokenLifetimeThatIsNotAPositiveNumberOfSecondsUpToOneHour(t *testing.T) {
	for _, value := range []string{"3601", "1h", "soon", "0", "-5", "1.5", "9999999999999"} {
		if _, err := Load(lookupFrom(map[string]string{"APP_AUTH_JWT_EXPIRY": value})); err == nil {
			t.Errorf("APP_AUTH_JWT_EXPIRY=%s: Load() error = nil", value)
		}
	}
}

func TestLoadReadsTheServiceSubjectsAsACommaSeparatedList(t *testing.T) {
	cfg, err := Load(lookupFrom(nil))
	if err != nil || len(cfg.ServiceSubjects) != 0 {
		t.Fatalf("default: cfg.ServiceSubjects = %v, err = %v; want none, so no service is allowed", cfg.ServiceSubjects, err)
	}
	cases := map[string][]string{
		"csp-worker":                     {"csp-worker"},
		" csp-worker , booking-service ": {"csp-worker", "booking-service"},
		"csp-worker,,":                   {"csp-worker"},
		" , ":                            nil,
	}
	for value, want := range cases {
		cfg, err = Load(lookupFrom(map[string]string{"SERVICE_SUBJECTS": value}))
		if err != nil || !reflect.DeepEqual(cfg.ServiceSubjects, want) {
			t.Errorf("SERVICE_SUBJECTS=%q: cfg.ServiceSubjects = %q, err = %v; want %q", value, cfg.ServiceSubjects, err, want)
		}
	}
}

func TestLoadReadsTheRefreshReuseGraceInSeconds(t *testing.T) {
	cfg, err := Load(lookupFrom(nil))
	if err != nil || cfg.RefreshReuseGrace != 10*time.Second {
		t.Fatalf("default: cfg.RefreshReuseGrace = %v, err = %v; want 10s", cfg.RefreshReuseGrace, err)
	}
	for value, want := range map[string]time.Duration{"1": time.Second, "30": 30 * time.Second, "60": time.Minute} {
		cfg, err = Load(lookupFrom(map[string]string{"APP_AUTH_REFRESH_REUSE_GRACE": value}))
		if err != nil || cfg.RefreshReuseGrace != want {
			t.Errorf("APP_AUTH_REFRESH_REUSE_GRACE=%s: cfg.RefreshReuseGrace = %v, err = %v; want %v", value, cfg.RefreshReuseGrace, err, want)
		}
	}
}

func TestLoadRejectsARefreshReuseGraceOutsideOneToSixtySeconds(t *testing.T) {
	for _, value := range []string{"0", "-1", "61", "10s", "ten", "1.5"} {
		if _, err := Load(lookupFrom(map[string]string{"APP_AUTH_REFRESH_REUSE_GRACE": value})); err == nil {
			t.Errorf("APP_AUTH_REFRESH_REUSE_GRACE=%s: Load() error = nil", value)
		}
	}
}

func TestLoadReadsTheRedisSettings(t *testing.T) {
	cfg, err := Load(lookupFrom(nil))
	if err != nil || cfg.RedisURL != "" || cfg.RedisTimeout != 2*time.Second {
		t.Fatalf("default: RedisURL = %q, RedisTimeout = %v, err = %v; want empty and 2s", cfg.RedisURL, cfg.RedisTimeout, err)
	}
	cfg, err = Load(lookupFrom(map[string]string{
		"APP_AUTH_REDIS_URL":     "redis://auth_app:secret@redis:6379/0",
		"APP_AUTH_REDIS_TIMEOUT": "500ms",
	}))
	if err != nil || cfg.RedisURL != "redis://auth_app:secret@redis:6379/0" || cfg.RedisTimeout != 500*time.Millisecond {
		t.Fatalf("RedisURL = %q, RedisTimeout = %v, err = %v", cfg.RedisURL, cfg.RedisTimeout, err)
	}
}

func TestLoadRejectsAnInvalidRedisTimeout(t *testing.T) {
	for _, value := range []string{"0", "-1s", "soon", "2"} {
		if _, err := Load(lookupFrom(map[string]string{"APP_AUTH_REDIS_TIMEOUT": value})); err == nil {
			t.Errorf("APP_AUTH_REDIS_TIMEOUT=%s: Load() error = nil", value)
		}
	}
}

func TestLoadReadsTheSMTPSettings(t *testing.T) {
	cfg, err := Load(lookupFrom(nil))
	if err != nil || cfg.SMTPHost != "" || cfg.SMTPPort != 587 || cfg.SMTPTLS != "starttls" || cfg.SMTPTimeout != 5*time.Second {
		t.Fatalf("default: %+v, err = %v; want no host, port 587, starttls and 5s", cfg, err)
	}
	cfg, err = Load(lookupFrom(map[string]string{
		"APP_AUTH_SMTP_HOST":     "mailpit",
		"APP_AUTH_SMTP_PORT":     "1025",
		"APP_AUTH_SMTP_USER":     "relay",
		"APP_AUTH_SMTP_PASSWORD": "secret",
		"APP_AUTH_SMTP_FROM":     "no-reply@cinesync.local",
		"APP_AUTH_SMTP_TLS":      "none",
		"APP_AUTH_SMTP_TIMEOUT":  "2s",
	}))
	if err != nil || cfg.SMTPHost != "mailpit" || cfg.SMTPPort != 1025 || cfg.SMTPUser != "relay" || cfg.SMTPPassword != "secret" ||
		cfg.SMTPFrom != "no-reply@cinesync.local" || cfg.SMTPTLS != "none" || cfg.SMTPTimeout != 2*time.Second {
		t.Fatalf("cfg = %+v, err = %v", cfg, err)
	}
}

func TestLoadRejectsAnInvalidSMTPSetting(t *testing.T) {
	base := map[string]string{"APP_AUTH_SMTP_HOST": "smtp.example.com", "APP_AUTH_SMTP_FROM": "no-reply@example.com"}
	if _, err := Load(lookupFrom(base)); err != nil {
		t.Fatalf("valid settings: Load() error = %v", err)
	}
	for name, change := range map[string]map[string]string{
		"from missing":         {"APP_AUTH_SMTP_FROM": ""},
		"from not an email":    {"APP_AUTH_SMTP_FROM": "no-reply"},
		"from with a name":     {"APP_AUTH_SMTP_FROM": "Cinesync <no-reply@example.com>"},
		"port zero":            {"APP_AUTH_SMTP_PORT": "0"},
		"port too large":       {"APP_AUTH_SMTP_PORT": "65536"},
		"port not a number":    {"APP_AUTH_SMTP_PORT": "smtp"},
		"unknown tls mode":     {"APP_AUTH_SMTP_TLS": "ssl"},
		"timeout not a time":   {"APP_AUTH_SMTP_TIMEOUT": "5"},
		"timeout not positive": {"APP_AUTH_SMTP_TIMEOUT": "0s"},
	} {
		env := map[string]string{}
		for k, v := range base {
			env[k] = v
		}
		for k, v := range change {
			env[k] = v
		}
		if _, err := Load(lookupFrom(env)); err == nil {
			t.Errorf("%s: Load() error = nil", name)
		}
	}
}

func TestLoadDoesNotValidateTheSMTPSettingsWithoutAHost(t *testing.T) {
	if _, err := Load(lookupFrom(map[string]string{"APP_AUTH_SMTP_FROM": "not-an-email"})); err != nil {
		t.Errorf("no host: Load() error = %v, want none because the email change is not enabled", err)
	}
}
