// Package config reads the service configuration from the environment.
// It is part of the composition root: only cmd/auth-api uses it.
package config

import (
	"errors"
	"fmt"
	"math"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const defaultPort = 8081

// Bounds of the bcrypt cost accepted by golang.org/x/crypto/bcrypt.
const (
	minBcryptRounds = 4
	maxBcryptRounds = 31
)

// maxAccessTokenTTL is the longest lifetime of an access token (security-rules.md).
const maxAccessTokenTTL = time.Hour

// defaultAccessTokenTTL is the lifetime of an access token when APP_AUTH_JWT_EXPIRY is not set (ADR-054: 15 minutes).
const defaultAccessTokenTTL = 15 * time.Minute

// defaultRefreshTokenTTL is the lifetime of a refresh token (security-rules.md: 7 days).
const defaultRefreshTokenTTL = 7 * 24 * time.Hour

// Bounds of the grace window in which the reuse of a spent refresh token is taken as a concurrent
// refresh (ADR-029).
const (
	defaultRefreshReuseGrace = 10 * time.Second
	maxRefreshReuseGrace     = time.Minute
)

// The two ways to secure the SMTP connection (ADR-034): STARTTLS is required unless the relay is a local catcher.
const (
	SMTPTLSStartTLS = "starttls"
	SMTPTLSNone     = "none"
)

// Config holds the settings of the HTTP server, the database pool, Redis, SMTP, the password hashing and the tokens.
// Every limit is explicit (Norma 5.3.10).
type Config struct {
	Port                   int
	ReadHeaderTimeout      time.Duration
	ReadTimeout            time.Duration
	WriteTimeout           time.Duration
	IdleTimeout            time.Duration
	ShutdownTimeout        time.Duration
	DatabaseURL            string
	DatabaseMaxConnections int
	DatabaseMinConnections int
	DatabaseConnectTimeout time.Duration
	DatabaseQueryTimeout   time.Duration
	BcryptRounds           int
	JWTPrivateKey          string
	JWTPrivateKeyFile      string
	AccessTokenTTL         time.Duration
	RefreshTokenTTL        time.Duration
	ServiceSubjects        []string
	RefreshReuseGrace      time.Duration
	RedisURL               string
	RedisTimeout           time.Duration
	LoginMaxAttempts       int
	LoginWindow            time.Duration
	LoginLock              time.Duration
	LoginLimitTimeout      time.Duration
	LoginLimitPause        time.Duration
	SMTPHost               string
	SMTPPort               int
	SMTPUser               string
	SMTPPassword           string
	SMTPFrom               string
	SMTPTLS                string
	SMTPTimeout            time.Duration

	EmailChangeMaxConcurrency int
	EmailChangeQueueTimeout   time.Duration

	PasswordResetURL            string
	PasswordResetMaxConcurrency int
	PasswordResetQueueTimeout   time.Duration

	PasswordChangeMaxAttempts    int
	PasswordChangeWindow         time.Duration
	PasswordChangeLock           time.Duration
	PasswordChangeMaxConcurrency int
	PasswordChangeQueueTimeout   time.Duration

	RequestTimeout            time.Duration
	DetachedDeadline          time.Duration
	MaxHeaderBytes            int64
	MaxBodyBytes              int64
	PasswordResetMaxBodyBytes int64

	RegisterMaxConcurrency int
	LoginMaxConcurrency    int
}

// Lookup returns the value of an environment variable, as os.LookupEnv does.
type Lookup func(key string) (string, bool)

// Load builds a Config from lookup, using the documented default for each missing variable.
func Load(lookup Lookup) (Config, error) {
	port, err := intValue(lookup, "PORT", defaultPort)
	if err != nil {
		return Config{}, err
	}
	if port < 1 || port > 65535 {
		return Config{}, fmt.Errorf("PORT %d is out of range 1-65535", port)
	}

	cfg := Config{Port: port}
	if err := loadDatabase(lookup, &cfg); err != nil {
		return Config{}, err
	}
	rounds, err := intValue(lookup, "APP_AUTH_BCRYPT_ROUNDS", 12)
	if err != nil {
		return Config{}, err
	}
	if rounds < minBcryptRounds || rounds > maxBcryptRounds {
		return Config{}, fmt.Errorf("APP_AUTH_BCRYPT_ROUNDS %d is out of range %d-%d", rounds, minBcryptRounds, maxBcryptRounds)
	}
	cfg.BcryptRounds = rounds
	if err := loadTokens(lookup, &cfg); err != nil {
		return Config{}, err
	}
	if err := loadRedis(lookup, &cfg); err != nil {
		return Config{}, err
	}
	if err := loadLoginLimit(lookup, &cfg); err != nil {
		return Config{}, err
	}
	if err := loadSMTP(lookup, &cfg); err != nil {
		return Config{}, err
	}
	if err := loadEmailChangeLimit(lookup, &cfg); err != nil {
		return Config{}, err
	}
	if err := loadPasswordReset(lookup, &cfg); err != nil {
		return Config{}, err
	}
	if err := loadPasswordChangeLimit(lookup, &cfg); err != nil {
		return Config{}, err
	}
	if err := loadRequestLimits(lookup, &cfg); err != nil {
		return Config{}, err
	}
	if err := loadCredentialLimits(lookup, &cfg); err != nil {
		return Config{}, err
	}

	durations := []struct {
		target *time.Duration
		key    string
		def    time.Duration
	}{
		{&cfg.ReadHeaderTimeout, "APP_AUTH_HTTP_READ_HEADER_TIMEOUT", 5 * time.Second},
		{&cfg.ReadTimeout, "APP_AUTH_HTTP_READ_TIMEOUT", 10 * time.Second},
		{&cfg.WriteTimeout, "APP_AUTH_HTTP_WRITE_TIMEOUT", 15 * time.Second},
		{&cfg.IdleTimeout, "APP_AUTH_HTTP_IDLE_TIMEOUT", 60 * time.Second},
		{&cfg.ShutdownTimeout, "APP_AUTH_HTTP_SHUTDOWN_TIMEOUT", 15 * time.Second},
	}
	for _, d := range durations {
		value, err := durationValue(lookup, d.key, d.def)
		if err != nil {
			return Config{}, err
		}
		*d.target = value
	}
	return cfg, nil
}

func loadDatabase(lookup Lookup, cfg *Config) error {
	cfg.DatabaseURL, _ = lookup("APP_AUTH_DATABASE_URL")
	var err error
	if cfg.DatabaseMaxConnections, err = intValue(lookup, "APP_AUTH_DATABASE_MAX_CONNECTIONS", 10); err != nil {
		return err
	}
	if cfg.DatabaseMinConnections, err = intValue(lookup, "APP_AUTH_DATABASE_MIN_CONNECTIONS", 2); err != nil {
		return err
	}
	if cfg.DatabaseMaxConnections < 1 || cfg.DatabaseMinConnections < 0 || cfg.DatabaseMinConnections > cfg.DatabaseMaxConnections {
		return fmt.Errorf("database connections must satisfy 0 <= min (%d) <= max (%d) and max >= 1", cfg.DatabaseMinConnections, cfg.DatabaseMaxConnections)
	}
	if cfg.DatabaseConnectTimeout, err = durationValue(lookup, "APP_AUTH_DATABASE_CONNECT_TIMEOUT", 5*time.Second); err != nil {
		return err
	}
	cfg.DatabaseQueryTimeout, err = durationValue(lookup, "APP_AUTH_DATABASE_QUERY_TIMEOUT", 5*time.Second)
	return err
}

// loadRedis reads the Redis of the auth state (ADR-028). An empty URL means it is not configured; the
// timeout bounds the connection, every read and every write (Norma 5.3.10).
func loadRedis(lookup Lookup, cfg *Config) error {
	cfg.RedisURL, _ = lookup("APP_AUTH_REDIS_URL")
	var err error
	cfg.RedisTimeout, err = durationValue(lookup, "APP_AUTH_REDIS_TIMEOUT", 2*time.Second)
	return err
}

// maxLoginAttempts bounds APP_AUTH_LOGIN_MAX_ATTEMPTS: a larger number is not a limit anymore.
const maxLoginAttempts = 1000

// loadLoginLimit reads the login attempt limit (HU-AUTH-005): failures allowed inside the window before an
// address is locked, and for how long. It only takes effect with Redis.
func loadLoginLimit(lookup Lookup, cfg *Config) error {
	var err error
	if cfg.LoginMaxAttempts, err = intValue(lookup, "APP_AUTH_LOGIN_MAX_ATTEMPTS", 10); err != nil {
		return err
	}
	if cfg.LoginMaxAttempts < 1 || cfg.LoginMaxAttempts > maxLoginAttempts {
		return fmt.Errorf("APP_AUTH_LOGIN_MAX_ATTEMPTS %d is out of range 1-%d", cfg.LoginMaxAttempts, maxLoginAttempts)
	}
	if cfg.LoginWindow, err = durationValue(lookup, "APP_AUTH_LOGIN_WINDOW", 5*time.Minute); err != nil {
		return err
	}
	cfg.LoginLock, err = durationValue(lookup, "APP_AUTH_LOGIN_LOCK", 5*time.Minute)
	if err != nil {
		return err
	}
	return loadLoginLimiterBounds(lookup, cfg)
}

// Bounds of the login limiter against Redis (ADR-048): the longest one call may wait and the longest pause after a failure.
const (
	maxLoginLimitTimeout = 5 * time.Second
	maxLoginLimitPause   = 5 * time.Minute
)

func loadLoginLimiterBounds(lookup Lookup, cfg *Config) error {
	var err error
	if cfg.LoginLimitTimeout, err = durationValue(lookup, "APP_AUTH_LOGIN_LIMIT_TIMEOUT", 300*time.Millisecond); err != nil {
		return err
	}
	if cfg.LoginLimitTimeout > maxLoginLimitTimeout {
		return fmt.Errorf("APP_AUTH_LOGIN_LIMIT_TIMEOUT %v is above the maximum %v", cfg.LoginLimitTimeout, maxLoginLimitTimeout)
	}
	if cfg.LoginLimitPause, err = durationValue(lookup, "APP_AUTH_LOGIN_LIMIT_PAUSE", 10*time.Second); err != nil {
		return err
	}
	if cfg.LoginLimitPause > maxLoginLimitPause {
		return fmt.Errorf("APP_AUTH_LOGIN_LIMIT_PAUSE %v is above the maximum %v", cfg.LoginLimitPause, maxLoginLimitPause)
	}
	return nil
}

// loadSMTP reads the SMTP relay that delivers the email verification code (ADR-034). An empty host means the
// email change is not enabled and nothing else is validated; the timeout bounds the whole exchange (Norma 5.3.10).
func loadSMTP(lookup Lookup, cfg *Config) error {
	cfg.SMTPHost, _ = lookup("APP_AUTH_SMTP_HOST")
	cfg.SMTPUser, _ = lookup("APP_AUTH_SMTP_USER")
	cfg.SMTPPassword, _ = lookup("APP_AUTH_SMTP_PASSWORD")
	cfg.SMTPFrom, _ = lookup("APP_AUTH_SMTP_FROM")
	cfg.SMTPTLS = SMTPTLSStartTLS
	if mode, _ := lookup("APP_AUTH_SMTP_TLS"); mode != "" {
		cfg.SMTPTLS = mode
	}
	cfg.SMTPPort, cfg.SMTPTimeout = 587, 5*time.Second
	if cfg.SMTPHost == "" {
		return nil
	}
	var err error
	if cfg.SMTPPort, err = intValue(lookup, "APP_AUTH_SMTP_PORT", 587); err != nil {
		return err
	}
	if cfg.SMTPPort < 1 || cfg.SMTPPort > 65535 {
		return fmt.Errorf("APP_AUTH_SMTP_PORT %d is out of range 1-65535", cfg.SMTPPort)
	}
	if address, err := mail.ParseAddress(cfg.SMTPFrom); err != nil || address.Address != cfg.SMTPFrom {
		return errors.New("APP_AUTH_SMTP_FROM must be an email address when APP_AUTH_SMTP_HOST is set")
	}
	if cfg.SMTPTLS != SMTPTLSStartTLS && cfg.SMTPTLS != SMTPTLSNone {
		return fmt.Errorf("APP_AUTH_SMTP_TLS must be %q or %q", SMTPTLSStartTLS, SMTPTLSNone)
	}
	cfg.SMTPTimeout, err = durationValue(lookup, "APP_AUTH_SMTP_TIMEOUT", 5*time.Second)
	return err
}

// maxEmailChangeQueueTimeout bounds APP_AUTH_EMAIL_CHANGE_QUEUE_TIMEOUT: a longer wait would approach the write timeout.
const maxEmailChangeQueueTimeout = 5 * time.Second

// loadEmailChangeLimit reads the bulkhead of PATCH /me/email (HU-AUTH-004, Norma 5.3.10): the request sends mail inside its
// database transaction, so only that many run at once and the next ones wait at most the queue timeout before a 429.
// With the email change enabled the concurrency has to stay below the pool, so the other routes always find a connection.
func loadEmailChangeLimit(lookup Lookup, cfg *Config) error {
	var err error
	if cfg.EmailChangeMaxConcurrency, err = intValue(lookup, "APP_AUTH_EMAIL_CHANGE_MAX_CONCURRENCY", 4); err != nil {
		return err
	}
	if cfg.EmailChangeMaxConcurrency < 1 {
		return fmt.Errorf("APP_AUTH_EMAIL_CHANGE_MAX_CONCURRENCY %d must be at least 1", cfg.EmailChangeMaxConcurrency)
	}
	if cfg.EmailChangeQueueTimeout, err = durationValue(lookup, "APP_AUTH_EMAIL_CHANGE_QUEUE_TIMEOUT", time.Second); err != nil {
		return err
	}
	if cfg.EmailChangeQueueTimeout > maxEmailChangeQueueTimeout {
		return fmt.Errorf("APP_AUTH_EMAIL_CHANGE_QUEUE_TIMEOUT %s exceeds the maximum of %s", cfg.EmailChangeQueueTimeout, maxEmailChangeQueueTimeout)
	}
	if cfg.SMTPHost != "" && cfg.EmailChangeMaxConcurrency >= cfg.DatabaseMaxConnections {
		return fmt.Errorf("APP_AUTH_EMAIL_CHANGE_MAX_CONCURRENCY %d must be below APP_AUTH_DATABASE_MAX_CONNECTIONS %d", cfg.EmailChangeMaxConcurrency, cfg.DatabaseMaxConnections)
	}
	return nil
}

// maxPasswordResetQueueTimeout bounds APP_AUTH_PASSWORD_RESET_QUEUE_TIMEOUT: a longer wait would approach the write timeout.
const maxPasswordResetQueueTimeout = 5 * time.Second

// loadPasswordReset reads the settings of the password reset (HU-AUTH-006, ADR-050): the page of the portal that the link of
// the message opens, and the bulkhead of each of the two routes (Norma 5.3.10). The routes need the SMTP relay and the URL,
// so the URL is only validated when it is set. With the relay configured the concurrency has to stay below the pool, so the
// other routes always find a connection.
func loadPasswordReset(lookup Lookup, cfg *Config) error {
	cfg.PasswordResetURL, _ = lookup("APP_AUTH_PASSWORD_RESET_URL")
	if cfg.PasswordResetURL != "" {
		if link, err := url.Parse(cfg.PasswordResetURL); err != nil || (link.Scheme != "http" && link.Scheme != "https") || link.Host == "" || link.Fragment != "" {
			return errors.New("APP_AUTH_PASSWORD_RESET_URL must be an absolute http or https URL without a fragment")
		}
	}
	var err error
	if cfg.PasswordResetMaxConcurrency, err = intValue(lookup, "APP_AUTH_PASSWORD_RESET_MAX_CONCURRENCY", 4); err != nil {
		return err
	}
	if cfg.PasswordResetMaxConcurrency < 1 {
		return fmt.Errorf("APP_AUTH_PASSWORD_RESET_MAX_CONCURRENCY %d must be at least 1", cfg.PasswordResetMaxConcurrency)
	}
	if cfg.PasswordResetQueueTimeout, err = durationValue(lookup, "APP_AUTH_PASSWORD_RESET_QUEUE_TIMEOUT", time.Second); err != nil {
		return err
	}
	if cfg.PasswordResetQueueTimeout > maxPasswordResetQueueTimeout {
		return fmt.Errorf("APP_AUTH_PASSWORD_RESET_QUEUE_TIMEOUT %s exceeds the maximum of %s", cfg.PasswordResetQueueTimeout, maxPasswordResetQueueTimeout)
	}
	if cfg.SMTPHost != "" && cfg.PasswordResetMaxConcurrency >= cfg.DatabaseMaxConnections {
		return fmt.Errorf("APP_AUTH_PASSWORD_RESET_MAX_CONCURRENCY %d must be below APP_AUTH_DATABASE_MAX_CONNECTIONS %d", cfg.PasswordResetMaxConcurrency, cfg.DatabaseMaxConnections)
	}
	return nil
}

// loadTokens reads where the signing key comes from (both sources empty means no key is configured)
// the lifetime of both token kinds, the refresh reuse grace window and the subjects of the services allowed to call the internal operations.
func loadTokens(lookup Lookup, cfg *Config) error {
	cfg.JWTPrivateKey, _ = lookup("APP_AUTH_JWT_PRIVATE_KEY")
	cfg.JWTPrivateKeyFile, _ = lookup("APP_AUTH_JWT_PRIVATE_KEY_FILE")
	ttl, err := secondsValue(lookup, "APP_AUTH_JWT_EXPIRY", defaultAccessTokenTTL)
	if err != nil {
		return err
	}
	if ttl > maxAccessTokenTTL {
		return fmt.Errorf("APP_AUTH_JWT_EXPIRY %d exceeds the maximum of %d seconds", int(ttl.Seconds()), int(maxAccessTokenTTL.Seconds()))
	}
	cfg.AccessTokenTTL = ttl
	if cfg.RefreshTokenTTL, err = secondsValue(lookup, "APP_AUTH_REFRESH_TOKEN_EXPIRY", defaultRefreshTokenTTL); err != nil {
		return err
	}
	cfg.RefreshReuseGrace, err = secondsValue(lookup, "APP_AUTH_REFRESH_REUSE_GRACE", defaultRefreshReuseGrace)
	if err == nil && cfg.RefreshReuseGrace > maxRefreshReuseGrace {
		return fmt.Errorf("APP_AUTH_REFRESH_REUSE_GRACE %d exceeds the maximum of %d seconds", int(cfg.RefreshReuseGrace.Seconds()), int(maxRefreshReuseGrace.Seconds()))
	}
	cfg.ServiceSubjects = listValue(lookup, "SERVICE_SUBJECTS")
	return err
}

// listValue reads a comma-separated list, trimming blanks and dropping empty items.
func listValue(lookup Lookup, key string) []string {
	raw, _ := lookup(key)
	var items []string
	for _, item := range strings.Split(raw, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	return items
}

func intValue(lookup Lookup, key string, def int) (int, error) {
	raw, ok := lookup(key)
	if !ok || raw == "" {
		return def, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", key, err)
	}
	return value, nil
}

func durationValue(lookup Lookup, key string, def time.Duration) (time.Duration, error) {
	raw, ok := lookup(key)
	if !ok || raw == "" {
		return def, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration such as 5s: %w", key, err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("%s must be positive", key)
	}
	return value, nil
}

// secondsValue reads a positive whole number of seconds, the unit of the documented token lifetimes.
func secondsValue(lookup Lookup, key string, def time.Duration) (time.Duration, error) {
	raw, ok := lookup(key)
	if !ok || raw == "" {
		return def, nil
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer number of seconds: %w", key, err)
	}
	if seconds <= 0 || int64(seconds) > math.MaxInt64/int64(time.Second) {
		return 0, fmt.Errorf("%s must be a positive number of seconds", key)
	}
	return time.Duration(seconds) * time.Second, nil
}
