// Package config reads the service configuration from the environment.
// It is part of the composition root: only cmd/auth-api uses it.
package config

import (
	"fmt"
	"strconv"
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

// defaultRefreshTokenTTL is the lifetime of a refresh token (security-rules.md: 7 days).
const defaultRefreshTokenTTL = 7 * 24 * time.Hour

// Config holds the settings of the HTTP server, the database pool, the password hashing and the tokens.
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

// loadTokens reads where the signing key comes from (both sources empty means no key is configured)
// and the lifetime of both token kinds.
func loadTokens(lookup Lookup, cfg *Config) error {
	cfg.JWTPrivateKey, _ = lookup("APP_AUTH_JWT_PRIVATE_KEY")
	cfg.JWTPrivateKeyFile, _ = lookup("APP_AUTH_JWT_PRIVATE_KEY_FILE")
	ttl, err := durationValue(lookup, "APP_AUTH_JWT_EXPIRY", maxAccessTokenTTL)
	if err != nil {
		return err
	}
	if ttl > maxAccessTokenTTL {
		return fmt.Errorf("APP_AUTH_JWT_EXPIRY %s exceeds the maximum of %s", ttl, maxAccessTokenTTL)
	}
	cfg.AccessTokenTTL = ttl
	cfg.RefreshTokenTTL, err = durationValue(lookup, "APP_AUTH_REFRESH_TOKEN_TTL", defaultRefreshTokenTTL)
	return err
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
