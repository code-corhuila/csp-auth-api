package config

import (
	"fmt"
	"time"
)

// Bounds of the request limits (Norma 5.3.10). A value above its maximum is not a limit anymore, so the service does not start.
const (
	defaultRequestTimeout       = 10 * time.Second
	maxRequestTimeout           = time.Minute
	defaultDetachedDeadline     = 10 * time.Second
	maxDetachedDeadline         = time.Minute
	defaultMaxHeaderBytes       = 64 << 10
	maxMaxHeaderBytes           = 1 << 20
	defaultMaxBodyBytes         = 1 << 20
	maxMaxBodyBytes             = 16 << 20
	defaultResetMaxBodyBytes    = 4 << 10
	defaultCredentialConcurrent = 8
	// CredentialQueueTimeout is the fixed wait of a request for a slot of the register and login bulkheads.
	CredentialQueueTimeout = time.Second
)

// loadRequestLimits reads what bounds a request: its deadline, which ends the wait for a pooled database connection, the size of
// its headers and of its body, and the deadline of the operations that must finish once started (logout, role change).
func loadRequestLimits(lookup Lookup, cfg *Config) error {
	var err error
	if cfg.RequestTimeout, err = boundedDuration(lookup, "APP_AUTH_HTTP_REQUEST_TIMEOUT", defaultRequestTimeout, maxRequestTimeout); err != nil {
		return err
	}
	if cfg.DetachedDeadline, err = boundedDuration(lookup, "APP_AUTH_DETACHED_DEADLINE", defaultDetachedDeadline, maxDetachedDeadline); err != nil {
		return err
	}
	if cfg.MaxHeaderBytes, err = boundedInt(lookup, "APP_AUTH_HTTP_MAX_HEADER_BYTES", defaultMaxHeaderBytes, maxMaxHeaderBytes); err != nil {
		return err
	}
	if cfg.MaxBodyBytes, err = boundedInt(lookup, "APP_AUTH_MAX_BODY_BYTES", defaultMaxBodyBytes, maxMaxBodyBytes); err != nil {
		return err
	}
	cfg.PasswordResetMaxBodyBytes, err = boundedInt(lookup, "APP_AUTH_PASSWORD_RESET_MAX_BODY_BYTES", defaultResetMaxBodyBytes, cfg.MaxBodyBytes)
	return err
}

// loadCredentialLimits reads the bulkheads of POST /register and POST /login, the routes that hash with bcrypt. The routes are
// enabled with the database, so the concurrency has to stay below the pool then and the other routes always find a connection.
func loadCredentialLimits(lookup Lookup, cfg *Config) error {
	var err error
	if cfg.RegisterMaxConcurrency, err = loadCredentialBulkhead(lookup, cfg, "APP_AUTH_REGISTER_MAX_CONCURRENCY"); err != nil {
		return err
	}
	cfg.LoginMaxConcurrency, err = loadCredentialBulkhead(lookup, cfg, "APP_AUTH_LOGIN_MAX_CONCURRENCY")
	return err
}

func loadCredentialBulkhead(lookup Lookup, cfg *Config, key string) (int, error) {
	concurrency, err := intValue(lookup, key, defaultCredentialConcurrent)
	if err != nil {
		return 0, err
	}
	if concurrency < 1 {
		return 0, fmt.Errorf("%s %d must be at least 1", key, concurrency)
	}
	if cfg.DatabaseURL != "" && concurrency >= cfg.DatabaseMaxConnections {
		return 0, fmt.Errorf("%s %d must be below APP_AUTH_DATABASE_MAX_CONNECTIONS %d", key, concurrency, cfg.DatabaseMaxConnections)
	}
	return concurrency, nil
}

func boundedDuration(lookup Lookup, key string, def, limit time.Duration) (time.Duration, error) {
	value, err := durationValue(lookup, key, def)
	if err == nil && value > limit {
		return 0, fmt.Errorf("%s %s exceeds the maximum of %s", key, value, limit)
	}
	return value, err
}

func boundedInt(lookup Lookup, key string, def int, limit int64) (int64, error) {
	value, err := intValue(lookup, key, def)
	if err != nil {
		return 0, err
	}
	if value < 1 || int64(value) > limit {
		return 0, fmt.Errorf("%s %d is out of range 1-%d", key, value, limit)
	}
	return int64(value), nil
}
