package config

import (
	"fmt"
	"time"
)

const (
	// maxPasswordChangeAttempts bounds APP_AUTH_PASSWORD_CHANGE_MAX_ATTEMPTS.
	maxPasswordChangeAttempts = 100
	// maxPasswordChangeQueueTimeout bounds APP_AUTH_PASSWORD_CHANGE_QUEUE_TIMEOUT: a longer wait would approach the write timeout.
	maxPasswordChangeQueueTimeout = 5 * time.Second
)

// loadPasswordChangeLimit reads the limits of POST /me/password (HU-AUTH-007, ADR-051, Norma 5.3.10): the wrong current
// passwords of one user allowed inside the window before the change is locked, and the bulkhead of the route, which hashes
// with bcrypt. The route is enabled with the database, so the concurrency has to stay below the pool then and the other
// routes always find a connection.
func loadPasswordChangeLimit(lookup Lookup, cfg *Config) error {
	var err error
	if cfg.PasswordChangeMaxAttempts, err = intValue(lookup, "APP_AUTH_PASSWORD_CHANGE_MAX_ATTEMPTS", 5); err != nil {
		return err
	}
	if cfg.PasswordChangeMaxAttempts < 1 || cfg.PasswordChangeMaxAttempts > maxPasswordChangeAttempts {
		return fmt.Errorf("APP_AUTH_PASSWORD_CHANGE_MAX_ATTEMPTS %d is out of range 1-%d", cfg.PasswordChangeMaxAttempts, maxPasswordChangeAttempts)
	}
	if cfg.PasswordChangeWindow, err = durationValue(lookup, "APP_AUTH_PASSWORD_CHANGE_WINDOW", 15*time.Minute); err != nil {
		return err
	}
	if cfg.PasswordChangeLock, err = durationValue(lookup, "APP_AUTH_PASSWORD_CHANGE_LOCK", 15*time.Minute); err != nil {
		return err
	}
	if cfg.PasswordChangeMaxConcurrency, err = intValue(lookup, "APP_AUTH_PASSWORD_CHANGE_MAX_CONCURRENCY", 4); err != nil {
		return err
	}
	if cfg.PasswordChangeMaxConcurrency < 1 {
		return fmt.Errorf("APP_AUTH_PASSWORD_CHANGE_MAX_CONCURRENCY %d must be at least 1", cfg.PasswordChangeMaxConcurrency)
	}
	if cfg.PasswordChangeQueueTimeout, err = durationValue(lookup, "APP_AUTH_PASSWORD_CHANGE_QUEUE_TIMEOUT", time.Second); err != nil {
		return err
	}
	if cfg.PasswordChangeQueueTimeout > maxPasswordChangeQueueTimeout {
		return fmt.Errorf("APP_AUTH_PASSWORD_CHANGE_QUEUE_TIMEOUT %s exceeds the maximum of %s", cfg.PasswordChangeQueueTimeout, maxPasswordChangeQueueTimeout)
	}
	if cfg.DatabaseURL != "" && cfg.PasswordChangeMaxConcurrency >= cfg.DatabaseMaxConnections {
		return fmt.Errorf("APP_AUTH_PASSWORD_CHANGE_MAX_CONCURRENCY %d must be below APP_AUTH_DATABASE_MAX_CONNECTIONS %d", cfg.PasswordChangeMaxConcurrency, cfg.DatabaseMaxConnections)
	}
	return nil
}
