// Package config reads the service configuration from the environment.
// It is part of the composition root: only cmd/auth-api uses it.
package config

import (
	"fmt"
	"strconv"
	"time"
)

const defaultPort = 8081

// Config holds the settings the HTTP server needs. Every limit is explicit (Norma 5.3.10).
type Config struct {
	Port              int
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
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
