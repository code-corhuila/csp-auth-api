package main

import (
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/redis"
)

func TestOpenRedisStateBoundsTheLoginLimiterWithItsOwnTimeoutAndPause(t *testing.T) {
	cfg := testConfig(t)
	cfg.RedisURL = "redis://auth_app:secret@127.0.0.1:1/0"

	state, closeState, err := openRedisState(discardLogger(), cfg)
	defer closeState()

	if _, bounded := state.attempts.(*redis.BoundedLoginAttempts); err != nil || !bounded {
		t.Errorf("attempts = %T, err = %v, want the limiter bounded by its timeout and pause (ADR-048)", state.attempts, err)
	}
}

func TestOpenRedisStateRefusesALoginLimiterWithoutATimeoutOrAPause(t *testing.T) {
	for name, change := range map[string]func(*time.Duration, *time.Duration){
		"no timeout": func(timeout, _ *time.Duration) { *timeout = 0 },
		"no pause":   func(_, pause *time.Duration) { *pause = 0 },
	} {
		cfg := testConfig(t)
		cfg.RedisURL = "redis://auth_app:secret@127.0.0.1:1/0"
		change(&cfg.LoginLimitTimeout, &cfg.LoginLimitPause)

		if _, _, err := openRedisState(discardLogger(), cfg); err == nil {
			t.Errorf("%s: openRedisState() error = nil, want the limiter to be refused", name)
		}
	}
}
