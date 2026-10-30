package main

import (
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/config"
)

func TestOpenRedisStateRefusesAnAccountSlowdownWithoutPositiveValues(t *testing.T) {
	for name, change := range map[string]func(*config.Config){
		"no failures": func(cfg *config.Config) { cfg.LoginAccountSlowAfter = 0 },
		"no window":   func(cfg *config.Config) { cfg.LoginAccountWindow = 0 },
		"no delay":    func(cfg *config.Config) { cfg.LoginAccountDelay = 0 },
	} {
		cfg := testConfig(t)
		cfg.RedisURL = "redis://auth_app:secret@127.0.0.1:1/0"
		change(&cfg)

		if _, _, err := openRedisState(discardLogger(), cfg); err == nil {
			t.Errorf("%s: openRedisState() error = nil, want the slowdown to be refused", name)
		}
	}
}

func TestOpenRedisStateEnablesTheAccountSlowdownWithRedisAndNotWithout(t *testing.T) {
	cfg := testConfig(t)
	cfg.RedisURL = "redis://auth_app:secret@127.0.0.1:1/0"
	state, closeState, err := openRedisState(discardLogger(), cfg)
	if err != nil {
		t.Fatalf("openRedisState() error = %v", err)
	}
	defer closeState()
	if state.accountFailures == nil || state.accountPolicy.SlowAfter != 20 {
		t.Errorf("accountFailures = %v, policy = %+v, want the counter and the default policy", state.accountFailures, state.accountPolicy)
	}

	cfg.RedisURL = ""
	withoutRedis, closeWithout, err := openRedisState(discardLogger(), cfg)
	if err != nil {
		t.Fatalf("openRedisState() without Redis error = %v", err)
	}
	defer closeWithout()
	if withoutRedis.accountFailures != nil {
		t.Error("without Redis nobody can be counted, so the slowdown must not be enabled")
	}
}
