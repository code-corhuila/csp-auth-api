package main

import (
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/security"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// The behaviour of the bound is tested in the security package; here only that the composition root builds the hasher with it.
func TestTheServiceHashesThroughTheBoundedHasherAndStillHashes(t *testing.T) {
	cfg := testConfig(t)
	cfg.BcryptRounds = 4
	cfg.BcryptMaxConcurrent = 1
	cfg.BcryptQueueTimeout = 10 * time.Millisecond

	hasher := newPasswordHasher(cfg)

	if _, bounded := hasher.(*security.BoundedPasswordHasher); !bounded {
		t.Fatalf("hasher = %T, want the bounded hasher (Norma 5.3.10)", hasher)
	}
	password, err := model.NewPassword("Secret123")
	if err != nil {
		t.Fatalf("NewPassword() error = %v", err)
	}
	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if ok, err := hasher.Verify(hash, "Secret123"); !ok || err != nil {
		t.Errorf("Verify() = %v, %v; want true, nil", ok, err)
	}
}

func TestTheServiceRefusesAnInvalidBoundOnTheHasher(t *testing.T) {
	for name, change := range map[string]func(*int, *time.Duration){
		"no slots":   func(slots *int, _ *time.Duration) { *slots = 0 },
		"no waiting": func(_ *int, wait *time.Duration) { *wait = 0 },
	} {
		cfg := testConfig(t)
		change(&cfg.BcryptMaxConcurrent, &cfg.BcryptQueueTimeout)

		if err := checkHasherBound(cfg); err == nil {
			t.Errorf("%s: checkHasherBound() error = nil, want the bound to be refused", name)
		}
	}
}
