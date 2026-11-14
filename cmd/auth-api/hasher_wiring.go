package main

import (
	"errors"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/security"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/config"
)

// checkHasherBound refuses a bound on the password hashes that is not a bound (Norma 5.3.10): at least one slot and a wait.
func checkHasherBound(cfg config.Config) error {
	if cfg.BcryptMaxConcurrent < 1 || cfg.BcryptQueueTimeout <= 0 {
		return errors.New("password hashing limit: the number of concurrent hashes and the queue timeout must be positive")
	}
	return nil
}

// newPasswordHasher builds the one hasher every route shares, so the bound counts the hashes of login, register, password
// change and password reset together and not each route apart.
func newPasswordHasher(cfg config.Config) out.PasswordHasher {
	return security.NewBoundedPasswordHasher(security.NewBcryptHasher(cfg.BcryptRounds), cfg.BcryptMaxConcurrent, cfg.BcryptQueueTimeout)
}
