// Package security holds the outbound adapters for cryptographic work.
package security

import (
	"golang.org/x/crypto/bcrypt"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// BcryptHasher implements out.PasswordHasher with bcrypt at a configured cost.
type BcryptHasher struct {
	cost int
}

var _ out.PasswordHasher = BcryptHasher{}

// NewBcryptHasher creates a hasher that uses cost as the bcrypt work factor.
func NewBcryptHasher(cost int) BcryptHasher {
	return BcryptHasher{cost: cost}
}

// Hash returns the bcrypt hash of password.
func (h BcryptHasher) Hash(password model.Password) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password.Reveal()), h.cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// Verify reports whether password matches the bcrypt hash. Any failure, including a malformed
// hash, is a mismatch; the cause is not exposed.
func (h BcryptHasher) Verify(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
