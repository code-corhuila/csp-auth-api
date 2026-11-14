package security

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

func mustPassword(t *testing.T, raw string) model.Password {
	t.Helper()
	password, err := model.NewPassword(raw)
	if err != nil {
		t.Fatalf("NewPassword() error = %v", err)
	}
	return password
}

func TestHashProducesABcryptHashWithTheConfiguredCost(t *testing.T) {
	hash, err := NewBcryptHasher(bcrypt.MinCost).Hash(mustPassword(t, "Secret123"))
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if !strings.HasPrefix(hash, "$2a$04$") {
		t.Errorf("hash = %q, want a bcrypt hash of cost 4", hash)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("Secret123")); err != nil {
		t.Errorf("hash does not match the password: %v", err)
	}
	if strings.Contains(hash, "Secret123") {
		t.Error("hash must not contain the password")
	}
}

func TestHashSaltsEveryCall(t *testing.T) {
	hasher := NewBcryptHasher(bcrypt.MinCost)
	first, _ := hasher.Hash(mustPassword(t, "Secret123"))
	second, _ := hasher.Hash(mustPassword(t, "Secret123"))
	if first == second {
		t.Error("two hashes of the same password must differ")
	}
}

func TestHashReportsAnInvalidCost(t *testing.T) {
	if _, err := NewBcryptHasher(bcrypt.MaxCost + 1).Hash(mustPassword(t, "Secret123")); err == nil {
		t.Error("Hash() error = nil, want an error for an unsupported cost")
	}
}

func TestVerifyAcceptsOnlyThePasswordBehindTheHash(t *testing.T) {
	hasher := NewBcryptHasher(bcrypt.MinCost)
	hash, _ := hasher.Hash(mustPassword(t, "Secret123"))

	if ok, err := hasher.Verify(hash, "Secret123"); !ok || err != nil {
		t.Errorf("Verify() = %v, %v for the right password, want true, nil", ok, err)
	}
	if ok, _ := hasher.Verify(hash, "secret123"); ok {
		t.Error("Verify() = true for a wrong password")
	}
	if ok, _ := hasher.Verify(hash, ""); ok {
		t.Error("Verify() = true for an empty password")
	}
}

func TestVerifyTreatsAMalformedHashAsAMismatch(t *testing.T) {
	if ok, err := NewBcryptHasher(bcrypt.MinCost).Verify("not-a-hash", "Secret123"); ok || err != nil {
		t.Errorf("Verify() = %v, %v for a malformed hash, want a plain mismatch (false, nil)", ok, err)
	}
}
