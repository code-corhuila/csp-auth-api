package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"unicode/utf8"
)

const (
	minIdempotencyKeyLength = 8
	maxIdempotencyKeyLength = 128
)

// IdempotencyKey is the client key that makes a registration safe to retry (Norma 5.3.8).
type IdempotencyKey struct {
	value string
}

// NewIdempotencyKey accepts raw as is when it has 8 to 128 characters.
func NewIdempotencyKey(raw string) (IdempotencyKey, error) {
	length := utf8.RuneCountInString(raw)
	if length < minIdempotencyKeyLength || length > maxIdempotencyKeyLength {
		return IdempotencyKey{}, ErrInvalidIdempotencyKey
	}
	return IdempotencyKey{value: raw}, nil
}

func (k IdempotencyKey) String() string {
	return k.value
}

// RegistrationRequestHash is the SHA-256 hex digest of the canonical registration request, used
// to tell a retry from a different request that reuses the key. The canonical form is the four
// values email, name, phone and address, in that order, each Go-quoted and joined by "|": quoting
// escapes both separators, so no two requests share a form. The email is already lowercase
// (Email). The password is deliberately absent: nothing derived from it may be stored with the key.
func RegistrationRequestHash(email Email, name Name, phone Phone, address Address) string {
	canonical := fmt.Sprintf("%q|%q|%q|%q", email.String(), name.String(), phone.String(), address.String())
	digest := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(digest[:])
}
