package model

import (
	"unicode"
	"unicode/utf8"
)

const (
	minPasswordLength = 8
	maxPasswordLength = 100
)

// Password is a plain-text password that satisfies the registration policy: 8 to 100
// characters with at least one uppercase letter and one digit (value object).
// It exists only until it is hashed and never prints its value.
type Password struct {
	value string
}

// NewPassword rejects any text that does not meet the policy.
func NewPassword(raw string) (Password, error) {
	length := utf8.RuneCountInString(raw)
	if length < minPasswordLength || length > maxPasswordLength {
		return Password{}, ErrWeakPassword
	}
	var hasUpper, hasDigit bool
	for _, char := range raw {
		hasUpper = hasUpper || unicode.IsUpper(char)
		hasDigit = hasDigit || unicode.IsDigit(char)
	}
	if !hasUpper || !hasDigit {
		return Password{}, ErrWeakPassword
	}
	return Password{value: raw}, nil
}

// Reveal returns the plain text. Only a password hasher should call it.
func (p Password) Reveal() string {
	return p.value
}

// String hides the value so it cannot reach logs by accident.
func (p Password) String() string {
	return "[REDACTED]"
}
