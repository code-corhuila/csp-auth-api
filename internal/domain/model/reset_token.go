package model

import "errors"

// ErrInvalidResetToken is a reset token that is not a lowercase UUID of 36 characters.
var ErrInvalidResetToken = errors.New("reset token must be a UUID of 36 characters")

const resetTokenLength = 36

// ResetToken is the secret of a password reset: the opaque UUID the user receives in the link
// (value object, ADR-050). Only its digest is ever stored, and it never prints its value.
type ResetToken struct {
	value string
}

// NewResetToken accepts the lowercase UUID form that NewOpaqueToken draws.
func NewResetToken(raw string) (ResetToken, error) {
	if len(raw) != resetTokenLength {
		return ResetToken{}, ErrInvalidResetToken
	}
	for i := 0; i < len(raw); i++ {
		switch char := raw[i]; {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if char != '-' {
				return ResetToken{}, ErrInvalidResetToken
			}
		case char < '0' || char > '9' && char < 'a' || char > 'f':
			return ResetToken{}, ErrInvalidResetToken
		}
	}
	return ResetToken{value: raw}, nil
}

// Hash is the SHA-256 digest in hexadecimal, the only form in which the token is stored or looked up.
func (t ResetToken) Hash() string {
	return HashOpaqueToken(t.value)
}

// Reveal returns the token. Only the message that carries it to the user should call it.
func (t ResetToken) Reveal() string {
	return t.value
}

// String hides the value so it cannot reach logs by accident.
func (t ResetToken) String() string {
	return "[REDACTED]"
}
