package model

import (
	"net/mail"
	"strings"
	"unicode/utf8"
)

// MaxEmailLength is the longest address, in characters, that the database stores (CHECK on app_user.email
// and email_verification.new_email). Every valid address has at least the 3 characters of the other CHECK.
const MaxEmailLength = 255

// Email is a valid address, normalized to lowercase (value object).
type Email struct {
	value string
}

// NewEmail trims and lowercases raw and rejects anything that is not a bare address
// or has more than MaxEmailLength characters.
func NewEmail(raw string) (Email, error) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if utf8.RuneCountInString(normalized) > MaxEmailLength {
		return Email{}, ErrInvalidEmail
	}
	address, err := mail.ParseAddress(normalized)
	if err != nil || address.Address != normalized {
		return Email{}, ErrInvalidEmail
	}
	return Email{value: normalized}, nil
}

func (e Email) String() string {
	return e.value
}
