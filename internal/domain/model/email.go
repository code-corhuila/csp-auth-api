package model

import (
	"net/mail"
	"strings"
)

// Email is a valid address, normalized to lowercase (value object).
type Email struct {
	value string
}

// NewEmail trims and lowercases raw and rejects anything that is not a bare address.
func NewEmail(raw string) (Email, error) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	address, err := mail.ParseAddress(normalized)
	if err != nil || address.Address != normalized {
		return Email{}, ErrInvalidEmail
	}
	return Email{value: normalized}, nil
}

func (e Email) String() string {
	return e.value
}
