package model

import (
	"strings"
	"unicode/utf8"
)

const maxAddressLength = 255

// Address is a contact address as free text, 1 to 255 characters once trimmed (value object).
type Address struct {
	value string
}

// NewAddress trims raw and rejects an empty or too long text.
func NewAddress(raw string) (Address, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || utf8.RuneCountInString(trimmed) > maxAddressLength {
		return Address{}, ErrInvalidAddress
	}
	return Address{value: trimmed}, nil
}

func (a Address) String() string {
	return a.value
}
