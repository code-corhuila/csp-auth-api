package model

import (
	"strings"
	"unicode/utf8"
)

const maxNameLength = 100

// Name is the display name of a user, 1 to 100 characters once trimmed (value object).
type Name struct {
	value string
}

// NewName trims raw and rejects an empty or too long text.
func NewName(raw string) (Name, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || utf8.RuneCountInString(trimmed) > maxNameLength {
		return Name{}, ErrInvalidName
	}
	return Name{value: trimmed}, nil
}

func (n Name) String() string {
	return n.value
}
