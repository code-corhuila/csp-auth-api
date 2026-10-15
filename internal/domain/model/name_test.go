package model

import (
	"errors"
	"strings"
	"testing"
)

func TestNewNameTrimsAndKeepsTheValue(t *testing.T) {
	name, err := NewName("  Ana María  ")
	if err != nil {
		t.Fatalf("NewName() error = %v", err)
	}
	if name.String() != "Ana María" {
		t.Errorf("String() = %q, want the trimmed value", name.String())
	}
}

func TestNewNameLengthLimits(t *testing.T) {
	cases := map[string]struct {
		raw  string
		want error
	}{
		"one character":   {"A", nil},
		"hundred runes":   {strings.Repeat("ñ", 100), nil},
		"empty":           {"", ErrInvalidName},
		"only spaces":     {"   ", ErrInvalidName},
		"hundred and one": {strings.Repeat("a", 101), ErrInvalidName},
	}
	for label, c := range cases {
		t.Run(label, func(t *testing.T) {
			if _, err := NewName(c.raw); !errors.Is(err, c.want) {
				t.Fatalf("NewName() error = %v, want %v", err, c.want)
			}
		})
	}
}
