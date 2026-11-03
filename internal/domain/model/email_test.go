package model

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestNewEmailNormalizesToLowercase(t *testing.T) {
	email, err := NewEmail("  Dev.User@Example.COM ")
	if err != nil {
		t.Fatalf("NewEmail() error = %v", err)
	}
	if got := email.String(); got != "dev.user@example.com" {
		t.Errorf("String() = %q, want dev.user@example.com", got)
	}
}

func TestNewEmailRejectsInvalidAddresses(t *testing.T) {
	for _, raw := range []string{"", "plain", "a@", "@b.com", "Name <a@b.com>", "a b@c.com"} {
		t.Run(raw, func(t *testing.T) {
			if _, err := NewEmail(raw); !errors.Is(err, ErrInvalidEmail) {
				t.Fatalf("NewEmail(%q) error = %v, want ErrInvalidEmail", raw, err)
			}
		})
	}
}

// addressOfLength builds a valid address of exactly n characters.
func addressOfLength(n int) string {
	const domain = "@example.com"
	return strings.Repeat("a", n-len(domain)) + domain
}

func TestNewEmailAcceptsTheLongestAddressTheDatabaseStores(t *testing.T) {
	raw := addressOfLength(MaxEmailLength)

	email, err := NewEmail(raw)

	if err != nil || email.String() != raw {
		t.Fatalf("NewEmail(%d characters) = %q, %v, want it accepted", len(raw), email.String(), err)
	}
}

func TestNewEmailRejectsMoreCharactersThanTheDatabaseStores(t *testing.T) {
	if _, err := NewEmail(addressOfLength(MaxEmailLength + 1)); !errors.Is(err, ErrInvalidEmail) {
		t.Fatalf("NewEmail(%d characters) error = %v, want ErrInvalidEmail", MaxEmailLength+1, err)
	}
}

func TestNewEmailCountsCharactersNotBytes(t *testing.T) {
	raw := strings.Repeat("ñ", MaxEmailLength-len("@example.com")) + "@example.com"

	if _, err := NewEmail(raw); err != nil {
		t.Fatalf("NewEmail(%d characters, %d bytes) error = %v, want it accepted: the database limit counts characters", utf8.RuneCountInString(raw), len(raw), err)
	}
}
