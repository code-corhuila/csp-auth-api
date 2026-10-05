package model

import (
	"errors"
	"testing"
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
