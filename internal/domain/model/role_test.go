package model

import (
	"errors"
	"testing"
)

func TestParseRoleAcceptsTheTwoRoles(t *testing.T) {
	for _, name := range []string{"CLIENT", "ADMIN"} {
		role, err := ParseRole(name)
		if err != nil {
			t.Fatalf("ParseRole(%q) error = %v", name, err)
		}
		if role.String() != name {
			t.Errorf("String() = %q, want %q", role.String(), name)
		}
	}
}

func TestParseRoleRejectsUnknownNames(t *testing.T) {
	for _, name := range []string{"", "client", "ROOT"} {
		if _, err := ParseRole(name); !errors.Is(err, ErrUnknownRole) {
			t.Errorf("ParseRole(%q) error = %v, want ErrUnknownRole", name, err)
		}
	}
}
