package model

import (
	"errors"
	"strings"
	"testing"
)

func TestNewPasswordAcceptsPolicyCompliantValues(t *testing.T) {
	cases := map[string]string{
		"minimum length":         "Abcdef12",
		"maximum length":         "A1" + strings.Repeat("b", 98),
		"with symbols":           "Secret123!",
		"multibyte counts runes": "Ñandú123",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			password, err := NewPassword(raw)
			if err != nil {
				t.Fatalf("NewPassword() error = %v", err)
			}
			if password.Reveal() != raw {
				t.Errorf("Reveal() = %q, want the raw value", password.Reveal())
			}
		})
	}
}

func TestNewPasswordRejectsWeakValues(t *testing.T) {
	cases := map[string]string{
		"empty":        "",
		"too short":    "Abcde12",
		"too long":     "A1" + strings.Repeat("b", 99),
		"no uppercase": "abcdefg1",
		"no digit":     "Abcdefgh",
		"only symbols": "!!!!!!!!",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewPassword(raw); !errors.Is(err, ErrWeakPassword) {
				t.Fatalf("NewPassword() error = %v, want ErrWeakPassword", err)
			}
		})
	}
}

func TestPasswordNeverPrintsItsValue(t *testing.T) {
	password, _ := NewPassword("Secret123!")
	for _, text := range []string{password.String(), (&password).String()} {
		if strings.Contains(text, "Secret123!") {
			t.Errorf("String() = %q leaks the password", text)
		}
	}
}
