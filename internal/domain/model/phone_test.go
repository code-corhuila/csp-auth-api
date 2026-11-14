package model

import (
	"errors"
	"testing"
)

func TestNewPhoneAcceptsDigitsWithOptionalPlus(t *testing.T) {
	for _, raw := range []string{"3001234567", "+573001234567", "1234567", "123456789012345"} {
		t.Run(raw, func(t *testing.T) {
			phone, err := NewPhone(raw)
			if err != nil {
				t.Fatalf("NewPhone(%q) error = %v", raw, err)
			}
			if phone.String() != raw {
				t.Errorf("String() = %q, want %q", phone.String(), raw)
			}
		})
	}
}

func TestNewPhoneRejectsInvalidValues(t *testing.T) {
	for _, raw := range []string{"", "123456", "1234567890123456", "300-123-4567", "30012a4567", "++573001234567", "573001234567+", " 3001234567", "+"} {
		t.Run(raw, func(t *testing.T) {
			if _, err := NewPhone(raw); !errors.Is(err, ErrInvalidPhone) {
				t.Fatalf("NewPhone(%q) error = %v, want ErrInvalidPhone", raw, err)
			}
		})
	}
}
