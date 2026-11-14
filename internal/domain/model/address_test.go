package model

import (
	"errors"
	"strings"
	"testing"
)

func TestNewAddressTrimsFreeText(t *testing.T) {
	address, err := NewAddress("  Calle 123 #45-67 ")
	if err != nil {
		t.Fatalf("NewAddress() error = %v", err)
	}
	if got := address.String(); got != "Calle 123 #45-67" {
		t.Errorf("String() = %q, want Calle 123 #45-67", got)
	}
}

func TestNewAddressAcceptsLimits(t *testing.T) {
	for _, raw := range []string{"x", strings.Repeat("ñ", 255)} {
		if _, err := NewAddress(raw); err != nil {
			t.Errorf("NewAddress(len %d) error = %v", len([]rune(raw)), err)
		}
	}
}

func TestNewAddressRejectsInvalidValues(t *testing.T) {
	for name, raw := range map[string]string{"empty": "", "blank": "   ", "too long": strings.Repeat("a", 256)} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewAddress(raw); !errors.Is(err, ErrInvalidAddress) {
				t.Fatalf("NewAddress() error = %v, want ErrInvalidAddress", err)
			}
		})
	}
}
