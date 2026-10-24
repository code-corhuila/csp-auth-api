package model

import (
	"errors"
	"strings"
	"testing"
)

func textOf(value string) *string { return &value }

func TestNewProfileChangeKeepsOnlyTheFieldsThatWereSent(t *testing.T) {
	change, err := NewProfileChange(textOf("  Ana Pérez "), nil, textOf("Calle 1 #2-3"))
	if err != nil {
		t.Fatalf("NewProfileChange() error = %v", err)
	}

	name, hasName := change.Name()
	_, hasPhone := change.Phone()
	address, hasAddress := change.Address()

	if !hasName || name.String() != "Ana Pérez" || hasPhone || !hasAddress || address.String() != "Calle 1 #2-3" {
		t.Errorf("name = %q (%v), phone sent = %v, address = %q (%v), want the trimmed name, no phone and the address",
			name, hasName, hasPhone, address, hasAddress)
	}
}

func TestNewProfileChangeNeedsAtLeastOneField(t *testing.T) {
	if _, err := NewProfileChange(nil, nil, nil); !errors.Is(err, ErrEmptyProfileChange) {
		t.Fatalf("NewProfileChange() error = %v, want ErrEmptyProfileChange", err)
	}
}

func TestNewProfileChangeAppliesTheRulesOfRegistrationAndReportsEveryInvalidField(t *testing.T) {
	_, err := NewProfileChange(textOf(" "), textOf("12-34"), textOf(strings.Repeat("a", 256)))

	for _, want := range []error{ErrInvalidName, ErrInvalidPhone, ErrInvalidAddress} {
		if !errors.Is(err, want) {
			t.Errorf("error = %v, want it to include %v", err, want)
		}
	}
	if _, err := NewProfileChange(textOf("Ana"), textOf("+573001234567"), nil); err != nil {
		t.Errorf("a valid name and phone: error = %v, want none", err)
	}
}
