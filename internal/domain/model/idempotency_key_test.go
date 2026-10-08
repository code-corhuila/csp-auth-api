package model

import (
	"errors"
	"strings"
	"testing"
)

func TestIdempotencyKeyAcceptsEightToOneHundredTwentyEightCharacters(t *testing.T) {
	for _, raw := range []string{strings.Repeat("k", 8), strings.Repeat("k", 128), strings.Repeat("ñ", 128), "3f2b8c1e-aaaa-bbbb-cccc-0123456789ab"} {
		key, err := NewIdempotencyKey(raw)
		if err != nil || key.String() != raw {
			t.Errorf("NewIdempotencyKey(%d chars) = %q, %v, want it accepted as is", len(raw), key.String(), err)
		}
	}
}

func TestIdempotencyKeyRejectsOtherLengths(t *testing.T) {
	for _, raw := range []string{"", strings.Repeat("k", 7), strings.Repeat("ñ", 7), strings.Repeat("k", 129)} {
		if _, err := NewIdempotencyKey(raw); !errors.Is(err, ErrInvalidIdempotencyKey) {
			t.Errorf("NewIdempotencyKey(%d chars) error = %v, want ErrInvalidIdempotencyKey", len(raw), err)
		}
	}
}

func registrationParts(t *testing.T, rawEmail, rawName, rawPhone, rawAddress string) (Email, Name, Phone, Address) {
	t.Helper()
	email, err := NewEmail(rawEmail)
	if err != nil {
		t.Fatal(err)
	}
	name, err := NewName(rawName)
	if err != nil {
		t.Fatal(err)
	}
	phone, err := NewPhone(rawPhone)
	if err != nil {
		t.Fatal(err)
	}
	address, err := NewAddress(rawAddress)
	if err != nil {
		t.Fatal(err)
	}
	return email, name, phone, address
}

func TestRegistrationRequestHashIsTheSHA256OfTheFixedCanonicalForm(t *testing.T) {
	email, name, phone, address := registrationParts(t, "Ana@Example.com", "Ana", "3001234567", "Calle 1")

	got := RegistrationRequestHash(email, name, phone, address)

	// sha256 of "ana@example.com"|"Ana"|"3001234567"|"Calle 1"
	const want = "f0e829fd9e4959f27ab680108ec1a7b0754b99e84c6a6be4cbbbc1cae759388d"
	if got != want {
		t.Errorf("RegistrationRequestHash() = %s, want %s", got, want)
	}
}

func TestRegistrationRequestHashIgnoresEmailCaseAndSurroundingSpace(t *testing.T) {
	a := RegistrationRequestHash(registrationParts(t, "Ana@Example.com", "Ana", "3001234567", "Calle 1"))
	b := RegistrationRequestHash(registrationParts(t, " ana@example.COM ", "Ana", "3001234567", "Calle 1"))

	if a != b {
		t.Errorf("hashes differ for the same email: %s and %s", a, b)
	}
}

func TestRegistrationRequestHashChangesWithEveryField(t *testing.T) {
	base := RegistrationRequestHash(registrationParts(t, "ana@example.com", "Ana", "3001234567", "Calle 1"))
	variants := map[string][4]string{
		"email":   {"bea@example.com", "Ana", "3001234567", "Calle 1"},
		"name":    {"ana@example.com", "Bea", "3001234567", "Calle 1"},
		"phone":   {"ana@example.com", "Ana", "3001234568", "Calle 1"},
		"address": {"ana@example.com", "Ana", "3001234567", "Calle 2"},
		// a value moving to the neighbouring field must not collide
		"name into address": {"ana@example.com", "Ana Calle", "3001234567", "1"},
		"name tail":         {"ana@example.com", "Ana\"|\"3001234567", "3001234567", "Calle 1"},
	}
	for label, v := range variants {
		if got := RegistrationRequestHash(registrationParts(t, v[0], v[1], v[2], v[3])); got == base {
			t.Errorf("changing %s keeps the hash %s", label, got)
		}
	}
}
