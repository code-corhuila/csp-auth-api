package model

import (
	"errors"
	"testing"
)

func TestNewVerificationCodeAcceptsExactlySixDigitsKeepingLeadingZeros(t *testing.T) {
	for _, raw := range []string{"000000", "012345", "999999"} {
		code, err := NewVerificationCode(raw)
		if err != nil || code.String() != raw {
			t.Errorf("NewVerificationCode(%q) = %q, %v, want it unchanged", raw, code.String(), err)
		}
	}
}

func TestNewVerificationCodeRejectsAnythingElse(t *testing.T) {
	for _, raw := range []string{"", "12345", "1234567", "12345a", " 12345", "12 456", "１２３４５６", "-12345", "+12345"} {
		if _, err := NewVerificationCode(raw); !errors.Is(err, ErrVerificationRejected) {
			t.Errorf("NewVerificationCode(%q) error = %v, want ErrVerificationRejected", raw, err)
		}
	}
}

func TestVerificationCodeMatchesOnlyTheSameCode(t *testing.T) {
	code, _ := NewVerificationCode("123456")
	same, _ := NewVerificationCode("123456")
	other, _ := NewVerificationCode("123457")
	first, _ := NewVerificationCode("023456")

	if !code.Matches(same) || code.Matches(other) || code.Matches(first) {
		t.Errorf("Matches: same = %v, last digit differs = %v, first digit differs = %v, want true false false",
			code.Matches(same), code.Matches(other), code.Matches(first))
	}
}
