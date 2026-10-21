package model

import "crypto/subtle"

const verificationCodeLength = 6

// VerificationCode is the six decimal digits a user receives to confirm a new email, leading zeros
// kept (value object, ADR-034).
type VerificationCode struct {
	value string
}

// NewVerificationCode accepts exactly six ASCII digits and rejects anything else with
// ErrVerificationRejected, the same answer every failed verification gets.
func NewVerificationCode(raw string) (VerificationCode, error) {
	if len(raw) != verificationCodeLength {
		return VerificationCode{}, ErrVerificationRejected
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return VerificationCode{}, ErrVerificationRejected
		}
	}
	return VerificationCode{value: raw}, nil
}

func (c VerificationCode) String() string {
	return c.value
}

// Matches compares the codes in constant time, so the time taken does not tell where they differ.
func (c VerificationCode) Matches(other VerificationCode) bool {
	return subtle.ConstantTimeCompare([]byte(c.value), []byte(other.value)) == 1
}
