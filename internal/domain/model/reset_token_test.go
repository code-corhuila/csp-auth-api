package model

import (
	"strings"
	"testing"
)

const validResetToken = "3f2c1b7e-5a9d-4c1e-8b6f-0a1b2c3d4e5f"

func TestNewResetTokenAcceptsTheUUIDThatNewOpaqueTokenDraws(t *testing.T) {
	raw, err := NewOpaqueToken()
	if err != nil {
		t.Fatalf("NewOpaqueToken() error = %v", err)
	}

	token, err := NewResetToken(raw)

	if err != nil || token.Reveal() != raw {
		t.Errorf("NewResetToken(%q) = %q, %v, want the same token", raw, token.Reveal(), err)
	}
}

func TestNewResetTokenRejectsAnythingThatIsNotALowercaseUUID(t *testing.T) {
	cases := map[string]string{
		"empty":                 "",
		"too short":             validResetToken[:35],
		"too long":              validResetToken + "0",
		"without dashes":        strings.ReplaceAll(validResetToken, "-", "0"),
		"dash in another place": "3f2c1b7e5-a9d-4c1e-8b6f-0a1b2c3d4e5f",
		"not hexadecimal":       "3f2c1b7e-5a9d-4c1e-8b6f-0a1b2c3d4e5g",
		"uppercase":             strings.ToUpper(validResetToken),
		"with spaces":           " " + validResetToken[1:],
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewResetToken(raw); err != ErrInvalidResetToken {
				t.Errorf("NewResetToken(%q) error = %v, want ErrInvalidResetToken", raw, err)
			}
		})
	}
}

func TestResetTokenHashIsTheSHA256DigestOfTheToken(t *testing.T) {
	token, err := NewResetToken(validResetToken)
	if err != nil {
		t.Fatal(err)
	}

	if token.Hash() != HashOpaqueToken(validResetToken) {
		t.Errorf("Hash() = %q, want the digest of the token", token.Hash())
	}
}

func TestResetTokenNeverPrintsItsValue(t *testing.T) {
	token, _ := NewResetToken(validResetToken)

	if shown := token.String(); strings.Contains(shown, validResetToken) {
		t.Errorf("String() = %q, leaks the token", shown)
	}
}
