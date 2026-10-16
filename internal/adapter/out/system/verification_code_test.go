package system

import (
	"bytes"
	"testing"
)

func TestNewCodeKeepsTheLeadingZeros(t *testing.T) {
	generator := VerificationCodeGenerator{source: bytes.NewReader(make([]byte, 64))}

	code, err := generator.NewCode()

	if err != nil || code.String() != "000000" {
		t.Errorf("NewCode() = %q, %v, want 000000", code.String(), err)
	}
}

func TestNewCodeIsSixDigitsAndVaries(t *testing.T) {
	generator := NewVerificationCodeGenerator()
	seen := map[string]bool{}

	for i := 0; i < 200; i++ {
		code, err := generator.NewCode()
		if err != nil || len(code.String()) != 6 {
			t.Fatalf("NewCode() = %q, %v, want six digits", code.String(), err)
		}
		seen[code.String()] = true
	}

	if len(seen) < 150 {
		t.Errorf("%d different codes in 200 draws, want them to be spread over the whole range", len(seen))
	}
}

func TestNewCodeReportsAnExhaustedSource(t *testing.T) {
	generator := VerificationCodeGenerator{source: bytes.NewReader(nil)}

	if _, err := generator.NewCode(); err == nil {
		t.Error("NewCode() error = nil, want the failure of the source")
	}
}
