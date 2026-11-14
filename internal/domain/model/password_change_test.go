package model

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDefaultPasswordChangePolicyLocksAfterFiveWrongPasswordsInFifteenMinutes(t *testing.T) {
	policy := DefaultPasswordChangePolicy()

	if policy.MaxAttempts != 5 || policy.Window != 15*time.Minute || policy.Lock != 15*time.Minute {
		t.Errorf("policy = %+v, want 5 attempts, a 15 minute window and a 15 minute lock", policy)
	}
	if policy.Reached(4) || !policy.Reached(5) {
		t.Error("the fifth wrong password, and not the fourth, must reach the policy")
	}
}

func TestCheckPresentedPasswordAcceptsFromOneToSeventyTwoBytes(t *testing.T) {
	for _, raw := range []string{"x", "any text, not judged by the policy", strings.Repeat("a", 72)} {
		if err := CheckPresentedPassword(raw); err != nil {
			t.Errorf("CheckPresentedPassword(%d bytes) error = %v, want none", len(raw), err)
		}
	}
}

func TestCheckPresentedPasswordRejectsAnEmptyOrTooLongText(t *testing.T) {
	for _, raw := range []string{"", strings.Repeat("a", 73), strings.Repeat("é", 37)} {
		if err := CheckPresentedPassword(raw); !errors.Is(err, ErrInvalidCurrentPassword) {
			t.Errorf("CheckPresentedPassword(%d bytes) error = %v, want ErrInvalidCurrentPassword", len(raw), err)
		}
	}
}

func TestPasswordChangeRateLimitedErrorIsTooManyAttemptsAndCarriesTheWait(t *testing.T) {
	var err error = &PasswordChangeRateLimitedError{RetryAfter: 90 * time.Second}

	var limited *PasswordChangeRateLimitedError
	if !errors.Is(err, ErrTooManyPasswordChangeAttempts) || !errors.As(err, &limited) || limited.RetryAfter != 90*time.Second {
		t.Errorf("error = %v, want ErrTooManyPasswordChangeAttempts that carries 90s", err)
	}
	if errors.Is(err, ErrTooManyLoginAttempts) {
		t.Error("a locked password change must not be taken for a locked login")
	}
}

func TestTheMessageOfAWrongCurrentPasswordIsTheOneOfTheContract(t *testing.T) {
	if ErrWrongCurrentPassword.Error() != "The current password is incorrect" {
		t.Errorf("message = %q, want the stable discriminator of the contract", ErrWrongCurrentPassword)
	}
}
