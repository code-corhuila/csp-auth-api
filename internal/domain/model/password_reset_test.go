package model

import (
	"errors"
	"testing"
	"time"
)

func resetToken(t *testing.T) ResetToken {
	t.Helper()
	token, err := NewResetToken(validResetToken)
	if err != nil {
		t.Fatalf("NewResetToken() error = %v", err)
	}
	return token
}

func TestNewPasswordResetLastsOneHourAndKeepsOnlyTheDigest(t *testing.T) {
	reset := NewPasswordReset("reset-1", "user-1", resetToken(t), requestedAt)

	if reset.ID() != "reset-1" || reset.UserID() != "user-1" || reset.TokenHash() != HashOpaqueToken(validResetToken) {
		t.Errorf("reset = %q %q %q, want the values it was created with and the digest", reset.ID(), reset.UserID(), reset.TokenHash())
	}
	if want := requestedAt.Add(time.Hour); !reset.ExpiresAt().Equal(want) || !reset.RequestedAt().Equal(requestedAt) || reset.UsedAt() != nil {
		t.Errorf("ExpiresAt = %v, RequestedAt = %v, UsedAt = %v, want %v, %v and nil", reset.ExpiresAt(), reset.RequestedAt(), reset.UsedAt(), want, requestedAt)
	}
}

func TestRedeemConsumesTheResetBeforeItExpires(t *testing.T) {
	reset := NewPasswordReset("reset-1", "user-1", resetToken(t), requestedAt)
	at := requestedAt.Add(59 * time.Minute)

	err := reset.Redeem(at)

	if err != nil || reset.UsedAt() == nil || !reset.UsedAt().Equal(at) {
		t.Errorf("Redeem() error = %v, UsedAt = %v, want nil and %v", err, reset.UsedAt(), at)
	}
}

func TestRedeemRejectsAnExpiredResetAndLeavesItUnused(t *testing.T) {
	for name, at := range map[string]time.Time{
		"at the expiry instant": requestedAt.Add(time.Hour),
		"after the expiry":      requestedAt.Add(2 * time.Hour),
	} {
		t.Run(name, func(t *testing.T) {
			reset := NewPasswordReset("reset-1", "user-1", resetToken(t), requestedAt)

			err := reset.Redeem(at)

			if !errors.Is(err, ErrPasswordResetRejected) || reset.UsedAt() != nil {
				t.Errorf("Redeem() error = %v, UsedAt = %v, want ErrPasswordResetRejected and unused", err, reset.UsedAt())
			}
		})
	}
}

func TestRedeemRejectsAResetThatWasAlreadyUsed(t *testing.T) {
	usedAt := requestedAt.Add(time.Minute)
	reset := RestorePasswordReset("reset-1", "user-1", resetToken(t).Hash(), requestedAt.Add(time.Hour), &usedAt)

	err := reset.Redeem(requestedAt.Add(2 * time.Minute))

	if !errors.Is(err, ErrPasswordResetRejected) || !reset.UsedAt().Equal(usedAt) {
		t.Errorf("Redeem() error = %v, UsedAt = %v, want ErrPasswordResetRejected and the first use kept", err, reset.UsedAt())
	}
}

func TestPasswordResetRequestsAreLimitedToThreePerWindow(t *testing.T) {
	for count, want := range map[int]bool{0: true, 1: true, 2: true, 3: false, 4: false} {
		if got := PasswordResetRequestAllowed(count); got != want {
			t.Errorf("PasswordResetRequestAllowed(%d) = %v, want %v", count, got, want)
		}
	}
}
