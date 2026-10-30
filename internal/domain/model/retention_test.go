package model

import (
	"errors"
	"testing"
	"time"
)

func TestNewPurgeBatchSizeAcceptsOneToFiveHundred(t *testing.T) {
	for _, value := range []int{1, DefaultPurgeBatchSize, MaxPurgeBatchSize} {
		got, err := NewPurgeBatchSize(value)
		if err != nil || int(got) != value {
			t.Errorf("NewPurgeBatchSize(%d) = %d, %v, want the value and no error", value, got, err)
		}
	}
}

func TestNewPurgeBatchSizeRejectsTheRestOfTheIntegers(t *testing.T) {
	for _, value := range []int{0, -1, MaxPurgeBatchSize + 1} {
		if _, err := NewPurgeBatchSize(value); !errors.Is(err, ErrInvalidPurgeBatchSize) {
			t.Errorf("NewPurgeBatchSize(%d) error = %v, want ErrInvalidPurgeBatchSize", value, err)
		}
	}
}

func TestDefaultRetentionPolicyIsTheOneOfADR030(t *testing.T) {
	policy := DefaultRetentionPolicy()

	if policy.OutboxEvents != 30*24*time.Hour || policy.RefreshTokens != 30*24*time.Hour || policy.IdempotencyKeys != 7*24*time.Hour ||
		policy.EmailVerifications != 7*24*time.Hour || policy.PasswordResets != 7*24*time.Hour {
		t.Errorf("policy = %+v, want 30 days for the outbox and the refresh tokens and 7 days for the idempotency keys, the email verifications and the password resets", policy)
	}
}
