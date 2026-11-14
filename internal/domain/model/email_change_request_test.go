package model

import (
	"errors"
	"testing"
	"time"
)

var requestedAt = time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)

func pendingRequest(t *testing.T, code string) *EmailChangeRequest {
	t.Helper()
	email, err := NewEmail("New.Address@Example.com")
	if err != nil {
		t.Fatalf("NewEmail() error = %v", err)
	}
	parsed, err := NewVerificationCode(code)
	if err != nil {
		t.Fatalf("NewVerificationCode() error = %v", err)
	}
	return NewEmailChangeRequest("request-1", "user-1", email, parsed, requestedAt)
}

func submitted(t *testing.T, code string) VerificationCode {
	t.Helper()
	parsed, err := NewVerificationCode(code)
	if err != nil {
		t.Fatalf("NewVerificationCode() error = %v", err)
	}
	return parsed
}

func TestNewEmailChangeRequestExpiresFifteenMinutesAfterTheRequestWithNoAttempts(t *testing.T) {
	request := pendingRequest(t, "012345")

	if request.ID() != "request-1" || request.UserID() != "user-1" || request.NewEmail().String() != "new.address@example.com" || request.Code().String() != "012345" {
		t.Errorf("request = %q %q %q %q, want the values it was created with", request.ID(), request.UserID(), request.NewEmail(), request.Code())
	}
	if want := requestedAt.Add(15 * time.Minute); !request.ExpiresAt().Equal(want) || request.Attempts() != 0 {
		t.Errorf("ExpiresAt = %v, Attempts = %d, want %v and 0", request.ExpiresAt(), request.Attempts(), want)
	}
}

func TestSubmitAcceptsTheRightCodeBeforeItExpires(t *testing.T) {
	request := pendingRequest(t, "123456")

	if err := request.Submit(submitted(t, "123456"), requestedAt.Add(14*time.Minute+59*time.Second)); err != nil {
		t.Errorf("Submit() error = %v, want nil", err)
	}
}

func TestSubmitRejectsAnExpiredRequestEvenWithTheRightCodeAndCountsNoAttempt(t *testing.T) {
	request := pendingRequest(t, "123456")

	err := request.Submit(submitted(t, "123456"), requestedAt.Add(15*time.Minute))

	if !errors.Is(err, ErrVerificationRejected) || request.Attempts() != 0 {
		t.Errorf("error = %v, attempts = %d, want ErrVerificationRejected and 0", err, request.Attempts())
	}
}

func TestSubmitCountsEachWrongCodeAndSaysSo(t *testing.T) {
	request := pendingRequest(t, "123456")

	err := request.Submit(submitted(t, "654321"), requestedAt)

	if !errors.Is(err, ErrWrongVerificationCode) || request.Attempts() != 1 || request.Exhausted() {
		t.Errorf("error = %v, attempts = %d, exhausted = %v, want ErrWrongVerificationCode, 1, false", err, request.Attempts(), request.Exhausted())
	}
}

func TestTheFifthWrongCodeExhaustsTheRequestAndNothingMoreIsAccepted(t *testing.T) {
	request := pendingRequest(t, "123456")
	for i := 0; i < 5; i++ {
		_ = request.Submit(submitted(t, "000000"), requestedAt)
	}

	err := request.Submit(submitted(t, "123456"), requestedAt)

	if !request.Exhausted() || request.Attempts() != 5 || !errors.Is(err, ErrVerificationRejected) {
		t.Errorf("exhausted = %v, attempts = %d, error = %v, want true, 5, ErrVerificationRejected", request.Exhausted(), request.Attempts(), err)
	}
}

func TestRestoreEmailChangeRequestKeepsTheStoredState(t *testing.T) {
	email, _ := NewEmail("a@example.com")
	expires := requestedAt.Add(time.Minute)

	request := RestoreEmailChangeRequest("r", "u", email, submitted(t, "111111"), expires, 3)

	if request.Attempts() != 3 || !request.ExpiresAt().Equal(expires) || request.Exhausted() {
		t.Errorf("attempts = %d, expiresAt = %v, exhausted = %v", request.Attempts(), request.ExpiresAt(), request.Exhausted())
	}
}
