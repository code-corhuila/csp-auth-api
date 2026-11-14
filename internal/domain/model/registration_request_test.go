package model

import (
	"errors"
	"testing"
	"time"
)

var registrationMoment = time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)

func newTestRegistrationRequest(t *testing.T) *RegistrationRequest {
	t.Helper()
	email, _ := NewEmail("ana@example.com")
	name, _ := NewName("Ana Perez")
	phone, _ := NewPhone("3001234567")
	address, _ := NewAddress("Calle 1")
	token, _ := NewResetToken("123e4567-e89b-42d3-a456-426614174000")
	return NewRegistrationRequest("req-1", email, "$2a$10$hash", name, phone, address, token, registrationMoment)
}

func TestRegistrationRequestExpiresAfterItsLifetimeAndKeepsTheTokenDigest(t *testing.T) {
	request := newTestRegistrationRequest(t)
	token, _ := NewResetToken("123e4567-e89b-42d3-a456-426614174000")
	if request.TokenHash() != token.Hash() {
		t.Fatalf("token hash = %q, want the digest of the token", request.TokenHash())
	}
	if !request.ExpiresAt().Equal(registrationMoment.Add(RegistrationLifetime)) || !request.RequestedAt().Equal(registrationMoment) {
		t.Fatalf("expiry %v, requested %v", request.ExpiresAt(), request.RequestedAt())
	}
}

func TestRegistrationRequestIsRedeemedOnceAndOnlyBeforeItExpires(t *testing.T) {
	request := newTestRegistrationRequest(t)
	if err := request.Redeem(registrationMoment.Add(time.Hour)); err != nil || request.UsedAt() == nil {
		t.Fatalf("first redeem: err %v, used %v", err, request.UsedAt())
	}
	if err := request.Redeem(registrationMoment.Add(2 * time.Hour)); !errors.Is(err, ErrRegistrationRejected) {
		t.Fatalf("second redeem err = %v, want ErrRegistrationRejected", err)
	}
	expired := newTestRegistrationRequest(t)
	if err := expired.Redeem(registrationMoment.Add(RegistrationLifetime)); !errors.Is(err, ErrRegistrationRejected) || expired.UsedAt() != nil {
		t.Fatalf("redeem at expiry err = %v, used %v", err, expired.UsedAt())
	}
}

func TestRegistrationRequestBuildsTheClientAccount(t *testing.T) {
	user, err := newTestRegistrationRequest(t).Account("user-1")
	if err != nil {
		t.Fatalf("Account() error = %v", err)
	}
	if user.ID() != "user-1" || user.Email().String() != "ana@example.com" || !user.HasRole(RoleClient) || user.PasswordHash() != "$2a$10$hash" {
		t.Fatalf("account = %+v", user)
	}
}

func TestRegistrationRequestAllowedStopsAtTheLimit(t *testing.T) {
	for requested, want := range map[int]bool{0: true, MaxRegistrationRequests - 1: true, MaxRegistrationRequests: false, MaxRegistrationRequests + 1: false} {
		if got := RegistrationRequestAllowed(requested); got != want {
			t.Errorf("RegistrationRequestAllowed(%d) = %v, want %v", requested, got, want)
		}
	}
}
