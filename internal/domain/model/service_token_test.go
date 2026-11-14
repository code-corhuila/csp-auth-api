package model

import (
	"errors"
	"testing"
	"time"
)

func TestNewServiceTokenRequestAcceptsTheServicesOfTheAllowList(t *testing.T) {
	for _, subject := range []string{"csp-worker", "booking-service", "csp-workflow"} {
		request, err := NewServiceTokenRequest(subject, 24*time.Hour)
		if err != nil || request.Subject != subject || request.Lifetime != 24*time.Hour {
			t.Errorf("NewServiceTokenRequest(%q) = %+v, %v; want the request", subject, request, err)
		}
	}
}

func TestNewServiceTokenRequestRefusesASubjectOutsideTheAllowList(t *testing.T) {
	for _, subject := range []string{"", "catalog-service", "CSP-WORKER", " csp-worker", "550e8400-e29b-41d4-a716-446655440000"} {
		if _, err := NewServiceTokenRequest(subject, time.Hour); !errors.Is(err, ErrServiceSubjectNotAllowed) {
			t.Errorf("NewServiceTokenRequest(%q) error = %v, want ErrServiceSubjectNotAllowed", subject, err)
		}
	}
}

func TestNewServiceTokenRequestBoundsTheLifetime(t *testing.T) {
	if _, err := NewServiceTokenRequest("csp-worker", MaxServiceTokenLifetime); err != nil {
		t.Errorf("the longest lifetime error = %v, want none", err)
	}
	for _, lifetime := range []time.Duration{0, -time.Hour, MaxServiceTokenLifetime + time.Second} {
		if _, err := NewServiceTokenRequest("csp-worker", lifetime); !errors.Is(err, ErrServiceTokenLifetime) {
			t.Errorf("NewServiceTokenRequest(lifetime %v) error = %v, want ErrServiceTokenLifetime", lifetime, err)
		}
	}
}
