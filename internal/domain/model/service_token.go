package model

import (
	"errors"
	"slices"
	"time"
)

// MaxServiceTokenLifetime is the longest lifetime of a service token (ADR-052).
const MaxServiceTokenLifetime = 90 * 24 * time.Hour

// serviceSubjects are the services that may hold a credential issued by this service (ADR-052). A
// closed list: the subject of a service token can never be the id of a user or of an unknown service.
var serviceSubjects = []string{"csp-worker", "booking-service", "csp-workflow"}

var (
	ErrServiceSubjectNotAllowed = errors.New("the subject is not a service that may hold a credential")
	ErrServiceTokenLifetime     = errors.New("the lifetime of a service token must be positive and at most 90 days")
)

// ServiceTokenRequest is the order to issue the credential of one service.
type ServiceTokenRequest struct {
	Subject  string
	Lifetime time.Duration
}

// NewServiceTokenRequest checks that subject is in the closed list and that lifetime is within the limit.
func NewServiceTokenRequest(subject string, lifetime time.Duration) (ServiceTokenRequest, error) {
	if !slices.Contains(serviceSubjects, subject) {
		return ServiceTokenRequest{}, ErrServiceSubjectNotAllowed
	}
	if lifetime <= 0 || lifetime > MaxServiceTokenLifetime {
		return ServiceTokenRequest{}, ErrServiceTokenLifetime
	}
	return ServiceTokenRequest{Subject: subject, Lifetime: lifetime}, nil
}

// IssuedServiceToken is a signed service credential with the data kept in the record of the issuance.
type IssuedServiceToken struct {
	Value     string
	TokenID   string
	ExpiresAt time.Time
}
