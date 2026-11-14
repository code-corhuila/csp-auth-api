package model

import (
	"errors"
	"time"
)

const (
	// RegistrationLifetime is how long the confirmation token of a registration can be used.
	RegistrationLifetime = 24 * time.Hour
	// MaxRegistrationRequests is the number of registration requests one address can make in RegistrationRequestWindow.
	MaxRegistrationRequests = 3
	// RegistrationRequestWindow is the rolling period in which MaxRegistrationRequests is counted.
	RegistrationRequestWindow = time.Hour
)

// ErrRegistrationRejected is the one answer for an unknown, expired, used or superseded confirmation token, so the answer
// does not tell which one it is.
var ErrRegistrationRejected = errors.New("the registration token is invalid or expired")

// RegistrationRequest is a registration waiting for its owner to confirm the address: the data the client sent, the
// bcrypt hash of the password, and the digest and expiry of the token mailed to the address (issue csp-docs#282). The
// account exists only once the token is redeemed, so a registration for an address that is not the requester's creates
// nothing that can be signed in to.
type RegistrationRequest struct {
	id           string
	email        Email
	passwordHash string
	name         Name
	phone        Phone
	address      Address
	tokenHash    string
	expiresAt    time.Time
	usedAt       *time.Time
}

// NewRegistrationRequest creates the request made at requestedAt for the token mailed to the address.
func NewRegistrationRequest(id string, email Email, passwordHash string, name Name, phone Phone, address Address, token ResetToken, requestedAt time.Time) *RegistrationRequest {
	return &RegistrationRequest{
		id: id, email: email, passwordHash: passwordHash, name: name, phone: phone, address: address,
		tokenHash: token.Hash(), expiresAt: requestedAt.Add(RegistrationLifetime),
	}
}

// RestoreRegistrationRequest rebuilds a stored request.
func RestoreRegistrationRequest(id string, email Email, passwordHash string, name Name, phone Phone, address Address, tokenHash string, expiresAt time.Time, usedAt *time.Time) *RegistrationRequest {
	return &RegistrationRequest{
		id: id, email: email, passwordHash: passwordHash, name: name, phone: phone, address: address,
		tokenHash: tokenHash, expiresAt: expiresAt, usedAt: usedAt,
	}
}

func (r *RegistrationRequest) ID() string { return r.id }

func (r *RegistrationRequest) Email() Email { return r.email }

func (r *RegistrationRequest) PasswordHash() string { return r.passwordHash }

func (r *RegistrationRequest) Name() Name { return r.name }

func (r *RegistrationRequest) Phone() Phone { return r.phone }

func (r *RegistrationRequest) Address() Address { return r.address }

func (r *RegistrationRequest) TokenHash() string { return r.tokenHash }

func (r *RegistrationRequest) ExpiresAt() time.Time { return r.expiresAt }

// RequestedAt is the instant of the request, RegistrationLifetime before the expiry.
func (r *RegistrationRequest) RequestedAt() time.Time { return r.expiresAt.Add(-RegistrationLifetime) }

// UsedAt returns the instant the token was consumed, or nil while it is unused.
func (r *RegistrationRequest) UsedAt() *time.Time { return r.usedAt }

// Redeem consumes the token at now. An expired or already used token is ErrRegistrationRejected and stays as it was.
func (r *RegistrationRequest) Redeem(now time.Time) error {
	if r.usedAt != nil || !now.Before(r.expiresAt) {
		return ErrRegistrationRejected
	}
	r.usedAt = &now
	return nil
}

// Account is the CLIENT account the confirmed request creates, with the given id.
func (r *RegistrationRequest) Account(userID string) (*User, error) {
	return NewUser(userID, r.name, r.email, r.passwordHash, r.phone, r.address, []Role{RoleClient})
}

// RegistrationRequestAllowed tells whether an address that received requested requests inside the rolling window,
// superseded ones and ones that created nothing included, may receive another.
func RegistrationRequestAllowed(requested int) bool {
	return requested < MaxRegistrationRequests
}
