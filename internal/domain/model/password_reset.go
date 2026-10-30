package model

import (
	"errors"
	"time"
)

const (
	// PasswordResetLifetime is how long a reset token can be used.
	PasswordResetLifetime = time.Hour
	// MaxPasswordResetRequests is the number of requests a user can make in PasswordResetRequestWindow.
	MaxPasswordResetRequests = 3
	// PasswordResetRequestWindow is the rolling period in which MaxPasswordResetRequests is counted.
	PasswordResetRequestWindow = time.Hour
)

// ErrPasswordResetRejected is the one answer for an unknown, expired, used or superseded reset token,
// and for an account that is no longer active, so the answer does not tell which one it is.
var ErrPasswordResetRejected = errors.New("the reset token is invalid or expired")

// ErrPasswordUnchanged is a reset to the password the account already has (ADR-050, amendment 2026-10-24). Its text
// is the message of the validation error, which clients may rely on.
var ErrPasswordUnchanged = errors.New("The new password must differ from the current one")

// PasswordReset is a request to choose a new password: the digest of the token sent to the user, its
// expiry and its use (ADR-050). Its methods keep the invariants: a token works once and only before it
// expires.
type PasswordReset struct {
	id        string
	userID    string
	tokenHash string
	expiresAt time.Time
	usedAt    *time.Time
}

// NewPasswordReset creates the request of userID made at requestedAt, for the token sent to them.
func NewPasswordReset(id, userID string, token ResetToken, requestedAt time.Time) *PasswordReset {
	return &PasswordReset{id: id, userID: userID, tokenHash: token.Hash(), expiresAt: requestedAt.Add(PasswordResetLifetime)}
}

// RestorePasswordReset rebuilds a stored request.
func RestorePasswordReset(id, userID, tokenHash string, expiresAt time.Time, usedAt *time.Time) *PasswordReset {
	return &PasswordReset{id: id, userID: userID, tokenHash: tokenHash, expiresAt: expiresAt, usedAt: usedAt}
}

func (r *PasswordReset) ID() string { return r.id }

func (r *PasswordReset) UserID() string { return r.userID }

func (r *PasswordReset) TokenHash() string { return r.tokenHash }

func (r *PasswordReset) ExpiresAt() time.Time { return r.expiresAt }

// RequestedAt is the instant of the request, PasswordResetLifetime before the expiry.
func (r *PasswordReset) RequestedAt() time.Time { return r.expiresAt.Add(-PasswordResetLifetime) }

// UsedAt returns the instant the token was consumed, or nil while it is unused.
func (r *PasswordReset) UsedAt() *time.Time { return r.usedAt }

// EnsureRedeemable tells, without consuming it, whether the token can be used at now. An expired or already
// used token is ErrPasswordResetRejected.
func (r *PasswordReset) EnsureRedeemable(now time.Time) error {
	if r.usedAt != nil || !now.Before(r.expiresAt) {
		return ErrPasswordResetRejected
	}
	return nil
}

// Redeem consumes the token at now. An expired or already used token is ErrPasswordResetRejected
// and stays as it was.
func (r *PasswordReset) Redeem(now time.Time) error {
	if err := r.EnsureRedeemable(now); err != nil {
		return err
	}
	r.usedAt = &now
	return nil
}

// PasswordResetRequestAllowed tells whether a user who made requested requests inside the rolling
// window, superseded ones included, may make another.
func PasswordResetRequestAllowed(requested int) bool {
	return requested < MaxPasswordResetRequests
}
