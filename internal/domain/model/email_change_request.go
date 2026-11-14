package model

import "time"

const (
	// EmailChangeCodeLifetime is how long a verification code can be used.
	EmailChangeCodeLifetime = 15 * time.Minute
	// MaxEmailChangeAttempts is the number of wrong codes after which a request is exhausted.
	MaxEmailChangeAttempts = 5
	// MaxEmailChangeRequests is the number of requests a user can make in EmailChangeRequestWindow.
	MaxEmailChangeRequests = 3
	// EmailChangeRequestWindow is the rolling period in which MaxEmailChangeRequests is counted.
	EmailChangeRequestWindow = time.Hour
)

// EmailChangeRequest is a pending change of the email of an account: the address to confirm, the
// code sent to it, its expiry and the wrong codes so far (ADR-034). Its methods keep the invariants:
// a code works only before it expires and while fewer than MaxEmailChangeAttempts were wrong.
type EmailChangeRequest struct {
	id        string
	userID    string
	newEmail  Email
	code      VerificationCode
	expiresAt time.Time
	attempts  int
}

// NewEmailChangeRequest creates the request of userID made at requestedAt.
func NewEmailChangeRequest(id, userID string, newEmail Email, code VerificationCode, requestedAt time.Time) *EmailChangeRequest {
	return &EmailChangeRequest{id: id, userID: userID, newEmail: newEmail, code: code, expiresAt: requestedAt.Add(EmailChangeCodeLifetime)}
}

// RestoreEmailChangeRequest rebuilds a stored request.
func RestoreEmailChangeRequest(id, userID string, newEmail Email, code VerificationCode, expiresAt time.Time, attempts int) *EmailChangeRequest {
	return &EmailChangeRequest{id: id, userID: userID, newEmail: newEmail, code: code, expiresAt: expiresAt, attempts: attempts}
}

func (r *EmailChangeRequest) ID() string { return r.id }

func (r *EmailChangeRequest) UserID() string { return r.userID }

func (r *EmailChangeRequest) NewEmail() Email { return r.newEmail }

func (r *EmailChangeRequest) Code() VerificationCode { return r.code }

func (r *EmailChangeRequest) ExpiresAt() time.Time { return r.expiresAt }

// Attempts is the number of wrong codes submitted so far.
func (r *EmailChangeRequest) Attempts() int { return r.attempts }

// Exhausted reports whether the request used all its wrong codes and can no longer be confirmed.
func (r *EmailChangeRequest) Exhausted() bool { return r.attempts >= MaxEmailChangeAttempts }

// Submit checks the code presented at now. It returns nil when the request can be confirmed,
// ErrVerificationRejected when it is expired or exhausted, and ErrWrongVerificationCode, after
// counting the attempt, when the code does not match.
func (r *EmailChangeRequest) Submit(code VerificationCode, now time.Time) error {
	if r.Exhausted() || !now.Before(r.expiresAt) {
		return ErrVerificationRejected
	}
	if !r.code.Matches(code) {
		r.attempts++
		return ErrWrongVerificationCode
	}
	return nil
}
