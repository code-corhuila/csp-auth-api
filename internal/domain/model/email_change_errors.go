package model

import "errors"

// Typed errors of the email change (ADR-034).
var (
	ErrTooManyEmailChangeRequests = errors.New("too many email change requests in the last hour")
	ErrEmailChangeNotFound        = errors.New("there is no pending email change")
	// ErrVerificationRejected is the one answer for a malformed, unknown, expired, exhausted or
	// wrong code, so the answer does not tell which one it is.
	ErrVerificationRejected = errors.New("the verification code is invalid or expired")
	// ErrWrongVerificationCode is raised inside the domain when a code does not match; the use case
	// turns it into ErrVerificationRejected.
	ErrWrongVerificationCode = errors.New("the verification code does not match")
)
