package model

import (
	"errors"
	"time"
)

// Defaults of the limit of the wrong current passwords (HU-AUTH-007, ADR-051): 5 of them from one user in 15 minutes lock
// the change of the password of that user for 15 minutes.
const (
	DefaultMaxPasswordChangeAttempts = 5
	DefaultPasswordChangeWindow      = 15 * time.Minute
	DefaultPasswordChangeLock        = 15 * time.Minute
)

var (
	// ErrWrongCurrentPassword is a change of password whose current password does not match. Its text is the message of the
	// validation error, which clients rely on to tell it from the other errors of the route.
	ErrWrongCurrentPassword = errors.New("The current password is incorrect")
	// ErrInvalidCurrentPassword is a current password that cannot be a password: empty, or longer than bcrypt reads.
	ErrInvalidCurrentPassword = errors.New("current password must have between 1 and 72 bytes")
	// ErrTooManyPasswordChangeAttempts is the lock after too many wrong current passwords of one user.
	ErrTooManyPasswordChangeAttempts = errors.New("too many wrong current passwords for this account")
)

// DefaultPasswordChangePolicy is the rule of the story, 5 failures in 15 minutes and a 15-minute lock. It has the shape of
// the login attempt policy and the same counting, but its subject is a user, not a client address.
func DefaultPasswordChangePolicy() LoginAttemptPolicy {
	return LoginAttemptPolicy{
		MaxAttempts: DefaultMaxPasswordChangeAttempts, Window: DefaultPasswordChangeWindow, Lock: DefaultPasswordChangeLock,
	}
}

// CheckPresentedPassword tells whether raw can be the password a user presents to prove who they are: from 1 to 72 bytes.
// Its content is not judged by the password policy, because a presented password is not chosen. A text that fails is not
// a wrong guess: it never reaches the comparison and does not count against the limit.
func CheckPresentedPassword(raw string) error {
	if raw == "" || len(raw) > maxPasswordBytes {
		return ErrInvalidCurrentPassword
	}
	return nil
}

// PasswordChangeRateLimitedError is ErrTooManyPasswordChangeAttempts with the time left of the lock, which the HTTP adapter
// answers as Retry-After.
type PasswordChangeRateLimitedError struct {
	RetryAfter time.Duration
}

func (e *PasswordChangeRateLimitedError) Error() string {
	return ErrTooManyPasswordChangeAttempts.Error()
}

// Is makes errors.Is(err, ErrTooManyPasswordChangeAttempts) true.
func (e *PasswordChangeRateLimitedError) Is(target error) bool {
	return target == ErrTooManyPasswordChangeAttempts
}
