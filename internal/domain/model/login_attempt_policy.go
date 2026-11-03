package model

import "time"

// Defaults of the login attempt limit (HU-AUTH-005): 10 failed logins from one client address in 5
// minutes lock that address for 5 minutes.
const (
	DefaultMaxLoginAttempts   = 10
	DefaultLoginAttemptWindow = 5 * time.Minute
	DefaultLoginLock          = 5 * time.Minute
)

// LoginAttemptPolicy says how many failed logins a client address may make inside Window before it
// is locked for Lock. The counting is done by the store behind out.LoginAttempts; the policy only
// holds the rule so that the store and the use case agree on it.
type LoginAttemptPolicy struct {
	MaxAttempts int
	Window      time.Duration
	Lock        time.Duration
}

// NewLoginAttemptPolicy validates the three values: each must be positive.
func NewLoginAttemptPolicy(maxAttempts int, window, lock time.Duration) (LoginAttemptPolicy, error) {
	if maxAttempts < 1 || window <= 0 || lock <= 0 {
		return LoginAttemptPolicy{}, ErrInvalidLoginPolicy
	}
	return LoginAttemptPolicy{MaxAttempts: maxAttempts, Window: window, Lock: lock}, nil
}

// DefaultLoginAttemptPolicy is the policy of the story, 10 failures in 5 minutes and a 5-minute lock.
func DefaultLoginAttemptPolicy() LoginAttemptPolicy {
	return LoginAttemptPolicy{MaxAttempts: DefaultMaxLoginAttempts, Window: DefaultLoginAttemptWindow, Lock: DefaultLoginLock}
}

// Reached reports whether failures failed logins inside the window lock the client.
func (p LoginAttemptPolicy) Reached(failures int) bool {
	return failures >= p.MaxAttempts
}

// LoginRateLimitedError is ErrTooManyLoginAttempts with the time left of the lock, which the HTTP
// adapter answers as Retry-After.
type LoginRateLimitedError struct {
	RetryAfter time.Duration
}

func (e *LoginRateLimitedError) Error() string { return ErrTooManyLoginAttempts.Error() }

// Is makes errors.Is(err, ErrTooManyLoginAttempts) true, so callers that only need the kind of error
// keep working.
func (e *LoginRateLimitedError) Is(target error) bool {
	return target == ErrTooManyLoginAttempts
}
