package model

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Defaults of the account slowdown (HU-AUTH-005, STRIDE S): after 20 failed logins for one email inside an hour, each
// further failed answer waits one second. The account is never locked, so nobody can lock another person out.
const (
	DefaultAccountSlowAfter = 20
	DefaultAccountWindow    = time.Hour
	DefaultAccountDelay     = time.Second
)

// AccountFailurePolicy says how many failed logins for one email, from any address, are answered at once before every
// further failed one is delayed by Delay. The counting is done by the store behind out.AccountLoginFailures; the policy
// only holds the rule so that the store and the use case agree on it.
type AccountFailurePolicy struct {
	SlowAfter int
	Window    time.Duration
	Delay     time.Duration
}

// NewAccountFailurePolicy validates the three values: each must be positive.
func NewAccountFailurePolicy(slowAfter int, window, delay time.Duration) (AccountFailurePolicy, error) {
	if slowAfter < 1 || window <= 0 || delay <= 0 {
		return AccountFailurePolicy{}, ErrInvalidLoginPolicy
	}
	return AccountFailurePolicy{SlowAfter: slowAfter, Window: window, Delay: delay}, nil
}

// Slows reports whether the failure that made the count reach failures is answered with the delay: the first SlowAfter
// failures are not, the next ones are.
func (p AccountFailurePolicy) Slows(failures int) bool {
	return failures > p.SlowAfter
}

// AccountSubject is what the counter of an account is filed under: the SHA-256 of the normalized email, so that the store
// never holds the email itself and keys have a fixed length.
func AccountSubject(email Email) string {
	sum := sha256.Sum256([]byte(email.String()))
	return hex.EncodeToString(sum[:])
}

// LoginSlowedError is ErrInvalidCredentials plus the time the answer must wait: the account has more failed logins than
// the policy allows. The HTTP adapter waits Delay and then answers the usual bad credentials, so a caller that only needs the
// kind of error keeps working.
type LoginSlowedError struct {
	Delay time.Duration
}

func (e *LoginSlowedError) Error() string { return ErrInvalidCredentials.Error() }

// Is makes errors.Is(err, ErrInvalidCredentials) true.
func (e *LoginSlowedError) Is(target error) bool {
	return target == ErrInvalidCredentials
}
