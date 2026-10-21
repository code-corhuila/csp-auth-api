package model

import (
	"errors"
	"testing"
	"time"
)

func TestNewLoginAttemptPolicyKeepsTheValuesItIsGiven(t *testing.T) {
	policy, err := NewLoginAttemptPolicy(10, 5*time.Minute, 2*time.Minute)

	if err != nil {
		t.Fatalf("NewLoginAttemptPolicy() error = %v", err)
	}
	if policy.MaxAttempts != 10 || policy.Window != 5*time.Minute || policy.Lock != 2*time.Minute {
		t.Errorf("policy = %+v, want 10 attempts, 5m window and 2m lock", policy)
	}
}

func TestNewLoginAttemptPolicyRejectsValuesThatCannotLimitAnything(t *testing.T) {
	cases := map[string]struct {
		max          int
		window, lock time.Duration
	}{
		"no attempts allowed": {0, time.Minute, time.Minute},
		"negative attempts":   {-1, time.Minute, time.Minute},
		"no window":           {10, 0, time.Minute},
		"no lock":             {10, time.Minute, 0},
		"negative lock":       {10, time.Minute, -time.Second},
	}
	for name, c := range cases {
		if _, err := NewLoginAttemptPolicy(c.max, c.window, c.lock); !errors.Is(err, ErrInvalidLoginPolicy) {
			t.Errorf("%s: error = %v, want ErrInvalidLoginPolicy", name, err)
		}
	}
}

func TestDefaultLoginAttemptPolicyIsTenFailuresInFiveMinutesAndAFiveMinuteLock(t *testing.T) {
	policy := DefaultLoginAttemptPolicy()

	if policy.MaxAttempts != 10 || policy.Window != 5*time.Minute || policy.Lock != 5*time.Minute {
		t.Errorf("policy = %+v, want 10 attempts, 5m window and 5m lock", policy)
	}
}

func TestLoginAttemptPolicyLocksOnTheFailureThatReachesTheMaximum(t *testing.T) {
	policy := DefaultLoginAttemptPolicy()

	for failures, want := range map[int]bool{1: false, 9: false, 10: true, 11: true} {
		if got := policy.Reached(failures); got != want {
			t.Errorf("Reached(%d) = %v, want %v", failures, got, want)
		}
	}
}

func TestLoginRateLimitedErrorIsErrTooManyLoginAttemptsAndCarriesTheWait(t *testing.T) {
	var err error = &LoginRateLimitedError{RetryAfter: 90 * time.Second}

	if !errors.Is(err, ErrTooManyLoginAttempts) {
		t.Errorf("errors.Is(err, ErrTooManyLoginAttempts) = false, want true")
	}
	var limited *LoginRateLimitedError
	if !errors.As(err, &limited) || limited.RetryAfter != 90*time.Second {
		t.Errorf("errors.As() = %+v, want the wait of 90s", limited)
	}
}
