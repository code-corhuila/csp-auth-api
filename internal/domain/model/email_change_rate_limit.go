package model

import "time"

// EmailChangeRateLimitedError is ErrTooManyEmailChangeRequests with the time left until the user
// can request again: RetryAfter is how long until the oldest request that blocks it leaves the
// rolling window (ADR-034).
type EmailChangeRateLimitedError struct {
	RetryAfter time.Duration
}

func (e *EmailChangeRateLimitedError) Error() string { return ErrTooManyEmailChangeRequests.Error() }

// Is makes errors.Is(err, ErrTooManyEmailChangeRequests) true, so callers that only need the kind of
// error keep working.
func (e *EmailChangeRateLimitedError) Is(target error) bool {
	return target == ErrTooManyEmailChangeRequests
}

// CheckEmailChangeRate decides whether a new request is allowed at now. requestedAt are the instants
// of the requests inside the rolling window, oldest first, superseded ones included. When
// MaxEmailChangeRequests or more exist it returns an *EmailChangeRateLimitedError whose RetryAfter
// is the time until enough of them leave the window to allow one more; a request leaves the window
// EmailChangeRequestWindow after it was made.
func CheckEmailChangeRate(requestedAt []time.Time, now time.Time) error {
	excess := len(requestedAt) - MaxEmailChangeRequests
	if excess < 0 {
		return nil
	}
	retryAfter := requestedAt[excess].Add(EmailChangeRequestWindow).Sub(now)
	return &EmailChangeRateLimitedError{RetryAfter: max(retryAfter, 0)}
}
