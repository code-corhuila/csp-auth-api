package model

import (
	"errors"
	"testing"
	"time"
)

func requestsAgo(now time.Time, ages ...time.Duration) []time.Time {
	times := make([]time.Time, len(ages))
	for i, age := range ages {
		times[i] = now.Add(-age)
	}
	return times
}

func TestCheckEmailChangeRateAcceptsFewerThanTheMaximumInTheWindow(t *testing.T) {
	now := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)

	for name, times := range map[string][]time.Time{
		"none": nil,
		"two":  requestsAgo(now, 50*time.Minute, 10*time.Minute),
	} {
		t.Run(name, func(t *testing.T) {
			if err := CheckEmailChangeRate(times, now); err != nil {
				t.Errorf("CheckEmailChangeRate() = %v, want nil", err)
			}
		})
	}
}

func TestCheckEmailChangeRateTellsWhenTheOldestRequestLeavesTheWindow(t *testing.T) {
	now := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	cases := map[string]struct {
		times []time.Time
		want  time.Duration
	}{
		"oldest 40 minutes ago":      {requestsAgo(now, 40*time.Minute, 20*time.Minute, 5*time.Minute), 20 * time.Minute},
		"one second left":            {requestsAgo(now, 59*time.Minute+59*time.Second, 20*time.Minute, 5*time.Minute), time.Second},
		"fractions of a second kept": {requestsAgo(now, 59*time.Minute+59*time.Second+400*time.Millisecond, time.Minute, 0), 600 * time.Millisecond},
		"exactly at the window edge": {requestsAgo(now, time.Hour, 20*time.Minute, 5*time.Minute), 0},
		"more than the maximum":      {requestsAgo(now, 50*time.Minute, 40*time.Minute, 30*time.Minute, 20*time.Minute), 20 * time.Minute},
		"all at the same instant":    {requestsAgo(now, time.Minute, time.Minute, time.Minute), 59 * time.Minute},
		"just created, whole window": {requestsAgo(now, 0, 0, 0), time.Hour},
		"the oldest decides":         {requestsAgo(now, 30*time.Minute, 29*time.Minute, 1*time.Minute), 30 * time.Minute},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := CheckEmailChangeRate(c.times, now)

			var limited *EmailChangeRateLimitedError
			if !errors.Is(err, ErrTooManyEmailChangeRequests) || !errors.As(err, &limited) || limited.RetryAfter != c.want {
				t.Errorf("CheckEmailChangeRate() = %v (%+v), want ErrTooManyEmailChangeRequests with RetryAfter %v", err, limited, c.want)
			}
		})
	}
}
