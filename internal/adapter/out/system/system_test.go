package system

import (
	"regexp"
	"testing"
	"time"
)

func TestUUIDGeneratorCreatesDistinctVersion4Identifiers(t *testing.T) {
	pattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	first, second := UUIDGenerator{}.NewID(), UUIDGenerator{}.NewID()
	if !pattern.MatchString(first) || first == second {
		t.Errorf("ids = %q, %q; want distinct version 4 UUIDs", first, second)
	}
}

func TestClockReturnsCurrentTimeInUTC(t *testing.T) {
	now := Clock{}.Now()
	if now.Location() != time.UTC || time.Since(now) > time.Minute {
		t.Errorf("Now() = %v, want the current time in UTC", now)
	}
}
