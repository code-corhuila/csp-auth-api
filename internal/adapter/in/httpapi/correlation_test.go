package httpapi

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("entropy exhausted") }

func TestCorrelationIDFallsBackWithoutPanickingWhenRandomFails(t *testing.T) {
	now := func() time.Time { return time.Unix(0, 42) }
	first := correlationIDFrom(failingReader{}, now)
	second := correlationIDFrom(failingReader{}, now)

	if !strings.HasPrefix(first, "fallback-42-") {
		t.Errorf("id = %q, want the fallback form", first)
	}
	if first == second {
		t.Errorf("fallback ids repeat: %q", first)
	}
	if !isPrintableASCII(first) || len(first) > maxCorrelationIDLen {
		t.Errorf("id %q is not safe to echo", first)
	}
}

func TestCorrelationIDIsAVersion4UUIDWhenRandomWorks(t *testing.T) {
	id := newCorrelationID()
	if len(id) != 36 || id[14] != '4' {
		t.Errorf("id = %q, want a version 4 UUID", id)
	}
}
