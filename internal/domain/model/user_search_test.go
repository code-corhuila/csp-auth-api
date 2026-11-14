package model

import (
	"errors"
	"strings"
	"testing"
)

func TestNewEmailPrefixLowerCasesAndBoundsTheText(t *testing.T) {
	prefix, err := NewEmailPrefix("Maria.Garcia@Exa")
	if err != nil || prefix.String() != "maria.garcia@exa" {
		t.Errorf("NewEmailPrefix() = %q, %v, want the lower-case text", prefix, err)
	}
	if _, err := NewEmailPrefix(strings.Repeat("a", 254)); err != nil {
		t.Errorf("254 characters: error = %v, want nil", err)
	}
	for name, raw := range map[string]string{"empty": "", "too long": strings.Repeat("a", 255)} {
		if _, err := NewEmailPrefix(raw); !errors.Is(err, ErrInvalidEmailPrefix) {
			t.Errorf("%s: error = %v, want ErrInvalidEmailPrefix", name, err)
		}
	}
}

func TestNewPageAcceptsTheBoundsOfTheContract(t *testing.T) {
	page, err := NewPage(3, 20)
	if err != nil || page.Number() != 3 || page.Limit() != 20 || page.Offset() != 40 {
		t.Errorf("NewPage(3, 20) = %+v, %v, want page 3, limit 20, offset 40", page, err)
	}
	for _, limit := range []int{1, 100} {
		if _, err := NewPage(1, limit); err != nil {
			t.Errorf("limit %d: error = %v, want nil", limit, err)
		}
	}
}

func TestNewPageRejectsWhatTheContractRejects(t *testing.T) {
	cases := map[string]struct {
		number, limit int
		want          error
	}{
		"page zero":     {0, 20, ErrInvalidPageNumber},
		"negative page": {-1, 20, ErrInvalidPageNumber},
		"limit zero":    {1, 0, ErrInvalidPageLimit},
		"limit above":   {1, 101, ErrInvalidPageLimit},
	}
	for name, c := range cases {
		if _, err := NewPage(c.number, c.limit); !errors.Is(err, c.want) {
			t.Errorf("%s: error = %v, want %v", name, err, c.want)
		}
	}
}
