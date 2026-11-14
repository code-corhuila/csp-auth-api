package model

import (
	"strings"
	"unicode/utf8"
)

// Limits of the search of users (auth-service contract, GET /users).
const (
	DefaultPage      = 1
	DefaultPageLimit = 20
	MaxPageLimit     = 100
	maxEmailPrefix   = 254
)

// EmailPrefix is the beginning of the email an administrator looks for: 1 to 254 characters,
// compared in lower case because emails are stored in lower case (value object). The zero value
// is "no filter".
type EmailPrefix struct {
	value string
}

// NewEmailPrefix lower-cases raw and rejects an empty or too long text.
func NewEmailPrefix(raw string) (EmailPrefix, error) {
	if raw == "" || utf8.RuneCountInString(raw) > maxEmailPrefix {
		return EmailPrefix{}, ErrInvalidEmailPrefix
	}
	return EmailPrefix{value: strings.ToLower(raw)}, nil
}

func (p EmailPrefix) String() string {
	return p.value
}

// Page is the window of a list a caller asks for (value object): page numbers start at 1 and a
// page has 1 to MaxPageLimit items.
type Page struct {
	number int
	limit  int
}

// NewPage validates a page number and a page size.
func NewPage(number, limit int) (Page, error) {
	if number < 1 {
		return Page{}, ErrInvalidPageNumber
	}
	if limit < 1 || limit > MaxPageLimit {
		return Page{}, ErrInvalidPageLimit
	}
	return Page{number: number, limit: limit}, nil
}

func (p Page) Number() int { return p.number }
func (p Page) Limit() int  { return p.limit }

// Offset is how many items come before the page.
func (p Page) Offset() int { return (p.number - 1) * p.limit }
