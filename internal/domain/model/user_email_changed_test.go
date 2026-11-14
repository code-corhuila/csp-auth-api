package model

import (
	"testing"
	"time"
)

func TestNewUserEmailChangedCarriesTheUserAndTheNewEmailOnly(t *testing.T) {
	email, _ := NewEmail("New@Example.com")
	at := time.Date(2026, 10, 16, 9, 5, 0, 0, time.UTC)

	event := NewUserEmailChanged("event-1", at, "user-1", email)

	if event.EventType() != "UserEmailChanged" || event.AggregateID() != "user-1" {
		t.Errorf("EventType = %q, AggregateID = %q", event.EventType(), event.AggregateID())
	}
	if event.EventID != "event-1" || !event.OccurredAt.Equal(at) || event.UserID != "user-1" || event.Email != "new@example.com" {
		t.Errorf("event = %+v", event)
	}
}
