package model

import (
	"reflect"
	"testing"
	"time"
)

func TestNewUserRegisteredCarriesOnlyIdentityData(t *testing.T) {
	user := newTestUser(t, RoleClient)
	at := time.Date(2026, 9, 6, 19, 0, 0, 0, time.UTC)

	event := NewUserRegistered("evt-1", at, user)

	if event.EventID != "evt-1" || !event.OccurredAt.Equal(at) {
		t.Errorf("event metadata = %q at %v, want evt-1 at %v", event.EventID, event.OccurredAt, at)
	}
	if event.EventType() != "UserRegistered" {
		t.Errorf("EventType() = %q, want UserRegistered", event.EventType())
	}
	if event.AggregateID() != user.ID() || event.UserID != user.ID() {
		t.Errorf("aggregate and user ids = %q/%q, want %q", event.AggregateID(), event.UserID, user.ID())
	}
	if event.Email != "dev@example.com" {
		t.Errorf("Email = %q, want dev@example.com", event.Email)
	}
	if want := []string{"CLIENT"}; !reflect.DeepEqual(event.Roles, want) {
		t.Errorf("Roles = %v, want %v", event.Roles, want)
	}
}
