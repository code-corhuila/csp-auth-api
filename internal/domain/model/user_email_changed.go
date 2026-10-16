package model

import "time"

const userEmailChangedType = "UserEmailChanged"

// UserEmailChanged is the domain event raised when a user confirms a new email (ADR-034). It
// carries the user and the new address only: never the code, never the old address.
type UserEmailChanged struct {
	EventID    string
	OccurredAt time.Time
	UserID     string
	Email      string
}

// NewUserEmailChanged builds the event of userID, identified by eventID and raised at occurredAt.
func NewUserEmailChanged(eventID string, occurredAt time.Time, userID string, email Email) UserEmailChanged {
	return UserEmailChanged{EventID: eventID, OccurredAt: occurredAt, UserID: userID, Email: email.String()}
}

// EventType is the name published in the envelope.
func (UserEmailChanged) EventType() string { return userEmailChangedType }

// AggregateID is the id of the user whose email changed.
func (e UserEmailChanged) AggregateID() string { return e.UserID }
