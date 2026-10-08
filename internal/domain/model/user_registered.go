package model

import "time"

const userRegisteredType = "UserRegistered"

// UserRegistered is the domain event raised when an account is created. It carries identity
// data only: never the password, the phone or the address (ADR-024).
type UserRegistered struct {
	EventID    string
	OccurredAt time.Time
	UserID     string
	Email      string
	Roles      []string
}

// NewUserRegistered builds the event of user, identified by eventID and raised at occurredAt.
func NewUserRegistered(eventID string, occurredAt time.Time, user *User) UserRegistered {
	roles := make([]string, 0, len(user.roles))
	for _, role := range user.roles {
		roles = append(roles, role.String())
	}
	return UserRegistered{EventID: eventID, OccurredAt: occurredAt, UserID: user.id, Email: user.email.String(), Roles: roles}
}

// EventType is the name published in the envelope.
func (UserRegistered) EventType() string { return userRegisteredType }

// AggregateID is the id of the user the event is about.
func (e UserRegistered) AggregateID() string { return e.UserID }
