package model

import "time"

const userRoleChangedType = "UserRoleChanged"

// UserRoleChanged is the domain event raised when an administrator grants or revokes a role and
// the roles of the user really change (ADR-031). It carries ids and the role only.
type UserRoleChanged struct {
	EventID    string
	OccurredAt time.Time
	UserID     string
	Role       string
	Enabled    bool
	ChangedBy  string
}

// NewUserRoleChanged builds the event of userID, identified by eventID and raised at occurredAt by
// the administrator changedBy.
func NewUserRoleChanged(eventID string, occurredAt time.Time, userID string, role Role, enabled bool, changedBy string) UserRoleChanged {
	return UserRoleChanged{EventID: eventID, OccurredAt: occurredAt, UserID: userID, Role: role.String(), Enabled: enabled, ChangedBy: changedBy}
}

// EventType is the name published in the envelope.
func (UserRoleChanged) EventType() string { return userRoleChangedType }

// AggregateID is the id of the user whose role changed.
func (e UserRoleChanged) AggregateID() string { return e.UserID }
