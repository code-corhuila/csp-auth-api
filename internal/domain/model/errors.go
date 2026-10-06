package model

import "errors"

// Typed domain errors. Adapters translate them; the domain never knows how they are shown.
var (
	ErrInvalidUserID       = errors.New("user id must not be empty")
	ErrInvalidEmail        = errors.New("email is not a valid address")
	ErrInvalidPasswordHash = errors.New("password must be stored as a bcrypt hash")
	ErrUnknownRole         = errors.New("role must be CLIENT or ADMIN")
	ErrNoRoles             = errors.New("user must have at least one role")
	ErrUserLocked          = errors.New("user is locked and cannot authenticate")
)
