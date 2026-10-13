package model

import "errors"

// Typed domain errors. Adapters translate them; the domain never knows how they are shown.
var (
	ErrInvalidUserID          = errors.New("user id must not be empty")
	ErrInvalidEmail           = errors.New("email is not a valid address")
	ErrInvalidPasswordHash    = errors.New("password must be stored as a bcrypt hash")
	ErrInvalidName            = errors.New("name must be between 1 and 100 characters")
	ErrWeakPassword           = errors.New("password must have at least 8 characters, at most 72 bytes, one uppercase letter and one number")
	ErrEmailAlreadyRegistered = errors.New("an account already exists with this email")
	ErrInvalidPhone           = errors.New("phone must be digits with an optional leading + (7 to 15 digits)")
	ErrInvalidAddress         = errors.New("address must be between 1 and 255 characters")
	ErrUnknownRole            = errors.New("role must be CLIENT or ADMIN")
	ErrNoRoles                = errors.New("user must have at least one role")
	ErrUserLocked             = errors.New("user is locked and cannot authenticate")
	ErrUserNotFound           = errors.New("user does not exist")
	ErrInvalidUserStatus      = errors.New("user status must be ACTIVE or LOCKED")
	ErrInvalidCredentials     = errors.New("email or password is incorrect")
	ErrInvalidRefreshToken    = errors.New("refresh token needs an id, an opaque value and a positive lifetime")
	ErrRefreshTokenRejected   = errors.New("refresh token is invalid, expired or already used")
	ErrRefreshTokenNotFound   = errors.New("refresh token does not exist")
	ErrRefreshTokenDuplicated = errors.New("a refresh token with this digest already exists")
	ErrInvalidIdempotencyKey  = errors.New("idempotency key must have between 8 and 128 characters")
	ErrIdempotencyKeyTaken    = errors.New("an idempotency key with this value already exists")
	ErrIdempotencyKeyConflict = errors.New("the idempotency key was already used with a different request")
)
