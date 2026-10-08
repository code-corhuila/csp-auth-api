package in

import "context"

// RegisterUserCommand is the raw data a prospective client submits. The use case validates it.
type RegisterUserCommand struct {
	Email    string
	Password string
	Name     string
	Phone    string
	Address  string
}

// RegisterUserResult is the public projection of the new account: no phone, no address (ADR-024).
type RegisterUserResult struct {
	UserID string
	Email  string
	Name   string
	Roles  []string
}

// RegisterUser is the use case of HU-AUTH-001: a client creates an account.
type RegisterUser interface {
	Register(ctx context.Context, command RegisterUserCommand) (RegisterUserResult, error)
}
