package in

import "context"

// RegisterUserCommand is the raw data a prospective client submits. The use case validates it.
// IdempotencyKey is the Idempotency-Key of the request (Norma 5.3.8); UserAgent identifies the
// client that asks for the session and may be empty.
type RegisterUserCommand struct {
	IdempotencyKey string
	Email          string
	Password       string
	Name           string
	Phone          string
	Address        string
	UserAgent      string
}

// RegisterUserResult is the outcome of a registration. Session.User is always set (no phone, no
// address, ADR-024). When Replayed is false the account was just created and the session carries
// its tokens; when Replayed is true the key had already registered this request, nothing was
// created and the session carries no tokens, because they are never stored.
type RegisterUserResult struct {
	Replayed bool
	Session  LoginUserResult
}

// RegisterUser is the use case of HU-AUTH-001: a client creates an account, once per idempotency key.
type RegisterUser interface {
	Register(ctx context.Context, command RegisterUserCommand) (RegisterUserResult, error)
}
