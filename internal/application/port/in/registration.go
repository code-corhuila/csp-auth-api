package in

import "context"

// RequestRegistrationCommand is the raw data a prospective client submits. The use case validates it.
// IdempotencyKey is the Idempotency-Key of the request (Norma 5.3.8).
type RequestRegistrationCommand struct {
	IdempotencyKey string
	Email          string
	Password       string
	Name           string
	Phone          string
	Address        string
}

// RequestRegistrationResult identifies the registration request the Idempotency-Key stands for. It is the same shape
// for every address, so it does not tell whether the address already has an account. Replayed is true when the key had
// already been used by this request.
type RequestRegistrationResult struct {
	RequestID string
	Replayed  bool
}

// RequestRegistration is the first step of the registration (issue csp-docs#282, Norma 5.3.8). The answer never tells
// whether the address already has an account: a free address gets a confirmation link, an address with an account gets
// a notice, an address over its limit of requests gets nothing, and the three are the same success. Only a malformed
// input, model.ErrInvalidIdempotencyKey included, a key used for another request, model.ErrIdempotencyKeyConflict, and a
// failure of the service are errors.
type RequestRegistration interface {
	Request(ctx context.Context, command RequestRegistrationCommand) (RequestRegistrationResult, error)
}

// ConfirmRegistrationCommand redeems the Token mailed to the address. IdempotencyKey is the Idempotency-Key of the
// confirmation (Norma 5.3.8); UserAgent identifies the client that asks for the session and may be empty.
type ConfirmRegistrationCommand struct {
	IdempotencyKey string
	Token          string
	UserAgent      string
}

// ConfirmRegistrationResult is the outcome of a confirmation. Session.User is always set (no phone, no address, ADR-024).
// When Replayed is false the account was just created and the session carries its tokens; when Replayed is true the key
// had already confirmed this token, nothing was created and the session carries no tokens, because they are never stored.
type ConfirmRegistrationResult struct {
	Replayed bool
	Session  LoginUserResult
}

// ConfirmRegistration is the second step of the registration (HU-AUTH-001, issue csp-docs#282): the owner of the mailbox
// proves it and the account is created, once per idempotency key. An unknown, expired, used or superseded token is
// model.ErrRegistrationRejected.
type ConfirmRegistration interface {
	Confirm(ctx context.Context, command ConfirmRegistrationCommand) (ConfirmRegistrationResult, error)
}
