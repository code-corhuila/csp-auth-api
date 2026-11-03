package in

import "context"

// AuthorizeService decides whether the caller of an internal operation is a service allowed to
// make it (ADR-020).
type AuthorizeService interface {
	// AuthorizeService takes the bearer token of the request. A missing or invalid token is
	// model.ErrServiceTokenInvalid; a valid token of a subject that is not allowed is
	// model.ErrServiceNotAllowed.
	AuthorizeService(ctx context.Context, bearerToken string) error
}
