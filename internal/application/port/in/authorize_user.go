package in

import "context"

// AuthorizeUser decides whether the caller of a protected operation holds the permission it needs
// (Norma 5.3.7: each service validates the access token itself).
type AuthorizeUser interface {
	// AuthorizeUser takes the bearer token of the request and returns the id of the user it
	// identifies. A missing or invalid token is model.ErrAccessTokenInvalid; a valid token without
	// permission is model.ErrPermissionDenied.
	AuthorizeUser(ctx context.Context, bearerToken, permission string) (userID string, err error)
}
