package httpapi

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// callerHandler handles a request whose caller was already authorized; callerID is the user in
// the token.
type callerHandler func(w http.ResponseWriter, r *http.Request, callerID string)

// requirePermission protects an operation of the users (bearerAuth and x-required-permissions in the
// contract): the handler runs only for a valid access token that holds permission. A missing or
// invalid token is 401 and a valid token without the permission is 403. The token is never logged.
func requirePermission(authorizer in.AuthorizeUser, permission string, next callerHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		traceID := correlationID(r)
		w.Header().Set(headerCorrelationID, traceID)
		callerID, err := authorizer.AuthorizeUser(r.Context(), bearerToken(r), permission)
		switch {
		case err == nil:
			next(w, r, callerID)
		case errors.Is(err, model.ErrAccessTokenInvalid):
			writeUnauthorized(w, traceID)
		case errors.Is(err, model.ErrPermissionDenied):
			writeForbidden(w, traceID)
		default:
			slog.Error("authorize user failed", "traceId", traceID, "error", err)
			writeInternal(w, traceID)
		}
	}
}
