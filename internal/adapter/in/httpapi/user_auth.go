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
// contract): the handler runs only for a valid access token, not revoked by a logout, that holds
// permission. A missing, invalid or revoked token is 401 and a valid token without the permission is
// 403. The token is never logged.
func requirePermission(authorizer in.AuthorizeUser, permission string, next callerHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		traceID := correlationID(r)
		w.Header().Set(headerCorrelationID, traceID)
		callerID, err := authorizer.AuthorizeUser(r.Context(), bearerToken(r), permission)
		switch {
		case err == nil:
			next(w, r, callerID)
		case errors.Is(err, model.ErrPermissionDenied):
			writeForbidden(w, traceID)
		default:
			writeAuthenticationError(w, traceID, err)
		}
	}
}

// claimsHandler handles a request whose caller was authenticated; claims are those of its token.
type claimsHandler func(w http.ResponseWriter, r *http.Request, claims model.AccessClaims)

// requireAuthentication protects an operation that any signed-in user may call (bearerAuth without
// x-required-permissions in the contract): the handler runs only for a valid access token, not
// revoked by a logout. A missing, invalid or revoked token is 401. The token is never logged.
func requireAuthentication(authenticator in.AuthenticateUser, next claimsHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		traceID := correlationID(r)
		w.Header().Set(headerCorrelationID, traceID)
		claims, err := authenticator.AuthenticateUser(r.Context(), bearerToken(r))
		if err != nil {
			writeAuthenticationError(w, traceID, err)
			return
		}
		next(w, r, claims)
	}
}

// writeAuthenticationError answers a token that could not be authenticated: 401 when it is missing,
// invalid or revoked, and 500 when the check itself failed. When the list of revoked tokens cannot
// be consulted the route fails closed and the log, at WARN, shows the cause but never the token or
// its jti.
func writeAuthenticationError(w http.ResponseWriter, traceID string, err error) {
	switch {
	case errors.Is(err, model.ErrAccessTokenInvalid):
		writeUnauthorized(w, traceID)
	case errors.Is(err, model.ErrRevokedTokensUnavailable):
		slog.Warn("revoked token list unavailable, request refused", "traceId", traceID, "error", err)
		writeInternal(w, traceID)
	default:
		slog.Error("authenticate user failed", "traceId", traceID, "error", err)
		writeInternal(w, traceID)
	}
}
