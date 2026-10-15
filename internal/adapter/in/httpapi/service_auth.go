package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// bearerPrefix starts the Authorization header of a bearer token; the scheme is case-insensitive (RFC 9110).
const bearerPrefix = "Bearer "

// serviceOnly protects an internal operation (bearerAuth in the contract): the handler runs only
// for a valid service token whose subject is allowed. A missing or invalid token is 401 and a valid
// token of another subject is 403. The token is never logged.
func serviceOnly(authorizer in.AuthorizeService, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		traceID := correlationID(r)
		w.Header().Set(headerCorrelationID, traceID)
		var token string
		if header := r.Header.Get("Authorization"); len(header) >= len(bearerPrefix) && strings.EqualFold(header[:len(bearerPrefix)], bearerPrefix) {
			token = header[len(bearerPrefix):]
		}
		switch err := authorizer.AuthorizeService(r.Context(), token); {
		case err == nil:
			next(w, r)
		case errors.Is(err, model.ErrServiceTokenInvalid):
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized, errorResponse{
				Error: codeUnauthorized, Message: "Authentication token required", TraceID: traceID,
			})
		case errors.Is(err, model.ErrServiceNotAllowed):
			writeJSON(w, http.StatusForbidden, errorResponse{
				Error: codeForbidden, Message: "You are not authorized to perform this action", TraceID: traceID,
			})
		default:
			slog.Error("authorize service failed", "traceId", traceID, "error", err)
			writeJSON(w, http.StatusInternalServerError, errorResponse{
				Error: codeInternal, Message: "an unexpected error occurred", TraceID: traceID,
			})
		}
	}
}
