package httpapi

import (
	"context"
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
		switch err := authorizer.AuthorizeService(r.Context(), bearerToken(r)); {
		case err == nil:
			next(w, r)
		case errors.Is(err, model.ErrServiceTokenInvalid):
			writeUnauthorized(w, traceID)
		case errors.Is(err, model.ErrServiceNotAllowed):
			writeForbidden(w, traceID)
		default:
			slog.Error("authorize service failed", "traceId", traceID, "error", err)
			writeInternal(w, traceID, err)
		}
	}
}

// bearerToken returns the token of the Authorization header, or "" when there is none.
func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if len(header) >= len(bearerPrefix) && strings.EqualFold(header[:len(bearerPrefix)], bearerPrefix) {
		return header[len(bearerPrefix):]
	}
	return ""
}

func writeUnauthorized(w http.ResponseWriter, traceID string) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeJSON(w, http.StatusUnauthorized, errorResponse{
		Error: codeUnauthorized, Message: "Authentication token required", TraceID: traceID,
	})
}

func writeForbidden(w http.ResponseWriter, traceID string) {
	writeJSON(w, http.StatusForbidden, errorResponse{
		Error: codeForbidden, Message: "You are not authorized to perform this action", TraceID: traceID,
	})
}

// writeHasherBusy answers a request that the bound on concurrent password hashes refused (model.ErrPasswordHasherBusy): a 503
// SERVICE_UNAVAILABLE that the client may retry at once, and one WARN with the trace id that carries no email, address or password.
func writeHasherBusy(w http.ResponseWriter, traceID string) {
	slog.Warn("password hashing refused: too many hashes at once", "traceId", traceID)
	w.Header().Set("Retry-After", busyRetryAfterSeconds)
	writeJSON(w, http.StatusServiceUnavailable, errorResponse{
		Error: codeServiceUnavailable, Message: "A required service or dependency is unavailable", TraceID: traceID,
	})
}

// writeInternal answers an unexpected failure. A request that ran out of its deadline (Limits.RequestTimeout), as one that
// waited too long for a database connection, is a 503 SERVICE_UNAVAILABLE that the client may retry; anything else is a
// 500 INTERNAL_ERROR. The cause only goes to the log.
func writeInternal(w http.ResponseWriter, traceID string, err error) {
	if errors.Is(err, context.DeadlineExceeded) {
		w.Header().Set("Retry-After", busyRetryAfterSeconds)
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{
			Error: codeServiceUnavailable, Message: "A required service or dependency is unavailable", TraceID: traceID,
		})
		return
	}
	writeJSON(w, http.StatusInternalServerError, errorResponse{
		Error: codeInternal, Message: "an unexpected error occurred", TraceID: traceID,
	})
}
