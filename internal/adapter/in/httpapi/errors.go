package httpapi

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// Error codes of the ErrorResponse envelope (_shared.yaml, Annex C).
const (
	codeValidation       = "VALIDATION_ERROR"
	codeEmailRegistered  = "EMAIL_ALREADY_REGISTERED"
	codeIdempotencyReuse = "IDEMPOTENCY_KEY_CONFLICT"
	codeInternal         = "INTERNAL_ERROR"
	codeBadCredentials   = "INVALID_CREDENTIALS"
	codeAccountLocked    = "ACCOUNT_LOCKED"
	codeBadRefreshToken  = "INVALID_REFRESH_TOKEN"
	codeUnauthorized     = "UNAUTHORIZED"
	codeForbidden        = "FORBIDDEN"
	codeNotFound         = "NOT_FOUND"
	codeLastAdmin        = "LAST_ADMIN"
	codeNoRoles          = "USER_WITHOUT_ROLES"
)

// fieldError names one invalid input: a body property or a header.
type fieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// errorResponse is the ErrorResponse schema of _shared.yaml.
type errorResponse struct {
	Error   string       `json:"error"`
	Message string       `json:"message"`
	Details []fieldError `json:"details,omitempty"`
	TraceID string       `json:"traceId"`
}

func writeValidation(w http.ResponseWriter, traceID string, details []fieldError) {
	writeJSON(w, http.StatusBadRequest, errorResponse{
		Error:   codeValidation,
		Message: "the request has invalid fields",
		Details: details,
		TraceID: traceID,
	})
}

// fieldOfDomainError tells which input a domain validation error belongs to.
var fieldOfDomainError = map[error]string{
	model.ErrInvalidIdempotencyKey: headerIdempotencyKey,
	model.ErrInvalidEmail:          "email",
	model.ErrWeakPassword:          "password",
	model.ErrInvalidName:           "name",
	model.ErrInvalidPhone:          "phone",
	model.ErrInvalidAddress:        "address",
}

// translateRegisterError is the only place that maps the errors of the register use case to HTTP.
// Anything it does not know is an internal error: the response is neutral and the cause goes
// only to the log, never to the client.
func translateRegisterError(w http.ResponseWriter, traceID string, err error) {
	for sentinel, field := range fieldOfDomainError {
		if errors.Is(err, sentinel) {
			writeValidation(w, traceID, []fieldError{{Field: field, Message: sentinel.Error()}})
			return
		}
	}
	switch {
	case errors.Is(err, model.ErrEmailAlreadyRegistered):
		writeJSON(w, http.StatusConflict, errorResponse{
			Error: codeEmailRegistered, Message: "the email is already registered", TraceID: traceID,
		})
	case errors.Is(err, model.ErrIdempotencyKeyConflict):
		writeJSON(w, http.StatusConflict, errorResponse{
			Error: codeIdempotencyReuse, Message: "the idempotency key was already used with a different request", TraceID: traceID,
		})
	default:
		slog.Error("register user failed", "traceId", traceID, "error", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{
			Error: codeInternal, Message: "an unexpected error occurred", TraceID: traceID,
		})
	}
}

// translateLoginError is the only place that maps the errors of the login use case to HTTP.
// Every credential failure gets the same fixed response, so the client cannot tell an unknown
// email from a wrong password. The cause of an unexpected error goes only to the log.
func translateLoginError(w http.ResponseWriter, traceID string, err error) {
	switch {
	case errors.Is(err, model.ErrInvalidCredentials):
		writeJSON(w, http.StatusUnauthorized, errorResponse{
			Error: codeBadCredentials, Message: "Incorrect email or password", TraceID: traceID,
		})
	case errors.Is(err, model.ErrUserLocked):
		writeJSON(w, http.StatusLocked, errorResponse{
			Error: codeAccountLocked, Message: "Account temporarily locked after repeated failed attempts", TraceID: traceID,
		})
	default:
		slog.Error("login user failed", "traceId", traceID, "error", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{
			Error: codeInternal, Message: "an unexpected error occurred", TraceID: traceID,
		})
	}
}

// translateRefreshError is the only place that maps the errors of the refresh use case to HTTP.
// A token that is unknown, expired or already used gets one fixed response, so the client cannot
// tell which. The cause of an unexpected error goes only to the log, which never sees the token.
func translateRefreshError(w http.ResponseWriter, traceID string, err error) {
	switch {
	case errors.Is(err, model.ErrRefreshTokenRejected):
		slog.Warn("refresh token rejected", "traceId", traceID)
		writeJSON(w, http.StatusUnauthorized, errorResponse{
			Error: codeBadRefreshToken, Message: "Refresh token is invalid, expired, or already used", TraceID: traceID,
		})
	case errors.Is(err, model.ErrUserLocked):
		writeJSON(w, http.StatusLocked, errorResponse{
			Error: codeAccountLocked, Message: "Account temporarily locked after repeated failed attempts", TraceID: traceID,
		})
	default:
		slog.Error("refresh session failed", "traceId", traceID, "error", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{
			Error: codeInternal, Message: "an unexpected error occurred", TraceID: traceID,
		})
	}
}

// translateChangeRoleError is the only place that maps the errors of the role change use case to
// HTTP. The cause of an unexpected error goes only to the log.
func translateChangeRoleError(w http.ResponseWriter, traceID string, err error) {
	switch {
	case errors.Is(err, model.ErrUnknownRole), errors.Is(err, model.ErrRoleNotChangeable):
		writeValidation(w, traceID, []fieldError{{Field: "role", Message: err.Error()}})
	case errors.Is(err, model.ErrUserNotFound):
		writeJSON(w, http.StatusNotFound, errorResponse{
			Error: codeNotFound, Message: "The requested resource does not exist", TraceID: traceID,
		})
	case errors.Is(err, model.ErrLastAdmin):
		writeJSON(w, http.StatusConflict, errorResponse{
			Error: codeLastAdmin, Message: "The last active administrator cannot lose the ADMIN role", TraceID: traceID,
		})
	case errors.Is(err, model.ErrNoRoles):
		writeJSON(w, http.StatusConflict, errorResponse{
			Error: codeNoRoles, Message: "A user must keep at least one role", TraceID: traceID,
		})
	default:
		slog.Error("change user role failed", "traceId", traceID, "error", err)
		writeInternal(w, traceID)
	}
}

// translateListUsersError is the only place that maps the errors of the list use case to HTTP.
func translateListUsersError(w http.ResponseWriter, traceID string, err error) {
	for sentinel, field := range map[error]string{
		model.ErrInvalidEmailPrefix: "email",
		model.ErrInvalidPageNumber:  "page",
		model.ErrInvalidPageLimit:   "limit",
	} {
		if errors.Is(err, sentinel) {
			writeValidation(w, traceID, []fieldError{{Field: field, Message: sentinel.Error()}})
			return
		}
	}
	slog.Error("list users failed", "traceId", traceID, "error", err)
	writeInternal(w, traceID)
}
