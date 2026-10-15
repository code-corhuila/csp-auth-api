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
