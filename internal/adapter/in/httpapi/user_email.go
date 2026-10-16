package httpapi

import (
	"net/http"
	"strconv"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// permissionUpdateProfile is the permission of the operations on the own account (x-required-permissions).
const permissionUpdateProfile = "profile:update:self"

// WithEmailChange publishes the two steps of the email change (HU-AUTH-004, ADR-034) at
// PATCH /me/email and POST /me/email/verify, open to the callers whose token holds
// profile:update:self. The account is always the one in the token.
func WithEmailChange(authorizer in.AuthorizeUser, request in.RequestEmailChange, verify in.VerifyEmailChange) Option {
	return func(mux *http.ServeMux) {
		mux.HandleFunc("PATCH "+BasePath+"/me/email",
			requirePermission(authorizer, permissionUpdateProfile, requestEmailChange(request)))
		mux.HandleFunc("POST "+BasePath+"/me/email/verify",
			requirePermission(authorizer, permissionUpdateProfile, verifyEmailChange(verify)))
	}
}

// requestEmailChangeRequest and verifyEmailChangeRequest are the request bodies of requestEmailChange
// and verifyEmailChange in the auth-service contract.
type requestEmailChangeRequest struct {
	Email string `json:"email"`
}

type verifyEmailChangeRequest struct {
	VerificationCode string `json:"verificationCode"`
}

// requestEmailChange answers 202 without a body: the code never travels in the response. The
// Idempotency-Key is only validated, because a repeated request replaces the code (ADR-034).
func requestEmailChange(useCase in.RequestEmailChange) callerHandler {
	return func(w http.ResponseWriter, r *http.Request, callerID string) {
		traceID := w.Header().Get(headerCorrelationID) // set by requirePermission, which wraps this handler
		w.Header().Set("Cache-Control", "no-store")

		body, unreadable := decodeBody[requestEmailChangeRequest](w, r)
		checks := []check{keyCheck(r)}
		if unreadable == nil {
			checks = append(checks, check{"email", errorOf(model.NewEmail(body.Email))})
		}
		if problems := append(problemsOf(checks), unreadable...); len(problems) > 0 {
			writeValidation(w, traceID, problems)
			return
		}

		if err := useCase.RequestChange(r.Context(), in.RequestEmailChangeCommand{UserID: callerID, Email: body.Email}); err != nil {
			translateRequestEmailChangeError(w, traceID, err)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}
}

// verifyEmailChange answers 204. A code that is missing, malformed or not the right one is judged by
// the use case, so that every cause gets the same answer.
func verifyEmailChange(useCase in.VerifyEmailChange) callerHandler {
	return func(w http.ResponseWriter, r *http.Request, callerID string) {
		traceID := w.Header().Get(headerCorrelationID)
		w.Header().Set("Cache-Control", "no-store")

		body, unreadable := decodeBody[verifyEmailChangeRequest](w, r)
		if problems := append(problemsOf([]check{keyCheck(r)}), unreadable...); len(problems) > 0 {
			writeValidation(w, traceID, problems)
			return
		}

		if err := useCase.VerifyChange(r.Context(), in.VerifyEmailChangeCommand{UserID: callerID, VerificationCode: body.VerificationCode}); err != nil {
			translateVerifyEmailChangeError(w, traceID, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func keyCheck(r *http.Request) check {
	return check{headerIdempotencyKey, errorOf(model.NewIdempotencyKey(r.Header.Get(headerIdempotencyKey)))}
}

func problemsOf(checks []check) []fieldError {
	var problems []fieldError
	for _, c := range checks {
		if c.err != nil {
			problems = append(problems, fieldError{Field: c.field, Message: c.err.Error()})
		}
	}
	return problems
}

// retryAfterEmailChange is the Retry-After of a rejected request: the whole rolling window, an upper
// bound of the wait because the oldest request of the window is not known here.
var retryAfterEmailChange = strconv.Itoa(int(model.EmailChangeRequestWindow.Seconds()))
