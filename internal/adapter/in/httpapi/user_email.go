package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// permissionUpdateProfile is the permission of the operations on the own account (x-required-permissions).
const permissionUpdateProfile = "profile:update:self"

// WithEmailChange publishes the two steps of the email change (HU-AUTH-004, ADR-034) at
// PATCH /me/email and POST /me/email/verify, open to the callers whose token holds
// profile:update:self. The account is always the one in the token. The request step sends mail inside its
// transaction, so gate caps how many of them run at once; the verification sends nothing and is not capped.
func WithEmailChange(authorizer in.AuthorizeUser, request in.RequestEmailChange, verify in.VerifyEmailChange, gate *Bulkhead) Option {
	return func(mux *http.ServeMux) {
		mux.HandleFunc("PATCH "+BasePath+"/me/email",
			requirePermission(authorizer, permissionUpdateProfile, requestEmailChange(request, gate)))
		mux.HandleFunc("POST "+BasePath+"/me/email/verify",
			requirePermission(authorizer, permissionUpdateProfile, verifyEmailChange(verify)))
	}
}

// busyRetryAfterSeconds is the Retry-After of a request the bulkhead refuses: the slots free up in seconds.
const busyRetryAfterSeconds = "1"

// admit takes a slot of gate for the request. When there is none it answers 429 with Retry-After, logs the refusal
// without any data of the request, and tells the caller to stop: the use case is never reached (Bulkhead).
func admit(w http.ResponseWriter, r *http.Request, gate *Bulkhead, traceID, route string) (release func(), admitted bool) {
	release, admitted = gate.Acquire(r.Context())
	if !admitted {
		slog.Warn(route+" refused: no free slot", "traceId", traceID, "limit", gate.Limit(), "wait", gate.Wait().String())
		w.Header().Set("Retry-After", busyRetryAfterSeconds)
		writeJSON(w, http.StatusTooManyRequests, errorResponse{
			Error: codeTooManyRequests, Message: "Too many requests", TraceID: traceID,
		})
	}
	return release, admitted
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
// Idempotency-Key is validated here and stored by the use case, so a replay answers 202 again and sends nothing
// (ADR-034). A request that finds no free slot of gate is refused with 429 before the use case opens a transaction.
func requestEmailChange(useCase in.RequestEmailChange, gate *Bulkhead) callerHandler {
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

		release, admitted := admit(w, r, gate, traceID, "email change request")
		if !admitted {
			return
		}
		defer release()

		if err := useCase.RequestChange(r.Context(), in.RequestEmailChangeCommand{
			UserID: callerID, Email: body.Email, IdempotencyKey: r.Header.Get(headerIdempotencyKey),
		}); err != nil {
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

// retryAfterSeconds is the Retry-After of a request rejected by the limit: the time until the oldest
// blocking request leaves the window, rounded up to whole seconds and never under one. An error that
// carries no wait gets the whole window, the upper bound.
func retryAfterSeconds(err error) string {
	wait := model.EmailChangeRequestWindow
	var limited *model.EmailChangeRateLimitedError
	if errors.As(err, &limited) {
		wait = limited.RetryAfter
	}
	return wholeSeconds(wait)
}

// loginRetryAfterSeconds is the Retry-After of a login rejected by the attempt limit: the time left of
// the lock. An error that carries no wait gets the default lock time, the upper bound.
func loginRetryAfterSeconds(err error) string {
	wait := model.DefaultLoginLock
	var limited *model.LoginRateLimitedError
	if errors.As(err, &limited) {
		wait = limited.RetryAfter
	}
	return wholeSeconds(wait)
}

// wholeSeconds rounds a wait up to whole seconds, never under one: Retry-After is an integer.
func wholeSeconds(wait time.Duration) string {
	seconds := int((wait + time.Second - 1) / time.Second)
	return strconv.Itoa(max(seconds, 1))
}
