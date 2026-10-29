package httpapi

import (
	"net/http"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// WithPasswordReset publishes the two steps of the password reset (HU-AUTH-006, ADR-050) at POST /forgot-password and
// POST /reset-password, public. Only forgot-password takes an Idempotency-Key (Norma 5.3.8): reset-password creates nothing. Each route has its own gate: forgotGate caps the requests
// that reach the database and resetGate the ones that also hash a password, so a flood of one cannot starve the other.
func WithPasswordReset(request in.RequestPasswordReset, reset in.ResetPassword, forgotGate, resetGate *Bulkhead) Option {
	return func(mux *http.ServeMux) {
		mux.HandleFunc("POST "+BasePath+"/forgot-password", forgotPassword(request, forgotGate))
		mux.HandleFunc("POST "+BasePath+"/reset-password", resetPassword(reset, resetGate))
	}
}

// WithPasswordResetNotEnabled answers the 404 of the contract at the two routes of the password reset, for a service
// that has no SMTP relay or no link configured.
func WithPasswordResetNotEnabled() Option {
	return func(mux *http.ServeMux) {
		for _, route := range []string{"/forgot-password", "/reset-password"} {
			mux.HandleFunc("POST "+BasePath+route, func(w http.ResponseWriter, r *http.Request) {
				traceID := correlationID(r)
				w.Header().Set(headerCorrelationID, traceID)
				writeJSON(w, http.StatusNotFound, errorResponse{
					Error: codeNotFound, Message: "The requested resource does not exist", TraceID: traceID,
				})
			})
		}
	}
}

// forgotPasswordRequest and resetPasswordRequest are the request bodies of requestPasswordReset and resetPassword in
// the auth-service contract.
type forgotPasswordRequest struct {
	Email string `json:"email"`
}

type resetPasswordRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

// forgotPassword answers 202 without a body whatever the account is, and also for a replay of its Idempotency-Key: the
// use case judges nothing the client could tell apart. The key is required and validated like the email, before the gate.
// A request that finds no free slot of gate is refused with 429 before the use case runs, which does not depend on the
// email.
func forgotPassword(useCase in.RequestPasswordReset, gate *Bulkhead) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		traceID := correlationID(r)
		w.Header().Set(headerCorrelationID, traceID)
		w.Header().Set("Cache-Control", "no-store")

		body, unreadable := decodeBodyWithin[forgotPasswordRequest](w, r, limitsOf(r.Context()).PasswordResetMaxBodyBytes)
		key := r.Header.Get(headerIdempotencyKey)
		checks := []check{{headerIdempotencyKey, errorOf(model.NewIdempotencyKey(key))}}
		if unreadable == nil {
			checks = append(checks, check{"email", errorOf(model.NewEmail(body.Email))})
		}
		if problems := append(problemsOf(checks), unreadable...); len(problems) > 0 {
			writeValidation(w, traceID, problems)
			return
		}

		release, admitted := admit(w, r, gate, traceID, "forgot password request")
		if !admitted {
			return
		}
		defer release()

		if err := useCase.RequestReset(r.Context(), in.RequestPasswordResetCommand{IdempotencyKey: key, Email: body.Email}); err != nil {
			translateRequestPasswordResetError(w, traceID, err)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}
}

// resetPassword answers 204. The token and the password are validated before the gate and the use case, so a
// malformed one costs nothing and a weak password does not consume the token.
func resetPassword(useCase in.ResetPassword, gate *Bulkhead) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		traceID := correlationID(r)
		w.Header().Set(headerCorrelationID, traceID)
		w.Header().Set("Cache-Control", "no-store")

		body, unreadable := decodeBodyWithin[resetPasswordRequest](w, r, limitsOf(r.Context()).PasswordResetMaxBodyBytes)
		var checks []check
		if unreadable == nil {
			checks = append(checks,
				check{"token", errorOf(model.NewResetToken(body.Token))},
				check{"password", errorOf(model.NewPassword(body.Password))})
		}
		if problems := append(problemsOf(checks), unreadable...); len(problems) > 0 {
			writeValidation(w, traceID, problems)
			return
		}

		release, admitted := admit(w, r, gate, traceID, "reset password request")
		if !admitted {
			return
		}
		defer release()

		if err := useCase.Reset(r.Context(), in.ResetPasswordCommand{Token: body.Token, Password: body.Password}); err != nil {
			translateResetPasswordError(w, traceID, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
