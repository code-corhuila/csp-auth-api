package httpapi

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// WithPasswordChange publishes the change of the own password (HU-AUTH-007, ADR-051) at POST /me/password, open to the
// callers whose token holds profile:update:self. The account is always the one in the token and the route takes no
// Idempotency-Key. The route hashes with bcrypt, so gate caps how many requests run at once: one that finds no free slot
// is refused with 429 before the use case opens a transaction.
func WithPasswordChange(authorizer in.AuthorizeUser, useCase in.ChangePassword, gate *Bulkhead) Option {
	return func(mux *http.ServeMux) {
		mux.HandleFunc("POST "+BasePath+"/me/password",
			requirePermission(authorizer, permissionUpdateProfile, changePassword(useCase, gate)))
	}
}

// changePassword answers 200 with the AuthResponse of the new session. The two passwords are validated before the gate and
// the use case, so a malformed body costs nothing and is not a guess of the current password.
func changePassword(useCase in.ChangePassword, gate *Bulkhead) callerHandler {
	return func(w http.ResponseWriter, r *http.Request, callerID string) {
		traceID := w.Header().Get(headerCorrelationID) // set by requirePermission, which wraps this handler
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")

		body, unreadable := decodeBodyWithin[propertiesBody](w, r, maxOwnAccountBodyBytes)
		if len(unreadable) > 0 {
			writeValidation(w, traceID, unreadable)
			return
		}
		texts, problems := body.texts("currentPassword", "newPassword")
		problems = append(problems, passwordProblems(texts, problems)...)
		if len(problems) > 0 {
			writeValidation(w, traceID, problems)
			return
		}

		release, admitted := admit(w, r, gate, traceID, "password change request")
		if !admitted {
			return
		}
		defer release()

		result, err := useCase.Change(r.Context(), in.ChangePasswordCommand{
			UserID: callerID, CurrentPassword: texts["currentPassword"], NewPassword: texts["newPassword"], UserAgent: r.UserAgent(),
		})
		if err != nil {
			translateChangePasswordError(w, traceID, err)
			return
		}
		writeJSON(w, http.StatusOK, authResponse{
			AccessToken: result.AccessToken, RefreshToken: result.RefreshToken, ExpiresIn: result.ExpiresIn, User: toUserSummary(result.User),
		})
	}
}

// passwordProblems asks the domain about both passwords, so all the invalid ones are reported at once and the rules stay in
// the domain. A property that already has a problem (null, not a string) is not judged again.
func passwordProblems(texts map[string]string, found []fieldError) []fieldError {
	flagged := map[string]bool{}
	for _, problem := range found {
		flagged[problem.Field] = true
	}
	var checks []check
	if !flagged["currentPassword"] {
		checks = append(checks, check{"currentPassword", model.CheckPresentedPassword(texts["currentPassword"])})
	}
	if !flagged["newPassword"] {
		checks = append(checks, check{"newPassword", errorOf(model.NewPassword(texts["newPassword"]))})
	}
	return problemsOf(checks)
}

// translateChangePasswordError is the only place that maps the errors of the password change to HTTP. A wrong current
// password is a 400 on its field, never a 401: the shell treats every 401 as an expired session (ADR-051). An account that
// is gone or locked is a token that identifies nobody. The cause of an unexpected error goes only to the log, which never
// sees a password or a token.
func translateChangePasswordError(w http.ResponseWriter, traceID string, err error) {
	switch {
	case errors.Is(err, model.ErrWrongCurrentPassword), errors.Is(err, model.ErrInvalidCurrentPassword):
		writeValidation(w, traceID, []fieldError{{Field: "currentPassword", Message: err.Error()}})
	case errors.Is(err, model.ErrPasswordUnchanged), errors.Is(err, model.ErrWeakPassword):
		writeValidation(w, traceID, []fieldError{{Field: "newPassword", Message: err.Error()}})
	case errors.Is(err, model.ErrTooManyPasswordChangeAttempts):
		w.Header().Set("Retry-After", passwordChangeRetryAfterSeconds(err))
		writeJSON(w, http.StatusTooManyRequests, errorResponse{
			Error: codeRateLimited, Message: "Too many wrong passwords, try again later", TraceID: traceID,
		})
	case errors.Is(err, model.ErrUserNotFound), errors.Is(err, model.ErrUserLocked):
		slog.Warn("password change refused: the account of the token is not active", "traceId", traceID)
		writeUnauthorized(w, traceID)
	default:
		slog.Error("change password failed", "traceId", traceID, "error", err)
		writeInternal(w, traceID)
	}
}

// passwordChangeRetryAfterSeconds is the Retry-After of a change rejected by the lock: the time left of it. An error that
// carries no wait gets the default lock time, the upper bound.
func passwordChangeRetryAfterSeconds(err error) string {
	wait := model.DefaultPasswordChangeLock
	var limited *model.PasswordChangeRateLimitedError
	if errors.As(err, &limited) {
		wait = limited.RetryAfter
	}
	return wholeSeconds(wait)
}
