package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

func fullGate() *Bulkhead {
	gate, _ := NewBulkhead(1, time.Millisecond)
	gate.Acquire(context.Background())
	return gate
}

// Every 429 of the service carries the code TOO_MANY_REQUESTS of the norm (Annex F), whatever limit refused the request.
func TestEveryRouteThatAnswers429UsesTheCodeOfTheNorm(t *testing.T) {
	cases := map[string]struct {
		send  func() *httptest.ResponseRecorder
		retry string
	}{
		"register bulkhead": {func() *httptest.ResponseRecorder {
			return sendGated(registerPath, validBody(), WithRegisterUser(&fakeRegister{result: createdSession()}, fullGate()), true)
		}, "1"},
		"login bulkhead": {func() *httptest.ResponseRecorder {
			return sendGated(loginPath, loginBody(), WithLoginUser(&fakeLogin{result: loggedInSession()}, fullGate()), false)
		}, "1"},
		"login client address limit": {func() *httptest.ResponseRecorder {
			return sendLogin(&fakeLogin{err: &model.LoginRateLimitedError{RetryAfter: 2 * time.Minute}}, attempt{body: loginBody()})
		}, "120"},
		"forgot password bulkhead": {func() *httptest.ResponseRecorder {
			return sendPasswordReset(resetGates{forgot: fullGate(), reset: openGates().reset}, &fakeRequestPasswordReset{}, &fakeResetPassword{}, forgotAttempt(forgotBody))
		}, "1"},
		"reset password bulkhead": {func() *httptest.ResponseRecorder {
			return sendPasswordReset(resetGates{forgot: openGates().forgot, reset: fullGate()}, &fakeRequestPasswordReset{}, &fakeResetPassword{}, resetPasswordAttempt(resetBody))
		}, "1"},
		"email change bulkhead": {func() *httptest.ResponseRecorder {
			return sendEmailChangeGated(fullGate(), &fakeUserAuthorizer{}, &fakeRequestEmailChange{}, &fakeVerifyEmailChange{}, requestAttempt(emailBody))
		}, "1"},
		"email change hourly limit": {func() *httptest.ResponseRecorder {
			return sendEmailChange(&fakeUserAuthorizer{}, &fakeRequestEmailChange{err: &model.EmailChangeRateLimitedError{RetryAfter: time.Hour}}, &fakeVerifyEmailChange{}, requestAttempt(emailBody))
		}, "3600"},
		"password change bulkhead": {func() *httptest.ResponseRecorder {
			return sendPasswordChange(fullGate(), &fakeUserAuthorizer{}, &fakeChangePassword{}, passwordAttempt{body: passwordBody})
		}, "1"},
		"password change lock": {func() *httptest.ResponseRecorder {
			return sendPasswordChange(openPasswordGate(), &fakeUserAuthorizer{}, &fakeChangePassword{err: &model.PasswordChangeRateLimitedError{RetryAfter: 15 * time.Minute}}, passwordAttempt{body: passwordBody})
		}, "900"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			captureLog(t)

			rec := c.send()

			if rec.Code != http.StatusTooManyRequests || decode(t, rec)["error"] != "TOO_MANY_REQUESTS" || rec.Header().Get("Retry-After") != c.retry {
				t.Errorf("status = %d, Retry-After = %q, body = %s, want 429 TOO_MANY_REQUESTS with Retry-After %s", rec.Code, rec.Header().Get("Retry-After"), rec.Body, c.retry)
			}
		})
	}
}
