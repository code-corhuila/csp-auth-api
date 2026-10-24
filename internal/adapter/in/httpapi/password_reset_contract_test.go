package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

func TestForgotPasswordResponsesFulfillTheContract(t *testing.T) {
	cases := map[string]struct {
		useCase in.RequestPasswordReset
		a       resetAttempt
	}{
		"202 accepted":       {&fakeRequestPasswordReset{}, tracedReset(forgotAttempt(forgotBody))},
		"202 longest email":  {&fakeRequestPasswordReset{}, tracedReset(forgotAttempt(`{"email":"` + addressOfLength(model.MaxEmailLength) + `"}`))},
		"400 missing email":  {&fakeRequestPasswordReset{}, tracedReset(forgotAttempt(`{}`))},
		"400 invalid email":  {&fakeRequestPasswordReset{err: model.ErrInvalidEmail}, tracedReset(forgotAttempt(forgotBody))},
		"400 email too long": {&fakeRequestPasswordReset{}, tracedReset(forgotAttempt(`{"email":"` + addressOfLength(model.MaxEmailLength+1) + `"}`))},
		"400 unreadable":     {&fakeRequestPasswordReset{}, tracedReset(forgotAttempt(`{"email":`))},
		"400 body too large": {&fakeRequestPasswordReset{}, tracedReset(forgotAttempt(`{"email":"` + strings.Repeat("a", 5000) + `"}`))},
		"500 unexpected":     {&fakeRequestPasswordReset{err: errors.New("driver failure")}, tracedReset(forgotAttempt(forgotBody))},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			captureLog(t)
			requireContract(t, http.MethodPost, forgotPath, sendPasswordReset(openGates(), c.useCase, &fakeResetPassword{}, c.a))
		})
	}
}

func TestResetPasswordResponsesFulfillTheContract(t *testing.T) {
	cases := map[string]struct {
		useCase in.ResetPassword
		a       resetAttempt
	}{
		"204 changed":          {&fakeResetPassword{}, tracedReset(resetPasswordAttempt(resetBody))},
		"400 invalid fields":   {&fakeResetPassword{}, tracedReset(resetPasswordAttempt(`{"token":"abc","password":"weak"}`))},
		"400 weak password":    {&fakeResetPassword{err: model.ErrWeakPassword}, tracedReset(resetPasswordAttempt(resetBody))},
		"400 current password": {&fakeResetPassword{err: model.ErrPasswordUnchanged}, tracedReset(resetPasswordAttempt(resetBody))},
		"400 unreadable":       {&fakeResetPassword{}, tracedReset(resetPasswordAttempt(`{`))},
		"400 body too large":   {&fakeResetPassword{}, tracedReset(resetPasswordAttempt(`{"token":"` + strings.Repeat("a", 5000) + `"}`))},
		"401 rejected token":   {&fakeResetPassword{err: model.ErrPasswordResetRejected}, tracedReset(resetPasswordAttempt(resetBody))},
		"500 unexpected":       {&fakeResetPassword{err: errors.New("driver failure")}, tracedReset(resetPasswordAttempt(resetBody))},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			captureLog(t)
			requireContract(t, http.MethodPost, resetPath, sendPasswordReset(openGates(), &fakeRequestPasswordReset{}, c.useCase, c.a))
		})
	}
}

func TestPasswordResetRoutesNotEnabledFulfillTheContract404(t *testing.T) {
	for _, path := range []string{forgotPath, resetPath} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(forgotBody))
		req.Header.Set("X-Correlation-Id", traceID)
		NewHandler(WithPasswordResetNotEnabled()).ServeHTTP(rec, req)

		requireContract(t, http.MethodPost, path, rec)
	}
}

func TestForgotPasswordAnswersTheSame202ForEveryAccount(t *testing.T) {
	registered := sendPasswordReset(openGates(), &fakeRequestPasswordReset{}, &fakeResetPassword{}, tracedReset(forgotAttempt(`{"email":"registered@example.com"}`)))
	unknown := sendPasswordReset(openGates(), &fakeRequestPasswordReset{}, &fakeResetPassword{}, tracedReset(forgotAttempt(`{"email":"nobody@example.com"}`)))

	if registered.Code != unknown.Code || registered.Body.String() != unknown.Body.String() || registered.Header().Get("Content-Type") != unknown.Header().Get("Content-Type") {
		t.Errorf("registered = %d %q, unknown = %d %q, want the same answer", registered.Code, registered.Body, unknown.Code, unknown.Body)
	}
	requireContract(t, http.MethodPost, forgotPath, registered)
}
