package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const (
	passwordPath = BasePath + "/me/password"
	passwordBody = `{"currentPassword":"CurrentSecret1","newPassword":"NewSecret123"}`
)

type fakeChangePassword struct {
	result  in.LoginUserResult
	err     error
	called  int
	command in.ChangePasswordCommand
}

func (f *fakeChangePassword) Change(_ context.Context, command in.ChangePasswordCommand) (in.LoginUserResult, error) {
	f.called++
	f.command = command
	return f.result, f.err
}

func changedSession() in.LoginUserResult {
	return in.LoginUserResult{
		AccessToken: "new.access.token", RefreshToken: "new-refresh-token", ExpiresIn: 900,
		User: in.UserSummary{ID: "admin-1", Email: "ana@example.com", Name: "Ana Pérez", Roles: []string{"CLIENT"}, Permissions: []string{"profile:update:self"}},
	}
}

type passwordAttempt struct {
	body        string
	contentType string
	headers     map[string]string
}

func sendPasswordChange(gate *Bulkhead, authorizer *fakeUserAuthorizer, useCase in.ChangePassword, a passwordAttempt) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, passwordPath, strings.NewReader(a.body))
	req.Header.Set("Content-Type", "application/json")
	if a.contentType != "" {
		req.Header.Set("Content-Type", a.contentType)
	}
	req.Header.Set("Authorization", "Bearer "+userSecret)
	req.Header.Set("User-Agent", "portal/1.0")
	for name, value := range a.headers {
		req.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	NewHandler(WithPasswordChange(authorizer, useCase, gate)).ServeHTTP(rec, req)
	return rec
}

func openPasswordGate() *Bulkhead {
	gate, _ := NewBulkhead(1000, time.Second)
	return gate
}

func fieldsOf(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var body errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q is not an error response: %v", rec.Body, err)
	}
	fields := map[string]string{}
	for _, detail := range body.Details {
		fields[detail.Field] = detail.Message
	}
	return fields
}

func TestPasswordChangeRouteExistsOnlyWhenTheUseCaseIsInjected(t *testing.T) {
	rec := httptest.NewRecorder()
	NewHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, passwordPath, nil))
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want the route to be absent", rec.Code)
	}
}

func TestPasswordChangeAnswers200WithAFreshSessionForTheAccountOfTheToken(t *testing.T) {
	useCase, authorizer := &fakeChangePassword{result: changedSession()}, &fakeUserAuthorizer{}

	rec := sendPasswordChange(openPasswordGate(), authorizer, useCase, passwordAttempt{body: passwordBody})

	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusOK || body["accessToken"] != "new.access.token" || body["refreshToken"] != "new-refresh-token" || body["expiresIn"] != float64(900) {
		t.Fatalf("status = %d, body = %s, want 200 with the tokens of the new session", rec.Code, rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" || rec.Header().Get("X-Correlation-Id") == "" {
		t.Errorf("headers = %v, want no-store, no-cache and a correlation id", rec.Header())
	}
	want := in.ChangePasswordCommand{UserID: "admin-1", CurrentPassword: "CurrentSecret1", NewPassword: "NewSecret123", UserAgent: "portal/1.0"}
	if useCase.command != want || authorizer.permission != "profile:update:self" {
		t.Errorf("command = %+v, permission = %q, want the account of the token with profile:update:self", useCase.command, authorizer.permission)
	}
}

func TestPasswordChangeReportsEveryInvalidInputAtOnceWithoutReachingTheUseCase(t *testing.T) {
	cases := map[string]struct {
		a      passwordAttempt
		fields []string
	}{
		"both passwords missing":     {passwordAttempt{body: `{}`}, []string{"currentPassword", "newPassword"}},
		"empty current":              {passwordAttempt{body: `{"currentPassword":"","newPassword":"NewSecret123"}`}, []string{"currentPassword"}},
		"current over 72 bytes":      {passwordAttempt{body: `{"currentPassword":"` + strings.Repeat("a", 73) + `","newPassword":"NewSecret123"}`}, []string{"currentPassword"}},
		"weak new":                   {passwordAttempt{body: `{"currentPassword":"CurrentSecret1","newPassword":"weakpass"}`}, []string{"newPassword"}},
		"null current":               {passwordAttempt{body: `{"currentPassword":null,"newPassword":"NewSecret123"}`}, []string{"currentPassword"}},
		"number as new":              {passwordAttempt{body: `{"currentPassword":"CurrentSecret1","newPassword":7}`}, []string{"newPassword"}},
		"unknown field":              {passwordAttempt{body: `{"currentPassword":"CurrentSecret1","newPassword":"NewSecret123","email":"x@example.com"}`}, []string{"email"}},
		"not JSON":                   {passwordAttempt{body: `{"currentPassword":`}, []string{"body"}},
		"wrong media type":           {passwordAttempt{body: passwordBody, contentType: "text/plain"}, []string{"Content-Type"}},
		"body over 4 KiB":            {passwordAttempt{body: `{"currentPassword":"` + strings.Repeat("a", 5000) + `"}`}, []string{"body"}},
		"idempotency key is ignored": {passwordAttempt{body: `{}`, headers: map[string]string{"Idempotency-Key": "short"}}, []string{"currentPassword", "newPassword"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			useCase := &fakeChangePassword{}

			rec := sendPasswordChange(openPasswordGate(), &fakeUserAuthorizer{}, useCase, c.a)

			fields := fieldsOf(t, rec)
			if rec.Code != http.StatusBadRequest || len(fields) != len(c.fields) || useCase.called != 0 {
				t.Fatalf("status = %d, fields = %v, calls = %d, want 400 naming %v and no call", rec.Code, fields, useCase.called, c.fields)
			}
			for _, field := range c.fields {
				if _, named := fields[field]; !named {
					t.Errorf("fields = %v, want %q named", fields, field)
				}
			}
		})
	}
}

func TestPasswordChangeAnswers400OnTheFieldOfTheCauseNeverA401ForAWrongCurrentPassword(t *testing.T) {
	cases := map[string]struct {
		err     error
		field   string
		message string
	}{
		"wrong current": {model.ErrWrongCurrentPassword, "currentPassword", "The current password is incorrect"},
		"same password": {model.ErrPasswordUnchanged, "newPassword", "The new password must differ from the current one"},
		"weak new":      {model.ErrWeakPassword, "newPassword", model.ErrWeakPassword.Error()},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			rec := sendPasswordChange(openPasswordGate(), &fakeUserAuthorizer{}, &fakeChangePassword{err: c.err}, passwordAttempt{body: passwordBody})

			var body errorResponse
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			if rec.Code != http.StatusBadRequest || body.Error != "VALIDATION_ERROR" || len(body.Details) != 1 || body.Details[0].Field != c.field || body.Details[0].Message != c.message {
				t.Errorf("status = %d, body = %s, want 400 VALIDATION_ERROR with %q: %q", rec.Code, rec.Body, c.field, c.message)
			}
		})
	}
}

func TestPasswordChangeAnswers429WithTheSecondsLeftOfTheLockRoundedUp(t *testing.T) {
	cases := map[string]struct {
		err  error
		want string
	}{
		"fifteen minutes": {&model.PasswordChangeRateLimitedError{RetryAfter: 15 * time.Minute}, "900"},
		"rounded up":      {&model.PasswordChangeRateLimitedError{RetryAfter: 1500 * time.Millisecond}, "2"},
		"at least one":    {&model.PasswordChangeRateLimitedError{RetryAfter: time.Millisecond}, "1"},
		"no wait carried": {model.ErrTooManyPasswordChangeAttempts, "900"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			rec := sendPasswordChange(openPasswordGate(), &fakeUserAuthorizer{}, &fakeChangePassword{err: c.err}, passwordAttempt{body: passwordBody})

			if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != c.want || !strings.Contains(rec.Body.String(), "RATE_LIMITED") {
				t.Errorf("status = %d, Retry-After = %q, body = %s, want 429 RATE_LIMITED with %s", rec.Code, rec.Header().Get("Retry-After"), rec.Body, c.want)
			}
		})
	}
}

func TestPasswordChangeAnswers429WithRetryAfterOneWhenThereIsNoFreeSlot(t *testing.T) {
	captureLog(t)
	gate, _ := NewBulkhead(1, 20*time.Millisecond)
	release, _ := gate.Acquire(context.Background())
	defer release()
	useCase := &fakeChangePassword{}

	rec := sendPasswordChange(gate, &fakeUserAuthorizer{}, useCase, passwordAttempt{body: passwordBody})

	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "1" || useCase.called != 0 {
		t.Errorf("status = %d, Retry-After = %q, calls = %d, want 429 with Retry-After 1 and no call", rec.Code, rec.Header().Get("Retry-After"), useCase.called)
	}
}

func TestPasswordChangeDoesNotTakeASlotForAnInvalidBody(t *testing.T) {
	gate, _ := NewBulkhead(1, 20*time.Millisecond)
	release, _ := gate.Acquire(context.Background())
	defer release()

	rec := sendPasswordChange(gate, &fakeUserAuthorizer{}, &fakeChangePassword{}, passwordAttempt{body: `{}`})

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: the body is judged before a slot is needed", rec.Code)
	}
}

func TestPasswordChangeDoesNotReachTheUseCaseWithoutAValidToken(t *testing.T) {
	captureLog(t)
	for name, err := range map[string]error{"invalid or revoked token": model.ErrAccessTokenInvalid, "no permission": model.ErrPermissionDenied, "revoked list down": errRevokedListDown} {
		useCase := &fakeChangePassword{}

		rec := sendPasswordChange(openPasswordGate(), &fakeUserAuthorizer{err: err}, useCase, passwordAttempt{body: passwordBody})

		if rec.Code < 400 || useCase.called != 0 {
			t.Errorf("%s: status = %d, calls = %d, want an error and no call", name, rec.Code, useCase.called)
		}
	}
}

func TestPasswordChangeAnswers401WhenTheAccountOfTheTokenIsGoneOrLockedAnd500ForTheRest(t *testing.T) {
	logs := captureLog(t)
	for _, cause := range []error{model.ErrUserNotFound, model.ErrUserLocked} {
		rec := sendPasswordChange(openPasswordGate(), &fakeUserAuthorizer{}, &fakeChangePassword{err: cause}, passwordAttempt{body: passwordBody})

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%v: status = %d, want 401: the token identifies no active account", cause, rec.Code)
		}
	}

	rec := sendPasswordChange(openPasswordGate(), &fakeUserAuthorizer{}, &fakeChangePassword{err: errors.New("driver failure")}, passwordAttempt{body: passwordBody})

	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "driver failure") {
		t.Errorf("status = %d, body = %s, want 500 without the cause", rec.Code, rec.Body)
	}
	for _, secret := range []string{userSecret, "CurrentSecret1", "NewSecret123"} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("log %q must not contain %q", logs, secret)
		}
	}
}
