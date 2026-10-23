package httpapi

import (
	"context"
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
	emailPath    = BasePath + "/me/email"
	verifyPath   = BasePath + "/me/email/verify"
	emailKey     = "email-key-0001"
	emailBody    = `{"email":"new.address@example.com"}`
	verifyBody   = `{"verificationCode":"012345"}`
	rejectedText = "the verification code is invalid or expired"
)

type fakeRequestEmailChange struct {
	err     error
	called  int
	command in.RequestEmailChangeCommand
}

func (f *fakeRequestEmailChange) RequestChange(_ context.Context, command in.RequestEmailChangeCommand) error {
	f.called++
	f.command = command
	return f.err
}

type fakeVerifyEmailChange struct {
	err     error
	called  int
	command in.VerifyEmailChangeCommand
}

func (f *fakeVerifyEmailChange) VerifyChange(_ context.Context, command in.VerifyEmailChangeCommand) error {
	f.called++
	f.command = command
	return f.err
}

type emailAttempt struct {
	method, path, key, body string
	contentType             string
	headers                 map[string]string
}

func sendEmailChange(authorizer *fakeUserAuthorizer, request in.RequestEmailChange, verify in.VerifyEmailChange, a emailAttempt) *httptest.ResponseRecorder {
	req := httptest.NewRequest(a.method, a.path, strings.NewReader(a.body))
	req.Header.Set("Content-Type", "application/json")
	if a.contentType != "" {
		req.Header.Set("Content-Type", a.contentType)
	}
	req.Header.Set("Authorization", "Bearer "+userSecret)
	if a.key != "" {
		req.Header.Set("Idempotency-Key", a.key)
	}
	for name, value := range a.headers {
		req.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	NewHandler(WithEmailChange(authorizer, request, verify)).ServeHTTP(rec, req)
	return rec
}

func requestAttempt(body string) emailAttempt {
	return emailAttempt{method: http.MethodPatch, path: emailPath, key: emailKey, body: body}
}

func verifyAttempt(body string) emailAttempt {
	return emailAttempt{method: http.MethodPost, path: verifyPath, key: emailKey, body: body}
}

func TestEmailChangeRoutesExistOnlyWhenTheUseCasesAreInjected(t *testing.T) {
	for _, route := range []emailAttempt{requestAttempt(emailBody), verifyAttempt(verifyBody)} {
		rec := httptest.NewRecorder()
		NewHandler().ServeHTTP(rec, httptest.NewRequest(route.method, route.path, nil))
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: status = %d, want the route to be absent", route.method, route.path, rec.Code)
		}
	}
}

func TestRequestEmailChangeAnswers202WithoutBodyForTheAccountOfTheToken(t *testing.T) {
	useCase, authorizer := &fakeRequestEmailChange{}, &fakeUserAuthorizer{}

	rec := sendEmailChange(authorizer, useCase, &fakeVerifyEmailChange{}, requestAttempt(emailBody))

	if rec.Code != http.StatusAccepted || rec.Body.Len() != 0 || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Correlation-Id") == "" {
		t.Fatalf("status = %d, body = %q, headers = %v, want 202, no body, no-store and a correlation id", rec.Code, rec.Body, rec.Header())
	}
	if want := (in.RequestEmailChangeCommand{UserID: "admin-1", Email: "new.address@example.com"}); useCase.command != want {
		t.Errorf("command = %+v, want %+v", useCase.command, want)
	}
	if authorizer.permission != "profile:update:self" {
		t.Errorf("permission = %q, want profile:update:self", authorizer.permission)
	}
}

func TestEmailChangeDoesNotReachTheUseCasesWithoutAValidToken(t *testing.T) {
	captureLog(t)
	for name, err := range map[string]error{"invalid or revoked token": model.ErrAccessTokenInvalid, "no permission": model.ErrPermissionDenied, "revoked list down": errRevokedListDown} {
		for _, route := range []emailAttempt{requestAttempt(emailBody), verifyAttempt(verifyBody)} {
			request, verify := &fakeRequestEmailChange{}, &fakeVerifyEmailChange{}

			rec := sendEmailChange(&fakeUserAuthorizer{err: err}, request, verify, route)

			if rec.Code < 400 || request.called+verify.called != 0 {
				t.Errorf("%s %s: status = %d, calls = %d, want an error and no call", name, route.path, rec.Code, request.called+verify.called)
			}
		}
	}
}

func TestRequestEmailChangeReportsEveryInvalidInputAtOnce(t *testing.T) {
	cases := map[string]emailAttempt{
		"missing key":      {method: http.MethodPatch, path: emailPath, body: emailBody},
		"short key":        {method: http.MethodPatch, path: emailPath, key: "short", body: emailBody},
		"invalid email":    requestAttempt(`{"email":"not-an-email"}`),
		"missing email":    requestAttempt(`{}`),
		"not JSON":         requestAttempt(`{"email":`),
		"wrong media type": {method: http.MethodPatch, path: emailPath, key: emailKey, body: emailBody, contentType: "text/plain"},
	}
	for name, a := range cases {
		t.Run(name, func(t *testing.T) {
			useCase := &fakeRequestEmailChange{}

			rec := sendEmailChange(&fakeUserAuthorizer{}, useCase, &fakeVerifyEmailChange{}, a)

			if rec.Code != http.StatusBadRequest || useCase.called != 0 || decode(t, rec)["error"] != "VALIDATION_ERROR" {
				t.Errorf("status = %d, calls = %d, body = %s, want 400 VALIDATION_ERROR and no call", rec.Code, useCase.called, rec.Body)
			}
		})
	}
}

func TestRequestEmailChangeMapsTheErrorsOfTheUseCase(t *testing.T) {
	cases := map[string]struct {
		err    error
		status int
		code   string
	}{
		"invalid email":    {model.ErrInvalidEmail, http.StatusBadRequest, "VALIDATION_ERROR"},
		"email registered": {model.ErrEmailAlreadyRegistered, http.StatusConflict, "EMAIL_ALREADY_REGISTERED"},
		"too many":         {model.ErrTooManyEmailChangeRequests, http.StatusTooManyRequests, "RATE_LIMITED"},
		"unexpected":       {errors.New("driver failure: password=hunter2"), http.StatusInternalServerError, "INTERNAL_ERROR"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			logs := captureLog(t)

			rec := sendEmailChange(&fakeUserAuthorizer{}, &fakeRequestEmailChange{err: c.err}, &fakeVerifyEmailChange{}, requestAttempt(emailBody))

			if rec.Code != c.status || decode(t, rec)["error"] != c.code {
				t.Errorf("status = %d, body = %s, want %d %s", rec.Code, rec.Body, c.status, c.code)
			}
			if strings.Contains(rec.Body.String(), "hunter2") || (c.status == http.StatusInternalServerError && !strings.Contains(logs.String(), "level=ERROR")) {
				t.Errorf("body = %s, log = %s, want the cause only in the log", rec.Body, logs)
			}
		})
	}
}

func TestRequestEmailChangeAnswersTheRemainingSecondsInRetryAfter(t *testing.T) {
	cases := map[string]struct {
		retryAfter time.Duration
		want       string
	}{
		"whole seconds":          {20 * time.Minute, "1200"},
		"rounded up":             {20*time.Minute + 100*time.Millisecond, "1201"},
		"a fraction of a second": {time.Millisecond, "1"},
		"one second":             {time.Second, "1"},
		"nothing left":           {0, "1"},
		"the whole window":       {time.Hour, "3600"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			useCase := &fakeRequestEmailChange{err: &model.EmailChangeRateLimitedError{RetryAfter: c.retryAfter}}

			rec := sendEmailChange(&fakeUserAuthorizer{}, useCase, &fakeVerifyEmailChange{}, requestAttempt(emailBody))

			if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != c.want {
				t.Errorf("status = %d, Retry-After = %q, want 429 and %q", rec.Code, rec.Header().Get("Retry-After"), c.want)
			}
		})
	}
}

func TestRequestEmailChangeAnswersTheWholeWindowWhenTheErrorCarriesNoWait(t *testing.T) {
	rec := sendEmailChange(&fakeUserAuthorizer{}, &fakeRequestEmailChange{err: model.ErrTooManyEmailChangeRequests}, &fakeVerifyEmailChange{}, requestAttempt(emailBody))

	if got := rec.Header().Get("Retry-After"); got != "3600" {
		t.Errorf("Retry-After = %q, want 3600 (the window, the safe upper bound)", got)
	}
}

func TestVerifyEmailChangeAnswers204AndPassesTheCodeAsSent(t *testing.T) {
	useCase, authorizer := &fakeVerifyEmailChange{}, &fakeUserAuthorizer{}

	rec := sendEmailChange(authorizer, &fakeRequestEmailChange{}, useCase, verifyAttempt(verifyBody))

	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Fatalf("status = %d, body = %q, want 204 and no body", rec.Code, rec.Body)
	}
	if want := (in.VerifyEmailChangeCommand{UserID: "admin-1", VerificationCode: "012345"}); useCase.command != want {
		t.Errorf("command = %+v, want %+v", useCase.command, want)
	}
	if authorizer.permission != "profile:update:self" {
		t.Errorf("permission = %q, want profile:update:self", authorizer.permission)
	}
}

func TestVerifyEmailChangeLeavesTheJudgmentOfTheCodeToTheUseCaseSoEveryCauseAnswersTheSame(t *testing.T) {
	var first string
	for _, body := range []string{`{"verificationCode":"12ab"}`, `{}`, `{"verificationCode":"999999"}`, verifyBody} {
		useCase := &fakeVerifyEmailChange{err: model.ErrVerificationRejected}

		rec := sendEmailChange(&fakeUserAuthorizer{}, &fakeRequestEmailChange{}, useCase, emailAttempt{
			method: http.MethodPost, path: verifyPath, key: emailKey, body: body, headers: withTrace(),
		})

		if rec.Code != http.StatusBadRequest || useCase.called != 1 {
			t.Fatalf("%s: status = %d, calls = %d, want 400 from the use case", body, rec.Code, useCase.called)
		}
		if first == "" {
			first = rec.Body.String()
			if !strings.Contains(first, `"error":"VALIDATION_ERROR"`) || !strings.Contains(first, rejectedText) {
				t.Fatalf("body = %s, want VALIDATION_ERROR with the fixed message", first)
			}
		}
		if rec.Body.String() != first {
			t.Errorf("%s: body = %s, want the same body as the first cause: %s", body, rec.Body, first)
		}
	}
}

func TestVerifyEmailChangeMapsTheOtherErrors(t *testing.T) {
	cases := map[string]struct {
		err    error
		status int
		code   string
	}{
		"address taken meanwhile": {model.ErrEmailAlreadyRegistered, http.StatusConflict, "EMAIL_ALREADY_REGISTERED"},
		"unexpected":              {errors.New("driver failure"), http.StatusInternalServerError, "INTERNAL_ERROR"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			captureLog(t)

			rec := sendEmailChange(&fakeUserAuthorizer{}, &fakeRequestEmailChange{}, &fakeVerifyEmailChange{err: c.err}, verifyAttempt(verifyBody))

			if rec.Code != c.status || decode(t, rec)["error"] != c.code {
				t.Errorf("status = %d, body = %s, want %d %s", rec.Code, rec.Body, c.status, c.code)
			}
		})
	}
}

func TestVerifyEmailChangeRejectsAMissingKeyAndAnUnreadableBodyWithoutCallingTheUseCase(t *testing.T) {
	for name, a := range map[string]emailAttempt{
		"missing key": {method: http.MethodPost, path: verifyPath, body: verifyBody},
		"not JSON":    verifyAttempt(`{"verificationCode":`),
	} {
		useCase := &fakeVerifyEmailChange{}

		rec := sendEmailChange(&fakeUserAuthorizer{}, &fakeRequestEmailChange{}, useCase, a)

		if rec.Code != http.StatusBadRequest || useCase.called != 0 {
			t.Errorf("%s: status = %d, calls = %d, want 400 and no call", name, rec.Code, useCase.called)
		}
	}
}

func TestRequestEmailChangeAnswers401WithoutAnErrorLogWhenTheAccountOfTheTokenIsGone(t *testing.T) {
	logs := captureLog(t)

	rec := sendEmailChange(&fakeUserAuthorizer{}, &fakeRequestEmailChange{err: model.ErrUserNotFound}, &fakeVerifyEmailChange{}, traced(requestAttempt(emailBody)))

	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"error":"UNAUTHORIZED"`) || rec.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("status = %d, body = %s, want 401 UNAUTHORIZED", rec.Code, rec.Body)
	}
	if strings.Contains(logs.String(), "level=ERROR") {
		t.Errorf("log = %s, want no ERROR line for an account that is gone", logs)
	}
}

// addressOfLength builds a valid address of exactly n characters.
func addressOfLength(n int) string {
	const domain = "@example.com"
	return strings.Repeat("a", n-len(domain)) + domain
}

func TestRequestEmailChangeRejectsAnEmailLongerThanTheDatabaseStoresWith400(t *testing.T) {
	useCase := &fakeRequestEmailChange{}

	rec := sendEmailChange(&fakeUserAuthorizer{}, useCase, &fakeVerifyEmailChange{},
		traced(requestAttempt(`{"email":"`+addressOfLength(model.MaxEmailLength+1)+`"}`)))

	if rec.Code != http.StatusBadRequest || useCase.called != 0 || !strings.Contains(rec.Body.String(), `"field":"email"`) {
		t.Errorf("status = %d, calls = %d, body = %s, want 400 on the field email and no call", rec.Code, useCase.called, rec.Body)
	}
}

func TestRequestEmailChangeAcceptsTheLongestEmail(t *testing.T) {
	useCase := &fakeRequestEmailChange{}

	rec := sendEmailChange(&fakeUserAuthorizer{}, useCase, &fakeVerifyEmailChange{},
		traced(requestAttempt(`{"email":"`+addressOfLength(model.MaxEmailLength)+`"}`)))

	if rec.Code != http.StatusAccepted || useCase.called != 1 {
		t.Errorf("status = %d, calls = %d, want 202 and one call", rec.Code, useCase.called)
	}
}
