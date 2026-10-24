package httpapi

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const logoutPath = BasePath + "/logout"

var tokenExpiry = time.Date(2026, 10, 15, 21, 0, 0, 0, time.UTC)

type fakeAuthenticator struct {
	err    error
	token  string
	claims model.AccessClaims
}

func (f *fakeAuthenticator) AuthenticateUser(_ context.Context, bearerToken string) (model.AccessClaims, error) {
	f.token = bearerToken
	if f.err != nil {
		return model.AccessClaims{}, f.err
	}
	if f.claims.Subject == "" {
		return model.AccessClaims{Subject: "user-1", TokenID: "jti-1", ExpiresAt: tokenExpiry}, nil
	}
	return f.claims, nil
}

type fakeLogout struct {
	err     error
	called  int
	command in.LogoutCommand
}

func (f *fakeLogout) Logout(_ context.Context, command in.LogoutCommand) error {
	f.called++
	f.command = command
	return f.err
}

type logoutAttempt struct {
	body    string
	headers map[string]string
}

func sendLogout(authenticator in.AuthenticateUser, useCase in.Logout, a logoutAttempt) *httptest.ResponseRecorder {
	var request *http.Request
	if a.body == "" {
		request = httptest.NewRequest(http.MethodPost, logoutPath, nil)
	} else {
		request = httptest.NewRequest(http.MethodPost, logoutPath, strings.NewReader(a.body))
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Authorization", "Bearer "+userSecret)
	for name, value := range a.headers {
		request.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	NewHandler(WithLogout(authenticator, useCase)).ServeHTTP(rec, request)
	return rec
}

func TestLogoutRouteExistsOnlyWhenTheUseCaseIsInjected(t *testing.T) {
	rec := httptest.NewRecorder()
	NewHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, logoutPath, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want the route to be absent", rec.Code)
	}
}

func TestLogoutWithoutABodyEndsTheSessionOfTheTokenAndAnswers204(t *testing.T) {
	authenticator, useCase := &fakeAuthenticator{}, &fakeLogout{}

	rec := sendLogout(authenticator, useCase, logoutAttempt{})

	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Errorf("status = %d, body = %q, want 204 and no body", rec.Code, rec.Body)
	}
	want := in.LogoutCommand{UserID: "user-1", TokenID: "jti-1", ExpiresAt: tokenExpiry}
	if authenticator.token != userSecret || useCase.command != want {
		t.Errorf("token = %q, command = %+v, want the bearer token and %+v", authenticator.token, useCase.command, want)
	}
}

func TestLogoutPassesTheRefreshTokenAndAllDevices(t *testing.T) {
	cases := map[string]struct {
		body string
		want in.LogoutCommand
	}{
		"refresh token":      {`{"refreshToken":"opaque-1"}`, in.LogoutCommand{RefreshToken: "opaque-1"}},
		"all devices":        {`{"allDevices":true}`, in.LogoutCommand{AllDevices: true}},
		"both":               {`{"refreshToken":"opaque-1","allDevices":true}`, in.LogoutCommand{RefreshToken: "opaque-1", AllDevices: true}},
		"empty object":       {`{}`, in.LogoutCommand{}},
		"unknown properties": {`{"device":"phone"}`, in.LogoutCommand{}},
	}
	for name, c := range cases {
		useCase := &fakeLogout{}

		rec := sendLogout(&fakeAuthenticator{}, useCase, logoutAttempt{body: c.body})

		c.want.UserID, c.want.TokenID, c.want.ExpiresAt = "user-1", "jti-1", tokenExpiry
		if rec.Code != http.StatusNoContent || useCase.command != c.want {
			t.Errorf("%s: status = %d, command = %+v, want 204 and %+v", name, rec.Code, useCase.command, c.want)
		}
	}
}

func TestLogoutRejectsAnUnreadableBodyWithoutEndingTheSession(t *testing.T) {
	for name, body := range map[string]string{"not json": `{"refreshToken":`, "wrong type": `{"allDevices":"yes"}`} {
		useCase := &fakeLogout{}

		rec := sendLogout(&fakeAuthenticator{}, useCase, logoutAttempt{body: body})

		if rec.Code != http.StatusBadRequest || useCase.called != 0 || !strings.Contains(rec.Body.String(), `"error":"VALIDATION_ERROR"`) {
			t.Errorf("%s: status = %d, called = %d, body = %s, want 400 VALIDATION_ERROR and no logout", name, rec.Code, useCase.called, rec.Body)
		}
	}
}

func TestLogoutAnswers401WhenTheTokenIsMissingOrInvalid(t *testing.T) {
	useCase := &fakeLogout{}

	rec := sendLogout(&fakeAuthenticator{err: model.ErrAccessTokenInvalid}, useCase, logoutAttempt{})

	body := rec.Body.String()
	if rec.Code != http.StatusUnauthorized || useCase.called != 0 || !strings.Contains(body, `"error":"UNAUTHORIZED"`) || rec.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("status = %d, called = %d, body = %s, want 401 UNAUTHORIZED and no logout", rec.Code, useCase.called, body)
	}
}

func TestLogoutAnswers500WithANeutralBodyAndNeverLogsTheTokens(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	rec := sendLogout(&fakeAuthenticator{}, &fakeLogout{err: errors.New("redis down")}, logoutAttempt{body: `{"refreshToken":"opaque-secret"}`})

	body := rec.Body.String()
	if rec.Code != http.StatusInternalServerError || !strings.Contains(body, `"error":"INTERNAL_ERROR"`) || strings.Contains(body, "redis") {
		t.Errorf("status = %d, body = %s, want a neutral 500 INTERNAL_ERROR", rec.Code, body)
	}
	for _, secret := range []string{userSecret, "opaque-secret", "jti-1"} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("the log contains %q: %s", secret, logs.String())
		}
	}
}

func TestRequireAuthenticationAnswers500WhenTheTokenCannotBeChecked(t *testing.T) {
	useCase := &fakeLogout{}

	rec := sendLogout(&fakeAuthenticator{err: errors.New("key store down")}, useCase, logoutAttempt{})

	if rec.Code != http.StatusInternalServerError || useCase.called != 0 || !strings.Contains(rec.Body.String(), `"error":"INTERNAL_ERROR"`) {
		t.Errorf("status = %d, called = %d, body = %s, want 500 INTERNAL_ERROR and no logout", rec.Code, useCase.called, rec.Body)
	}
}

// cancellingLogout stands for the use case while the browser leaves the page: the client connection
// goes away (the request context is cancelled) in the middle of the call, and the work only
// completes if the context it received is still alive and bounded.
type cancellingLogout struct {
	cancelRequest context.CancelFunc
	revoked       bool
	hasDeadline   bool
	traceID       any
}

func (f *cancellingLogout) Logout(ctx context.Context, _ in.LogoutCommand) error {
	f.cancelRequest()
	_, f.hasDeadline = ctx.Deadline()
	f.traceID = ctx.Value(traceKey{})
	if err := ctx.Err(); err != nil {
		return err
	}
	f.revoked = true
	return nil
}

type traceKey struct{}

func TestLogoutCompletesWhenTheClientDisconnectsInTheMiddleOfTheCall(t *testing.T) {
	requestCtx, cancel := context.WithCancel(context.WithValue(context.Background(), traceKey{}, "trace-1"))
	defer cancel()
	useCase := &cancellingLogout{cancelRequest: cancel}
	request := httptest.NewRequest(http.MethodPost, logoutPath, nil).WithContext(requestCtx)
	request.Header.Set("Authorization", "Bearer "+userSecret)
	rec := httptest.NewRecorder()

	NewHandler(WithLogout(&fakeAuthenticator{}, useCase)).ServeHTTP(rec, request)

	if rec.Code != http.StatusNoContent || !useCase.revoked {
		t.Errorf("status = %d, revoked = %t, want 204 and the session ended although the client left", rec.Code, useCase.revoked)
	}
	if !useCase.hasDeadline || useCase.traceID != "trace-1" {
		t.Errorf("deadline = %t, trace = %v, want a bounded context that keeps the values of the request", useCase.hasDeadline, useCase.traceID)
	}
}
