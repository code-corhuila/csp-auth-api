package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const (
	roleTargetID = "3f2a9c1e-5b7d-4e08-9a41-6c2d8e0f1a23"
	roleKey      = "role-key-0001"
	grantBody    = `{"role":"ADMIN","enabled":true}`
)

type fakeChangeRole struct {
	summary in.UserSummary
	err     error
	called  int
	command in.ChangeUserRoleCommand
}

func (f *fakeChangeRole) ChangeRole(_ context.Context, command in.ChangeUserRoleCommand) (in.UserSummary, error) {
	f.called++
	f.command = command
	return f.summary, f.err
}

func promotedUser() in.UserSummary {
	return in.UserSummary{
		ID: roleTargetID, Email: "maria@example.com", Name: "Maria Garcia",
		Roles: []string{"ADMIN", "CLIENT"}, Permissions: []string{"catalog:read", "user:role:update"},
	}
}

type roleAttempt struct {
	userID  string
	key     string
	body    string
	headers map[string]string
}

func sendRoleChange(authorizer *fakeUserAuthorizer, useCase in.ChangeUserRole, a roleAttempt) *httptest.ResponseRecorder {
	if a.userID == "" {
		a.userID = roleTargetID
	}
	request := httptest.NewRequest(http.MethodPatch, BasePath+"/users/"+a.userID+"/role", strings.NewReader(a.body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+userSecret)
	if a.key != "" {
		request.Header.Set("Idempotency-Key", a.key)
	}
	for name, value := range a.headers {
		request.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	NewHandler(WithChangeUserRole(authorizer, useCase)).ServeHTTP(rec, request)
	return rec
}

func TestChangeUserRoleRouteExistsOnlyWhenTheUseCaseIsInjected(t *testing.T) {
	rec := httptest.NewRecorder()
	NewHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPatch, BasePath+"/users/"+roleTargetID+"/role", nil))
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want the route to be absent", rec.Code)
	}
}

func TestChangeUserRoleAnswersTheUserAndPassesTheCallerToTheUseCase(t *testing.T) {
	useCase := &fakeChangeRole{summary: promotedUser()}
	authorizer := &fakeUserAuthorizer{}

	rec := sendRoleChange(authorizer, useCase, roleAttempt{key: roleKey, body: grantBody})

	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Correlation-Id") == "" {
		t.Fatalf("status = %d, headers = %v, want 200, no-store and a correlation id", rec.Code, rec.Header())
	}
	want := in.ChangeUserRoleCommand{ActingAdminID: "admin-1", UserID: roleTargetID, Role: "ADMIN", Enabled: true}
	if useCase.command != want {
		t.Errorf("command = %+v, want %+v", useCase.command, want)
	}
	body := decode(t, rec)
	if body["id"] != roleTargetID || body["email"] != "maria@example.com" {
		t.Errorf("body = %v, want the user after the change", body)
	}
	if authorizer.permission != "user:role:update" {
		t.Errorf("permission = %q, want user:role:update", authorizer.permission)
	}
}

func TestChangeUserRoleDoesNotReachTheUseCaseWithoutPermission(t *testing.T) {
	for name, err := range map[string]error{"no token": model.ErrAccessTokenInvalid, "no permission": model.ErrPermissionDenied} {
		useCase := &fakeChangeRole{}

		rec := sendRoleChange(&fakeUserAuthorizer{err: err}, useCase, roleAttempt{key: roleKey, body: grantBody})

		if (rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden) || useCase.called != 0 {
			t.Errorf("%s: status = %d, calls = %d, want 401 or 403 and no call", name, rec.Code, useCase.called)
		}
	}
}

func TestChangeUserRoleReportsEveryInvalidInputAtOnce(t *testing.T) {
	cases := map[string]roleAttempt{
		"missing key":        {key: "", body: grantBody},
		"short key":          {key: "short", body: grantBody},
		"userId not a UUID":  {userID: "not-a-uuid", key: roleKey, body: grantBody},
		"missing role":       {key: roleKey, body: `{"enabled":true}`},
		"missing enabled":    {key: roleKey, body: `{"role":"ADMIN"}`},
		"enabled not a bool": {key: roleKey, body: `{"role":"ADMIN","enabled":"yes"}`},
		"not JSON":           {key: roleKey, body: `{"role":`},
	}
	for name, a := range cases {
		useCase := &fakeChangeRole{}

		rec := sendRoleChange(&fakeUserAuthorizer{}, useCase, a)

		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"error":"VALIDATION_ERROR"`) || useCase.called != 0 {
			t.Errorf("%s: status = %d, calls = %d, body = %s, want 400 VALIDATION_ERROR and no call", name, rec.Code, useCase.called, rec.Body)
		}
	}
}

func TestChangeUserRoleTranslatesTheErrorsOfTheUseCase(t *testing.T) {
	cases := map[string]struct {
		err    error
		status int
		code   string
	}{
		"unknown role":       {model.ErrUnknownRole, http.StatusBadRequest, "VALIDATION_ERROR"},
		"CLIENT role":        {model.ErrRoleNotChangeable, http.StatusBadRequest, "VALIDATION_ERROR"},
		"unknown user":       {model.ErrUserNotFound, http.StatusNotFound, "NOT_FOUND"},
		"last administrator": {model.ErrLastAdmin, http.StatusConflict, "LAST_ADMIN"},
		"only role":          {model.ErrNoRoles, http.StatusConflict, "USER_WITHOUT_ROLES"},
		"unexpected":         {errors.New("driver failure"), http.StatusInternalServerError, "INTERNAL_ERROR"},
	}
	for name, c := range cases {
		rec := sendRoleChange(&fakeUserAuthorizer{}, &fakeChangeRole{err: c.err}, roleAttempt{key: roleKey, body: grantBody})

		body := rec.Body.String()
		if rec.Code != c.status || !strings.Contains(body, `"error":"`+c.code+`"`) || strings.Contains(body, "driver failure") {
			t.Errorf("%s: status = %d, body = %s, want %d %s without the cause", name, rec.Code, body, c.status, c.code)
		}
	}
}

// The role and the refresh tokens are already committed when the marker of the access tokens cannot
// be written; the call answers 500 and logs an ERROR that names neither the token nor a jti
// (ADR-031, amendment 2026-10-24).
var errSessionsNotMarked = fmt.Errorf("the role was changed but the sessions of the user could not be marked as ended: %w", errors.New("dial tcp 10.0.0.5:6379: connection refused"))

func TestChangeUserRoleAnswers500AndLogsAnErrorWhenTheSessionsCannotBeMarked(t *testing.T) {
	logs := captureLog(t)

	rec := sendRoleChange(&fakeUserAuthorizer{}, &fakeChangeRole{err: errSessionsNotMarked}, roleAttempt{key: roleKey, body: `{"role":"ADMIN","enabled":false}`})

	body := rec.Body.String()
	if rec.Code != http.StatusInternalServerError || !strings.Contains(body, `"error":"INTERNAL_ERROR"`) || strings.Contains(body, "refused") {
		t.Errorf("status = %d, body = %s, want a neutral 500 INTERNAL_ERROR", rec.Code, body)
	}
	if !strings.Contains(logs.String(), "level=ERROR") || strings.Contains(logs.String(), userSecret) || strings.Contains(logs.String(), "jti") {
		t.Errorf("log = %s, want an ERROR without the token or the jti", logs)
	}
}

func TestChangeUserRoleCompletesWhenTheClientDisconnectsInTheMiddleOfTheCall(t *testing.T) {
	requestCtx, cancel := context.WithCancel(context.WithValue(context.Background(), traceKey{}, "trace-1"))
	defer cancel()
	useCase := &cancellingChangeRole{cancelRequest: cancel}
	request := httptest.NewRequest(http.MethodPatch, BasePath+"/users/"+roleTargetID+"/role", strings.NewReader(grantBody)).WithContext(requestCtx)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+userSecret)
	request.Header.Set("Idempotency-Key", roleKey)
	rec := httptest.NewRecorder()

	NewHandler(WithChangeUserRole(&fakeUserAuthorizer{}, useCase)).ServeHTTP(rec, request)

	if rec.Code != http.StatusOK || !useCase.completed {
		t.Errorf("status = %d, completed = %t, want 200 and the change finished although the client left", rec.Code, useCase.completed)
	}
	if !useCase.hasDeadline || useCase.traceID != "trace-1" {
		t.Errorf("deadline = %t, trace = %v, want a bounded context that keeps the values of the request", useCase.hasDeadline, useCase.traceID)
	}
}

// cancellingChangeRole stands for the use case while the client leaves: the request context is cancelled in the
// middle of the call and the change (commit and marker) only completes if the context it received is still alive.
type cancellingChangeRole struct {
	cancelRequest context.CancelFunc
	completed     bool
	hasDeadline   bool
	traceID       any
}

func (f *cancellingChangeRole) ChangeRole(ctx context.Context, _ in.ChangeUserRoleCommand) (in.UserSummary, error) {
	f.cancelRequest()
	_, f.hasDeadline = ctx.Deadline()
	f.traceID = ctx.Value(traceKey{})
	if err := ctx.Err(); err != nil {
		return in.UserSummary{}, err
	}
	f.completed = true
	return promotedUser(), nil
}
