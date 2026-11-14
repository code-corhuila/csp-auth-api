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

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const userSecret = "eyJhbGciOiJSUzI1NiJ9.user.signature"

type fakeUserAuthorizer struct {
	err        error
	token      string
	permission string
}

func (f *fakeUserAuthorizer) AuthorizeUser(_ context.Context, bearerToken, permission string) (string, error) {
	f.token, f.permission = bearerToken, permission
	if f.err != nil {
		return "", f.err
	}
	return "admin-1", nil
}

func callPermissionProtected(authorizer *fakeUserAuthorizer, headers map[string]string) (*httptest.ResponseRecorder, []string) {
	var callers []string
	protected := requirePermission(authorizer, "user:role:update", func(w http.ResponseWriter, _ *http.Request, callerID string) {
		callers = append(callers, callerID)
		w.WriteHeader(http.StatusNoContent)
	})
	request := httptest.NewRequest(http.MethodGet, BasePath+"/users", nil)
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, request)
	return rec, callers
}

func TestRequirePermissionLetsTheCallerThroughAndPassesItsId(t *testing.T) {
	authorizer := &fakeUserAuthorizer{}

	rec, callers := callPermissionProtected(authorizer, map[string]string{"Authorization": "Bearer " + userSecret})

	if rec.Code != http.StatusNoContent || len(callers) != 1 || callers[0] != "admin-1" {
		t.Errorf("status = %d, callers = %v, want 204 and admin-1", rec.Code, callers)
	}
	if authorizer.token != userSecret || authorizer.permission != "user:role:update" {
		t.Errorf("authorized %q for %q, want the bearer token and the required permission", authorizer.token, authorizer.permission)
	}
}

func TestRequirePermissionAnswers401WhenTheTokenIsMissingOrInvalid(t *testing.T) {
	cases := map[string]map[string]string{
		"no header":     nil,
		"basic scheme":  {"Authorization": "Basic dXNlcjpwYXNz"},
		"invalid token": {"Authorization": "Bearer " + userSecret},
	}
	for name, headers := range cases {
		rec, callers := callPermissionProtected(&fakeUserAuthorizer{err: model.ErrAccessTokenInvalid}, headers)

		body := rec.Body.String()
		if rec.Code != http.StatusUnauthorized || len(callers) != 0 || !strings.Contains(body, `"error":"UNAUTHORIZED"`) || !strings.Contains(body, `"traceId"`) {
			t.Errorf("%s: status = %d, callers = %v, body = %s, want 401 UNAUTHORIZED and the handler not reached", name, rec.Code, callers, body)
		}
		if rec.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Errorf("%s: WWW-Authenticate = %q, want Bearer", name, rec.Header().Get("WWW-Authenticate"))
		}
	}
}

func TestRequirePermissionAnswers403ForAValidTokenWithoutThePermission(t *testing.T) {
	rec, callers := callPermissionProtected(&fakeUserAuthorizer{err: model.ErrPermissionDenied},
		map[string]string{"Authorization": "Bearer " + userSecret, "X-Correlation-Id": "trace-1"})

	body := rec.Body.String()
	if rec.Code != http.StatusForbidden || len(callers) != 0 || !strings.Contains(body, `"error":"FORBIDDEN"`) || !strings.Contains(body, `"traceId":"trace-1"`) {
		t.Errorf("status = %d, callers = %v, body = %s, want 403 FORBIDDEN with the correlation id", rec.Code, callers, body)
	}
}

func TestRequirePermissionAnswersAGenericErrorAndLogsNoToken(t *testing.T) {
	var logged bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	rec, callers := callPermissionProtected(&fakeUserAuthorizer{err: errors.New("boom")}, map[string]string{"Authorization": "Bearer " + userSecret})

	body := rec.Body.String()
	if rec.Code != http.StatusInternalServerError || len(callers) != 0 || !strings.Contains(body, `"error":"INTERNAL_ERROR"`) || strings.Contains(body, "boom") {
		t.Errorf("status = %d, callers = %v, body = %s, want a neutral 500", rec.Code, callers, body)
	}
	if !strings.Contains(logged.String(), "boom") || strings.Contains(logged.String(), userSecret) {
		t.Errorf("log = %q, want the cause and never the token", logged.String())
	}
}
