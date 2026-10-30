package httpapi

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

var errRevokedListDown = fmt.Errorf("%w: dial tcp 10.0.0.5:6379: connection refused", model.ErrRevokedTokensUnavailable)

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logs
}

func TestProtectedRoutesAnswer401ForARevokedToken(t *testing.T) {
	for name, call := range map[string]func() (*httptest.ResponseRecorder, int){
		"permission guard": func() (*httptest.ResponseRecorder, int) {
			rec, callers := callPermissionProtected(&fakeUserAuthorizer{err: model.ErrAccessTokenInvalid}, map[string]string{"Authorization": "Bearer " + userSecret})
			return rec, len(callers)
		},
		"authentication guard": func() (*httptest.ResponseRecorder, int) {
			useCase := &fakeLogout{}
			return sendLogout(&fakeAuthenticator{err: model.ErrAccessTokenInvalid}, useCase, logoutAttempt{}), useCase.called
		},
	} {
		rec, reached := call()

		if rec.Code != http.StatusUnauthorized || reached != 0 || !strings.Contains(rec.Body.String(), `"error":"UNAUTHORIZED"`) {
			t.Errorf("%s: status = %d, handler reached = %d, body = %s, want 401 UNAUTHORIZED", name, rec.Code, reached, rec.Body)
		}
	}
}

func TestPermissionGuardFailsClosedWhenTheRevokedListIsDownAndLogsOnlyAWarning(t *testing.T) {
	logs := captureLog(t)

	rec, callers := callPermissionProtected(&fakeUserAuthorizer{err: errRevokedListDown}, map[string]string{"Authorization": "Bearer " + userSecret})

	body := rec.Body.String()
	if rec.Code != http.StatusInternalServerError || len(callers) != 0 || !strings.Contains(body, `"error":"INTERNAL_ERROR"`) || strings.Contains(body, "refused") {
		t.Errorf("status = %d, callers = %v, body = %s, want a neutral 500 INTERNAL_ERROR", rec.Code, callers, body)
	}
	if !strings.Contains(logs.String(), "level=WARN") || strings.Contains(logs.String(), userSecret) || strings.Contains(logs.String(), "jti") {
		t.Errorf("log = %s, want a WARN without the token or the jti", logs)
	}
}

func TestLogoutGoesOnWhenTheRevokedListIsDownAndLogsOnlyAWarning(t *testing.T) {
	logs := captureLog(t)
	useCase := &fakeLogout{}

	rec := sendLogout(&fakeAuthenticator{err: errRevokedListDown}, useCase, logoutAttempt{})

	if rec.Code != http.StatusNoContent || useCase.called != 1 {
		t.Errorf("status = %d, logout calls = %d, want 204 and the logout run", rec.Code, useCase.called)
	}
	if !strings.Contains(logs.String(), "level=WARN") || strings.Contains(logs.String(), userSecret) || strings.Contains(logs.String(), "jti") {
		t.Errorf("log = %s, want a WARN without the token or the jti", logs)
	}
}
