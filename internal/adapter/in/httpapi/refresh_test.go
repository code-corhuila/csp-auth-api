package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const (
	refreshPath    = BasePath + "/refresh"
	presentedToken = "7b7f1a52-0c1e-4f0b-9d55-3f6c1b9e2a10"
)

type fakeRefresh struct {
	result  in.LoginUserResult
	err     error
	called  int
	command in.RefreshSessionCommand
}

func (f *fakeRefresh) Refresh(_ context.Context, command in.RefreshSessionCommand) (in.LoginUserResult, error) {
	f.called++
	f.command = command
	return f.result, f.err
}

func refreshBody() string {
	return `{"refreshToken":"` + presentedToken + `"}`
}

func sendRefresh(useCase in.RefreshSession, a attempt) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, refreshPath, strings.NewReader(a.body))
	if a.contentType == "" {
		a.contentType = "application/json"
	}
	request.Header.Set("Content-Type", a.contentType)
	for name, value := range a.headers {
		request.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	NewHandler(WithRefreshSession(useCase)).ServeHTTP(rec, request)
	return rec
}

func TestRefreshRouteExistsOnlyWhenTheUseCaseIsInjected(t *testing.T) {
	rec := httptest.NewRecorder()
	NewHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, refreshPath, nil))
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want the route to be absent", rec.Code)
	}
}

func TestRefreshAnswers200WithAuthResponseAndNoStoreHeaders(t *testing.T) {
	useCase := &fakeRefresh{result: loggedInSession()}

	rec := sendRefresh(useCase, attempt{body: refreshBody(), headers: map[string]string{"User-Agent": "cinesync-portal/1.0", "X-Correlation-Id": "trace-1"}})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body)
	}
	for header, want := range map[string]string{
		"Cache-Control": "no-store", "Pragma": "no-cache", "X-Correlation-Id": "trace-1", "Content-Type": "application/json",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	body := decode(t, rec)
	requireKeys(t, body, "accessToken", "refreshToken", "expiresIn", "user")
	if body["accessToken"] != "access.jwt.value" || body["refreshToken"] != "refresh-value" || body["expiresIn"] != float64(3600) {
		t.Errorf("tokens = %v", body)
	}
	if want := (in.RefreshSessionCommand{RefreshToken: presentedToken, UserAgent: "cinesync-portal/1.0"}); useCase.command != want {
		t.Errorf("command = %+v, want %+v", useCase.command, want)
	}
}

func TestRefreshRejectsAMissingOrEmptyTokenNamingTheProperty(t *testing.T) {
	for name, body := range map[string]string{"empty object": `{}`, "empty token": `{"refreshToken":""}`} {
		t.Run(name, func(t *testing.T) {
			useCase := &fakeRefresh{}
			rec := sendRefresh(useCase, attempt{body: body})
			envelope := decode(t, rec)
			if rec.Code != http.StatusBadRequest || envelope["error"] != "VALIDATION_ERROR" {
				t.Fatalf("status = %d, body = %v, want 400 VALIDATION_ERROR", rec.Code, envelope)
			}
			if got := strings.Join(detailFields(t, envelope), ","); got != "refreshToken" {
				t.Errorf("details fields = %s, want refreshToken", got)
			}
			if useCase.called != 0 {
				t.Error("the use case must not run")
			}
		})
	}
}

func TestRefreshRejectsUnreadableBodies(t *testing.T) {
	cases := map[string]attempt{
		"malformed json":     {body: `{"refreshToken":`},
		"not an object":      {body: `[]`},
		"trailing data":      {body: refreshBody() + `{}`},
		"empty body":         {body: ``},
		"wrong content type": {body: refreshBody(), contentType: "text/plain"},
		"oversized body":     {body: `{"refreshToken":"` + strings.Repeat("a", maxBodyBytes) + `"}`},
		"token not a string": {body: `{"refreshToken":42}`},
	}
	for name, a := range cases {
		t.Run(name, func(t *testing.T) {
			useCase := &fakeRefresh{}
			rec := sendRefresh(useCase, a)
			envelope := decode(t, rec)
			if rec.Code != http.StatusBadRequest || envelope["error"] != "VALIDATION_ERROR" || len(detailFields(t, envelope)) == 0 {
				t.Fatalf("status = %d, envelope = %v, want 400 VALIDATION_ERROR with details", rec.Code, envelope)
			}
			if useCase.called != 0 {
				t.Error("the use case must not run")
			}
		})
	}
}

func TestRefreshRejectedTokensShareOneFixedBodyThatNeverEchoesTheToken(t *testing.T) {
	causes := map[string]error{
		"plain":   model.ErrRefreshTokenRejected,
		"wrapped": errors.Join(errors.New("token expired"), model.ErrRefreshTokenRejected),
	}
	var bodies []map[string]any
	for name, cause := range causes {
		t.Run(name, func(t *testing.T) {
			rec := sendRefresh(&fakeRefresh{err: cause}, attempt{body: refreshBody(), headers: map[string]string{"X-Correlation-Id": "same-trace"}})
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			envelope := decode(t, rec)
			if envelope["error"] != "INVALID_REFRESH_TOKEN" || envelope["message"] != "Refresh token is invalid, expired, or already used" {
				t.Errorf("envelope = %v", envelope)
			}
			if _, hasDetails := envelope["details"]; hasDetails {
				t.Error("a rejection must not say why")
			}
			if strings.Contains(rec.Body.String(), presentedToken) || strings.Contains(rec.Body.String(), "expired\"") {
				t.Errorf("the response leaks the token or the cause: %s", rec.Body)
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
			}
			bodies = append(bodies, envelope)
		})
	}
	if len(bodies) == 2 && (bodies[0]["error"] != bodies[1]["error"] || bodies[0]["message"] != bodies[1]["message"] || bodies[0]["traceId"] != bodies[1]["traceId"]) {
		t.Errorf("bodies differ: %v vs %v", bodies[0], bodies[1])
	}
}

func TestRefreshLockedAccountAnswers423(t *testing.T) {
	rec := sendRefresh(&fakeRefresh{err: model.ErrUserLocked}, attempt{body: refreshBody()})

	envelope := decode(t, rec)
	if rec.Code != http.StatusLocked || envelope["error"] != "ACCOUNT_LOCKED" {
		t.Errorf("status = %d, body = %v, want 423 ACCOUNT_LOCKED", rec.Code, envelope)
	}
	requireKeys(t, envelope, "message", "traceId")
}

func TestRefreshUnexpectedErrorAnswersGeneric500(t *testing.T) {
	cause := errors.New("pq: password authentication failed for user auth_app " + presentedToken)

	rec := sendRefresh(&fakeRefresh{err: cause}, attempt{body: refreshBody()})

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	envelope := decode(t, rec)
	if envelope["error"] != "INTERNAL_ERROR" {
		t.Errorf("error = %v, want INTERNAL_ERROR", envelope["error"])
	}
	requireKeys(t, envelope, "traceId")
	if strings.Contains(rec.Body.String(), "pq:") || strings.Contains(rec.Body.String(), presentedToken) {
		t.Errorf("the response leaks the cause: %s", rec.Body)
	}
}
