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

const loginPath = BasePath + "/login"

type fakeLogin struct {
	result  in.LoginUserResult
	err     error
	called  int
	command in.LoginUserCommand
}

func (f *fakeLogin) Login(_ context.Context, command in.LoginUserCommand) (in.LoginUserResult, error) {
	f.called++
	f.command = command
	return f.result, f.err
}

func loggedInSession() in.LoginUserResult {
	return createdSession().Session
}

func loginBody() string {
	return `{"email":"Maria@Example.com","password":"` + secret + `"}`
}

func sendLogin(useCase in.LoginUser, a attempt) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, loginPath, strings.NewReader(a.body))
	if a.contentType == "" {
		a.contentType = "application/json"
	}
	request.Header.Set("Content-Type", a.contentType)
	for name, value := range a.headers {
		request.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	NewHandler(WithLoginUser(useCase)).ServeHTTP(rec, request)
	return rec
}

func TestLoginRouteExistsOnlyWhenTheUseCaseIsInjected(t *testing.T) {
	rec := httptest.NewRecorder()
	NewHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, loginPath, nil))
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want the route to be absent", rec.Code)
	}
}

func TestLoginAnswers200WithAuthResponseAndNoStoreHeaders(t *testing.T) {
	useCase := &fakeLogin{result: loggedInSession()}

	rec := sendLogin(useCase, attempt{body: loginBody(), headers: map[string]string{"User-Agent": "cinesync-portal/1.0", "X-Correlation-Id": "trace-1"}})

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
	user, _ := body["user"].(map[string]any)
	requireKeys(t, user, "id", "email", "name", "roles", "permissions")
	if user["id"] != userID || user["email"] != "maria@example.com" {
		t.Errorf("user = %v", user)
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Error("the response contains the password")
	}
}

func TestLoginPassesTheCredentialsAndTheUserAgentToTheUseCase(t *testing.T) {
	useCase := &fakeLogin{result: loggedInSession()}

	sendLogin(useCase, attempt{body: loginBody(), headers: map[string]string{"User-Agent": "cinesync-portal/1.0"}})

	want := in.LoginUserCommand{Email: "Maria@Example.com", Password: secret, UserAgent: "cinesync-portal/1.0"}
	if useCase.command != want {
		t.Errorf("command = %+v, want %+v", useCase.command, want)
	}
}

func TestLoginDoesNotApplyThePasswordPolicy(t *testing.T) {
	useCase := &fakeLogin{result: loggedInSession()}

	rec := sendLogin(useCase, attempt{body: `{"email":"maria@example.com","password":"x"}`})

	if rec.Code != http.StatusOK || useCase.called != 1 {
		t.Errorf("status = %d, calls = %d, want 200 and one call: a short password is a credential, not a choice", rec.Code, useCase.called)
	}
}

func TestLoginMalformedEmailIsLeftToTheUseCase(t *testing.T) {
	useCase := &fakeLogin{err: model.ErrInvalidCredentials}

	rec := sendLogin(useCase, attempt{body: `{"email":"not-an-email","password":"` + secret + `"}`})

	if rec.Code != http.StatusUnauthorized || useCase.called != 1 {
		t.Errorf("status = %d, calls = %d, want 401 from the use case", rec.Code, useCase.called)
	}
}

func TestLoginRejectsMissingOrEmptyFieldsNamingThem(t *testing.T) {
	cases := map[string]struct {
		body string
		want string
	}{
		"empty object":   {`{}`, "email,password"},
		"empty email":    {`{"email":"","password":"x"}`, "email"},
		"missing secret": {`{"email":"maria@example.com"}`, "password"},
		"empty password": {`{"email":"maria@example.com","password":""}`, "password"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			useCase := &fakeLogin{}
			rec := sendLogin(useCase, attempt{body: c.body})
			envelope := decode(t, rec)
			if rec.Code != http.StatusBadRequest || envelope["error"] != "VALIDATION_ERROR" {
				t.Fatalf("status = %d, body = %v, want 400 VALIDATION_ERROR", rec.Code, envelope)
			}
			requireKeys(t, envelope, "message", "traceId")
			if got := strings.Join(detailFields(t, envelope), ","); got != c.want {
				t.Errorf("details fields = %s, want %s", got, c.want)
			}
			if useCase.called != 0 {
				t.Error("the use case must not run")
			}
		})
	}
}

func TestLoginRejectsUnreadableBodies(t *testing.T) {
	cases := map[string]attempt{
		"malformed json":     {body: `{"email":`},
		"not an object":      {body: `[]`},
		"trailing data":      {body: loginBody() + `{}`},
		"empty body":         {body: ``},
		"wrong content type": {body: loginBody(), contentType: "text/plain"},
		"oversized body":     {body: `{"password":"` + strings.Repeat("a", maxBodyBytes) + `"}`},
		"email not a string": {body: `{"email":42,"password":"x"}`},
		"password not text":  {body: `{"email":"maria@example.com","password":["x"]}`},
	}
	for name, a := range cases {
		t.Run(name, func(t *testing.T) {
			useCase := &fakeLogin{}
			rec := sendLogin(useCase, a)
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

func TestLoginWrongPropertyTypeNamesTheProperty(t *testing.T) {
	rec := sendLogin(&fakeLogin{}, attempt{body: `{"email":42,"password":"x"}`})
	if got := detailFields(t, decode(t, rec)); len(got) != 1 || got[0] != "email" {
		t.Errorf("details fields = %v, want [email]", got)
	}
}

func TestLoginCredentialFailuresShareOneFixedBody(t *testing.T) {
	causes := map[string]error{
		"plain":   model.ErrInvalidCredentials,
		"wrapped": errors.Join(errors.New("email not found"), model.ErrInvalidCredentials),
	}
	var bodies []map[string]any
	for name, cause := range causes {
		t.Run(name, func(t *testing.T) {
			rec := sendLogin(&fakeLogin{err: cause}, attempt{body: loginBody(), headers: map[string]string{"X-Correlation-Id": "same-trace"}})
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			envelope := decode(t, rec)
			if envelope["error"] != "INVALID_CREDENTIALS" || envelope["message"] != "Incorrect email or password" {
				t.Errorf("envelope = %v", envelope)
			}
			if _, hasDetails := envelope["details"]; hasDetails {
				t.Error("a credential failure must not say which part failed")
			}
			if strings.Contains(rec.Body.String(), secret) || strings.Contains(rec.Body.String(), "not found") {
				t.Errorf("the response leaks input or cause: %s", rec.Body)
			}
			bodies = append(bodies, envelope)
		})
	}
	if len(bodies) == 2 && (bodies[0]["error"] != bodies[1]["error"] || bodies[0]["message"] != bodies[1]["message"] || bodies[0]["traceId"] != bodies[1]["traceId"]) {
		t.Errorf("bodies differ: %v vs %v", bodies[0], bodies[1])
	}
}

func TestLoginLockedAccountAnswers423(t *testing.T) {
	rec := sendLogin(&fakeLogin{err: model.ErrUserLocked}, attempt{body: loginBody()})

	if rec.Code != http.StatusLocked {
		t.Fatalf("status = %d, want 423", rec.Code)
	}
	envelope := decode(t, rec)
	requireKeys(t, envelope, "error", "message", "traceId")
	if envelope["error"] != "ACCOUNT_LOCKED" {
		t.Errorf("error = %v, want ACCOUNT_LOCKED", envelope["error"])
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Correlation-Id") == "" {
		t.Errorf("headers = %v, want no-store and a correlation id", rec.Header())
	}
}

func TestLoginUnexpectedErrorAnswersGeneric500(t *testing.T) {
	cause := errors.New("pq: password authentication failed for user auth_app " + secret)

	rec := sendLogin(&fakeLogin{err: cause}, attempt{body: loginBody()})

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	envelope := decode(t, rec)
	if envelope["error"] != "INTERNAL_ERROR" {
		t.Errorf("error = %v, want INTERNAL_ERROR", envelope["error"])
	}
	requireKeys(t, envelope, "traceId")
	if strings.Contains(rec.Body.String(), "pq:") || strings.Contains(rec.Body.String(), secret) {
		t.Errorf("the response leaks the cause: %s", rec.Body)
	}
}
