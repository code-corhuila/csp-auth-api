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

const serviceSecret = "eyJhbGciOiJSUzI1NiJ9.service.signature"

type fakeAuthorizer struct {
	err   error
	token string
	calls int
}

func (f *fakeAuthorizer) AuthorizeService(_ context.Context, bearerToken string) error {
	f.calls++
	f.token = bearerToken
	if bearerToken == "" {
		return model.ErrServiceTokenInvalid
	}
	return f.err
}

func callProtected(authorizer *fakeAuthorizer, headers map[string]string) (*httptest.ResponseRecorder, *int) {
	reached := 0
	protected := serviceOnly(authorizer, func(w http.ResponseWriter, _ *http.Request) {
		reached++
		w.WriteHeader(http.StatusNoContent)
	})
	request := httptest.NewRequest(http.MethodPost, BasePath+"/internal/test", nil)
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, request)
	return rec, &reached
}

func TestServiceOnlyLetsAnAuthorizedServiceThrough(t *testing.T) {
	authorizer := &fakeAuthorizer{}

	rec, reached := callProtected(authorizer, map[string]string{"Authorization": "Bearer " + serviceSecret})

	if rec.Code != http.StatusNoContent || *reached != 1 || authorizer.token != serviceSecret {
		t.Errorf("status = %d, reached = %d, token = %q, want 204, 1 and the bearer token", rec.Code, *reached, authorizer.token)
	}
}

func TestServiceOnlyReadsTheBearerSchemeInAnyCase(t *testing.T) {
	authorizer := &fakeAuthorizer{}

	rec, reached := callProtected(authorizer, map[string]string{"Authorization": "bearer " + serviceSecret})

	if rec.Code != http.StatusNoContent || *reached != 1 || authorizer.token != serviceSecret {
		t.Errorf("status = %d, reached = %d, token = %q, want 204, 1 and the bearer token", rec.Code, *reached, authorizer.token)
	}
}

func TestServiceOnlyAnswers401WhenTheTokenIsMissingOrInvalid(t *testing.T) {
	cases := map[string]struct {
		headers map[string]string
		err     error
	}{
		"no header":               {nil, nil},
		"empty header":            {map[string]string{"Authorization": ""}, nil},
		"basic scheme":            {map[string]string{"Authorization": "Basic dXNlcjpwYXNz"}, nil},
		"bearer without token":    {map[string]string{"Authorization": "Bearer "}, nil},
		"token rejected":          {map[string]string{"Authorization": "Bearer " + serviceSecret}, model.ErrServiceTokenInvalid},
		"token rejected, wrapped": {map[string]string{"Authorization": "Bearer " + serviceSecret}, errors.Join(model.ErrServiceTokenInvalid, errors.New("expired"))},
	}
	for name, c := range cases {
		authorizer := &fakeAuthorizer{err: c.err}

		rec, reached := callProtected(authorizer, c.headers)

		body := rec.Body.String()
		if rec.Code != http.StatusUnauthorized || *reached != 0 || !strings.Contains(body, `"error":"UNAUTHORIZED"`) || !strings.Contains(body, `"traceId"`) {
			t.Errorf("%s: status = %d, reached = %d, body = %s, want 401 UNAUTHORIZED and the handler not reached", name, rec.Code, *reached, body)
		}
		if rec.Header().Get("WWW-Authenticate") != "Bearer" || rec.Header().Get("Content-Type") != "application/json" {
			t.Errorf("%s: headers = %v, want WWW-Authenticate: Bearer and JSON", name, rec.Header())
		}
	}
}

func TestServiceOnlyAnswers403ForAValidTokenOfAnotherSubject(t *testing.T) {
	authorizer := &fakeAuthorizer{err: model.ErrServiceNotAllowed}

	rec, reached := callProtected(authorizer, map[string]string{"Authorization": "Bearer " + serviceSecret, "X-Correlation-Id": "trace-1"})

	body := rec.Body.String()
	if rec.Code != http.StatusForbidden || *reached != 0 || !strings.Contains(body, `"error":"FORBIDDEN"`) || !strings.Contains(body, `"traceId":"trace-1"`) {
		t.Errorf("status = %d, reached = %d, body = %s, want 403 FORBIDDEN with the correlation id", rec.Code, *reached, body)
	}
	if rec.Header().Get("X-Correlation-Id") != "trace-1" {
		t.Errorf("X-Correlation-Id = %q, want it echoed", rec.Header().Get("X-Correlation-Id"))
	}
}

func TestServiceOnlyAnswersAGenericErrorAndLogsNoTokenWhenTheAuthorizationFails(t *testing.T) {
	var logged bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	authorizer := &fakeAuthorizer{err: errors.New("boom")}

	rec, reached := callProtected(authorizer, map[string]string{"Authorization": "Bearer " + serviceSecret})

	body := rec.Body.String()
	if rec.Code != http.StatusInternalServerError || *reached != 0 || !strings.Contains(body, `"error":"INTERNAL_ERROR"`) || strings.Contains(body, "boom") {
		t.Errorf("status = %d, reached = %d, body = %s, want a neutral 500", rec.Code, *reached, body)
	}
	if !strings.Contains(logged.String(), "boom") || strings.Contains(logged.String(), serviceSecret) {
		t.Errorf("log = %q, want the cause and never the token", logged.String())
	}
}
