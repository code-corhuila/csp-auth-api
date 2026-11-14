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
	confirmPath  = BasePath + "/register/confirm"
	confirmToken = "3f2c1b7e-5a9d-4c1e-8b6f-0a1b2c3d4e5f"
)

type fakeConfirm struct {
	result  in.ConfirmRegistrationResult
	err     error
	called  int
	command in.ConfirmRegistrationCommand
}

func (f *fakeConfirm) Confirm(_ context.Context, command in.ConfirmRegistrationCommand) (in.ConfirmRegistrationResult, error) {
	f.called++
	f.command = command
	return f.result, f.err
}

func createdSession() in.ConfirmRegistrationResult {
	return in.ConfirmRegistrationResult{Session: in.LoginUserResult{
		AccessToken:  "access.jwt.value",
		RefreshToken: "refresh-value",
		ExpiresIn:    3600,
		User: in.UserSummary{
			ID: userID, Email: "maria@example.com", Name: "Maria Garcia",
			Roles: []string{"CLIENT"}, Permissions: []string{"catalog:read"},
		},
	}}
}

func confirmBody() string { return `{"token":"` + confirmToken + `"}` }

func sendConfirm(useCase in.ConfirmRegistration, a attempt) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, confirmPath, strings.NewReader(a.body))
	request.Header.Set("Content-Type", "application/json")
	if a.key != "" {
		request.Header.Set("Idempotency-Key", a.key)
	}
	for name, value := range a.headers {
		request.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	NewHandler(WithRegistration(&fakeRegister{}, useCase, openGate())).ServeHTTP(rec, request)
	return rec
}

func TestConfirmRegistrationAnswers201WithTheAuthResponseAndLocation(t *testing.T) {
	useCase := &fakeConfirm{result: createdSession()}
	rec := sendConfirm(useCase, attempt{body: confirmBody(), key: validKey, headers: map[string]string{"User-Agent": "cinema-portal/1.0", "X-Correlation-Id": "trace-abc-1"}})

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Location"); got != BasePath+"/users/"+userID {
		t.Errorf("Location = %q", got)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Correlation-Id") != "trace-abc-1" {
		t.Errorf("Cache-Control = %q, X-Correlation-Id = %q", rec.Header().Get("Cache-Control"), rec.Header().Get("X-Correlation-Id"))
	}
	body := decode(t, rec)
	user := body["user"].(map[string]any)
	if body["expiresIn"] != float64(3600) || user["name"] != "Maria Garcia" {
		t.Errorf("unexpected body %v", body)
	}
	for _, leaked := range []string{"phone", "address", "password", "passwordHash"} {
		if _, ok := user[leaked]; ok {
			t.Errorf("user exposes %q", leaked)
		}
	}
	want := in.ConfirmRegistrationCommand{IdempotencyKey: validKey, Token: confirmToken, UserAgent: "cinema-portal/1.0"}
	if useCase.command != want {
		t.Errorf("command = %+v, want %+v", useCase.command, want)
	}
}

func TestConfirmRegistrationReplayAnswers200WithoutTokens(t *testing.T) {
	replay := createdSession()
	replay.Replayed = true
	replay.Session.AccessToken, replay.Session.RefreshToken, replay.Session.ExpiresIn = "", "", 0
	rec := sendConfirm(&fakeConfirm{result: replay}, attempt{body: confirmBody(), key: validKey})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Header().Get("Location") != "" {
		t.Error("a replay must not carry Location")
	}
	body := decode(t, rec)
	for _, token := range []string{"accessToken", "refreshToken", "expiresIn", "user"} {
		if _, ok := body[token]; ok {
			t.Errorf("replay exposes %q", token)
		}
	}
	if body["id"] != userID {
		t.Errorf("body = %v, want the summary of the account", body)
	}
}

func TestConfirmRegistrationValidatesTheKeyAndTheTokenBeforeTheUseCase(t *testing.T) {
	cases := map[string]struct {
		a      attempt
		fields []string
	}{
		"both invalid":     {attempt{body: `{"token":"nope"}`, key: "short"}, []string{"Idempotency-Key", "token"}},
		"missing key":      {attempt{body: confirmBody()}, []string{"Idempotency-Key"}},
		"missing token":    {attempt{body: `{}`, key: validKey}, []string{"token"}},
		"uppercase token":  {attempt{body: `{"token":"` + strings.ToUpper(confirmToken) + `"}`, key: validKey}, []string{"token"}},
		"unreadable body":  {attempt{body: `{"token":`, key: validKey}, []string{"body"}},
		"oversized body":   {attempt{body: `{"token":"` + strings.Repeat("a", 5000) + `"}`, key: validKey}, []string{"body"}},
		"wrong token type": {attempt{body: `{"token":1}`, key: validKey}, []string{"token"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			useCase := &fakeConfirm{}
			rec := sendConfirm(useCase, c.a)
			if rec.Code != http.StatusBadRequest || useCase.called != 0 {
				t.Fatalf("status = %d, calls = %d, want 400 and no call: %s", rec.Code, useCase.called, rec.Body)
			}
			if envelope := decode(t, rec); envelope["error"] != "VALIDATION_ERROR" || len(detailFields(t, envelope)) == 0 {
				t.Errorf("envelope = %v", envelope)
			}
		})
	}
}

func TestConfirmRegistrationTranslatesUseCaseErrors(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"rejected token", model.ErrRegistrationRejected, http.StatusUnauthorized, "INVALID_TOKEN"},
		{"email taken meanwhile", model.ErrEmailAlreadyRegistered, http.StatusConflict, "EMAIL_ALREADY_REGISTERED"},
		{"key reused", model.ErrIdempotencyKeyConflict, http.StatusConflict, "IDEMPOTENCY_KEY_CONFLICT"},
		{"replay without account", model.ErrUserNotFound, http.StatusInternalServerError, "INTERNAL_ERROR"},
		{"driver failure", errors.New("pq: connection refused at 10.0.0.5:5432 token=" + confirmToken), http.StatusInternalServerError, "INTERNAL_ERROR"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := sendConfirm(&fakeConfirm{err: c.err}, attempt{body: confirmBody(), key: validKey, headers: map[string]string{"X-Correlation-Id": "trace-5"}})
			if rec.Code != c.status {
				t.Fatalf("status = %d, want %d", rec.Code, c.status)
			}
			envelope := decode(t, rec)
			if envelope["error"] != c.code || envelope["traceId"] != "trace-5" || rec.Header().Get("X-Correlation-Id") != "trace-5" {
				t.Errorf("envelope = %v", envelope)
			}
			for _, leaked := range []string{confirmToken, "pq:", "10.0.0.5"} {
				if strings.Contains(rec.Body.String(), leaked) {
					t.Errorf("the response leaks %q: %s", leaked, rec.Body)
				}
			}
		})
	}
}
