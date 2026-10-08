package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const (
	registerPath = BasePath + "/register"
	secret       = "Sup3rSecretPass"
	validKey     = "key-12345678"
	userID       = "11111111-2222-4333-8444-555555555555"
)

type fakeRegister struct {
	result  in.RegisterUserResult
	err     error
	called  int
	command in.RegisterUserCommand
}

func (f *fakeRegister) Register(_ context.Context, command in.RegisterUserCommand) (in.RegisterUserResult, error) {
	f.called++
	f.command = command
	return f.result, f.err
}

func createdSession() in.RegisterUserResult {
	return in.RegisterUserResult{Session: in.LoginUserResult{
		AccessToken:  "access.jwt.value",
		RefreshToken: "refresh-value",
		ExpiresIn:    3600,
		User: in.UserSummary{
			ID: userID, Email: "maria@example.com", Name: "Maria Garcia",
			Roles: []string{"CLIENT"}, Permissions: []string{"catalog:read"},
		},
	}}
}

func validBody() string {
	return `{"email":"Maria@Example.com","password":"` + secret + `","name":"Maria Garcia","phone":"3001234567","address":"Calle 123 #45-67"}`
}

type attempt struct {
	body        string
	key         string
	contentType string
	headers     map[string]string
}

func send(useCase in.RegisterUser, a attempt) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, registerPath, strings.NewReader(a.body))
	if a.contentType == "" {
		a.contentType = "application/json"
	}
	request.Header.Set("Content-Type", a.contentType)
	if a.key != "" {
		request.Header.Set("Idempotency-Key", a.key)
	}
	for name, value := range a.headers {
		request.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	NewHandler(WithRegisterUser(useCase)).ServeHTTP(rec, request)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not a JSON object: %v (%s)", err, rec.Body.String())
	}
	return body
}

// requireKeys checks the required properties of a schema of auth-service.yaml / _shared.yaml.
func requireKeys(t *testing.T, body map[string]any, required ...string) {
	t.Helper()
	for _, key := range required {
		if _, ok := body[key]; !ok {
			t.Errorf("missing required property %q in %v", key, body)
		}
	}
}

func detailFields(t *testing.T, body map[string]any) []string {
	t.Helper()
	details, _ := body["details"].([]any)
	var fields []string
	for _, item := range details {
		fields = append(fields, item.(map[string]any)["field"].(string))
	}
	return fields
}

func TestRegisterRouteExistsOnlyWhenTheUseCaseIsInjected(t *testing.T) {
	rec := httptest.NewRecorder()
	NewHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, registerPath, nil))
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want the route to be absent", rec.Code)
	}
}

func TestRegisterCreatesTheAccountAndAnswers201WithAuthResponse(t *testing.T) {
	useCase := &fakeRegister{result: createdSession()}
	rec := send(useCase, attempt{
		body: validBody(), key: validKey,
		headers: map[string]string{"X-Correlation-Id": "trace-abc-1", "User-Agent": "cinema-portal/1.0"},
	})

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Location"); got != BasePath+"/users/"+userID {
		t.Errorf("Location = %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("X-Correlation-Id"); got != "trace-abc-1" {
		t.Errorf("X-Correlation-Id = %q, want the received one", got)
	}
	body := decode(t, rec)
	requireKeys(t, body, "accessToken", "refreshToken", "expiresIn", "user") // AuthResponse.required
	user := body["user"].(map[string]any)
	requireKeys(t, user, "id", "email", "roles") // UserSummary.required
	if body["expiresIn"] != float64(3600) || user["name"] != "Maria Garcia" {
		t.Errorf("unexpected body %v", body)
	}
	for _, leaked := range []string{"phone", "address", "password", "passwordHash"} {
		if _, ok := user[leaked]; ok {
			t.Errorf("user exposes %q", leaked)
		}
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Error("the response contains the password")
	}
}

func TestRegisterPassesTheRawRequestToTheUseCase(t *testing.T) {
	useCase := &fakeRegister{result: createdSession()}
	send(useCase, attempt{body: validBody(), key: validKey, headers: map[string]string{"User-Agent": "cinema-portal/1.0"}})

	want := in.RegisterUserCommand{
		IdempotencyKey: validKey, Email: "Maria@Example.com", Password: secret, Name: "Maria Garcia",
		Phone: "3001234567", Address: "Calle 123 #45-67", UserAgent: "cinema-portal/1.0",
	}
	if useCase.command != want {
		t.Errorf("command = %+v, want %+v", useCase.command, want)
	}
}

func TestRegisterGeneratesACorrelationIdWhenNoneIsSafe(t *testing.T) {
	for name, received := range map[string]string{"absent": "", "too long": strings.Repeat("a", 129), "spaces": "has space"} {
		t.Run(name, func(t *testing.T) {
			rec := send(&fakeRegister{result: createdSession()}, attempt{
				body: validBody(), key: validKey, headers: map[string]string{"X-Correlation-Id": received},
			})
			got := rec.Header().Get("X-Correlation-Id")
			if len(got) != 36 || got == received {
				t.Errorf("X-Correlation-Id = %q, want a generated UUID", got)
			}
		})
	}
}

func TestRegisterReplayAnswers200WithoutTokens(t *testing.T) {
	replay := createdSession()
	replay.Replayed = true
	replay.Session.AccessToken, replay.Session.RefreshToken, replay.Session.ExpiresIn = "", "", 0
	rec := send(&fakeRegister{result: replay}, attempt{body: validBody(), key: validKey})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Header().Get("Location") != "" {
		t.Error("a replay must not carry Location")
	}
	body := decode(t, rec)
	requireKeys(t, body, "id", "email", "roles") // UserSummary.required
	for _, token := range []string{"accessToken", "refreshToken", "expiresIn", "user"} {
		if _, ok := body[token]; ok {
			t.Errorf("replay exposes %q", token)
		}
	}
}

func TestRegisterReportsEveryInvalidFieldAtOnce(t *testing.T) {
	useCase := &fakeRegister{}
	body := `{"email":"nope","password":"weakpw","name":"","phone":"abc","address":""}`
	rec := send(useCase, attempt{body: body, key: "short", headers: map[string]string{"X-Correlation-Id": "trace-9"}})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	envelope := decode(t, rec)
	requireKeys(t, envelope, "error", "message", "traceId") // ErrorResponse.required
	if envelope["error"] != "VALIDATION_ERROR" || envelope["traceId"] != "trace-9" {
		t.Errorf("envelope = %v", envelope)
	}
	want := []string{"Idempotency-Key", "email", "password", "name", "phone", "address"}
	if got := detailFields(t, envelope); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("details fields = %v, want %v", got, want)
	}
	if useCase.called != 0 {
		t.Error("the use case must not run with invalid input")
	}
	if strings.Contains(rec.Body.String(), "weakpw") {
		t.Error("the response echoes the password")
	}
}

func TestRegisterRejectsAMissingIdempotencyKey(t *testing.T) {
	rec := send(&fakeRegister{}, attempt{body: validBody()})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := detailFields(t, decode(t, rec)); len(got) != 1 || got[0] != "Idempotency-Key" {
		t.Errorf("details fields = %v, want [Idempotency-Key]", got)
	}
}

func TestRegisterRejectsAPasswordOver72Bytes(t *testing.T) {
	body := strings.Replace(validBody(), secret, "A1"+strings.Repeat("b", 71), 1)
	rec := send(&fakeRegister{}, attempt{body: body, key: validKey})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := detailFields(t, decode(t, rec)); len(got) != 1 || got[0] != "password" {
		t.Errorf("details fields = %v, want [password]", got)
	}
}

func TestRegisterRejectsUnreadableBodies(t *testing.T) {
	cases := map[string]attempt{
		"malformed json":      {body: `{"email":`, key: validKey},
		"not an object":       {body: `[]`, key: validKey},
		"trailing data":       {body: validBody() + `{}`, key: validKey},
		"empty body":          {body: ``, key: validKey},
		"wrong content type":  {body: validBody(), key: validKey, contentType: "text/plain"},
		"oversized body":      {body: `{"name":"` + strings.Repeat("a", maxRegisterBodyBytes) + `"}`, key: validKey},
		"wrong property type": {body: `{"phone":3001234567}`, key: validKey},
	}
	for name, a := range cases {
		t.Run(name, func(t *testing.T) {
			useCase := &fakeRegister{}
			rec := send(useCase, a)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			envelope := decode(t, rec)
			if envelope["error"] != "VALIDATION_ERROR" || len(detailFields(t, envelope)) == 0 {
				t.Errorf("envelope = %v", envelope)
			}
			if useCase.called != 0 {
				t.Error("the use case must not run")
			}
		})
	}
}

func TestRegisterWrongPropertyTypeNamesTheProperty(t *testing.T) {
	rec := send(&fakeRegister{}, attempt{body: `{"phone":3001234567}`, key: validKey})
	if got := detailFields(t, decode(t, rec)); len(got) != 1 || got[0] != "phone" {
		t.Errorf("details fields = %v, want [phone]", got)
	}
}

func TestRegisterTranslatesUseCaseErrors(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		status     int
		code       string
		detailName string
	}{
		{"email taken", model.ErrEmailAlreadyRegistered, http.StatusConflict, "EMAIL_ALREADY_REGISTERED", ""},
		{"key reused", model.ErrIdempotencyKeyConflict, http.StatusConflict, "IDEMPOTENCY_KEY_CONFLICT", ""},
		{"wrapped domain validation", errors.Join(errors.New("ctx"), model.ErrInvalidPhone), http.StatusBadRequest, "VALIDATION_ERROR", "phone"},
		{"replay without account", model.ErrUserNotFound, http.StatusInternalServerError, "INTERNAL_ERROR", ""},
		{"driver failure", errors.New("pq: connection refused at 10.0.0.5:5432 password=" + secret), http.StatusInternalServerError, "INTERNAL_ERROR", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := send(&fakeRegister{err: c.err}, attempt{
				body: validBody(), key: validKey, headers: map[string]string{"X-Correlation-Id": "trace-5"},
			})
			if rec.Code != c.status {
				t.Fatalf("status = %d, want %d", rec.Code, c.status)
			}
			envelope := decode(t, rec)
			requireKeys(t, envelope, "error", "message", "traceId")
			if envelope["error"] != c.code || envelope["traceId"] != "trace-5" {
				t.Errorf("envelope = %v", envelope)
			}
			if rec.Header().Get("X-Correlation-Id") != "trace-5" {
				t.Error("the error response must repeat X-Correlation-Id")
			}
			if c.detailName != "" && detailFields(t, envelope)[0] != c.detailName {
				t.Errorf("details = %v", envelope["details"])
			}
			text := rec.Body.String()
			for _, leaked := range []string{secret, "pq:", "10.0.0.5", "does not exist"} {
				if strings.Contains(text, leaked) {
					t.Errorf("the response leaks %q: %s", leaked, text)
				}
			}
		})
	}
}
