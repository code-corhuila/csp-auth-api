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
	requestID    = "99999999-2222-4333-8444-555555555555"
)

type fakeRegister struct {
	result  in.RequestRegistrationResult
	err     error
	called  int
	command in.RequestRegistrationCommand
}

func (f *fakeRegister) Request(_ context.Context, command in.RequestRegistrationCommand) (in.RequestRegistrationResult, error) {
	f.called++
	f.command = command
	return f.result, f.err
}

func requestedRegistration() in.RequestRegistrationResult {
	return in.RequestRegistrationResult{RequestID: requestID}
}

// withRegister publishes only the first step of the registration, with a confirmation that is never reached.
func withRegister(useCase in.RequestRegistration, gate *Bulkhead) Option {
	return WithRegistration(useCase, &fakeConfirm{}, gate)
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

func send(useCase in.RequestRegistration, a attempt) *httptest.ResponseRecorder {
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
	NewHandler(withRegister(useCase, openGate())).ServeHTTP(rec, request)
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

func TestRegisterAnswers201WithTheIdOfTheRegistrationRequestAndNothingElse(t *testing.T) {
	useCase := &fakeRegister{result: requestedRegistration()}
	rec := send(useCase, attempt{body: validBody(), key: validKey, headers: map[string]string{"X-Correlation-Id": "trace-abc-1"}})

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Location"); got != BasePath+"/registrations/"+requestID {
		t.Errorf("Location = %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("X-Correlation-Id"); got != "trace-abc-1" {
		t.Errorf("X-Correlation-Id = %q, want the received one", got)
	}
	body := decode(t, rec)
	if len(body) != 1 || body["id"] != requestID {
		t.Errorf("body = %v, want only the id of the request", body)
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Error("the response contains the password")
	}
}

func TestRegisterPassesTheRawRequestToTheUseCase(t *testing.T) {
	useCase := &fakeRegister{result: requestedRegistration()}
	send(useCase, attempt{body: validBody(), key: validKey})

	want := in.RequestRegistrationCommand{
		IdempotencyKey: validKey, Email: "Maria@Example.com", Password: secret, Name: "Maria Garcia",
		Phone: "3001234567", Address: "Calle 123 #45-67",
	}
	if useCase.command != want {
		t.Errorf("command = %+v, want %+v", useCase.command, want)
	}
}

func TestRegisterGeneratesACorrelationIdWhenNoneIsSafe(t *testing.T) {
	for name, received := range map[string]string{"absent": "", "too long": strings.Repeat("a", 129), "spaces": "has space"} {
		t.Run(name, func(t *testing.T) {
			rec := send(&fakeRegister{result: requestedRegistration()}, attempt{
				body: validBody(), key: validKey, headers: map[string]string{"X-Correlation-Id": received},
			})
			got := rec.Header().Get("X-Correlation-Id")
			if len(got) != 36 || got == received {
				t.Errorf("X-Correlation-Id = %q, want a generated UUID", got)
			}
		})
	}
}

func TestRegisterReplayAnswers200WithTheSameBodyAndNoLocation(t *testing.T) {
	replay := requestedRegistration()
	replay.Replayed = true
	rec := send(&fakeRegister{result: replay}, attempt{body: validBody(), key: validKey})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Header().Get("Location") != "" {
		t.Error("a replay must not carry Location")
	}
	if body := decode(t, rec); len(body) != 1 || body["id"] != requestID {
		t.Errorf("body = %v, want the id of the first request", body)
	}
}

func TestRegisterAnswersTheSameShapeForEveryAddress(t *testing.T) {
	free := send(&fakeRegister{result: requestedRegistration()}, attempt{body: validBody(), key: validKey})
	taken := send(&fakeRegister{result: in.RequestRegistrationResult{RequestID: "88888888-2222-4333-8444-555555555555"}}, attempt{body: validBody(), key: validKey})

	if free.Code != taken.Code || len(decode(t, free)) != len(decode(t, taken)) || free.Header().Get("Content-Type") != taken.Header().Get("Content-Type") {
		t.Errorf("free %d %s / taken %d %s: status, shape and content type must match", free.Code, free.Body, taken.Code, taken.Body)
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
		"oversized body":      {body: `{"name":"` + strings.Repeat("a", int(fallbackLimits.MaxBodyBytes)) + `"}`, key: validKey},
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
		{"key reused", model.ErrIdempotencyKeyConflict, http.StatusConflict, "IDEMPOTENCY_KEY_CONFLICT", ""},
		{"busy hasher", model.ErrPasswordHasherBusy, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", ""},
		{"wrapped domain validation", errors.Join(errors.New("ctx"), model.ErrInvalidPhone), http.StatusBadRequest, "VALIDATION_ERROR", "phone"},
		{"an email taken is not an error of this route", model.ErrEmailAlreadyRegistered, http.StatusInternalServerError, "INTERNAL_ERROR", ""},
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

func TestRegisterRejectsAnEmailLongerThanTheDatabaseStoresWith400(t *testing.T) {
	useCase := &fakeRegister{}
	body := strings.Replace(validBody(), "Maria@Example.com", addressOfLength(model.MaxEmailLength+1), 1)

	rec := send(useCase, attempt{body: body, key: validKey})

	if rec.Code != http.StatusBadRequest || useCase.called != 0 || !strings.Contains(rec.Body.String(), `"field":"email"`) {
		t.Errorf("status = %d, calls = %d, body = %s, want 400 on the field email and no call", rec.Code, useCase.called, rec.Body)
	}
}
