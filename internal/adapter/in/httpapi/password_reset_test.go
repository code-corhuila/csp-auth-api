package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const (
	forgotPath      = BasePath + "/forgot-password"
	resetPath       = BasePath + "/reset-password"
	forgotBody      = `{"email":"ana@example.com"}`
	forgotKey       = "forgot-key-0001"
	resetTokenText  = "3f2c1b7e-5a9d-4c1e-8b6f-0a1b2c3d4e5f"
	resetPasswordIn = "NewSecret123"
	resetBody       = `{"token":"` + resetTokenText + `","password":"` + resetPasswordIn + `"}`
)

type fakeRequestPasswordReset struct {
	err     error
	called  int
	command in.RequestPasswordResetCommand
}

func (f *fakeRequestPasswordReset) RequestReset(_ context.Context, command in.RequestPasswordResetCommand) error {
	f.called++
	f.command = command
	return f.err
}

type fakeResetPassword struct {
	err     error
	called  int
	command in.ResetPasswordCommand
}

func (f *fakeResetPassword) Reset(_ context.Context, command in.ResetPasswordCommand) error {
	f.called++
	f.command = command
	return f.err
}

type resetAttempt struct {
	path, body  string
	contentType string
	headers     map[string]string
}

func forgotAttempt(body string) resetAttempt {
	return resetAttempt{path: forgotPath, body: body, headers: map[string]string{"Idempotency-Key": forgotKey}}
}

func resetPasswordAttempt(body string) resetAttempt { return resetAttempt{path: resetPath, body: body} }

func tracedReset(a resetAttempt) resetAttempt {
	if a.headers == nil {
		a.headers = map[string]string{}
	}
	a.headers["X-Correlation-Id"] = traceID
	return a
}

type resetGates struct{ forgot, reset *Bulkhead }

func openGates() resetGates {
	forgot, _ := NewBulkhead(1000, time.Second)
	reset, _ := NewBulkhead(1000, time.Second)
	return resetGates{forgot, reset}
}

func sendPasswordReset(gates resetGates, request in.RequestPasswordReset, reset in.ResetPassword, a resetAttempt) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, a.path, strings.NewReader(a.body))
	req.Header.Set("Content-Type", "application/json")
	if a.contentType != "" {
		req.Header.Set("Content-Type", a.contentType)
	}
	for name, value := range a.headers {
		req.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	NewHandler(WithPasswordReset(request, reset, gates.forgot, gates.reset)).ServeHTTP(rec, req)
	return rec
}

func TestPasswordResetRoutesExistOnlyWhenTheUseCasesAreInjected(t *testing.T) {
	for _, path := range []string{forgotPath, resetPath} {
		rec := httptest.NewRecorder()
		NewHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("POST %s: status = %d, want 404 while the routes are not injected", path, rec.Code)
		}
	}
}

func TestPasswordResetRoutesAnswerAJSON404WhenTheyAreNotEnabled(t *testing.T) {
	for _, path := range []string{forgotPath, resetPath} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(forgotBody))
		req.Header.Set("X-Correlation-Id", traceID)
		NewHandler(WithPasswordResetNotEnabled()).ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), `"error":"NOT_FOUND"`) || rec.Header().Get("X-Correlation-Id") != traceID {
			t.Errorf("POST %s: status = %d, body = %s, want the 404 envelope of the contract", path, rec.Code, rec.Body)
		}
	}
}

func TestForgotPasswordAnswers202WithoutBodyAndWithoutAuthentication(t *testing.T) {
	useCase := &fakeRequestPasswordReset{}

	rec := sendPasswordReset(openGates(), useCase, &fakeResetPassword{}, forgotAttempt(` {"email":" Ana@Example.com "}`))

	if rec.Code != http.StatusAccepted || rec.Body.Len() != 0 || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Correlation-Id") == "" {
		t.Fatalf("status = %d, body = %q, headers = %v, want 202, no body, no-store and a correlation id", rec.Code, rec.Body, rec.Header())
	}
	if want := (in.RequestPasswordResetCommand{IdempotencyKey: forgotKey, Email: " Ana@Example.com "}); useCase.command != want {
		t.Errorf("command = %+v, want %+v", useCase.command, want)
	}
}

func TestForgotPasswordRequiresAnIdempotencyKeyOf8To128CharactersBeforeTheUseCaseAndTheGate(t *testing.T) {
	keys := map[string]*string{
		"missing":   nil,
		"too short": ptr("1234567"),
		"too long":  ptr(strings.Repeat("k", 129)),
	}
	for name, key := range keys {
		t.Run(name, func(t *testing.T) {
			useCase, gates := &fakeRequestPasswordReset{}, openGates()
			gates.forgot, _ = NewBulkhead(1, time.Millisecond)
			a := tracedReset(forgotAttempt(forgotBody))
			delete(a.headers, "Idempotency-Key")
			if key != nil {
				a.headers["Idempotency-Key"] = *key
			}

			rec := sendPasswordReset(gates, useCase, &fakeResetPassword{}, a)

			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"field":"Idempotency-Key"`) || useCase.called != 0 {
				t.Fatalf("status = %d, body = %s, calls = %d, want 400 with a detail for Idempotency-Key and no call", rec.Code, rec.Body, useCase.called)
			}
			if _, admitted := gates.forgot.Acquire(context.Background()); !admitted {
				t.Error("an invalid request took a slot of the gate")
			}
		})
	}
}

func TestResetPasswordTakesNoIdempotencyKey(t *testing.T) {
	useCase := &fakeResetPassword{}

	rec := sendPasswordReset(openGates(), &fakeRequestPasswordReset{}, useCase, resetPasswordAttempt(resetBody))

	if rec.Code != http.StatusNoContent || useCase.called != 1 {
		t.Errorf("status = %d, calls = %d, want 204 without the header", rec.Code, useCase.called)
	}
}

func ptr(value string) *string { return &value }

func TestForgotPasswordRejectsAnInvalidBodyBeforeTheUseCaseAndTheGate(t *testing.T) {
	cases := map[string]resetAttempt{
		"missing email":    forgotAttempt(`{}`),
		"invalid email":    forgotAttempt(`{"email":"not-an-email"}`),
		"email too long":   forgotAttempt(`{"email":"` + addressOfLength(model.MaxEmailLength+1) + `"}`),
		"not JSON":         forgotAttempt(`{"email":`),
		"wrong media type": {path: forgotPath, body: forgotBody, contentType: "text/plain", headers: map[string]string{"Idempotency-Key": forgotKey}},
		"body over 4 KiB":  forgotAttempt(`{"email":"ana@example.com","padding":"` + strings.Repeat("a", 4096) + `"}`),
	}
	for name, a := range cases {
		t.Run(name, func(t *testing.T) {
			useCase, gates := &fakeRequestPasswordReset{}, openGates()
			gates.forgot, _ = NewBulkhead(1, time.Millisecond)

			rec := sendPasswordReset(gates, useCase, &fakeResetPassword{}, tracedReset(a))

			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"error":"VALIDATION_ERROR"`) || useCase.called != 0 {
				t.Fatalf("status = %d, body = %s, calls = %d, want 400 VALIDATION_ERROR and no call", rec.Code, rec.Body, useCase.called)
			}
			if _, admitted := gates.forgot.Acquire(context.Background()); !admitted {
				t.Error("an invalid request took a slot of the gate")
			}
		})
	}
}

func TestForgotPasswordMapsTheErrorsOfTheUseCase(t *testing.T) {
	logs := captureLog(t)
	cases := map[string]struct {
		err        error
		wantStatus int
		wantError  string
	}{
		"invalid email":    {model.ErrInvalidEmail, http.StatusBadRequest, "VALIDATION_ERROR"},
		"invalid key":      {model.ErrInvalidIdempotencyKey, http.StatusBadRequest, "VALIDATION_ERROR"},
		"key conflict":     {model.ErrIdempotencyKeyConflict, http.StatusConflict, "IDEMPOTENCY_KEY_CONFLICT"},
		"unexpected error": {errors.New("driver failure for ana@example.com"), http.StatusInternalServerError, "INTERNAL_ERROR"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			rec := sendPasswordReset(openGates(), &fakeRequestPasswordReset{err: c.err}, &fakeResetPassword{}, tracedReset(forgotAttempt(forgotBody)))

			if rec.Code != c.wantStatus || !strings.Contains(rec.Body.String(), `"error":"`+c.wantError+`"`) || strings.Contains(rec.Body.String(), "driver") {
				t.Errorf("status = %d, body = %s, want %d %s and a neutral message", rec.Code, rec.Body, c.wantStatus, c.wantError)
			}
		})
	}
	if strings.Contains(logs.String(), resetPasswordIn) || strings.Contains(logs.String(), resetTokenText) {
		t.Errorf("log = %s, leaks a secret", logs)
	}
}

func TestResetPasswordAnswers204WithoutBodyAndWithoutAuthentication(t *testing.T) {
	useCase := &fakeResetPassword{}

	rec := sendPasswordReset(openGates(), &fakeRequestPasswordReset{}, useCase, resetPasswordAttempt(resetBody))

	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Correlation-Id") == "" {
		t.Fatalf("status = %d, body = %q, headers = %v, want 204, no body, no-store and a correlation id", rec.Code, rec.Body, rec.Header())
	}
	if want := (in.ResetPasswordCommand{Token: resetTokenText, Password: resetPasswordIn}); useCase.command != want {
		t.Errorf("command = %+v, want %+v", useCase.command, want)
	}
}

func TestResetPasswordReportsEveryInvalidFieldBeforeTheUseCaseAndTheGate(t *testing.T) {
	cases := map[string]struct {
		a      resetAttempt
		fields []string
	}{
		"missing token":      {resetPasswordAttempt(`{"password":"` + resetPasswordIn + `"}`), []string{"token"}},
		"malformed token":    {resetPasswordAttempt(`{"token":"abc","password":"` + resetPasswordIn + `"}`), []string{"token"}},
		"weak password":      {resetPasswordAttempt(`{"token":"` + resetTokenText + `","password":"weak"}`), []string{"password"}},
		"missing password":   {resetPasswordAttempt(`{"token":"` + resetTokenText + `"}`), []string{"password"}},
		"both invalid":       {resetPasswordAttempt(`{"token":"abc","password":"weak"}`), []string{"token", "password"}},
		"not JSON":           {resetPasswordAttempt(`{"token":`), []string{"body"}},
		"wrong media type":   {resetAttempt{path: resetPath, body: resetBody, contentType: "text/plain"}, []string{"Content-Type"}},
		"body over 4 KiB":    {resetPasswordAttempt(`{"token":"` + resetTokenText + `","password":"` + resetPasswordIn + `","padding":"` + strings.Repeat("a", 4096) + `"}`), []string{"body"}},
		"password too large": {resetPasswordAttempt(`{"token":"` + resetTokenText + `","password":"A1` + strings.Repeat("a", 71) + `"}`), []string{"password"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			useCase, gates := &fakeResetPassword{}, openGates()
			gates.reset, _ = NewBulkhead(1, time.Millisecond)

			rec := sendPasswordReset(gates, &fakeRequestPasswordReset{}, useCase, tracedReset(c.a))

			if rec.Code != http.StatusBadRequest || useCase.called != 0 {
				t.Fatalf("status = %d, body = %s, calls = %d, want 400 and no call", rec.Code, rec.Body, useCase.called)
			}
			for _, field := range c.fields {
				if !strings.Contains(rec.Body.String(), `"field":"`+field+`"`) {
					t.Errorf("body = %s, want a detail for %q", rec.Body, field)
				}
			}
			if _, admitted := gates.reset.Acquire(context.Background()); !admitted {
				t.Error("an invalid request took a slot of the gate")
			}
		})
	}
}

func TestResetPasswordAnswersTheValidationErrorOfTheCurrentPasswordWithItsStableMessage(t *testing.T) {
	rec := sendPasswordReset(openGates(), &fakeRequestPasswordReset{}, &fakeResetPassword{err: model.ErrPasswordUnchanged}, tracedReset(resetPasswordAttempt(resetBody)))

	var got struct {
		Error   string `json:"error"`
		Details []struct{ Field, Message string }
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body = %s, error = %v", rec.Body, err)
	}
	if rec.Code != http.StatusBadRequest || got.Error != "VALIDATION_ERROR" || len(got.Details) != 1 ||
		got.Details[0].Field != "password" || got.Details[0].Message != "The new password must differ from the current one" {
		t.Errorf("status = %d, body = %s, want 400 VALIDATION_ERROR with the field password and the stable message", rec.Code, rec.Body)
	}
}

func TestResetPasswordMapsTheErrorsOfTheUseCase(t *testing.T) {
	logs := captureLog(t)
	cases := map[string]struct {
		err        error
		wantStatus int
		wantError  string
	}{
		"rejected token":   {model.ErrPasswordResetRejected, http.StatusUnauthorized, "INVALID_TOKEN"},
		"malformed token":  {model.ErrInvalidResetToken, http.StatusBadRequest, "VALIDATION_ERROR"},
		"weak password":    {model.ErrWeakPassword, http.StatusBadRequest, "VALIDATION_ERROR"},
		"unexpected error": {errors.New("driver failure"), http.StatusInternalServerError, "INTERNAL_ERROR"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			rec := sendPasswordReset(openGates(), &fakeRequestPasswordReset{}, &fakeResetPassword{err: c.err}, tracedReset(resetPasswordAttempt(resetBody)))

			if rec.Code != c.wantStatus || !strings.Contains(rec.Body.String(), `"error":"`+c.wantError+`"`) {
				t.Errorf("status = %d, body = %s, want %d %s", rec.Code, rec.Body, c.wantStatus, c.wantError)
			}
		})
	}
	if strings.Contains(logs.String(), resetPasswordIn) || strings.Contains(logs.String(), resetTokenText) {
		t.Errorf("log = %s, leaks a secret", logs)
	}
}

// blockingPasswordReset holds every call until it is released, like a slow database.
type blockingPasswordReset struct {
	entered chan struct{}
	proceed chan struct{}
	mu      sync.Mutex
	calls   int
}

func (b *blockingPasswordReset) hold() {
	b.mu.Lock()
	b.calls++
	b.mu.Unlock()
	b.entered <- struct{}{}
	<-b.proceed
}

func (b *blockingPasswordReset) RequestReset(context.Context, in.RequestPasswordResetCommand) error {
	b.hold()
	return nil
}

func (b *blockingPasswordReset) Reset(context.Context, in.ResetPasswordCommand) error {
	b.hold()
	return nil
}

func (b *blockingPasswordReset) callCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

// The slow call never ends until the test releases it, so a refused request that came back at all was answered
// without waiting for it. The test does not time that answer: it only fails when the request is stuck.
func TestPasswordResetRoutesAreRefusedWith429BeforeTheUseCaseWhenTheirSlotsAreTaken(t *testing.T) {
	cases := map[string]struct {
		attempt resetAttempt
		send    func(*Bulkhead, *blockingPasswordReset, resetAttempt) *httptest.ResponseRecorder
	}{
		"forgot-password": {tracedReset(forgotAttempt(forgotBody)), func(gate *Bulkhead, slow *blockingPasswordReset, a resetAttempt) *httptest.ResponseRecorder {
			return sendPasswordReset(resetGates{forgot: gate, reset: openGates().reset}, slow, &fakeResetPassword{}, a)
		}},
		"reset-password": {tracedReset(resetPasswordAttempt(resetBody)), func(gate *Bulkhead, slow *blockingPasswordReset, a resetAttempt) *httptest.ResponseRecorder {
			return sendPasswordReset(resetGates{forgot: openGates().forgot, reset: gate}, &fakeRequestPasswordReset{}, slow, a)
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			logs := captureLog(t)
			gate, _ := NewBulkhead(1, 20*time.Millisecond)
			slow := &blockingPasswordReset{entered: make(chan struct{}, 4), proceed: make(chan struct{})}
			done := make(chan struct{})
			go func() {
				c.send(gate, slow, c.attempt)
				close(done)
			}()
			<-slow.entered
			t.Cleanup(func() { close(slow.proceed); <-done })

			var rec *httptest.ResponseRecorder
			within(t, "a request without a free slot must be refused, not held behind the slow one", func() {
				rec = c.send(gate, slow, c.attempt)
			})

			if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "1" || !strings.Contains(rec.Body.String(), `"error":"TOO_MANY_REQUESTS"`) {
				t.Errorf("status = %d, Retry-After = %q, body = %s, want 429 TOO_MANY_REQUESTS with Retry-After 1", rec.Code, rec.Header().Get("Retry-After"), rec.Body)
			}
			if calls := slow.callCount(); calls != 1 {
				t.Errorf("use case calls = %d, want the refused request to never reach it", calls)
			}
			if line := logs.String(); !strings.Contains(line, "level=WARN") || !strings.Contains(line, "limit=1") || strings.Contains(line, "example.com") {
				t.Errorf("log = %s, want a WARN with the limit and no address", line)
			}
			requireContract(t, http.MethodPost, c.attempt.path, rec)
		})
	}
}

func TestEachPasswordResetRouteHasItsOwnGateAndReleasesItsSlot(t *testing.T) {
	captureLog(t)
	gates := openGates()
	gates.forgot, _ = NewBulkhead(1, 10*time.Millisecond)
	gates.reset, _ = NewBulkhead(1, 10*time.Millisecond)
	gates.forgot.Acquire(context.Background())
	request, reset := &fakeRequestPasswordReset{}, &fakeResetPassword{err: errors.New("driver failure")}

	resetRec := sendPasswordReset(gates, request, reset, tracedReset(resetPasswordAttempt(resetBody)))
	again := sendPasswordReset(gates, request, reset, tracedReset(resetPasswordAttempt(resetBody)))

	if resetRec.Code != http.StatusInternalServerError || again.Code != http.StatusInternalServerError || reset.called != 2 {
		t.Errorf("statuses = %d and %d, calls = %d, want the full gate of forgot-password not to matter and the slot of a failed reset to be released",
			resetRec.Code, again.Code, reset.called)
	}
	if forgot := sendPasswordReset(gates, request, reset, tracedReset(forgotAttempt(forgotBody))); forgot.Code != http.StatusTooManyRequests {
		t.Errorf("forgot-password status = %d, want 429 while its own slot is taken", forgot.Code)
	}
}
