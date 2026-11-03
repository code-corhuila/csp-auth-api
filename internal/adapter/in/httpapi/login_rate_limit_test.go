package httpapi

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

func TestLoginPassesTheClientAddressOfTheGatewayToTheUseCase(t *testing.T) {
	useCase := &fakeLogin{result: loggedInSession()}

	sendLogin(useCase, attempt{body: loginBody(), headers: map[string]string{"X-Forwarded-For": "1.2.3.4, 203.0.113.7"}})

	if want := (in.LoginUserCommand{Email: "Maria@Example.com", Password: secret, ClientIP: "203.0.113.7"}); useCase.command != want {
		t.Errorf("command = %+v, want %+v", useCase.command, want)
	}
}

func TestLoginRateLimitedAnswers429WithRetryAfterAndTheSharedEnvelope(t *testing.T) {
	err := &model.LoginRateLimitedError{RetryAfter: 4*time.Minute + 30*time.Second + 400*time.Millisecond}

	rec := sendLogin(&fakeLogin{err: err}, attempt{body: loginBody()})

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "271" {
		t.Errorf("Retry-After = %q, want the remaining lock rounded up to 271 seconds", got)
	}
	envelope := decode(t, rec)
	if envelope["error"] != "TOO_MANY_REQUESTS" || envelope["traceId"] == "" {
		t.Errorf("envelope = %v, want TOO_MANY_REQUESTS with a trace id", envelope)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Correlation-Id") == "" {
		t.Errorf("headers = %v, want no-store and a correlation id", rec.Header())
	}
}

func TestLoginRateLimitedWithoutAWaitUsesTheWholeLock(t *testing.T) {
	rec := sendLogin(&fakeLogin{err: model.ErrTooManyLoginAttempts}, attempt{body: loginBody()})

	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "300" {
		t.Errorf("status = %d, Retry-After = %q, want 429 and 300", rec.Code, rec.Header().Get("Retry-After"))
	}
}

func TestLoginRetryAfterIsNeverUnderOneSecond(t *testing.T) {
	for _, wait := range []time.Duration{0, time.Millisecond, -time.Second} {
		if got := loginRetryAfterSeconds(&model.LoginRateLimitedError{RetryAfter: wait}); got != "1" {
			t.Errorf("wait %v: Retry-After = %q, want 1", wait, got)
		}
	}
}

func TestLoginTellsARateLimitApartFromAnUnexpectedError(t *testing.T) {
	rec := sendLogin(&fakeLogin{err: errors.New("driver failure")}, attempt{body: loginBody()})

	if rec.Code != http.StatusInternalServerError || rec.Header().Get("Retry-After") != "" {
		t.Errorf("status = %d, Retry-After = %q, want 500 without Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}
}
