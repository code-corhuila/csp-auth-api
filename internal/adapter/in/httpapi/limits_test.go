package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
)

func openGate() *Bulkhead {
	gate, _ := NewBulkhead(1000, time.Second)
	return gate
}

// waitingRegister is a use case that waits for the context, like a request queued for a pooled database connection.
type waitingRegister struct{}

func (waitingRegister) Register(ctx context.Context, _ in.RegisterUserCommand) (in.RegisterUserResult, error) {
	<-ctx.Done()
	return in.RegisterUserResult{}, fmt.Errorf("acquire a connection: %w", ctx.Err())
}

func serveWithLimits(limits Limits, useCase in.RegisterUser, a attempt) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, registerPath, strings.NewReader(a.body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", validKey)
	rec := httptest.NewRecorder()
	WithLimits(NewHandler(WithRegisterUser(useCase, openGate())), limits).ServeHTTP(rec, request)
	return rec
}

func TestTheRequestDeadlineEndsAWaitForAConnectionWith503(t *testing.T) {
	limits := fallbackLimits
	limits.RequestTimeout = 30 * time.Millisecond

	started := time.Now()
	rec := serveWithLimits(limits, waitingRegister{}, attempt{body: validBody()})

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body = %s", rec.Code, rec.Body.String())
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Errorf("the request took %s, want it to end at its deadline", elapsed)
	}
	body := decode(t, rec)
	if body["error"] != "SERVICE_UNAVAILABLE" || body["traceId"] == "" {
		t.Errorf("body = %v, want the SERVICE_UNAVAILABLE envelope with a traceId", body)
	}
	if rec.Header().Get("Retry-After") != "1" {
		t.Errorf("Retry-After = %q, want 1", rec.Header().Get("Retry-After"))
	}
}

func TestAnUnexpectedErrorStaysA500(t *testing.T) {
	rec := send(&fakeRegister{err: context.Canceled}, attempt{body: validBody(), key: validKey})

	if rec.Code != http.StatusInternalServerError || decode(t, rec)["error"] != "INTERNAL_ERROR" {
		t.Errorf("status = %d, body = %s, want 500 INTERNAL_ERROR", rec.Code, rec.Body.String())
	}
}

func TestTheBodyLimitComesFromTheLimits(t *testing.T) {
	limits := fallbackLimits
	limits.MaxBodyBytes = 64

	rec := serveWithLimits(limits, &fakeRegister{}, attempt{body: validBody()})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a body over the configured limit", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "must be at most 64 bytes") {
		t.Errorf("body = %s, want the configured limit in the message", rec.Body.String())
	}
}

func TestThePasswordResetBodyLimitComesFromTheLimits(t *testing.T) {
	limits := fallbackLimits
	limits.PasswordResetMaxBodyBytes = 16
	request := httptest.NewRequest(http.MethodPost, BasePath+"/forgot-password", strings.NewReader(`{"email":"maria@example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", validKey)
	rec := httptest.NewRecorder()

	WithLimits(NewHandler(WithPasswordReset(&fakeRequestPasswordReset{}, &fakeResetPassword{}, openGate(), openGate())), limits).ServeHTTP(rec, request)

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "must be at most 16 bytes") {
		t.Errorf("status = %d, body = %s, want 400 at the configured limit", rec.Code, rec.Body.String())
	}
}

func TestTheDetachedDeadlineComesFromTheLimitsAndSurvivesTheClient(t *testing.T) {
	limits := fallbackLimits
	limits.DetachedDeadline = 3 * time.Second
	var detached context.Context
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		ctx, cancel := detachedFromClient(r)
		defer cancel()
		detached = ctx
	})
	clientGone, leave := context.WithCancel(context.Background())
	leave()

	WithLimits(next, limits).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil).WithContext(clientGone))

	deadline, ok := detached.Deadline()
	if !ok || time.Until(deadline) > 3*time.Second {
		t.Errorf("deadline = %v (%v), want one within the configured 3s", deadline, ok)
	}
	if limitsOf(detached).DetachedDeadline != 3*time.Second {
		t.Error("the detached context lost the limits")
	}
}

func TestWithoutLimitsTheHandlersUseTheFallback(t *testing.T) {
	if got := limitsOf(context.Background()); got != fallbackLimits {
		t.Errorf("limits = %+v, want the fallback", got)
	}
}

func TestRegisterAndLoginRefuseWith429WhenTheBulkheadIsFull(t *testing.T) {
	registerUse, loginUse := &fakeRegister{result: createdSession()}, &fakeLogin{result: loggedInSession()}
	routes := map[string]struct {
		send  func(*Bulkhead) *httptest.ResponseRecorder
		calls *int
	}{
		"register": {func(gate *Bulkhead) *httptest.ResponseRecorder {
			return sendGated(registerPath, validBody(), WithRegisterUser(registerUse, gate), true)
		}, &registerUse.called},
		"login": {func(gate *Bulkhead) *httptest.ResponseRecorder {
			return sendGated(loginPath, loginBody(), WithLoginUser(loginUse, gate), false)
		}, &loginUse.called},
	}

	for name, route := range routes {
		t.Run(name, func(t *testing.T) {
			gate, _ := NewBulkhead(1, 10*time.Millisecond)
			release, _ := gate.Acquire(context.Background())

			rec := route.send(gate)

			if rec.Code != http.StatusTooManyRequests || decode(t, rec)["error"] != "RATE_LIMITED" || rec.Header().Get("Retry-After") != "1" {
				t.Errorf("status = %d, Retry-After = %q, body = %s, want 429 RATE_LIMITED with Retry-After 1", rec.Code, rec.Header().Get("Retry-After"), rec.Body.String())
			}
			if *route.calls != 0 {
				t.Errorf("the use case ran %d times, want it not to run when the bulkhead is full", *route.calls)
			}
			release()
			for call := 1; call <= 2; call++ {
				if rec = route.send(gate); rec.Code >= 300 || *route.calls != call {
					t.Errorf("request %d after the slot was freed: status = %d, calls = %d, want a success and its slot released", call, rec.Code, *route.calls)
				}
			}
		})
	}
}

func TestAnInvalidRegisterOrLoginDoesNotTakeASlot(t *testing.T) {
	gate, _ := NewBulkhead(1, 10*time.Millisecond)
	release, _ := gate.Acquire(context.Background())
	defer release()

	registerRec := sendGated(registerPath, `{}`, WithRegisterUser(&fakeRegister{}, gate), true)
	loginRec := sendGated(loginPath, `{}`, WithLoginUser(&fakeLogin{}, gate), false)

	if registerRec.Code != http.StatusBadRequest || loginRec.Code != http.StatusBadRequest {
		t.Errorf("statuses = %d and %d, want 400 before the bulkhead", registerRec.Code, loginRec.Code)
	}
}

func sendGated(path, body string, option Option, withKey bool) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if withKey {
		request.Header.Set("Idempotency-Key", validKey)
	}
	rec := httptest.NewRecorder()
	NewHandler(option).ServeHTTP(rec, request)
	return rec
}
