package httpapi

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
)

func TestNewBulkheadRejectsALimitUnderOneAndANonPositiveWait(t *testing.T) {
	for name, c := range map[string]struct {
		limit int
		wait  time.Duration
	}{"zero limit": {0, time.Second}, "negative limit": {-1, time.Second}, "zero wait": {1, 0}} {
		if _, err := NewBulkhead(c.limit, c.wait); err == nil {
			t.Errorf("%s: NewBulkhead() error = nil, want an error", name)
		}
	}
}

func TestBulkheadAdmitsTheLimitAndRefusesTheNextAfterTheWait(t *testing.T) {
	gate, _ := NewBulkhead(2, 30*time.Millisecond)
	for i := 0; i < 2; i++ {
		if _, ok := gate.Acquire(context.Background()); !ok {
			t.Fatalf("Acquire() #%d refused, want admitted", i+1)
		}
	}

	started := time.Now()
	_, ok := gate.Acquire(context.Background())

	if ok || time.Since(started) < 30*time.Millisecond {
		t.Errorf("third Acquire() ok = %v after %v, want refused only after the 30ms wait", ok, time.Since(started))
	}
}

func TestBulkheadReleaseFreesTheSlotAndIsHarmlessWhenRepeated(t *testing.T) {
	gate, _ := NewBulkhead(1, 10*time.Millisecond)
	release, _ := gate.Acquire(context.Background())
	release()
	release()

	second, ok := gate.Acquire(context.Background())
	_, third := gate.Acquire(context.Background())

	if !ok || third {
		t.Errorf("after a double release: second ok = %v, third ok = %v, want true and false: the limit stays 1", ok, third)
	}
	second()
}

func TestBulkheadAdmitsAWaiterAsSoonAsASlotIsFree(t *testing.T) {
	gate, _ := NewBulkhead(1, 2*time.Second)
	release, _ := gate.Acquire(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); release() }()

	started := time.Now()
	_, ok := gate.Acquire(context.Background())

	if !ok || time.Since(started) > time.Second {
		t.Errorf("Acquire() ok = %v after %v, want admitted as soon as the slot is released", ok, time.Since(started))
	}
}

func TestBulkheadStopsWaitingWhenTheCallerIsGone(t *testing.T) {
	gate, _ := NewBulkhead(1, 5*time.Second)
	gate.Acquire(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	started := time.Now()
	_, ok := gate.Acquire(ctx)

	if ok || time.Since(started) > time.Second {
		t.Errorf("Acquire() ok = %v after %v, want refused at once for a cancelled request", ok, time.Since(started))
	}
}

// blockingRequestEmailChange holds every call until it is released, like a slow SMTP relay.
type blockingRequestEmailChange struct {
	entered chan struct{}
	proceed chan struct{}
	panics  bool
	mu      sync.Mutex
	calls   int
}

func (b *blockingRequestEmailChange) RequestChange(context.Context, in.RequestEmailChangeCommand) error {
	b.mu.Lock()
	b.calls++
	b.mu.Unlock()
	b.entered <- struct{}{}
	<-b.proceed
	if b.panics {
		panic("delivery blew up")
	}
	return nil
}

func TestRequestEmailChangeIsRefusedWith429BeforeTheUseCaseWhenNoSlotIsFree(t *testing.T) {
	logs := captureLog(t)
	gate, _ := NewBulkhead(1, 20*time.Millisecond)
	slow := &blockingRequestEmailChange{entered: make(chan struct{}, 4), proceed: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		sendEmailChangeGated(gate, &fakeUserAuthorizer{}, slow, &fakeVerifyEmailChange{}, traced(requestAttempt(emailBody)))
		close(done)
	}()
	<-slow.entered

	started := time.Now()
	rec := sendEmailChangeGated(gate, &fakeUserAuthorizer{}, slow, &fakeVerifyEmailChange{}, traced(requestAttempt(emailBody)))
	took := time.Since(started)

	requireContract(t, http.MethodPatch, emailPath, rec)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "1" || !strings.Contains(rec.Body.String(), `"error":"RATE_LIMITED"`) {
		t.Errorf("status = %d, Retry-After = %q, body = %s, want 429 RATE_LIMITED with Retry-After 1", rec.Code, rec.Header().Get("Retry-After"), rec.Body)
	}
	if slow.calls != 1 || took > time.Second {
		t.Errorf("use case calls = %d after %v, want the refused request to never reach it and to be answered at once", slow.calls, took)
	}
	line := logs.String()
	if !strings.Contains(line, "level=WARN") || !strings.Contains(line, "limit=1") || strings.Contains(line, "example.com") {
		t.Errorf("log = %s, want a WARN with the limit and no address", line)
	}
	close(slow.proceed)
	<-done
}

func TestRequestEmailChangeReleasesItsSlotWhenTheUseCaseFailsOrPanics(t *testing.T) {
	captureLog(t)
	for name, panics := range map[string]bool{"error": false, "panic": true} {
		t.Run(name, func(t *testing.T) {
			gate, _ := NewBulkhead(1, 10*time.Millisecond)
			use := &blockingRequestEmailChange{entered: make(chan struct{}, 2), proceed: make(chan struct{}), panics: panics}
			close(use.proceed)

			func() {
				defer func() { _ = recover() }()
				sendEmailChangeGated(gate, &fakeUserAuthorizer{}, use, &fakeVerifyEmailChange{}, traced(requestAttempt(emailBody)))
			}()

			if _, ok := gate.Acquire(context.Background()); !ok {
				t.Error("the slot is still taken after the request ended, want it released")
			}
		})
	}
}

func TestVerifyEmailChangeIsNotLimitedByTheBulkhead(t *testing.T) {
	gate, _ := NewBulkhead(1, 10*time.Millisecond)
	gate.Acquire(context.Background())
	verify := &fakeVerifyEmailChange{}

	rec := sendEmailChangeGated(gate, &fakeUserAuthorizer{}, &fakeRequestEmailChange{}, verify, traced(verifyAttempt(verifyBody)))

	if rec.Code != http.StatusNoContent || verify.called != 1 {
		t.Errorf("status = %d, calls = %d, want 204: the verification neither sends mail nor holds a slot", rec.Code, verify.called)
	}
}
