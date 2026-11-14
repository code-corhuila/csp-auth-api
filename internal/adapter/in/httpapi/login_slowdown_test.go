package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

func serveLogin(useCase *fakeLogin, gate *Bulkhead) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, loginPath, strings.NewReader(loginBody()))
	request.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	NewHandler(WithLoginUser(useCase, gate)).ServeHTTP(rec, request)
	return rec
}

func TestASlowedLoginAnswersTheSame401AfterTheDelay(t *testing.T) {
	delay := 200 * time.Millisecond
	useCase := &fakeLogin{err: &model.LoginSlowedError{Delay: delay}}
	started := time.Now()

	rec := serveLogin(useCase, openGate())

	if elapsed := time.Since(started); elapsed < delay {
		t.Errorf("answered after %v, want at least %v", elapsed, delay)
	}
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), codeBadCredentials) {
		t.Errorf("status = %d, body = %s, want the usual 401 bad credentials", rec.Code, rec.Body.String())
	}
}

func TestASlowedLoginGivesBackItsSlotBeforeItWaits(t *testing.T) {
	gate, err := NewBulkhead(1, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("NewBulkhead() error = %v", err)
	}
	done := make(chan struct{})
	go func() {
		serveLogin(&fakeLogin{err: &model.LoginSlowedError{Delay: 400 * time.Millisecond}}, gate)
		close(done)
	}()
	time.Sleep(100 * time.Millisecond)

	release, admitted := gate.Acquire(context.Background())

	if !admitted {
		t.Error("the slot is still taken while the slowed answer waits: an attacker could fill the login slots with slowed requests")
	} else {
		release()
	}
	<-done
}

func TestASlowedLoginStopsWaitingWhenTheClientLeaves(t *testing.T) {
	useCase := &fakeLogin{err: &model.LoginSlowedError{Delay: 5 * time.Second}}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	request := httptest.NewRequest(http.MethodPost, loginPath, strings.NewReader(loginBody())).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	started := time.Now()

	NewHandler(WithLoginUser(useCase, openGate())).ServeHTTP(httptest.NewRecorder(), request)

	if elapsed := time.Since(started); elapsed > time.Second {
		t.Errorf("waited %v for a client that had already gone", elapsed)
	}
}

func TestALoginThatIsNotSlowedAnswersAtOnce(t *testing.T) {
	started := time.Now()

	rec := serveLogin(&fakeLogin{err: model.ErrInvalidCredentials}, openGate())

	if elapsed := time.Since(started); rec.Code != http.StatusUnauthorized || elapsed > 150*time.Millisecond {
		t.Errorf("status = %d after %v, want an immediate 401", rec.Code, elapsed)
	}
}
