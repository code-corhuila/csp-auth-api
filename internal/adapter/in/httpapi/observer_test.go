package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

type observation struct {
	route, method string
	status        int
	duration      time.Duration
}

type recordingObserver struct {
	mu   sync.Mutex
	seen []observation
}

func (o *recordingObserver) Observe(route, method string, status int, duration time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.seen = append(o.seen, observation{route, method, status, duration})
}

func (o *recordingObserver) only(t *testing.T) observation {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.seen) != 1 {
		t.Fatalf("observations = %d, want exactly one", len(o.seen))
	}
	return o.seen[0]
}

// panickingLogin is a use case that fails the way a bug does.
type panickingLogin struct{}

func (panickingLogin) Login(context.Context, in.LoginUserCommand) (in.LoginUserResult, error) {
	panic("boom")
}

func observed(observer Observer, options ...Option) http.Handler {
	return WithObserver(NewHandler(options...), observer)
}

func TestARequestIsObservedWithTheRoutePatternItsMethodAndItsStatus(t *testing.T) {
	observer := &recordingObserver{}
	handler := observed(observer, WithLoginUser(&fakeLogin{err: model.ErrInvalidCredentials}, openGate()))
	request := httptest.NewRequest(http.MethodPost, loginPath, strings.NewReader(loginBody()))
	request.Header.Set("Content-Type", "application/json")

	handler.ServeHTTP(httptest.NewRecorder(), request)

	got := observer.only(t)
	if got.route != BasePath+"/login" || got.method != "POST" || got.status != http.StatusUnauthorized {
		t.Errorf("observation = %+v, want POST %s answered 401", got, BasePath+"/login")
	}
}

func TestTheRouteIsThePatternAndNeverTheRawPath(t *testing.T) {
	observer := &recordingObserver{}
	handler := observed(observer)

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, BasePath+"/health?x=secret-value", nil))

	got := observer.only(t)
	if got.route != BasePath+"/health" || strings.Contains(got.route, "secret") {
		t.Errorf("route = %q, want the pattern without the query string", got.route)
	}
}

func TestAnUnmatchedRequestIsOneBoundedSeriesWhateverThePath(t *testing.T) {
	observer := &recordingObserver{}
	handler := observed(observer)

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodDelete, "/some/path/7a3d9e10-52c4-4b8e", nil))

	got := observer.only(t)
	if got.route != "unmatched" || got.method != "other" || got.status != http.StatusNotFound {
		t.Errorf("observation = %+v, want unmatched, other and 404", got)
	}
}

func TestThePanicOfAHandlerIsObservedAsAnError(t *testing.T) {
	observer := &recordingObserver{}
	handler := observed(observer, WithLoginUser(panickingLogin{}, openGate()))
	request := httptest.NewRequest(http.MethodPost, loginPath, strings.NewReader(loginBody()))
	request.Header.Set("Content-Type", "application/json")

	handler.ServeHTTP(httptest.NewRecorder(), request)

	if got := observer.only(t); got.status != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", got.status)
	}
}

func TestTheIntentionalWaitOfASlowedLoginIsNotLatency(t *testing.T) {
	observer := &recordingObserver{}
	wait := 300 * time.Millisecond
	handler := observed(observer, WithLoginUser(&fakeLogin{err: &model.LoginSlowedError{Delay: wait}}, openGate()))
	request := httptest.NewRequest(http.MethodPost, loginPath, strings.NewReader(loginBody()))
	request.Header.Set("Content-Type", "application/json")
	started := time.Now()

	handler.ServeHTTP(httptest.NewRecorder(), request)

	if time.Since(started) < wait {
		t.Fatalf("the answer did not wait: the test would prove nothing")
	}
	if got := observer.only(t); got.duration >= wait/2 || got.status != http.StatusUnauthorized {
		t.Errorf("observed %v with status %d, want the work without the %v wait and the usual 401", got.duration, got.status, wait)
	}
}

func TestWithoutAnObserverTheHandlerWorksAsBefore(t *testing.T) {
	rec := httptest.NewRecorder()

	WithObserver(NewHandler(), nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, BasePath+"/health", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestTheMetricsRouteAnswersWhatTheHandlerWritesAndIsNotUnderTheContractBase(t *testing.T) {
	scrape := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("auth_http_requests_total 1\n")) })
	handler := NewHandler(WithMetricsRoute(scrape))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	under := httptest.NewRecorder()
	handler.ServeHTTP(under, httptest.NewRequest(http.MethodGet, BasePath+"/metrics", nil))

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "auth_http_requests_total") {
		t.Errorf("GET /metrics = %d %q, want the scrape", rec.Code, rec.Body.String())
	}
	if under.Code != http.StatusNotFound {
		t.Errorf("GET %s/metrics = %d, want 404: the contract path space has no metrics", BasePath, under.Code)
	}
}

func TestOnlyGetCanScrape(t *testing.T) {
	handler := NewHandler(WithMetricsRoute(http.NotFoundHandler()))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/metrics", nil))

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /metrics = %d, want 405", rec.Code)
	}
}
