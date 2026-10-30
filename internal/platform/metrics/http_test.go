package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func scrape(t *testing.T, m *HTTP) (string, *httptest.ResponseRecorder) {
	t.Helper()
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rec.Body.String(), rec
}

func TestTheCounterIsKeptPerRouteMethodAndOutcome(t *testing.T) {
	m := NewHTTP()
	m.Observe("/api/v1/auth/login", "POST", http.StatusOK, 40*time.Millisecond)
	m.Observe("/api/v1/auth/login", "POST", http.StatusUnauthorized, 300*time.Millisecond)
	m.Observe("/api/v1/auth/login", "POST", http.StatusUnauthorized, 300*time.Millisecond)
	m.Observe("/api/v1/auth/login", "POST", http.StatusServiceUnavailable, 5*time.Millisecond)

	body, _ := scrape(t, m)

	for _, want := range []string{
		`auth_http_requests_total{route="/api/v1/auth/login",method="POST",outcome="success"} 1`,
		`auth_http_requests_total{route="/api/v1/auth/login",method="POST",outcome="client_error"} 2`,
		`auth_http_requests_total{route="/api/v1/auth/login",method="POST",outcome="error"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the scrape misses %q:\n%s", want, body)
		}
	}
}

func TestTheOutcomeOfAStatus(t *testing.T) {
	for status, want := range map[int]string{200: "success", 201: "success", 204: "success", 302: "success", 400: "client_error", 401: "client_error", 429: "client_error", 500: "error", 503: "error"} {
		if got := Outcome(status); got != want {
			t.Errorf("Outcome(%d) = %q, want %q", status, got, want)
		}
	}
}

func TestTheHistogramIsCumulativeWithTheBucketsOfTheWorkshop(t *testing.T) {
	m := NewHTTP()
	m.Observe("/api/v1/auth/register", "POST", 201, 40*time.Millisecond)
	m.Observe("/api/v1/auth/register", "POST", 201, 300*time.Millisecond)
	m.Observe("/api/v1/auth/register", "POST", 201, 3*time.Second)

	body, _ := scrape(t, m)

	for _, want := range []string{
		`auth_http_request_duration_seconds_bucket{route="/api/v1/auth/register",method="POST",le="0.05"} 1`,
		`auth_http_request_duration_seconds_bucket{route="/api/v1/auth/register",method="POST",le="0.1"} 1`,
		`auth_http_request_duration_seconds_bucket{route="/api/v1/auth/register",method="POST",le="0.25"} 1`,
		`auth_http_request_duration_seconds_bucket{route="/api/v1/auth/register",method="POST",le="0.5"} 2`,
		`auth_http_request_duration_seconds_bucket{route="/api/v1/auth/register",method="POST",le="1"} 2`,
		`auth_http_request_duration_seconds_bucket{route="/api/v1/auth/register",method="POST",le="2.5"} 2`,
		`auth_http_request_duration_seconds_bucket{route="/api/v1/auth/register",method="POST",le="+Inf"} 3`,
		`auth_http_request_duration_seconds_count{route="/api/v1/auth/register",method="POST"} 3`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the scrape misses %q:\n%s", want, body)
		}
	}
	if !strings.Contains(body, `auth_http_request_duration_seconds_sum{route="/api/v1/auth/register",method="POST"} 3.34`) {
		t.Errorf("the sum of the durations is not 3.34 seconds:\n%s", body)
	}
}

func TestTheScrapeDeclaresTheTypesAndTheFormatOfPrometheus(t *testing.T) {
	m := NewHTTP()
	m.Observe("/api/v1/auth/jwks", "GET", 200, time.Millisecond)

	body, rec := scrape(t, m)

	if !strings.Contains(body, "# TYPE auth_http_requests_total counter") || !strings.Contains(body, "# TYPE auth_http_request_duration_seconds histogram") {
		t.Errorf("the scrape does not declare the types:\n%s", body)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/plain; version=0.0.4; charset=utf-8" {
		t.Errorf("Content-Type = %q, want the text format 0.0.4 of Prometheus", got)
	}
}

func TestAScrapeBeforeAnyRequestIsValidAndEmpty(t *testing.T) {
	body, rec := scrape(t, NewHTTP())

	if rec.Code != http.StatusOK || strings.Contains(body, "auth_http_requests_total{") {
		t.Errorf("status = %d, body = %q, want 200 and no series", rec.Code, body)
	}
}

func TestTheSeriesAreWrittenInAStableOrder(t *testing.T) {
	m := NewHTTP()
	m.Observe("/b", "POST", 200, time.Millisecond)
	m.Observe("/a", "GET", 200, time.Millisecond)
	m.Observe("/a", "POST", 500, time.Millisecond)

	first, _ := scrape(t, m)
	second, _ := scrape(t, m)

	if first != second {
		t.Error("two scrapes of the same state differ: the series order must be stable")
	}
	if strings.Index(first, `route="/a",method="GET"`) > strings.Index(first, `route="/b"`) {
		t.Error("the series are not sorted by route")
	}
}

func TestObservingFromManyRequestsAtOnceLosesNothing(t *testing.T) {
	m := NewHTTP()
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				m.Observe("/api/v1/auth/login", "POST", 401, time.Millisecond)
			}
		}()
	}
	wg.Wait()

	body, _ := scrape(t, m)

	if !strings.Contains(body, `auth_http_requests_total{route="/api/v1/auth/login",method="POST",outcome="client_error"} 1000`) {
		t.Errorf("the counter is not 1000:\n%s", body)
	}
}
