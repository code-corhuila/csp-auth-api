package httpapi

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// Observer is told about every answered request: the pattern of the route (or "unmatched"), the method (or "other"), the
// status and how long the service worked on it. internal/platform/metrics implements it.
type Observer interface {
	Observe(route, method string, status int, duration time.Duration)
}

// requestNotes is what the inner steps tell the observer about a request: the route the mux matched, which only the root
// step knows, and the time the request waited on purpose, which is not latency.
type requestNotes struct {
	pattern string
	waited  time.Duration
}

type notesKey struct{}

func notesOf(ctx context.Context) *requestNotes {
	notes, _ := ctx.Value(notesKey{}).(*requestNotes)
	return notes
}

// noteRoute is called by the root step with the pattern the mux matched ("" when none did).
func noteRoute(ctx context.Context, pattern string) {
	if notes := notesOf(ctx); notes != nil {
		notes.pattern = pattern
	}
}

// noteWait is called by a step that held the answer on purpose (the slowdown of a login, ADR-059).
func noteWait(ctx context.Context, waited time.Duration) {
	if notes := notesOf(ctx); notes != nil {
		notes.waited += waited
	}
}

// WithObserver wraps next so that every request is reported to observer when it ends, whatever the answer. A nil observer
// leaves next as it is.
func WithObserver(next http.Handler, observer Observer) http.Handler {
	if observer == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		notes := &requestNotes{}
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		started := time.Now()
		defer func() {
			route, method := routeAndMethod(notes.pattern)
			observer.Observe(route, method, recorder.status, time.Since(started)-notes.waited)
		}()
		next.ServeHTTP(recorder, r.WithContext(context.WithValue(r.Context(), notesKey{}, notes)))
	})
}

// routeAndMethod splits the pattern of the mux ("POST /api/v1/auth/login") into the labels of the metrics. A request that
// matched no route is one series, so a scan of random paths cannot create series.
func routeAndMethod(pattern string) (route, method string) {
	method, route, found := strings.Cut(pattern, " ")
	if !found || route == "" {
		return "unmatched", "other"
	}
	return route, method
}

// statusRecorder remembers the status the handler answered.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(status int) {
	if !s.wroteHeader {
		s.status, s.wroteHeader = status, true
	}
	s.ResponseWriter.WriteHeader(status)
}

func (s *statusRecorder) Write(p []byte) (int, error) {
	s.wroteHeader = true
	return s.ResponseWriter.Write(p)
}

// Flush keeps http.Flusher available through the wrapper.
func (s *statusRecorder) Flush() {
	s.wroteHeader = true
	if flusher, ok := s.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// WithMetricsRoute publishes the scrape of the metrics at GET /metrics. It is an operations endpoint, outside the contract
// and outside BasePath: the gateway routes only the operations of the contract, so it is reachable on the platform network only.
func WithMetricsRoute(scrape http.Handler) Option {
	return func(mux *http.ServeMux) {
		mux.Handle("GET /metrics", scrape)
	}
}
