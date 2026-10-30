package httpapi

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/platform/logging"
)

const (
	codeMethodNotAllowed = "METHOD_NOT_ALLOWED"
	headerAllow          = "Allow"
)

// withCorrelationID returns the context that carries the correlation id of the request. The id lives in the neutral
// logging package, so the use cases and the adapters that log with the context get it without importing this adapter.
func withCorrelationID(ctx context.Context, id string) context.Context {
	return logging.WithTraceID(ctx, id)
}

// CorrelationIDFrom returns the correlation id the root wrapper stored in the context, or "" when there is none.
func CorrelationIDFrom(ctx context.Context) string {
	return logging.TraceIDFrom(ctx)
}

// root is the outermost step of the service (Norma 5.3.5 and 5.3.9). It decides the correlation id once, returns it in
// the header of every response and stores it in the context; it answers the unknown routes and the wrong methods with
// the common envelope instead of the plain text of net/http; it turns a panic into the INTERNAL_ERROR envelope; and it
// writes the access log line of the request (Norma 5.3.9).
func root(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := correlationID(r)
		w.Header().Set(headerCorrelationID, id)
		r = r.WithContext(withCorrelationID(r.Context(), id))
		guarded := &startTracker{ResponseWriter: w, status: http.StatusOK}
		started := time.Now()
		_, pattern := mux.Handler(r)
		noteRoute(r.Context(), pattern)
		defer logAccess(r, guarded, routeOf(r, pattern), started)
		defer recoverToEnvelope(guarded, id)

		if pattern == "" {
			serveUnmatched(guarded, r, mux, id)
			return
		}
		mux.ServeHTTP(guarded, r)
	})
}

// routeOf is what the access log names as the route: the pattern that matched, or the path without its query string
// when none did.
func routeOf(r *http.Request, pattern string) string {
	if pattern != "" {
		return pattern
	}
	return r.Method + " " + r.URL.Path
}

// logAccess writes the one line per request. It carries no header, query string or body, so no token, Idempotency-Key,
// password or address can reach it.
func logAccess(r *http.Request, w *startTracker, route string, started time.Time) {
	slog.InfoContext(r.Context(), "request handled",
		"method", r.Method, "route", route, "status", w.status, "durationMs", time.Since(started).Milliseconds())
}

// serveUnmatched lets the mux answer the request that matches no route, and replaces its 404 and 405 with the envelope.
// Any other answer (the redirect to a clean path, for example) is passed on unchanged.
func serveUnmatched(w http.ResponseWriter, r *http.Request, mux *http.ServeMux, traceID string) {
	held := &heldResponse{header: http.Header{}}
	mux.ServeHTTP(held, r)
	switch held.status {
	case http.StatusNotFound:
		writeJSON(w, http.StatusNotFound, errorResponse{Error: codeNotFound, Message: "The requested resource does not exist", TraceID: traceID})
	case http.StatusMethodNotAllowed:
		w.Header().Set(headerAllow, held.header.Get(headerAllow))
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: codeMethodNotAllowed, Message: "The method is not allowed for this resource", TraceID: traceID})
	default:
		for name, values := range held.header {
			w.Header()[name] = values
		}
		w.WriteHeader(held.status)
		_, _ = w.Write(held.body.Bytes())
	}
}

// heldResponse keeps what the mux writes, so the root can decide what the client receives.
type heldResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (h *heldResponse) Header() http.Header { return h.header }

func (h *heldResponse) WriteHeader(status int) {
	if h.status == 0 {
		h.status = status
	}
}

func (h *heldResponse) Write(p []byte) (int, error) {
	h.WriteHeader(http.StatusOK)
	return h.body.Write(p)
}

// startTracker remembers whether the response has started, because an envelope can no longer be sent after that.
type startTracker struct {
	http.ResponseWriter
	started bool
	status  int
}

func (s *startTracker) WriteHeader(status int) {
	if !s.started {
		s.status = status
	}
	s.started = true
	s.ResponseWriter.WriteHeader(status)
}

func (s *startTracker) Write(p []byte) (int, error) {
	s.started = true
	return s.ResponseWriter.Write(p)
}

// Flush keeps http.Flusher available through the wrapper.
func (s *startTracker) Flush() {
	s.started = true
	if flusher, ok := s.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (s *startTracker) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// recoverToEnvelope answers a panic with INTERNAL_ERROR; the cause goes only to the log. http.ErrAbortHandler is the
// deliberate abort of net/http and is raised again.
func recoverToEnvelope(w *startTracker, traceID string) {
	cause := recover()
	if cause == nil {
		return
	}
	if err, ok := cause.(error); ok && errors.Is(err, http.ErrAbortHandler) {
		panic(cause)
	}
	slog.Error("request panicked", "traceId", traceID, "panic", cause)
	if w.started {
		return
	}
	writeJSON(w, http.StatusInternalServerError, errorResponse{
		Error: codeInternal, Message: "an unexpected error occurred", TraceID: traceID,
	})
}
