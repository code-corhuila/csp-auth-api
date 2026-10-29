package httpapi

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
)

const (
	codeMethodNotAllowed = "METHOD_NOT_ALLOWED"
	headerAllow          = "Allow"
)

type correlationKey struct{}

// withCorrelationID returns the context that carries the correlation id of the request.
func withCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationKey{}, id)
}

// CorrelationIDFrom returns the correlation id the root wrapper stored in the context, or "" when there is none.
func CorrelationIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(correlationKey{}).(string)
	return id
}

// root is the outermost step of the service (Norma 5.3.5 and 5.3.9). It decides the correlation id once, returns it in
// the header of every response and stores it in the context; it answers the unknown routes and the wrong methods with
// the common envelope instead of the plain text of net/http; and it turns a panic into the INTERNAL_ERROR envelope.
func root(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := correlationID(r)
		w.Header().Set(headerCorrelationID, id)
		r = r.WithContext(withCorrelationID(r.Context(), id))
		guarded := &startTracker{ResponseWriter: w}
		defer recoverToEnvelope(guarded, id)

		if _, pattern := mux.Handler(r); pattern == "" {
			serveUnmatched(guarded, r, mux, id)
			return
		}
		mux.ServeHTTP(guarded, r)
	})
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
}

func (s *startTracker) WriteHeader(status int) {
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
