// Package logging carries the trace id of a request through the context and puts it in every structured log line
// (Norma 5.3.9). It is neutral on purpose: the http adapter stores the id, and the use cases and the other adapters log with
// slog.XContext(ctx, ...) without importing the http adapter.
package logging

import (
	"context"
	"log/slog"
)

// TraceIDKey is the attribute that carries the correlation id in every log line, as in the error envelope.
const TraceIDKey = "traceId"

type traceKey struct{}

// WithTraceID returns the context that carries the trace id of the request.
func WithTraceID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, traceKey{}, id)
}

// TraceIDFrom returns the trace id stored in ctx, or "" when there is none.
func TraceIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(traceKey{}).(string)
	return id
}

// NewTraceHandler wraps inner (pattern Decorator): a record logged with a context that carries a trace id gets the traceId
// attribute, unless the record already has one.
func NewTraceHandler(inner slog.Handler) slog.Handler {
	return traceHandler{inner: inner}
}

type traceHandler struct {
	inner slog.Handler
}

func (h traceHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h traceHandler) Handle(ctx context.Context, record slog.Record) error {
	if id := TraceIDFrom(ctx); id != "" && !hasTraceID(record) {
		record.AddAttrs(slog.String(TraceIDKey, id))
	}
	return h.inner.Handle(ctx, record)
}

func (h traceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return traceHandler{inner: h.inner.WithAttrs(attrs)}
}

func (h traceHandler) WithGroup(name string) slog.Handler {
	return traceHandler{inner: h.inner.WithGroup(name)}
}

func hasTraceID(record slog.Record) bool {
	found := false
	record.Attrs(func(attr slog.Attr) bool {
		found = attr.Key == TraceIDKey
		return !found
	})
	return found
}
