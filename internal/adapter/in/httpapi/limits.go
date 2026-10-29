package httpapi

import (
	"context"
	"net/http"
	"time"
)

// Limits are the explicit limits of a request (Norma 5.3.10) that the composition root reads from its configuration.
type Limits struct {
	// RequestTimeout is the deadline of every request: it ends the wait for a pooled database connection and the work after it.
	RequestTimeout time.Duration
	// DetachedDeadline bounds the operations that must finish once started, whatever the client does.
	DetachedDeadline time.Duration
	// MaxBodyBytes is the limit of the body of a request.
	MaxBodyBytes int64
	// PasswordResetMaxBodyBytes is the smaller limit of the body of the two password reset routes (ADR-050).
	PasswordResetMaxBodyBytes int64
}

// fallbackLimits apply to a handler built without WithLimits, which only the unit tests do: the service always starts
// through the composition root, which passes the validated configuration.
var fallbackLimits = Limits{
	RequestTimeout:            10 * time.Second,
	DetachedDeadline:          10 * time.Second,
	MaxBodyBytes:              1 << 20,
	PasswordResetMaxBodyBytes: 4 << 10,
}

type limitsKey struct{}

// WithLimits gives every request of next its deadline and makes limits available to the handlers, which read the body and
// detached limits from the request context.
func WithLimits(next http.Handler, limits Limits) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.WithValue(r.Context(), limitsKey{}, limits), limits.RequestTimeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func limitsOf(ctx context.Context) Limits {
	if limits, ok := ctx.Value(limitsKey{}).(Limits); ok {
		return limits
	}
	return fallbackLimits
}
