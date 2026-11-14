package httpapi

import (
	"context"
	"net/http"
)

// detachedFromClient returns the context of an operation whose effects are split between PostgreSQL and Redis
// (sign out, removal of ADMIN): a client that leaves right after the click cancels its request, which must not stop
// the operation between the commit and the write to Redis. The context keeps the values of the request but not its
// cancellation, and ends at Limits.DetachedDeadline (norm 5.3.10). The authentication and the body are read on the request context.
func detachedFromClient(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), limitsOf(r.Context()).DetachedDeadline)
}
