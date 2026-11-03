// Package audit holds the adapters that record the security events of the service for review.
package audit

import (
	"context"
	"log/slog"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// LoginLockLog implements out.LoginLockAudit as one structured log record per lock, identified by the field audit. The
// traceId is added by the logging handler from the context of the request.
type LoginLockLog struct {
	logger *slog.Logger
}

var _ out.LoginLockAudit = (*LoginLockLog)(nil)

// NewLoginLockLog writes the events through logger.
func NewLoginLockLog(logger *slog.Logger) *LoginLockLog {
	return &LoginLockLog{logger: logger}
}

// RecordLoginLocked writes the hash of the address, the attempts, the time and the length of the lock.
func (l *LoginLockLog) RecordLoginLocked(ctx context.Context, event model.LoginLocked) error {
	l.logger.WarnContext(ctx, "login address locked",
		"audit", "login_locked",
		"clientHash", event.ClientHash,
		"attempts", event.Attempts,
		"lockedAt", event.LockedAt.UTC().Format(time.RFC3339),
		"lockSeconds", int(event.LockFor.Seconds()))
	return nil
}
