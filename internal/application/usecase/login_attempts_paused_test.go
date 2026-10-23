package usecase

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
)

func captureLoginLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logs
}

// While the limiter is paused (ADR-048) the login goes on exactly as when the store fails, but it writes nothing:
// the decorator already wrote the one WARN of the pause.
func TestLoginGoesOnWithoutLoggingWhileTheLimiterIsPaused(t *testing.T) {
	attempts := newLoginAttempts()
	attempts.err = out.ErrLoginAttemptsPaused
	f := newLimitedLoginFixture(t, attempts)
	logs := captureLoginLog(t)

	if err := loginFrom(f, clientAddress, rightPass); err != nil {
		t.Errorf("right password: error = %v, want the login to go on", err)
	}
	if err := loginFrom(f, clientAddress, "Wrong1234"); err == nil || strings.Contains(err.Error(), "paused") {
		t.Errorf("wrong password: error = %v, want the credential failure, not the pause", err)
	}
	if logs.Len() != 0 {
		t.Errorf("log = %q, want nothing while the limiter is paused", logs.String())
	}
}
