package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
	"github.com/code-corhuila/csp-auth-api/internal/platform/logging"
)

func recordWith(t *testing.T, ctx context.Context, event model.LoginLocked) (map[string]any, string) {
	t.Helper()
	var buffer bytes.Buffer
	logger := slog.New(logging.NewTraceHandler(slog.NewJSONHandler(&buffer, nil)))
	if err := NewLoginLockLog(logger).RecordLoginLocked(ctx, event); err != nil {
		t.Fatalf("RecordLoginLocked() error = %v", err)
	}
	line := strings.TrimSpace(buffer.String())
	var fields map[string]any
	if err := json.Unmarshal([]byte(line), &fields); err != nil {
		t.Fatalf("the audit line is not JSON: %q (%v)", line, err)
	}
	return fields, line
}

func TestTheLockIsWrittenAsOneLineWithTheHashTheAttemptsTheTimeAndTheTraceId(t *testing.T) {
	at := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	event := model.NewLoginLocked("203.0.113.7", 10, at, 5*time.Minute)

	fields, _ := recordWith(t, logging.WithTraceID(context.Background(), "trace-1"), event)

	want := map[string]any{
		"audit":       "login_locked",
		"clientHash":  event.ClientHash,
		"attempts":    float64(10),
		"lockedAt":    "2026-10-30T12:00:00Z",
		"lockSeconds": float64(300),
		"traceId":     "trace-1",
	}
	for key, value := range want {
		if fields[key] != value {
			t.Errorf("%s = %v, want %v (line: %v)", key, fields[key], value, fields)
		}
	}
}

func TestTheLockLineNeverCarriesTheAddressTheEmailOrAPassword(t *testing.T) {
	event := model.NewLoginLocked("203.0.113.7", 10, time.Now(), time.Minute)

	_, line := recordWith(t, logging.WithTraceID(context.Background(), "trace-1"), event)

	for _, forbidden := range []string{"203.0.113.7", "@", "password", "email"} {
		if strings.Contains(strings.ToLower(line), forbidden) {
			t.Errorf("the audit line %q contains %q", line, forbidden)
		}
	}
}
