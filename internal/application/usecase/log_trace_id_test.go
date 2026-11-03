package usecase

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
	"github.com/code-corhuila/csp-auth-api/internal/platform/logging"
)

func TestAUseCaseLogWrittenWithTheContextCarriesTheTraceIDOfTheRequest(t *testing.T) {
	var out bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(logging.NewTraceHandler(slog.NewJSONHandler(&out, nil))))
	t.Cleanup(func() { slog.SetDefault(previous) })
	f := newRefreshFixture(t, storedUser(t, model.UserActive, model.RoleClient))
	f.addToken("token-2", "user-1", "sibling")
	f.stored().Revoke(registeredAt.Add(-time.Minute))
	ctx := logging.WithTraceID(context.Background(), "trace-uc-1")

	_, _ = f.useCase.Refresh(ctx, in.RefreshSessionCommand{RefreshToken: presentedToken})

	var line map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &line); err != nil {
		t.Fatalf("log %q is not one JSON line: %v", out.String(), err)
	}
	if line["level"] != "WARN" || line["traceId"] != "trace-uc-1" {
		t.Errorf("line = %v, want the WARN of the reuse with traceId trace-uc-1", line)
	}
}
