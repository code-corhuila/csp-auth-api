package httpapi

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// Every route that hashes a password answers a saturated hasher the same way: 503 SERVICE_UNAVAILABLE with Retry-After, one
// WARN with the traceId, and the cause is not an internal error.
func TestEveryRouteThatHashesAnswers503WithRetryAfterAndAWarnWithTheTraceIdWhenTheHasherIsBusy(t *testing.T) {
	routes := map[string]func(http.ResponseWriter, string, error){
		"login":           translateLoginError,
		"register":        translateRegisterError,
		"change password": translateChangePasswordError,
		"reset password":  translateResetPasswordError,
	}
	for name, translate := range routes {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
			defer slog.SetDefault(previous)
			rec := httptest.NewRecorder()

			translate(rec, "trace-busy-1", fmt.Errorf("hash: %w", model.ErrPasswordHasherBusy))

			if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "1" {
				t.Errorf("status = %d, Retry-After = %q, want 503 and 1", rec.Code, rec.Header().Get("Retry-After"))
			}
			body := rec.Body.String()
			if !strings.Contains(body, `"error":"SERVICE_UNAVAILABLE"`) || !strings.Contains(body, `"traceId":"trace-busy-1"`) {
				t.Errorf("body = %s, want SERVICE_UNAVAILABLE with the traceId", body)
			}
			line := logs.String()
			if !strings.Contains(line, `"level":"WARN"`) || !strings.Contains(line, "trace-busy-1") || strings.Contains(line, `"level":"ERROR"`) {
				t.Errorf("log = %s, want one WARN with the traceId and no ERROR", line)
			}
		})
	}
}
