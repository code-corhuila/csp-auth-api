package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

func TestSendLogsTheCodeWithTheUserAndTheRequestAtInfoAndNothingElse(t *testing.T) {
	var buffer bytes.Buffer
	sender := NewVerificationCodeSender(slog.New(slog.NewJSONHandler(&buffer, nil)))
	email, _ := model.NewEmail("new@example.com")
	code, _ := model.NewVerificationCode("012345")

	err := sender.Send(context.Background(), out.VerificationCodeDelivery{
		RequestID: "request-1", UserID: "user-1", NewEmail: email, Code: code, ExpiresAt: time.Now(),
	})

	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	var entry map[string]any
	if err := json.Unmarshal(buffer.Bytes(), &entry); err != nil {
		t.Fatalf("log line %q is not JSON: %v", buffer.String(), err)
	}
	want := map[string]any{"level": "INFO", "msg": "email verification code issued", "userId": "user-1", "requestId": "request-1", "code": "012345"}
	for key, value := range want {
		if entry[key] != value {
			t.Errorf("%s = %v, want %v", key, entry[key], value)
		}
	}
	if strings.Contains(buffer.String(), "new@example.com") {
		t.Errorf("log line %q contains the address", buffer.String())
	}
}
