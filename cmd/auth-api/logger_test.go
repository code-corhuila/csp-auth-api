package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/platform/logging"
)

func TestTheServiceLoggerWritesJSONWithTheTraceIDOfTheContext(t *testing.T) {
	var out bytes.Buffer

	newLogger(&out).WarnContext(logging.WithTraceID(context.Background(), "trace-main"), "hello")

	var line map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &line); err != nil {
		t.Fatalf("log %q is not one JSON line: %v", out.String(), err)
	}
	if line["msg"] != "hello" || line["traceId"] != "trace-main" {
		t.Errorf("line = %v, want msg hello and traceId trace-main", line)
	}
}
