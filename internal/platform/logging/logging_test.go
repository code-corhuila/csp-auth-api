package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
)

func lineOf(t *testing.T, buffer *bytes.Buffer) map[string]any {
	t.Helper()
	var line map[string]any
	if err := json.Unmarshal(buffer.Bytes(), &line); err != nil {
		t.Fatalf("log output %q is not one JSON line: %v", buffer.String(), err)
	}
	return line
}

func TestARecordLoggedWithAContextCarriesTheTraceID(t *testing.T) {
	var out bytes.Buffer
	logger := slog.New(NewTraceHandler(slog.NewJSONHandler(&out, nil)))

	logger.WarnContext(WithTraceID(context.Background(), "trace-1"), "something happened", "userId", "u-1")

	line := lineOf(t, &out)
	if line["traceId"] != "trace-1" || line["msg"] != "something happened" || line["userId"] != "u-1" {
		t.Errorf("line = %v, want msg, userId and traceId trace-1", line)
	}
}

func TestARecordWithoutATraceIDInTheContextIsLeftAlone(t *testing.T) {
	var out bytes.Buffer
	logger := slog.New(NewTraceHandler(slog.NewJSONHandler(&out, nil)))

	logger.Info("start-up")
	logger.InfoContext(WithTraceID(context.Background(), ""), "empty id")

	if bytes.Contains(out.Bytes(), []byte("traceId")) {
		t.Errorf("output %q has a traceId, want none", out.String())
	}
}

func TestARecordThatAlreadyHasATraceIDKeepsOnlyThatOne(t *testing.T) {
	var out bytes.Buffer
	logger := slog.New(NewTraceHandler(slog.NewJSONHandler(&out, nil)))

	logger.ErrorContext(WithTraceID(context.Background(), "from-context"), "failed", "traceId", "explicit")

	if got := bytes.Count(out.Bytes(), []byte(`"traceId"`)); got != 1 {
		t.Fatalf("traceId appears %d times in %q, want 1", got, out.String())
	}
	if line := lineOf(t, &out); line["traceId"] != "explicit" {
		t.Errorf("traceId = %v, want explicit", line["traceId"])
	}
}

func TestTheTraceIDSurvivesWithAttrs(t *testing.T) {
	var out bytes.Buffer
	logger := slog.New(NewTraceHandler(slog.NewJSONHandler(&out, nil))).With("component", "mail")

	logger.InfoContext(WithTraceID(context.Background(), "trace-2"), "delivered")

	line := lineOf(t, &out)
	if line["traceId"] != "trace-2" || line["component"] != "mail" {
		t.Errorf("line = %v, want component mail and traceId trace-2", line)
	}
}

func TestTraceIDFromAContextWithoutOneIsEmpty(t *testing.T) {
	if got := TraceIDFrom(context.Background()); got != "" {
		t.Errorf("TraceIDFrom = %q, want empty", got)
	}
}
