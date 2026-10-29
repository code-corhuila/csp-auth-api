package httpapi

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/platform/logging"
)

// captureJSONLogs makes the traced JSON logger the default one, as main does, and returns what it writes.
func captureJSONLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var out bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(logging.NewTraceHandler(slog.NewJSONHandler(&out, nil))))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &out
}

func jsonLines(t *testing.T, out *bytes.Buffer) []map[string]any {
	t.Helper()
	var lines []map[string]any
	for _, text := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if text == "" {
			continue
		}
		var line map[string]any
		if err := json.Unmarshal([]byte(text), &line); err != nil {
			t.Fatalf("log line %q is not JSON: %v", text, err)
		}
		lines = append(lines, line)
	}
	return lines
}

func TestEveryRequestWritesOneAccessLineWithItsTraceID(t *testing.T) {
	cases := map[string]struct {
		method, path string
		status       int
		route        string
	}{
		"matched route": {http.MethodGet, "/api/v1/auth/health?probe=1", http.StatusOK, "GET " + BasePath + "/health"},
		"unknown route": {http.MethodGet, "/api/v1/auth/unknown?token=secret", http.StatusNotFound, "GET /api/v1/auth/unknown"},
		"wrong method":  {http.MethodPost, "/api/v1/auth/health", http.StatusMethodNotAllowed, "POST /api/v1/auth/health"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			logs := captureJSONLogs(t)
			request := httptest.NewRequest(c.method, c.path, nil)
			request.Header.Set(headerCorrelationID, "client-id-9")
			request.Header.Set("Authorization", "Bearer secret-token")
			request.Header.Set("Idempotency-Key", "secret-key")
			rec := httptest.NewRecorder()

			NewHandler().ServeHTTP(rec, request)

			lines := jsonLines(t, logs)
			if len(lines) != 1 {
				t.Fatalf("%d log lines %q, want exactly the access line", len(lines), logs.String())
			}
			line := lines[0]
			if line["method"] != c.method || line["route"] != c.route || line["status"] != float64(c.status) || line["traceId"] != "client-id-9" {
				t.Errorf("access line = %v, want %s %q status %d traceId client-id-9", line, c.method, c.route, c.status)
			}
			if _, ok := line["durationMs"].(float64); !ok {
				t.Errorf("access line = %v, want a numeric durationMs", line)
			}
			for _, secret := range []string{"secret-token", "secret-key", "token=secret", "probe"} {
				if strings.Contains(logs.String(), secret) {
					t.Errorf("log %q leaks %q", logs.String(), secret)
				}
			}
		})
	}
}

func TestAPanicWritesTheAccessLineWith500(t *testing.T) {
	logs := captureJSONLogs(t)
	handler := root(panickingMux())

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/boom", nil))

	lines := jsonLines(t, logs)
	last := lines[len(lines)-1]
	if last["msg"] != "request handled" || last["status"] != float64(http.StatusInternalServerError) {
		t.Errorf("last line = %v, want the access line with status 500", last)
	}
}

func TestALogWrittenWithTheContextOfTheRequestCarriesItsTraceID(t *testing.T) {
	logs := captureJSONLogs(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /work", func(w http.ResponseWriter, r *http.Request) {
		slog.WarnContext(r.Context(), "a use case warns")
	})
	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/work", nil)
	request.Header.Set(headerCorrelationID, "trace-77")

	root(mux).ServeHTTP(rec, request)

	var warned map[string]any
	for _, line := range jsonLines(t, logs) {
		if line["msg"] == "a use case warns" {
			warned = line
		}
	}
	if warned == nil || warned["traceId"] != "trace-77" || rec.Header().Get(headerCorrelationID) != "trace-77" {
		t.Errorf("lines %q, want the warning with traceId trace-77", logs.String())
	}
}

func panickingMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /boom", func(http.ResponseWriter, *http.Request) { panic("boom") })
	return mux
}
