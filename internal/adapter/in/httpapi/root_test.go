package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func serve(handler http.Handler, method, path, correlation string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	request := httptest.NewRequest(method, path, nil)
	if correlation != "" {
		request.Header.Set(headerCorrelationID, correlation)
	}
	handler.ServeHTTP(rec, request)
	return rec
}

func decodeEnvelope(t *testing.T, rec *httptest.ResponseRecorder) errorResponse {
	t.Helper()
	var body errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q is not the envelope: %v", rec.Body.String(), err)
	}
	return body
}

func TestUnknownRouteAnswersTheEnvelopeWithTheCorrelationID(t *testing.T) {
	rec := serve(NewHandler(), http.MethodGet, "/api/v1/auth/unknown", "client-id-7")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	body := decodeEnvelope(t, rec)
	if body.Error != "NOT_FOUND" || body.Message == "" || body.TraceID != "client-id-7" {
		t.Errorf("envelope = %+v, want NOT_FOUND with message and traceId client-id-7", body)
	}
	if got := rec.Header().Get(headerCorrelationID); got != "client-id-7" {
		t.Errorf("%s = %q, want the received id", headerCorrelationID, got)
	}
}

func TestWrongMethodAnswers405WithAllowAndTheEnvelope(t *testing.T) {
	rec := serve(NewHandler(), http.MethodPost, "/api/v1/auth/health", "")

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); !strings.Contains(allow, "GET") {
		t.Errorf("Allow = %q, want it to list GET", allow)
	}
	body := decodeEnvelope(t, rec)
	if body.Error != "METHOD_NOT_ALLOWED" || body.Message == "" || body.TraceID == "" {
		t.Errorf("envelope = %+v, want METHOD_NOT_ALLOWED with message and traceId", body)
	}
	if got := rec.Header().Get(headerCorrelationID); got != body.TraceID {
		t.Errorf("%s = %q, want the traceId %q", headerCorrelationID, got, body.TraceID)
	}
}

func TestEveryPublicRouteReturnsAGeneratedIDAndEchoesAValidOne(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	handler := NewHandler(WithPublicKeys(fixedKeys{{KeyID: "kid-1", Key: &key.PublicKey}}))
	for _, path := range []string{"/api/v1/auth/health", "/api/v1/auth/health/ready", "/api/v1/auth/jwks", "/api/v1/auth/nothing-here"} {
		generated := serve(handler, http.MethodGet, path, "").Header().Get(headerCorrelationID)
		if len(generated) != 36 || generated[14] != '4' {
			t.Errorf("%s: generated id = %q, want a version 4 UUID", path, generated)
		}
		if echoed := serve(handler, http.MethodGet, path, "abc-123").Header().Get(headerCorrelationID); echoed != "abc-123" {
			t.Errorf("%s: echoed id = %q, want abc-123", path, echoed)
		}
	}
}

func TestAnInvalidReceivedIDIsReplaced(t *testing.T) {
	for name, received := range map[string]string{
		"with a space": "not valid",
		"too long":     strings.Repeat("a", maxCorrelationIDLen+1),
	} {
		got := serve(NewHandler(), http.MethodGet, "/api/v1/auth/health", received).Header().Get(headerCorrelationID)
		if got == received || len(got) != 36 {
			t.Errorf("%s: id = %q, want a generated one", name, got)
		}
	}
}

func TestTheHandlersReadTheCorrelationIDFromTheContext(t *testing.T) {
	var seen, fromHelper string
	probe := func(mux *http.ServeMux) {
		mux.HandleFunc("GET /probe", func(_ http.ResponseWriter, r *http.Request) {
			seen = CorrelationIDFrom(r.Context())
			fromHelper = correlationID(r)
		})
	}
	rec := serve(NewHandler(probe), http.MethodGet, "/probe", "ctx-id-1")

	if seen != "ctx-id-1" || fromHelper != "ctx-id-1" || rec.Header().Get(headerCorrelationID) != "ctx-id-1" {
		t.Errorf("context = %q, helper = %q, header = %q, want ctx-id-1 in all", seen, fromHelper, rec.Header().Get(headerCorrelationID))
	}
	if CorrelationIDFrom(context.Background()) != "" {
		t.Error("a context without the wrapper must have no id")
	}
}

func TestAPanicBecomesTheInternalErrorEnvelopeWithoutTheCause(t *testing.T) {
	panicking := func(mux *http.ServeMux) {
		mux.HandleFunc("GET /boom", func(http.ResponseWriter, *http.Request) { panic("secret cause: db password") })
	}
	rec := serve(NewHandler(panicking), http.MethodGet, "/boom", "boom-id")

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	body := decodeEnvelope(t, rec)
	if body.Error != "INTERNAL_ERROR" || body.TraceID != "boom-id" {
		t.Errorf("envelope = %+v, want INTERNAL_ERROR with traceId boom-id", body)
	}
	if strings.Contains(rec.Body.String(), "secret cause") {
		t.Errorf("body %q leaks the cause of the panic", rec.Body.String())
	}
	if rec.Header().Get(headerCorrelationID) != "boom-id" {
		t.Errorf("%s = %q, want boom-id", headerCorrelationID, rec.Header().Get(headerCorrelationID))
	}
}

func TestAPanicAfterTheResponseStartedKeepsTheAnswerAlreadySent(t *testing.T) {
	late := func(mux *http.ServeMux) {
		mux.HandleFunc("GET /late", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusAccepted)
			panic("after the header")
		})
	}
	rec := serve(NewHandler(late), http.MethodGet, "/late", "")

	if rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
		t.Errorf("status = %d, body = %q, want the 202 already sent and nothing more", rec.Code, rec.Body.String())
	}
}

func TestTheAbortOfTheHandlerIsNotSwallowed(t *testing.T) {
	aborting := func(mux *http.ServeMux) {
		mux.HandleFunc("GET /abort", func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) })
	}
	defer func() {
		if recover() != http.ErrAbortHandler {
			t.Error("http.ErrAbortHandler must reach net/http")
		}
	}()
	serve(NewHandler(aborting), http.MethodGet, "/abort", "")
}

func TestTheRedirectToACleanPathIsPassedOn(t *testing.T) {
	rec := serve(NewHandler(), http.MethodGet, "/api/v1/auth//health", "")

	if rec.Code != http.StatusTemporaryRedirect || rec.Header().Get("Location") == "" {
		t.Errorf("status = %d, Location = %q, want the redirect of the mux", rec.Code, rec.Header().Get("Location"))
	}
}
