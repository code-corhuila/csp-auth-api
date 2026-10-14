package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// Contract tests: the real handlers answer through fakes of the use cases, and every response is
// validated against auth-service.yaml of csp-docs (07-api/contracts/openapi). The contract is not
// changed here. A status the contract does not declare for an operation (see undocumentedStatuses)
// is not validated as declared: its body must at least be the ErrorResponse of _shared.yaml, and
// the gap is logged so it can be fixed in csp-docs.

const contractFileVariable = "AUTH_CONTRACT_FILE"

var (
	loadContractOnce sync.Once
	contractDoc      *openapi3.T
	contractErr      error
)

// contract loads auth-service.yaml and the _shared.yaml it references. A missing file skips the
// test on a workstation but fails it in CI (the CI variable), so the check cannot be lost silently.
func contract(t *testing.T) *openapi3.T {
	t.Helper()
	path := os.Getenv(contractFileVariable)
	if path == "" {
		if os.Getenv("CI") != "" {
			t.Fatalf("%s must point to auth-service.yaml of csp-docs", contractFileVariable)
		}
		t.Skipf("%s is not set: contract tests need auth-service.yaml of csp-docs", contractFileVariable)
	}
	loadContractOnce.Do(func() {
		loader := openapi3.NewLoader()
		loader.IsExternalRefsAllowed = true
		contractDoc, contractErr = loader.LoadFromFile(path)
		if contractErr == nil {
			contractErr = contractDoc.Validate(loader.Context)
		}
	})
	if contractErr != nil {
		t.Fatalf("the contract %s cannot be loaded: %v", path, contractErr)
	}
	return contractDoc
}

// requireContract fails unless rec is a response the contract declares for the operation: status,
// declared headers, content type and body schema.
func requireContract(t *testing.T, method, path string, rec *httptest.ResponseRecorder) {
	t.Helper()
	doc := contract(t)
	contractPath := strings.TrimPrefix(path, BasePath)
	item := doc.Paths.Find(contractPath)
	if item == nil || item.GetOperation(method) == nil {
		t.Fatalf("the contract has no %s %s", method, contractPath)
	}
	operation := item.GetOperation(method)
	if operation.Responses.Status(rec.Code) == nil && undocumentedStatuses[fmt.Sprintf("%s %s %d", method, contractPath, rec.Code)] {
		requireErrorResponse(t, doc, rec)
		t.Logf("%s %s %d is not declared by the contract; checked against ErrorResponse only", method, contractPath, rec.Code)
		return
	}
	request := httptest.NewRequest(method, path, nil)
	input := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request: request,
			Route: &routers.Route{
				Spec: doc, Path: contractPath, PathItem: item, Method: method, Operation: operation,
			},
		},
		Status:  rec.Code,
		Header:  rec.Header(),
		Options: &openapi3filter.Options{IncludeResponseStatus: true, MultiError: true},
	}
	input.SetBodyBytes(rec.Body.Bytes())
	if err := openapi3filter.ValidateResponse(context.Background(), input); err != nil {
		t.Errorf("%s %s answered %d against the contract: %v\nbody: %s", method, contractPath, rec.Code, err, rec.Body)
	}
	declared := operation.Responses.Status(rec.Code)
	if declared == nil || declared.Value == nil {
		return
	}
	for name := range declared.Value.Headers {
		if rec.Header().Get(name) == "" {
			t.Errorf("%s %s %d: the contract declares the header %s and the response has none", method, contractPath, rec.Code, name)
		}
	}
}

// undocumentedStatuses are answers of the service that auth-service.yaml 1.3.1 does not declare.
// Once csp-docs declares one, the response is validated in full and the entry can be removed.
var undocumentedStatuses = map[string]bool{
	"POST /register 500": true,
	"POST /login 400":    true,
	"POST /login 500":    true,
	"POST /refresh 400":  true,
	"POST /refresh 423":  true,
	"POST /refresh 500":  true,
}

// requireErrorResponse checks the body of rec against the ErrorResponse schema of _shared.yaml and
// that the response repeats the correlation id.
func requireErrorResponse(t *testing.T, doc *openapi3.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	var body any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v (%s)", err, rec.Body)
	}
	if err := doc.Components.Schemas["ErrorResponse"].Value.VisitJSON(body); err != nil {
		t.Errorf("the body is not an ErrorResponse: %v\nbody: %s", err, rec.Body)
	}
	if rec.Header().Get("X-Correlation-Id") == "" {
		t.Error("the response has no X-Correlation-Id")
	}
}

const traceID = "550e8400-e29b-41d4-a716-446655440000"

func withTrace() map[string]string { return map[string]string{"X-Correlation-Id": traceID} }

func TestRegisterResponsesFulfillTheContract(t *testing.T) {
	replay := createdSession()
	replay.Replayed = true
	cases := map[string]struct {
		useCase in.RegisterUser
		a       attempt
	}{
		"201 created":                {&fakeRegister{result: createdSession()}, attempt{body: validBody(), key: validKey, headers: withTrace()}},
		"200 replay":                 {&fakeRegister{result: replay}, attempt{body: validBody(), key: validKey, headers: withTrace()}},
		"400 invalid fields":         {&fakeRegister{}, attempt{body: `{"email":"nope","password":"weakpw"}`, key: "short", headers: withTrace()}},
		"400 unreadable body":        {&fakeRegister{}, attempt{body: `{"email":`, key: validKey}},
		"400 domain validation":      {&fakeRegister{err: model.ErrInvalidPhone}, attempt{body: validBody(), key: validKey, headers: withTrace()}},
		"409 email registered":       {&fakeRegister{err: model.ErrEmailAlreadyRegistered}, attempt{body: validBody(), key: validKey, headers: withTrace()}},
		"409 key reused":             {&fakeRegister{err: model.ErrIdempotencyKeyConflict}, attempt{body: validBody(), key: validKey, headers: withTrace()}},
		"500 unexpected":             {&fakeRegister{err: errors.New("driver failure")}, attempt{body: validBody(), key: validKey, headers: withTrace()}},
		"500 replay without account": {&fakeRegister{err: model.ErrUserNotFound}, attempt{body: validBody(), key: validKey}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			requireContract(t, http.MethodPost, registerPath, send(c.useCase, c.a))
		})
	}
}

func TestLoginResponsesFulfillTheContract(t *testing.T) {
	cases := map[string]struct {
		useCase in.LoginUser
		a       attempt
	}{
		"200 signed in":       {&fakeLogin{result: loggedInSession()}, attempt{body: loginBody(), headers: withTrace()}},
		"400 missing fields":  {&fakeLogin{}, attempt{body: `{}`, headers: withTrace()}},
		"401 bad credentials": {&fakeLogin{err: model.ErrInvalidCredentials}, attempt{body: loginBody(), headers: withTrace()}},
		"423 locked":          {&fakeLogin{err: model.ErrUserLocked}, attempt{body: loginBody(), headers: withTrace()}},
		"500 unexpected":      {&fakeLogin{err: errors.New("driver failure")}, attempt{body: loginBody()}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			requireContract(t, http.MethodPost, loginPath, sendLogin(c.useCase, c.a))
		})
	}
}

func TestRefreshResponsesFulfillTheContract(t *testing.T) {
	cases := map[string]struct {
		useCase in.RefreshSession
		a       attempt
	}{
		"200 renewed":        {&fakeRefresh{result: loggedInSession()}, attempt{body: refreshBody(), headers: withTrace()}},
		"400 missing token":  {&fakeRefresh{}, attempt{body: `{}`, headers: withTrace()}},
		"401 rejected token": {&fakeRefresh{err: model.ErrRefreshTokenRejected}, attempt{body: refreshBody(), headers: withTrace()}},
		"423 locked":         {&fakeRefresh{err: model.ErrUserLocked}, attempt{body: refreshBody(), headers: withTrace()}},
		"500 unexpected":     {&fakeRefresh{err: errors.New("driver failure")}, attempt{body: refreshBody()}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			requireContract(t, http.MethodPost, refreshPath, sendRefresh(c.useCase, c.a))
		})
	}
}

func TestJWKSResponseFulfillsTheContract(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys := fixedKeys{{KeyID: "key-1", Key: &key.PublicKey}}
	rec := httptest.NewRecorder()
	NewHandler(WithPublicKeys(keys)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, BasePath+"/jwks", nil))

	requireContract(t, http.MethodGet, BasePath+"/jwks", rec)
}
