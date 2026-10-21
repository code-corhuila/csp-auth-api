package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// Contract tests: the real handlers answer through fakes of the use cases, and every response is
// validated against auth-service.yaml of csp-docs (07-api/contracts/openapi). The contract is not
// changed here.

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
		"429 rate limited":    {&fakeLogin{err: &model.LoginRateLimitedError{RetryAfter: 90 * time.Second}}, attempt{body: loginBody(), headers: withTrace()}},
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

func TestUpdateUserRoleResponsesFulfillTheContract(t *testing.T) {
	path := BasePath + "/users/{userId}/role"
	headers := func(extra map[string]string) map[string]string {
		merged := withTrace()
		for name, value := range extra {
			merged[name] = value
		}
		return merged
	}
	cases := map[string]struct {
		authorizer *fakeUserAuthorizer
		useCase    in.ChangeUserRole
		a          roleAttempt
	}{
		"200 granted":               {&fakeUserAuthorizer{}, &fakeChangeRole{summary: promotedUser()}, roleAttempt{key: roleKey, body: grantBody, headers: withTrace()}},
		"200 no change":             {&fakeUserAuthorizer{}, &fakeChangeRole{summary: promotedUser()}, roleAttempt{key: roleKey, body: `{"role":"ADMIN","enabled":false}`, headers: withTrace()}},
		"400 invalid fields":        {&fakeUserAuthorizer{}, &fakeChangeRole{}, roleAttempt{key: "short", body: `{}`, headers: withTrace()}},
		"400 role not changeable":   {&fakeUserAuthorizer{}, &fakeChangeRole{err: model.ErrRoleNotChangeable}, roleAttempt{key: roleKey, body: `{"role":"CLIENT","enabled":true}`, headers: withTrace()}},
		"401 no token":              {&fakeUserAuthorizer{err: model.ErrAccessTokenInvalid}, &fakeChangeRole{}, roleAttempt{key: roleKey, body: grantBody, headers: withTrace()}},
		"403 without permission":    {&fakeUserAuthorizer{err: model.ErrPermissionDenied}, &fakeChangeRole{}, roleAttempt{key: roleKey, body: grantBody, headers: withTrace()}},
		"404 unknown user":          {&fakeUserAuthorizer{}, &fakeChangeRole{err: model.ErrUserNotFound}, roleAttempt{key: roleKey, body: grantBody, headers: headers(nil)}},
		"409 last administrator":    {&fakeUserAuthorizer{}, &fakeChangeRole{err: model.ErrLastAdmin}, roleAttempt{key: roleKey, body: `{"role":"ADMIN","enabled":false}`, headers: withTrace()}},
		"409 user without roles":    {&fakeUserAuthorizer{}, &fakeChangeRole{err: model.ErrNoRoles}, roleAttempt{key: roleKey, body: `{"role":"ADMIN","enabled":false}`, headers: withTrace()}},
		"500 unexpected":            {&fakeUserAuthorizer{}, &fakeChangeRole{err: errors.New("driver failure")}, roleAttempt{key: roleKey, body: grantBody, headers: withTrace()}},
		"500 authorizer unexpected": {&fakeUserAuthorizer{err: errors.New("key store down")}, &fakeChangeRole{}, roleAttempt{key: roleKey, body: grantBody, headers: withTrace()}},
		"401 revoked token":         {&fakeUserAuthorizer{err: model.ErrAccessTokenInvalid}, &fakeChangeRole{}, roleAttempt{key: roleKey, body: grantBody, headers: withTrace()}},
		"500 revoked list down":     {&fakeUserAuthorizer{err: errRevokedListDown}, &fakeChangeRole{}, roleAttempt{key: roleKey, body: grantBody, headers: withTrace()}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			requireContract(t, http.MethodPatch, path, sendRoleChange(c.authorizer, c.useCase, c.a))
		})
	}
}

func TestListUsersResponsesFulfillTheContract(t *testing.T) {
	cases := map[string]struct {
		authorizer *fakeUserAuthorizer
		useCase    in.ListUsers
		query      string
	}{
		"200 page":                  {&fakeUserAuthorizer{}, &fakeListUsers{page: onePage()}, "?email=mar&page=1&limit=20"},
		"200 empty page":            {&fakeUserAuthorizer{}, &fakeListUsers{page: in.UserPage{Page: 1, Limit: 20}}, "?email=nobody"},
		"400 page not an integer":   {&fakeUserAuthorizer{}, &fakeListUsers{}, "?page=two"},
		"400 empty prefix":          {&fakeUserAuthorizer{}, &fakeListUsers{err: model.ErrInvalidEmailPrefix}, "?email="},
		"400 limit too big":         {&fakeUserAuthorizer{}, &fakeListUsers{err: model.ErrInvalidPageLimit}, "?limit=101"},
		"401 no token":              {&fakeUserAuthorizer{err: model.ErrAccessTokenInvalid}, &fakeListUsers{}, ""},
		"403 without permission":    {&fakeUserAuthorizer{err: model.ErrPermissionDenied}, &fakeListUsers{}, ""},
		"500 unexpected":            {&fakeUserAuthorizer{}, &fakeListUsers{err: errors.New("driver failure")}, ""},
		"500 authorizer unexpected": {&fakeUserAuthorizer{err: errors.New("key store down")}, &fakeListUsers{}, ""},
		"401 revoked token":         {&fakeUserAuthorizer{err: model.ErrAccessTokenInvalid}, &fakeListUsers{}, "?email=mar"},
		"500 revoked list down":     {&fakeUserAuthorizer{err: errRevokedListDown}, &fakeListUsers{}, "?email=mar"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			requireContract(t, http.MethodGet, usersPath, sendList(c.authorizer, c.useCase, c.query, withTrace()))
		})
	}
}

func TestLogoutResponsesFulfillTheContract(t *testing.T) {
	cases := map[string]struct {
		authenticator *fakeAuthenticator
		useCase       in.Logout
		a             logoutAttempt
	}{
		"204 without body":        {&fakeAuthenticator{}, &fakeLogout{}, logoutAttempt{headers: withTrace()}},
		"204 refresh token":       {&fakeAuthenticator{}, &fakeLogout{}, logoutAttempt{body: `{"refreshToken":"opaque-1"}`, headers: withTrace()}},
		"204 all devices":         {&fakeAuthenticator{}, &fakeLogout{}, logoutAttempt{body: `{"allDevices":true}`, headers: withTrace()}},
		"400 unreadable body":     {&fakeAuthenticator{}, &fakeLogout{}, logoutAttempt{body: `{"refreshToken":`, headers: withTrace()}},
		"400 wrong type":          {&fakeAuthenticator{}, &fakeLogout{}, logoutAttempt{body: `{"allDevices":"yes"}`, headers: withTrace()}},
		"401 no token":            {&fakeAuthenticator{err: model.ErrAccessTokenInvalid}, &fakeLogout{}, logoutAttempt{headers: withTrace()}},
		"500 unexpected":          {&fakeAuthenticator{}, &fakeLogout{err: errors.New("redis down")}, logoutAttempt{headers: withTrace()}},
		"500 verifier unexpected": {&fakeAuthenticator{err: errors.New("key store down")}, &fakeLogout{}, logoutAttempt{}},
		"401 revoked token":       {&fakeAuthenticator{err: model.ErrAccessTokenInvalid}, &fakeLogout{}, logoutAttempt{body: `{"allDevices":true}`, headers: withTrace()}},
		"500 revoked list down":   {&fakeAuthenticator{err: errRevokedListDown}, &fakeLogout{err: errors.New("redis down")}, logoutAttempt{headers: withTrace()}},
		"204 revoked list down":   {&fakeAuthenticator{err: errRevokedListDown}, &fakeLogout{}, logoutAttempt{headers: withTrace()}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			requireContract(t, http.MethodPost, logoutPath, sendLogout(c.authenticator, c.useCase, c.a))
		})
	}
}
