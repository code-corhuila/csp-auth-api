package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

func traced(a emailAttempt) emailAttempt {
	a.headers = withTrace()
	return a
}

func TestRequestEmailChangeResponsesFulfillTheContract(t *testing.T) {
	cases := map[string]struct {
		authorizer *fakeUserAuthorizer
		useCase    in.RequestEmailChange
		a          emailAttempt
	}{
		"202 accepted":          {&fakeUserAuthorizer{}, &fakeRequestEmailChange{}, traced(requestAttempt(emailBody))},
		"400 invalid fields":    {&fakeUserAuthorizer{}, &fakeRequestEmailChange{}, traced(emailAttempt{method: http.MethodPatch, path: emailPath, key: "short", body: `{"email":"nope"}`})},
		"400 invalid email":     {&fakeUserAuthorizer{}, &fakeRequestEmailChange{err: model.ErrInvalidEmail}, traced(requestAttempt(emailBody))},
		"401 no token":          {&fakeUserAuthorizer{err: model.ErrAccessTokenInvalid}, &fakeRequestEmailChange{}, traced(requestAttempt(emailBody))},
		"401 revoked token":     {&fakeUserAuthorizer{err: model.ErrAccessTokenInvalid}, &fakeRequestEmailChange{}, traced(requestAttempt(emailBody))},
		"409 email registered":  {&fakeUserAuthorizer{}, &fakeRequestEmailChange{err: model.ErrEmailAlreadyRegistered}, traced(requestAttempt(emailBody))},
		"429 too many requests": {&fakeUserAuthorizer{}, &fakeRequestEmailChange{err: &model.EmailChangeRateLimitedError{RetryAfter: 1500 * time.Millisecond}}, traced(requestAttempt(emailBody))},
		"500 unexpected":        {&fakeUserAuthorizer{}, &fakeRequestEmailChange{err: errors.New("driver failure")}, traced(requestAttempt(emailBody))},
		"500 revoked list down": {&fakeUserAuthorizer{err: errRevokedListDown}, &fakeRequestEmailChange{}, traced(requestAttempt(emailBody))},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			captureLog(t)
			requireContract(t, http.MethodPatch, emailPath, sendEmailChange(c.authorizer, c.useCase, &fakeVerifyEmailChange{}, c.a))
		})
	}
}

func TestRequestEmailChange429DeclaresRetryAfterAsAnIntegerOfSeconds(t *testing.T) {
	captureLog(t)
	rec := sendEmailChange(&fakeUserAuthorizer{}, &fakeRequestEmailChange{err: &model.EmailChangeRateLimitedError{RetryAfter: 1500 * time.Millisecond}}, &fakeVerifyEmailChange{}, traced(requestAttempt(emailBody)))

	declared := contract(t).Paths.Find(strings.TrimPrefix(emailPath, BasePath)).Patch.Responses.Status(http.StatusTooManyRequests)
	header := declared.Value.Headers["Retry-After"]
	seconds, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	if header == nil || !header.Value.Schema.Value.Type.Is("integer") || err != nil || seconds != 2 {
		t.Errorf("declared header = %v, Retry-After = %q (%v), want an integer in the contract and 2 for 1.5 s", header, rec.Header().Get("Retry-After"), err)
	}
}

func TestVerifyEmailChangeResponsesFulfillTheContract(t *testing.T) {
	cases := map[string]struct {
		authorizer *fakeUserAuthorizer
		useCase    in.VerifyEmailChange
		a          emailAttempt
	}{
		"204 verified":          {&fakeUserAuthorizer{}, &fakeVerifyEmailChange{}, traced(verifyAttempt(verifyBody))},
		"400 invalid fields":    {&fakeUserAuthorizer{}, &fakeVerifyEmailChange{}, traced(emailAttempt{method: http.MethodPost, path: verifyPath, key: "short", body: `{`})},
		"400 rejected code":     {&fakeUserAuthorizer{}, &fakeVerifyEmailChange{err: model.ErrVerificationRejected}, traced(verifyAttempt(verifyBody))},
		"401 no token":          {&fakeUserAuthorizer{err: model.ErrAccessTokenInvalid}, &fakeVerifyEmailChange{}, traced(verifyAttempt(verifyBody))},
		"401 revoked token":     {&fakeUserAuthorizer{err: model.ErrAccessTokenInvalid}, &fakeVerifyEmailChange{}, traced(verifyAttempt(verifyBody))},
		"409 address taken":     {&fakeUserAuthorizer{}, &fakeVerifyEmailChange{err: model.ErrEmailAlreadyRegistered}, traced(verifyAttempt(verifyBody))},
		"500 unexpected":        {&fakeUserAuthorizer{}, &fakeVerifyEmailChange{err: errors.New("driver failure")}, traced(verifyAttempt(verifyBody))},
		"500 revoked list down": {&fakeUserAuthorizer{err: errRevokedListDown}, &fakeVerifyEmailChange{}, traced(verifyAttempt(verifyBody))},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			captureLog(t)
			requireContract(t, http.MethodPost, verifyPath, sendEmailChange(c.authorizer, &fakeRequestEmailChange{}, c.useCase, c.a))
		})
	}
}
