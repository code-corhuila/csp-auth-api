package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

func tracedPassword(body string) passwordAttempt {
	return passwordAttempt{body: body, headers: withTrace()}
}

func TestChangePasswordResponsesFulfillTheContract(t *testing.T) {
	cases := map[string]struct {
		authorizer *fakeUserAuthorizer
		useCase    in.ChangePassword
		a          passwordAttempt
	}{
		"200 changed":              {&fakeUserAuthorizer{}, &fakeChangePassword{result: changedSession()}, tracedPassword(passwordBody)},
		"400 invalid fields":       {&fakeUserAuthorizer{}, &fakeChangePassword{}, tracedPassword(`{"currentPassword":"","newPassword":"weak"}`)},
		"400 unknown field":        {&fakeUserAuthorizer{}, &fakeChangePassword{}, tracedPassword(`{"currentPassword":"CurrentSecret1","newPassword":"NewSecret123","x":1}`)},
		"400 unreadable":           {&fakeUserAuthorizer{}, &fakeChangePassword{}, tracedPassword(`{"currentPassword":`)},
		"400 body too large":       {&fakeUserAuthorizer{}, &fakeChangePassword{}, tracedPassword(`{"currentPassword":"` + strings.Repeat("a", 5000) + `"}`)},
		"400 wrong current":        {&fakeUserAuthorizer{}, &fakeChangePassword{err: model.ErrWrongCurrentPassword}, tracedPassword(passwordBody)},
		"400 same password":        {&fakeUserAuthorizer{}, &fakeChangePassword{err: model.ErrPasswordUnchanged}, tracedPassword(passwordBody)},
		"401 no token":             {&fakeUserAuthorizer{err: model.ErrAccessTokenInvalid}, &fakeChangePassword{}, tracedPassword(passwordBody)},
		"401 account is gone":      {&fakeUserAuthorizer{}, &fakeChangePassword{err: model.ErrUserNotFound}, tracedPassword(passwordBody)},
		"429 locked":               {&fakeUserAuthorizer{}, &fakeChangePassword{err: &model.PasswordChangeRateLimitedError{RetryAfter: 15 * time.Minute}}, tracedPassword(passwordBody)},
		"500 unexpected":           {&fakeUserAuthorizer{}, &fakeChangePassword{err: errors.New("driver failure")}, tracedPassword(passwordBody)},
		"500 revoked list is down": {&fakeUserAuthorizer{err: errRevokedListDown}, &fakeChangePassword{}, tracedPassword(passwordBody)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			captureLog(t)
			requireContract(t, http.MethodPost, passwordPath, sendPasswordChange(openPasswordGate(), c.authorizer, c.useCase, c.a))
		})
	}
}

func TestChangePassword429ForNoFreeSlotFulfillsTheContract(t *testing.T) {
	captureLog(t)
	gate, _ := NewBulkhead(1, 20*time.Millisecond)
	release, _ := gate.Acquire(context.Background())
	defer release()

	requireContract(t, http.MethodPost, passwordPath, sendPasswordChange(gate, &fakeUserAuthorizer{}, &fakeChangePassword{}, tracedPassword(passwordBody)))
}

func TestChangePassword429DeclaresRetryAfterAsAnIntegerOfSeconds(t *testing.T) {
	rec := sendPasswordChange(openPasswordGate(), &fakeUserAuthorizer{}, &fakeChangePassword{err: &model.PasswordChangeRateLimitedError{RetryAfter: 1500 * time.Millisecond}}, tracedPassword(passwordBody))

	declared := contract(t).Paths.Find("/me/password").Post.Responses.Status(http.StatusTooManyRequests)
	header := declared.Value.Headers["Retry-After"]
	seconds, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	if header == nil || !header.Value.Schema.Value.Type.Is("integer") || err != nil || seconds != 2 {
		t.Errorf("declared header = %v, Retry-After = %q (%v), want an integer in the contract and 2 for 1.5 s", header, rec.Header().Get("Retry-After"), err)
	}
}

func TestChangePasswordDeclaresNoIdempotencyKey(t *testing.T) {
	for _, parameter := range contract(t).Paths.Find("/me/password").Post.Parameters {
		if parameter.Value != nil && parameter.Value.Name == "Idempotency-Key" {
			t.Error("the contract declares an Idempotency-Key for POST /me/password; ADR-051 does not accept it")
		}
	}
}
