package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

func tracedProfile(a profileAttempt) profileAttempt {
	a.headers = withTrace()
	return a
}

func profileWithoutContactData() in.Profile {
	profile := ownProfile()
	profile.Phone, profile.Address = nil, nil
	return profile
}

func TestGetProfileResponsesFulfillTheContract(t *testing.T) {
	cases := map[string]struct {
		authorizer *fakeUserAuthorizer
		get        *fakeGetProfile
	}{
		"200 profile":                    {&fakeUserAuthorizer{}, &fakeGetProfile{profile: ownProfile()}},
		"200 phone and address are null": {&fakeUserAuthorizer{}, &fakeGetProfile{profile: profileWithoutContactData()}},
		"401 no token":                   {&fakeUserAuthorizer{err: model.ErrAccessTokenInvalid}, &fakeGetProfile{}},
		"401 account is gone":            {&fakeUserAuthorizer{}, &fakeGetProfile{err: model.ErrUserNotFound}},
		"401 account is locked":          {&fakeUserAuthorizer{}, &fakeGetProfile{err: model.ErrUserLocked}},
		"500 unexpected":                 {&fakeUserAuthorizer{}, &fakeGetProfile{err: errors.New("driver failure")}},
		"500 revoked list down":          {&fakeUserAuthorizer{err: errRevokedListDown}, &fakeGetProfile{}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			captureLog(t)
			requireContract(t, http.MethodGet, profilePath, sendProfile(c.authorizer, c.get, &fakeUpdateProfile{}, tracedProfile(getAttempt())))
		})
	}
}

func TestPatchProfileResponsesFulfillTheContract(t *testing.T) {
	cases := map[string]struct {
		authorizer *fakeUserAuthorizer
		update     *fakeUpdateProfile
		a          profileAttempt
	}{
		"200 updated":           {&fakeUserAuthorizer{}, &fakeUpdateProfile{profile: ownProfile()}, tracedProfile(patchAttempt(`{"name":"Ana María"}`))},
		"400 null field":        {&fakeUserAuthorizer{}, &fakeUpdateProfile{}, tracedProfile(patchAttempt(`{"phone":null}`))},
		"400 unknown field":     {&fakeUserAuthorizer{}, &fakeUpdateProfile{}, tracedProfile(patchAttempt(`{"email":"other@example.com"}`))},
		"400 wrong type":        {&fakeUserAuthorizer{}, &fakeUpdateProfile{}, tracedProfile(patchAttempt(`{"name":7}`))},
		"400 unreadable":        {&fakeUserAuthorizer{}, &fakeUpdateProfile{}, tracedProfile(patchAttempt(`{"name":`))},
		"400 body too large":    {&fakeUserAuthorizer{}, &fakeUpdateProfile{}, tracedProfile(patchAttempt(`{"address":"` + strings.Repeat("a", 5000) + `"}`))},
		"400 empty edit":        {&fakeUserAuthorizer{}, &fakeUpdateProfile{err: model.ErrEmptyProfileChange}, tracedProfile(patchAttempt(`{}`))},
		"400 invalid fields":    {&fakeUserAuthorizer{}, &fakeUpdateProfile{err: errors.Join(model.ErrInvalidName, model.ErrInvalidPhone)}, tracedProfile(patchAttempt(`{"name":"","phone":"1"}`))},
		"401 no token":          {&fakeUserAuthorizer{err: model.ErrAccessTokenInvalid}, &fakeUpdateProfile{}, tracedProfile(patchAttempt(`{"name":"Ana"}`))},
		"401 account is gone":   {&fakeUserAuthorizer{}, &fakeUpdateProfile{err: model.ErrUserNotFound}, tracedProfile(patchAttempt(`{"name":"Ana"}`))},
		"500 unexpected":        {&fakeUserAuthorizer{}, &fakeUpdateProfile{err: errors.New("driver failure")}, tracedProfile(patchAttempt(`{"name":"Ana"}`))},
		"500 revoked list down": {&fakeUserAuthorizer{err: errRevokedListDown}, &fakeUpdateProfile{}, tracedProfile(patchAttempt(`{"name":"Ana"}`))},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			captureLog(t)
			requireContract(t, http.MethodPatch, profilePath, sendProfile(c.authorizer, &fakeGetProfile{}, c.update, c.a))
		})
	}
}
