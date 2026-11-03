package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const profilePath = BasePath + "/me"

type fakeGetProfile struct {
	profile in.Profile
	err     error
	userID  string
}

func (f *fakeGetProfile) Get(_ context.Context, userID string) (in.Profile, error) {
	f.userID = userID
	return f.profile, f.err
}

type fakeUpdateProfile struct {
	profile in.Profile
	err     error
	called  int
	command in.UpdateProfileCommand
}

func (f *fakeUpdateProfile) Update(_ context.Context, command in.UpdateProfileCommand) (in.Profile, error) {
	f.called++
	f.command = command
	return f.profile, f.err
}

func ownProfile() in.Profile {
	phone, address := "3001234567", "Calle 123 #45-67"
	return in.Profile{ID: "admin-1", Email: "ana@example.com", Name: "Ana Pérez", Phone: &phone, Address: &address, Roles: []string{"CLIENT"}}
}

type profileAttempt struct {
	method      string
	body        string
	contentType string
	headers     map[string]string
}

func sendProfile(authorizer *fakeUserAuthorizer, get in.GetProfile, update in.UpdateProfile, a profileAttempt) *httptest.ResponseRecorder {
	req := httptest.NewRequest(a.method, profilePath, strings.NewReader(a.body))
	req.Header.Set("Content-Type", "application/json")
	if a.contentType != "" {
		req.Header.Set("Content-Type", a.contentType)
	}
	req.Header.Set("Authorization", "Bearer "+userSecret)
	for name, value := range a.headers {
		req.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	NewHandler(WithOwnProfile(authorizer, get, update)).ServeHTTP(rec, req)
	return rec
}

func getAttempt() profileAttempt { return profileAttempt{method: http.MethodGet} }

func patchAttempt(body string) profileAttempt {
	return profileAttempt{method: http.MethodPatch, body: body}
}

func TestOwnProfileRoutesExistOnlyWhenTheUseCasesAreInjected(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPatch} {
		rec := httptest.NewRecorder()
		NewHandler().ServeHTTP(rec, httptest.NewRequest(method, profilePath, nil))
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want the route to be absent", method, rec.Code)
		}
	}
}

func TestGetProfileAnswers200WithThePersonalDataOfTheAccountOfTheToken(t *testing.T) {
	get, authorizer := &fakeGetProfile{profile: ownProfile()}, &fakeUserAuthorizer{}

	rec := sendProfile(authorizer, get, &fakeUpdateProfile{}, getAttempt())

	want := `{"id":"admin-1","email":"ana@example.com","name":"Ana Pérez","phone":"3001234567","address":"Calle 123 #45-67","roles":["CLIENT"]}`
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != want || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status = %d, body = %s, Cache-Control = %q, want 200, %s and no-store", rec.Code, rec.Body, rec.Header().Get("Cache-Control"), want)
	}
	if get.userID != "admin-1" || authorizer.permission != "profile:read:self" {
		t.Errorf("read the profile of %q with permission %q, want the account of the token and profile:read:self", get.userID, authorizer.permission)
	}
}

func TestGetProfileAnswersNullForAPhoneAndAnAddressThatWereNeverGiven(t *testing.T) {
	profile := ownProfile()
	profile.Phone, profile.Address = nil, nil

	rec := sendProfile(&fakeUserAuthorizer{}, &fakeGetProfile{profile: profile}, &fakeUpdateProfile{}, getAttempt())

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q is not JSON: %v", rec.Body, err)
	}
	if phone, ok := body["phone"]; !ok || phone != nil {
		t.Errorf("body = %v, want phone and address present as null", body)
	}
	if address, ok := body["address"]; !ok || address != nil {
		t.Errorf("body = %v, want phone and address present as null", body)
	}
}

func TestPatchProfileWritesOnlyTheFieldsSentAndAnswersTheProfileAfterTheChange(t *testing.T) {
	update, authorizer := &fakeUpdateProfile{profile: ownProfile()}, &fakeUserAuthorizer{}

	rec := sendProfile(authorizer, &fakeGetProfile{}, update, patchAttempt(`{"name":"Ana María","address":"Carrera 7 #8-9"}`))

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"email":"ana@example.com"`) || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status = %d, body = %s, want 200 with the profile and no-store", rec.Code, rec.Body)
	}
	command := update.command
	if command.UserID != "admin-1" || command.Name == nil || *command.Name != "Ana María" || command.Phone != nil || command.Address == nil || *command.Address != "Carrera 7 #8-9" {
		t.Errorf("command = %+v, want the name and the address of admin-1 and no phone", command)
	}
	if authorizer.permission != "profile:update:self" {
		t.Errorf("permission = %q, want profile:update:self", authorizer.permission)
	}
}

func TestPatchProfileRejectsAnUnacceptableBodyNamingTheFieldAndChangesNothing(t *testing.T) {
	cases := map[string]struct {
		a     profileAttempt
		field string
	}{
		"null field":       {patchAttempt(`{"phone":null}`), "phone"},
		"unknown field":    {patchAttempt(`{"name":"Ana","email":"other@example.com"}`), "email"},
		"roles":            {patchAttempt(`{"roles":["ADMIN"]}`), "roles"},
		"id":               {patchAttempt(`{"id":"someone-else"}`), "id"},
		"number as name":   {patchAttempt(`{"name":7}`), "name"},
		"not JSON":         {patchAttempt(`{"name":`), "body"},
		"wrong media type": {profileAttempt{method: http.MethodPatch, body: `{"name":"Ana"}`, contentType: "text/plain"}, "Content-Type"},
		"body too large":   {patchAttempt(`{"address":"` + strings.Repeat("a", 5000) + `"}`), "body"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			update := &fakeUpdateProfile{}

			rec := sendProfile(&fakeUserAuthorizer{}, &fakeGetProfile{}, update, c.a)

			var body errorResponse
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			if rec.Code != http.StatusBadRequest || body.Error != "VALIDATION_ERROR" || len(body.Details) == 0 || body.Details[0].Field != c.field || update.called != 0 {
				t.Errorf("status = %d, body = %s, calls = %d, want 400 VALIDATION_ERROR naming %q and no call", rec.Code, rec.Body, update.called, c.field)
			}
		})
	}
}

func TestPatchProfileNamesEveryInvalidFieldTheDomainRejects(t *testing.T) {
	cases := map[string]struct {
		err    error
		fields []string
	}{
		"empty edit":     {model.ErrEmptyProfileChange, []string{"body"}},
		"invalid phone":  {model.ErrInvalidPhone, []string{"phone"}},
		"several fields": {errors.Join(model.ErrInvalidName, model.ErrInvalidPhone, model.ErrInvalidAddress), []string{"name", "phone", "address"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			rec := sendProfile(&fakeUserAuthorizer{}, &fakeGetProfile{}, &fakeUpdateProfile{err: c.err}, patchAttempt(`{}`))

			var body errorResponse
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			var fields []string
			for _, detail := range body.Details {
				fields = append(fields, detail.Field)
			}
			if rec.Code != http.StatusBadRequest || strings.Join(fields, ",") != strings.Join(c.fields, ",") {
				t.Errorf("status = %d, fields = %v, want 400 naming %v", rec.Code, fields, c.fields)
			}
		})
	}
}

func TestOwnProfileRoutesDoNotReachTheUseCasesWithoutAValidToken(t *testing.T) {
	captureLog(t)
	for name, err := range map[string]error{"invalid or revoked token": model.ErrAccessTokenInvalid, "no permission": model.ErrPermissionDenied, "revoked list down": errRevokedListDown} {
		for _, a := range []profileAttempt{getAttempt(), patchAttempt(`{"name":"Ana"}`)} {
			get, update := &fakeGetProfile{}, &fakeUpdateProfile{}

			rec := sendProfile(&fakeUserAuthorizer{err: err}, get, update, a)

			if rec.Code < 400 || get.userID != "" || update.called != 0 {
				t.Errorf("%s %s: status = %d, want an error and no call", name, a.method, rec.Code)
			}
		}
	}
}

func TestOwnProfileAnswers401WhenTheAccountOfTheTokenIsGoneOrLocked(t *testing.T) {
	captureLog(t)
	for _, cause := range []error{model.ErrUserNotFound, model.ErrUserLocked} {
		for _, a := range []profileAttempt{getAttempt(), patchAttempt(`{"name":"Ana"}`)} {
			rec := sendProfile(&fakeUserAuthorizer{}, &fakeGetProfile{err: cause}, &fakeUpdateProfile{err: cause}, a)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%v on %s: status = %d, want 401: the token identifies no active account", cause, a.method, rec.Code)
			}
		}
	}
}

func TestOwnProfileAnswers500WithoutTheCauseAndLogsNeitherTheTokenNorTheBody(t *testing.T) {
	logs := captureLog(t)
	failure := errors.New("driver failure")

	for _, a := range []profileAttempt{getAttempt(), patchAttempt(`{"phone":"3009998877","address":"Calle Secreta 1"}`)} {
		rec := sendProfile(&fakeUserAuthorizer{}, &fakeGetProfile{err: failure}, &fakeUpdateProfile{err: failure}, a)

		if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "driver failure") {
			t.Errorf("%s: status = %d, body = %s, want 500 without the cause", a.method, rec.Code, rec.Body)
		}
	}
	if strings.Contains(logs.String(), userSecret) || strings.Contains(logs.String(), "3009998877") || strings.Contains(logs.String(), "Calle Secreta") {
		t.Errorf("log %q must contain neither the token nor the phone and the address of the body", logs)
	}
}
