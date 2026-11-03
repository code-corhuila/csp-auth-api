package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const usersPath = BasePath + "/users"

type fakeListUsers struct {
	page   in.UserPage
	err    error
	called int
	query  in.ListUsersQuery
}

func (f *fakeListUsers) ListUsers(_ context.Context, query in.ListUsersQuery) (in.UserPage, error) {
	f.called++
	f.query = query
	return f.page, f.err
}

func onePage() in.UserPage {
	return in.UserPage{
		Users: []in.UserSummary{{ID: roleTargetID, Email: "maria@example.com", Name: "Maria Garcia", Roles: []string{"CLIENT"}}},
		Page:  1, Limit: 20, Total: 41,
	}
}

func sendList(authorizer *fakeUserAuthorizer, useCase in.ListUsers, query string, headers map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, usersPath+query, nil)
	request.Header.Set("Authorization", "Bearer "+userSecret)
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	NewHandler(WithListUsers(authorizer, useCase)).ServeHTTP(rec, request)
	return rec
}

func TestListUsersRouteExistsOnlyWhenTheUseCaseIsInjected(t *testing.T) {
	rec := httptest.NewRecorder()
	NewHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, usersPath, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want the route to be absent", rec.Code)
	}
}

func TestListUsersAnswersThePageWithItsMetaAndNoPermissions(t *testing.T) {
	useCase := &fakeListUsers{page: onePage()}
	authorizer := &fakeUserAuthorizer{}

	rec := sendList(authorizer, useCase, "?email=Mar&page=1&limit=20", nil)

	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" || authorizer.permission != "user:role:update" {
		t.Fatalf("status = %d, headers = %v, permission = %q, want 200, no-store and user:role:update", rec.Code, rec.Header(), authorizer.permission)
	}
	want := `{"data":[{"id":"` + roleTargetID + `","email":"maria@example.com","name":"Maria Garcia","roles":["CLIENT"]}],` +
		`"meta":{"page":1,"limit":20,"total":41,"totalPages":3}}` + "\n"
	if rec.Body.String() != want {
		t.Errorf("body = %s, want %s", rec.Body, want)
	}
	if useCase.query.EmailPrefix == nil || *useCase.query.EmailPrefix != "Mar" || useCase.query.Page != 1 || useCase.query.Limit != 20 {
		t.Errorf("query = %+v, want prefix Mar, page 1, limit 20", useCase.query)
	}
}

func TestListUsersUsesTheDefaultsOfTheContractAndAnEmptyPageHasNoPages(t *testing.T) {
	useCase := &fakeListUsers{page: in.UserPage{Page: 1, Limit: 20}}

	rec := sendList(&fakeUserAuthorizer{}, useCase, "", nil)

	if useCase.query.EmailPrefix != nil || useCase.query.Page != 1 || useCase.query.Limit != 20 {
		t.Errorf("query = %+v, want no prefix, page 1 and limit 20", useCase.query)
	}
	if want := `{"data":[],"meta":{"page":1,"limit":20,"total":0,"totalPages":0}}` + "\n"; rec.Code != http.StatusOK || rec.Body.String() != want {
		t.Errorf("status = %d, body = %s, want 200 and %s", rec.Code, rec.Body, want)
	}
}

func TestListUsersPassesAnEmptyPrefixToTheUseCaseWhichRejectsIt(t *testing.T) {
	useCase := &fakeListUsers{err: model.ErrInvalidEmailPrefix}

	rec := sendList(&fakeUserAuthorizer{}, useCase, "?email=", nil)

	if useCase.query.EmailPrefix == nil || *useCase.query.EmailPrefix != "" {
		t.Errorf("query = %+v, want a present, empty prefix", useCase.query)
	}
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"field":"email"`) {
		t.Errorf("status = %d, body = %s, want 400 on email", rec.Code, rec.Body)
	}
}

func TestListUsersRejectsNumbersThatAreNotIntegersBeforeCallingTheUseCase(t *testing.T) {
	useCase := &fakeListUsers{}

	rec := sendList(&fakeUserAuthorizer{}, useCase, "?page=two&limit=1.5", nil)

	body := rec.Body.String()
	if rec.Code != http.StatusBadRequest || useCase.called != 0 || !strings.Contains(body, `"field":"page"`) || !strings.Contains(body, `"field":"limit"`) {
		t.Errorf("status = %d, calls = %d, body = %s, want 400 on page and limit and no call", rec.Code, useCase.called, body)
	}
}

func TestListUsersTranslatesTheErrorsOfTheUseCase(t *testing.T) {
	cases := map[string]struct {
		err    error
		status int
		code   string
		field  string
	}{
		"page":       {model.ErrInvalidPageNumber, http.StatusBadRequest, "VALIDATION_ERROR", "page"},
		"limit":      {model.ErrInvalidPageLimit, http.StatusBadRequest, "VALIDATION_ERROR", "limit"},
		"unexpected": {errors.New("driver failure"), http.StatusInternalServerError, "INTERNAL_ERROR", ""},
	}
	for name, c := range cases {
		rec := sendList(&fakeUserAuthorizer{}, &fakeListUsers{err: c.err}, "", nil)

		body := rec.Body.String()
		if rec.Code != c.status || !strings.Contains(body, `"error":"`+c.code+`"`) || !strings.Contains(body, c.field) || strings.Contains(body, "driver failure") {
			t.Errorf("%s: status = %d, body = %s, want %d %s without the cause", name, rec.Code, body, c.status, c.code)
		}
	}
}

func TestListUsersDoesNotReachTheUseCaseWithoutPermission(t *testing.T) {
	for name, err := range map[string]error{"no token": model.ErrAccessTokenInvalid, "no permission": model.ErrPermissionDenied} {
		useCase := &fakeListUsers{}

		rec := sendList(&fakeUserAuthorizer{err: err}, useCase, "", nil)

		if (rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden) || useCase.called != 0 {
			t.Errorf("%s: status = %d, calls = %d, want 401 or 403 and no call", name, rec.Code, useCase.called)
		}
	}
}
