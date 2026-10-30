package usecase

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

type fakeUserReader struct {
	page   out.UserListPage
	err    error
	called int
	prefix model.EmailPrefix
	asked  model.Page
}

func (f *fakeUserReader) SearchUsers(_ context.Context, prefix model.EmailPrefix, page model.Page) (out.UserListPage, error) {
	f.called++
	f.prefix, f.asked = prefix, page
	return f.page, f.err
}

func textPtr(text string) *string { return &text }

func TestListUsersAnswersTheSummariesWithoutPermissions(t *testing.T) {
	reader := &fakeUserReader{page: out.UserListPage{
		Total: 41,
		Items: []out.UserListItem{{ID: "user-1", Email: "ana@example.com", Name: "Ana", Roles: []model.Role{model.RoleAdmin, model.RoleClient}}},
	}}

	result, err := NewListUsers(reader).ListUsers(context.Background(), in.ListUsersQuery{EmailPrefix: textPtr("Ana"), Page: 2, Limit: 20})

	if err != nil {
		t.Fatalf("ListUsers() error = %v", err)
	}
	want := in.UserPage{
		Users: []in.UserSummary{{ID: "user-1", Email: "ana@example.com", Name: "Ana", Roles: []string{"ADMIN", "CLIENT"}}},
		Page:  2, Limit: 20, Total: 41,
	}
	if !reflect.DeepEqual(result, want) {
		t.Errorf("result = %+v, want %+v", result, want)
	}
	if reader.prefix.String() != "ana" || reader.asked.Number() != 2 || reader.asked.Limit() != 20 {
		t.Errorf("reader asked prefix %q and page %+v, want the lower-cased prefix and page 2 of 20", reader.prefix, reader.asked)
	}
}

func TestListUsersWithoutPrefixListsEveryoneAndAnEmptyPageHasNoNilSlice(t *testing.T) {
	reader := &fakeUserReader{}

	result, err := NewListUsers(reader).ListUsers(context.Background(), in.ListUsersQuery{Page: 1, Limit: 20})

	if err != nil || result.Users == nil || len(result.Users) != 0 || result.Total != 0 {
		t.Errorf("result = %+v, error = %v, want an empty, non-nil page", result, err)
	}
	if reader.prefix.String() != "" {
		t.Errorf("prefix = %q, want none", reader.prefix)
	}
}

func TestListUsersRejectsAnInvalidQueryWithoutReading(t *testing.T) {
	cases := map[string]struct {
		query in.ListUsersQuery
		want  error
	}{
		"empty prefix":  {in.ListUsersQuery{EmailPrefix: textPtr(""), Page: 1, Limit: 20}, model.ErrInvalidEmailPrefix},
		"page zero":     {in.ListUsersQuery{Page: 0, Limit: 20}, model.ErrInvalidPageNumber},
		"limit too big": {in.ListUsersQuery{Page: 1, Limit: 101}, model.ErrInvalidPageLimit},
	}
	for name, c := range cases {
		reader := &fakeUserReader{}

		_, err := NewListUsers(reader).ListUsers(context.Background(), c.query)

		if !errors.Is(err, c.want) || reader.called != 0 {
			t.Errorf("%s: error = %v, reads = %d, want %v and no read", name, err, reader.called, c.want)
		}
	}
}

func TestListUsersPassesTheReaderFailureOn(t *testing.T) {
	failure := errors.New("database down")

	_, err := NewListUsers(&fakeUserReader{err: failure}).ListUsers(context.Background(), in.ListUsersQuery{Page: 1, Limit: 20})

	if !errors.Is(err, failure) {
		t.Errorf("error = %v, want %v", err, failure)
	}
}
