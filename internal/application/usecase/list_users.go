package usecase

import (
	"context"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// ListUsers implements in.ListUsers (HU-AUTH-003, ADR-031).
type ListUsers struct {
	users out.UserReader
}

var _ in.ListUsers = (*ListUsers)(nil)

// NewListUsers wires the use case with the reader of users.
func NewListUsers(users out.UserReader) *ListUsers {
	return &ListUsers{users: users}
}

// ListUsers validates the query with the domain value objects and answers the page the reader finds.
func (l *ListUsers) ListUsers(ctx context.Context, query in.ListUsersQuery) (in.UserPage, error) {
	var prefix model.EmailPrefix
	if query.EmailPrefix != nil {
		var err error
		if prefix, err = model.NewEmailPrefix(*query.EmailPrefix); err != nil {
			return in.UserPage{}, err
		}
	}
	page, err := model.NewPage(query.Page, query.Limit)
	if err != nil {
		return in.UserPage{}, err
	}
	found, err := l.users.SearchUsers(ctx, prefix, page)
	if err != nil {
		return in.UserPage{}, err
	}
	users := make([]in.UserSummary, 0, len(found.Items))
	for _, item := range found.Items {
		roles := make([]string, 0, len(item.Roles))
		for _, role := range item.Roles {
			roles = append(roles, role.String())
		}
		users = append(users, in.UserSummary{ID: item.ID, Email: item.Email, Name: item.Name, Roles: roles})
	}
	return in.UserPage{Users: users, Page: page.Number(), Limit: page.Limit(), Total: found.Total}, nil
}
