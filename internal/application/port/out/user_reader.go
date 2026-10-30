package out

import (
	"context"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// UserListItem is a user as the list shows it: identity and active roles, nothing else.
type UserListItem struct {
	ID    string
	Email string
	Name  string
	Roles []model.Role
}

// UserListPage is one page of users and how many users match in all.
type UserListPage struct {
	Items []UserListItem
	Total int
}

// UserReader reads users for lists (pattern CQRS read side), apart from the aggregate repository.
type UserReader interface {
	// SearchUsers returns the page of users whose email starts with prefix (all users when prefix is
	// the zero value), ordered from newest to oldest (created_at, then id, both descending). Soft-deleted users are not read.
	SearchUsers(ctx context.Context, prefix model.EmailPrefix, page model.Page) (UserListPage, error)
}
