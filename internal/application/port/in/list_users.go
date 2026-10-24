package in

import "context"

// ListUsersQuery asks for one page of users. EmailPrefix is nil to list every user; Page and Limit
// are validated by the use case.
type ListUsersQuery struct {
	EmailPrefix *string
	Page        int
	Limit       int
}

// UserPage is one page of users, without permissions, and the total of users that match.
type UserPage struct {
	Users []UserSummary
	Page  int
	Limit int
	Total int
}

// ListUsers is the use case that lets an administrator find the user whose role to change
// (HU-AUTH-003, ADR-031). Users are ordered by email and then id; soft-deleted users are not
// listed. Errors: model.ErrInvalidEmailPrefix, model.ErrInvalidPageNumber and model.ErrInvalidPageLimit.
type ListUsers interface {
	ListUsers(ctx context.Context, query ListUsersQuery) (UserPage, error)
}
