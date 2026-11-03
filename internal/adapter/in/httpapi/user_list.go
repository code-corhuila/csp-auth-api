package httpapi

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// WithListUsers publishes the use case at GET /users (HU-AUTH-003, ADR-031), open to the callers
// whose token holds user:role:update.
func WithListUsers(authorizer in.AuthorizeUser, useCase in.ListUsers) Option {
	return func(mux *http.ServeMux) {
		mux.HandleFunc("GET "+BasePath+"/users", requirePermission(authorizer, permissionManageRoles, listUsers(useCase)))
	}
}

// userListItem is the UserSummary of the list: no permissions.
type userListItem struct {
	ID    string   `json:"id"`
	Email string   `json:"email"`
	Name  string   `json:"name"`
	Roles []string `json:"roles"`
}

// pageMeta is the PaginatedMeta schema of _shared.yaml.
type pageMeta struct {
	Page       int `json:"page"`
	Limit      int `json:"limit"`
	Total      int `json:"total"`
	TotalPages int `json:"totalPages"`
}

// userListResponse is the UserListResponse schema of the auth-service contract.
type userListResponse struct {
	Data []userListItem `json:"data"`
	Meta pageMeta       `json:"meta"`
}

func listUsers(useCase in.ListUsers) callerHandler {
	return func(w http.ResponseWriter, r *http.Request, _ string) {
		traceID := w.Header().Get(headerCorrelationID) // set by requirePermission, which wraps this handler
		w.Header().Set("Cache-Control", "no-store")

		values := r.URL.Query()
		query := in.ListUsersQuery{Page: model.DefaultPage, Limit: model.DefaultPageLimit}
		var problems []fieldError
		if values.Has("email") {
			prefix := values.Get("email")
			query.EmailPrefix = &prefix
		}
		for _, number := range []struct {
			field  string
			target *int
		}{{"page", &query.Page}, {"limit", &query.Limit}} {
			if problem := readInteger(values, number.field, number.target); problem != nil {
				problems = append(problems, *problem)
			}
		}
		if len(problems) > 0 {
			writeValidation(w, traceID, problems)
			return
		}

		page, err := useCase.ListUsers(r.Context(), query)
		if err != nil {
			translateListUsersError(w, traceID, err)
			return
		}
		data := make([]userListItem, 0, len(page.Users))
		for _, user := range page.Users {
			data = append(data, userListItem{ID: user.ID, Email: user.Email, Name: user.Name, Roles: nonNil(user.Roles)})
		}
		writeJSON(w, http.StatusOK, userListResponse{
			Data: data,
			Meta: pageMeta{Page: page.Page, Limit: page.Limit, Total: page.Total, TotalPages: (page.Total + page.Limit - 1) / page.Limit},
		})
	}
}

// readInteger stores the integer of the query parameter name in target when it is present.
func readInteger(values url.Values, name string, target *int) *fieldError {
	if !values.Has(name) {
		return nil
	}
	number, err := strconv.Atoi(values.Get(name))
	if err != nil {
		return &fieldError{Field: name, Message: "must be an integer"}
	}
	*target = number
	return nil
}
