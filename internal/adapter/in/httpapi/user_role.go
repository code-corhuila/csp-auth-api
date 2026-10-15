package httpapi

import (
	"net/http"
	"regexp"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// permissionManageRoles is the permission of the operations that manage users (x-required-permissions).
const permissionManageRoles = "user:role:update"

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// WithChangeUserRole publishes the use case at PATCH /users/{userId}/role (HU-AUTH-003, ADR-031),
// open to the callers whose token holds user:role:update.
func WithChangeUserRole(authorizer in.AuthorizeUser, useCase in.ChangeUserRole) Option {
	return func(mux *http.ServeMux) {
		mux.HandleFunc("PATCH "+BasePath+"/users/{userId}/role",
			requirePermission(authorizer, permissionManageRoles, changeUserRole(useCase)))
	}
}

// changeRoleRequest is the request body of updateUserRole in the auth-service contract. Both
// properties are pointers so that a missing one can be told from a zero value.
type changeRoleRequest struct {
	Role    *string `json:"role"`
	Enabled *bool   `json:"enabled"`
}

func changeUserRole(useCase in.ChangeUserRole) callerHandler {
	return func(w http.ResponseWriter, r *http.Request, callerID string) {
		traceID := w.Header().Get(headerCorrelationID) // set by requirePermission, which wraps this handler
		w.Header().Set("Cache-Control", "no-store")

		userID := r.PathValue("userId")
		body, unreadable := decodeBody[changeRoleRequest](w, r)
		problems := append(validateRoleChange(r.Header.Get(headerIdempotencyKey), userID, body, unreadable == nil), unreadable...)
		if len(problems) > 0 {
			writeValidation(w, traceID, problems)
			return
		}

		summary, err := useCase.ChangeRole(r.Context(), in.ChangeUserRoleCommand{
			ActingAdminID: callerID,
			UserID:        userID,
			Role:          *body.Role,
			Enabled:       *body.Enabled,
		})
		if err != nil {
			translateChangeRoleError(w, traceID, err)
			return
		}
		writeJSON(w, http.StatusOK, toUserSummary(summary))
	}
}

// validateRoleChange reports every invalid input at once. The Idempotency-Key is only validated:
// the operation sets a desired state, so repeating it is harmless and the key is not stored
// (ADR-031). The body is checked only when it could be read.
func validateRoleChange(key, userID string, body changeRoleRequest, bodyRead bool) []fieldError {
	var problems []fieldError
	if err := errorOf(model.NewIdempotencyKey(key)); err != nil {
		problems = append(problems, fieldError{Field: headerIdempotencyKey, Message: err.Error()})
	}
	if !uuidPattern.MatchString(userID) {
		problems = append(problems, fieldError{Field: "userId", Message: "must be a UUID"})
	}
	if !bodyRead {
		return problems
	}
	if body.Role == nil {
		problems = append(problems, fieldError{Field: "role", Message: "is required"})
	}
	if body.Enabled == nil {
		problems = append(problems, fieldError{Field: "enabled", Message: "is required"})
	}
	return problems
}
