package httpapi

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const (
	// permissionReadProfile is the permission of reading the own profile (x-required-permissions).
	permissionReadProfile = "profile:read:self"
	// maxOwnAccountBodyBytes is the limit of the body of the routes of the own account (ADR-051, Norma 5.3.10).
	maxOwnAccountBodyBytes = 4 << 10
)

// WithOwnProfile publishes the reading and the edition of the own profile (HU-AUTH-007, ADR-051) at GET /me and
// PATCH /me, open to the callers whose token holds profile:read:self and profile:update:self. The account is always the
// one in the token: no id travels in the path or in the body. Neither route takes an Idempotency-Key.
func WithOwnProfile(authorizer in.AuthorizeUser, get in.GetProfile, update in.UpdateProfile) Option {
	return func(mux *http.ServeMux) {
		mux.HandleFunc("GET "+BasePath+"/me", requirePermission(authorizer, permissionReadProfile, getProfile(get)))
		mux.HandleFunc("PATCH "+BasePath+"/me", requirePermission(authorizer, permissionUpdateProfile, patchProfile(update)))
	}
}

// profileResponse is the ProfileResponse schema of the auth-service contract. Phone and address are null, not absent,
// for an account that never gave them.
type profileResponse struct {
	ID      string   `json:"id"`
	Email   string   `json:"email"`
	Name    string   `json:"name"`
	Phone   *string  `json:"phone"`
	Address *string  `json:"address"`
	Roles   []string `json:"roles"`
}

func toProfileResponse(profile in.Profile) profileResponse {
	return profileResponse{
		ID: profile.ID, Email: profile.Email, Name: profile.Name,
		Phone: profile.Phone, Address: profile.Address, Roles: nonNil(profile.Roles),
	}
}

func getProfile(useCase in.GetProfile) callerHandler {
	return func(w http.ResponseWriter, r *http.Request, callerID string) {
		traceID := w.Header().Get(headerCorrelationID) // set by requirePermission, which wraps this handler
		w.Header().Set("Cache-Control", "no-store")

		profile, err := useCase.Get(r.Context(), callerID)
		if err != nil {
			translateProfileError(w, traceID, "get profile", err)
			return
		}
		writeJSON(w, http.StatusOK, toProfileResponse(profile))
	}
}

// command turns the texts of the body into the command of the use case; a property that was not sent stays nil.
func (r propertiesBody) command(callerID string) (in.UpdateProfileCommand, []fieldError) {
	texts, problems := r.texts("name", "phone", "address")
	return in.UpdateProfileCommand{UserID: callerID, Name: sent(texts, "name"), Phone: sent(texts, "phone"), Address: sent(texts, "address")}, problems
}

func patchProfile(useCase in.UpdateProfile) callerHandler {
	return func(w http.ResponseWriter, r *http.Request, callerID string) {
		traceID := w.Header().Get(headerCorrelationID)
		w.Header().Set("Cache-Control", "no-store")

		body, unreadable := decodeBodyWithin[propertiesBody](w, r, maxOwnAccountBodyBytes)
		command, problems := body.command(callerID)
		if problems = append(problems, unreadable...); len(problems) > 0 {
			writeValidation(w, traceID, problems)
			return
		}

		profile, err := useCase.Update(r.Context(), command)
		if err != nil {
			translateProfileError(w, traceID, "update profile", err)
			return
		}
		writeJSON(w, http.StatusOK, toProfileResponse(profile))
	}
}

// translateProfileError is the only place that maps the errors of the own profile use cases to HTTP. An account that is
// gone or locked is a token that identifies nobody, 401, never a server failure. The cause of an unexpected error goes
// only to the log, which never sees the token or the personal data.
func translateProfileError(w http.ResponseWriter, traceID, operation string, err error) {
	switch {
	case errors.Is(err, model.ErrEmptyProfileChange):
		writeValidation(w, traceID, []fieldError{{Field: "body", Message: err.Error()}})
	case errors.Is(err, model.ErrInvalidName), errors.Is(err, model.ErrInvalidPhone), errors.Is(err, model.ErrInvalidAddress):
		writeValidation(w, traceID, invalidProfileFields(err))
	case errors.Is(err, model.ErrUserNotFound), errors.Is(err, model.ErrUserLocked):
		slog.Warn(operation+" refused: the account of the token is not active", "traceId", traceID)
		writeUnauthorized(w, traceID)
	default:
		slog.Error(operation+" failed", "traceId", traceID, "error", err)
		writeInternal(w, traceID)
	}
}

// invalidProfileFields names, in the order of the profile, each field the domain rejected.
func invalidProfileFields(err error) []fieldError {
	var problems []fieldError
	for _, sentinel := range []error{model.ErrInvalidName, model.ErrInvalidPhone, model.ErrInvalidAddress} {
		if errors.Is(err, sentinel) {
			problems = append(problems, fieldError{Field: fieldOfDomainError[sentinel], Message: sentinel.Error()})
		}
	}
	return problems
}
