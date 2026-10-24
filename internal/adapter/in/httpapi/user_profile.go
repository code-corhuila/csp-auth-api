package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const (
	// permissionReadProfile is the permission of reading the own profile (x-required-permissions).
	permissionReadProfile = "profile:read:self"
	// maxProfileBodyBytes is the limit of the body of the routes of the own account (ADR-051, Norma 5.3.10).
	maxProfileBodyBytes = 4 << 10
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

// updateProfileRequest is the UpdateProfileRequest schema of the auth-service contract. It keeps the properties of the
// body as they came, so that a null, a property of another type and an unknown one can be told from a property that
// was not sent.
type updateProfileRequest struct {
	properties map[string]any
}

func (r *updateProfileRequest) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &r.properties)
}

func (r updateProfileRequest) sortedProperties() []string {
	names := make([]string, 0, len(r.properties))
	for name := range r.properties {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// command turns the properties into the command of the use case. Its problems name each property that is unknown, null
// or not a string; the content of a text is judged by the domain.
func (r updateProfileRequest) command(callerID string) (in.UpdateProfileCommand, []fieldError) {
	command := in.UpdateProfileCommand{UserID: callerID}
	fields := map[string]**string{"name": &command.Name, "phone": &command.Phone, "address": &command.Address}
	var problems []fieldError
	for _, property := range r.sortedProperties() {
		target, known := fields[property]
		text, isText := r.properties[property].(string)
		switch {
		case !known:
			problems = append(problems, fieldError{Field: property, Message: "is not a field of the profile"})
		case r.properties[property] == nil:
			problems = append(problems, fieldError{Field: property, Message: "must not be null"})
		case !isText:
			problems = append(problems, fieldError{Field: property, Message: "must be a string"})
		default:
			*target = &text
		}
	}
	return command, problems
}

func patchProfile(useCase in.UpdateProfile) callerHandler {
	return func(w http.ResponseWriter, r *http.Request, callerID string) {
		traceID := w.Header().Get(headerCorrelationID)
		w.Header().Set("Cache-Control", "no-store")

		body, unreadable := decodeBodyWithin[updateProfileRequest](w, r, maxProfileBodyBytes)
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
