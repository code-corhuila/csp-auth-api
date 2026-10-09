package httpapi

import (
	"net/http"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const (
	headerIdempotencyKey = "Idempotency-Key"
)

// WithRegisterUser publishes the use case at POST /register (HU-AUTH-001), public.
func WithRegisterUser(useCase in.RegisterUser) Option {
	return func(mux *http.ServeMux) {
		mux.HandleFunc("POST "+BasePath+"/register", register(useCase))
	}
}

// registerRequest is the RegisterRequest schema of the auth-service contract.
type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
	Phone    string `json:"phone"`
	Address  string `json:"address"`
}

// userSummary is the UserSummary schema: no phone, no address, no password hash (ADR-024).
type userSummary struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	Name        string   `json:"name"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

// authResponse is the AuthResponse schema of the auth-service contract.
type authResponse struct {
	AccessToken  string      `json:"accessToken"`
	RefreshToken string      `json:"refreshToken"`
	ExpiresIn    int         `json:"expiresIn"`
	User         userSummary `json:"user"`
}

func register(useCase in.RegisterUser) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		traceID := correlationID(r)
		w.Header().Set(headerCorrelationID, traceID)
		w.Header().Set("Cache-Control", "no-store")

		key := r.Header.Get(headerIdempotencyKey)
		body, unreadable := decodeBody[registerRequest](w, r)
		problems := validateRegistration(key, body, unreadable == nil)
		problems = append(problems, unreadable...)
		if len(problems) > 0 {
			writeValidation(w, traceID, problems)
			return
		}

		result, err := useCase.Register(r.Context(), in.RegisterUserCommand{
			IdempotencyKey: key,
			Email:          body.Email,
			Password:       body.Password,
			Name:           body.Name,
			Phone:          body.Phone,
			Address:        body.Address,
			UserAgent:      r.UserAgent(),
		})
		if err != nil {
			translateRegisterError(w, traceID, err)
			return
		}
		user := toUserSummary(result.Session.User)
		if result.Replayed {
			writeJSON(w, http.StatusOK, user)
			return
		}
		w.Header().Set("Location", BasePath+"/users/"+user.ID)
		writeJSON(w, http.StatusCreated, authResponse{
			AccessToken:  result.Session.AccessToken,
			RefreshToken: result.Session.RefreshToken,
			ExpiresIn:    result.Session.ExpiresIn,
			User:         user,
		})
	}
}

// validateRegistration asks the domain constructors about every input, so all the invalid fields
// are reported at once and the rules stay in the domain. The body fields are checked only when
// the body could be read.
func validateRegistration(key string, body registerRequest, bodyRead bool) []fieldError {
	checks := []check{{headerIdempotencyKey, errorOf(model.NewIdempotencyKey(key))}}
	if bodyRead {
		checks = append(checks,
			check{"email", errorOf(model.NewEmail(body.Email))},
			check{"password", errorOf(model.NewPassword(body.Password))},
			check{"name", errorOf(model.NewName(body.Name))},
			check{"phone", errorOf(model.NewPhone(body.Phone))},
			check{"address", errorOf(model.NewAddress(body.Address))},
		)
	}
	var problems []fieldError
	for _, c := range checks {
		if c.err != nil {
			problems = append(problems, fieldError{Field: c.field, Message: c.err.Error()})
		}
	}
	return problems
}

type check struct {
	field string
	err   error
}

func errorOf[T any](_ T, err error) error {
	return err
}

func toUserSummary(user in.UserSummary) userSummary {
	return userSummary{
		ID:          user.ID,
		Email:       user.Email,
		Name:        user.Name,
		Roles:       nonNil(user.Roles),
		Permissions: nonNil(user.Permissions),
	}
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
