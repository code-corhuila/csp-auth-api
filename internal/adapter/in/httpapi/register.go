package httpapi

import (
	"net/http"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const (
	headerIdempotencyKey = "Idempotency-Key"
)

// WithRegistration publishes the two steps of the registration at POST /register and POST /register/confirm (HU-AUTH-001,
// issue csp-docs#282), public. Both take an Idempotency-Key (Norma 5.3.8). The first hashes with bcrypt and the second
// opens a session, so gate caps how many requests of either run at once (Norma 5.3.10): one that finds no free slot is
// refused with 429 before any work.
func WithRegistration(request in.RequestRegistration, confirm in.ConfirmRegistration, gate *Bulkhead) Option {
	return func(mux *http.ServeMux) {
		mux.HandleFunc("POST "+BasePath+"/register", register(request, gate))
		mux.HandleFunc("POST "+BasePath+"/register/confirm", confirmRegistration(confirm, gate))
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

// registrationResponse is the RegistrationRequest schema: the id of the registration request, the same shape whether the
// address already has an account or not.
type registrationResponse struct {
	ID string `json:"id"`
}

// confirmRegistrationRequest is the ConfirmRegistrationRequest schema of the auth-service contract.
type confirmRegistrationRequest struct {
	Token string `json:"token"`
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

// register answers 201 with the id of the registration request, or 200 for a replay of its Idempotency-Key, and nothing
// else tells an address with an account from a free one.
func register(useCase in.RequestRegistration, gate *Bulkhead) http.HandlerFunc {
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

		release, admitted := admit(w, r, gate, traceID, "register request")
		if !admitted {
			return
		}
		defer release()

		result, err := useCase.Request(r.Context(), in.RequestRegistrationCommand{
			IdempotencyKey: key,
			Email:          body.Email,
			Password:       body.Password,
			Name:           body.Name,
			Phone:          body.Phone,
			Address:        body.Address,
		})
		if err != nil {
			translateRegisterError(w, traceID, err)
			return
		}
		if result.Replayed {
			writeJSON(w, http.StatusOK, registrationResponse{ID: result.RequestID})
			return
		}
		w.Header().Set("Location", BasePath+"/registrations/"+result.RequestID)
		writeJSON(w, http.StatusCreated, registrationResponse{ID: result.RequestID})
	}
}

// confirmRegistration answers 201 with the session of the account it created, or 200 with its summary and no tokens for
// a replay of its Idempotency-Key. The token and the key are validated before the gate and the use case.
func confirmRegistration(useCase in.ConfirmRegistration, gate *Bulkhead) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		traceID := correlationID(r)
		w.Header().Set(headerCorrelationID, traceID)
		w.Header().Set("Cache-Control", "no-store")

		key := r.Header.Get(headerIdempotencyKey)
		body, unreadable := decodeBodyWithin[confirmRegistrationRequest](w, r, limitsOf(r.Context()).PasswordResetMaxBodyBytes)
		checks := []check{{headerIdempotencyKey, errorOf(model.NewIdempotencyKey(key))}}
		if unreadable == nil {
			checks = append(checks, check{"token", errorOf(model.NewResetToken(body.Token))})
		}
		if problems := append(problemsOf(checks), unreadable...); len(problems) > 0 {
			writeValidation(w, traceID, problems)
			return
		}

		release, admitted := admit(w, r, gate, traceID, "confirm registration request")
		if !admitted {
			return
		}
		defer release()

		result, err := useCase.Confirm(r.Context(), in.ConfirmRegistrationCommand{IdempotencyKey: key, Token: body.Token, UserAgent: r.UserAgent()})
		if err != nil {
			translateConfirmRegistrationError(w, traceID, err)
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
