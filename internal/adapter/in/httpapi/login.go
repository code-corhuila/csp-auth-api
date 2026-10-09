package httpapi

import (
	"net/http"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
)

// WithLoginUser publishes the use case at POST /login (HU-AUTH-002), public.
func WithLoginUser(useCase in.LoginUser) Option {
	return func(mux *http.ServeMux) {
		mux.HandleFunc("POST "+BasePath+"/login", login(useCase))
	}
}

// loginRequest is the LoginRequest schema of the auth-service contract.
type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func login(useCase in.LoginUser) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		traceID := correlationID(r)
		w.Header().Set(headerCorrelationID, traceID)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")

		body, unreadable := decodeBody[loginRequest](w, r)
		problems := append(validateLogin(body, unreadable == nil), unreadable...)
		if len(problems) > 0 {
			writeValidation(w, traceID, problems)
			return
		}

		result, err := useCase.Login(r.Context(), in.LoginUserCommand{
			Email:     body.Email,
			Password:  body.Password,
			UserAgent: r.UserAgent(),
		})
		if err != nil {
			translateLoginError(w, traceID, err)
			return
		}
		writeJSON(w, http.StatusOK, authResponse{
			AccessToken:  result.AccessToken,
			RefreshToken: result.RefreshToken,
			ExpiresIn:    result.ExpiresIn,
			User:         toUserSummary(result.User),
		})
	}
}

// validateLogin checks only that the credentials are present. Their content is judged by the use
// case: a malformed email is a failed login like an unknown one, and the password policy of the
// registration does not apply to a password that is only being presented.
func validateLogin(body loginRequest, bodyRead bool) []fieldError {
	if !bodyRead {
		return nil
	}
	var problems []fieldError
	if body.Email == "" {
		problems = append(problems, fieldError{Field: "email", Message: "is required"})
	}
	if body.Password == "" {
		problems = append(problems, fieldError{Field: "password", Message: "is required"})
	}
	return problems
}
