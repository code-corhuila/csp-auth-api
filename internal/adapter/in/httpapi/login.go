package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// WithLoginUser publishes the use case at POST /login (HU-AUTH-002), public. The route compares with bcrypt, so gate caps
// how many requests run at once (Norma 5.3.10): one that finds no free slot is refused with 429 before the comparison.
func WithLoginUser(useCase in.LoginUser, gate *Bulkhead) Option {
	return func(mux *http.ServeMux) {
		mux.HandleFunc("POST "+BasePath+"/login", login(useCase, gate))
	}
}

// loginRequest is the LoginRequest schema of the auth-service contract.
type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func login(useCase in.LoginUser, gate *Bulkhead) http.HandlerFunc {
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

		release, admitted := admit(w, r, gate, traceID, "login request")
		if !admitted {
			return
		}
		defer release()

		result, err := useCase.Login(r.Context(), in.LoginUserCommand{
			Email:     body.Email,
			Password:  body.Password,
			UserAgent: r.UserAgent(),
			ClientIP:  clientAddress(r),
		})
		if err != nil {
			release()
			waitOutSlowdown(r.Context(), err)
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

// waitOutSlowdown holds the answer of a failed login of an account that has too many failures (model.LoginSlowedError)
// for the delay of the policy. The caller gave its bulkhead slot back first, so a flood of slowed requests cannot fill the
// slots of the route, and a client that leaves ends the wait.
func waitOutSlowdown(ctx context.Context, err error) {
	var slowed *model.LoginSlowedError
	if !errors.As(err, &slowed) {
		return
	}
	started := time.Now()
	defer func() { noteWait(ctx, time.Since(started)) }()
	timer := time.NewTimer(slowed.Delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
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
