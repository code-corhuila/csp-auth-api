package httpapi

import (
	"net/http"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
)

// WithRefreshSession publishes the use case at POST /refresh (HU-AUTH-002), public: the refresh
// token in the body is the credential.
func WithRefreshSession(useCase in.RefreshSession) Option {
	return func(mux *http.ServeMux) {
		mux.HandleFunc("POST "+BasePath+"/refresh", refresh(useCase))
	}
}

// refreshRequest is the request body of POST /refresh in the auth-service contract.
type refreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

func refresh(useCase in.RefreshSession) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		traceID := correlationID(r)
		w.Header().Set(headerCorrelationID, traceID)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")

		body, unreadable := decodeBody[refreshRequest](w, r)
		problems := unreadable
		if unreadable == nil && body.RefreshToken == "" {
			problems = []fieldError{{Field: "refreshToken", Message: "is required"}}
		}
		if len(problems) > 0 {
			writeValidation(w, traceID, problems)
			return
		}

		result, err := useCase.Refresh(r.Context(), in.RefreshSessionCommand{
			RefreshToken: body.RefreshToken,
			UserAgent:    r.UserAgent(),
		})
		if err != nil {
			translateRefreshError(w, traceID, err)
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
