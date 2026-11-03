package httpapi

import (
	"net/http"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// WithLogout publishes the use case at POST /logout (HU-AUTH-003, ADR-033), open to any user with a
// valid access token.
func WithLogout(authenticator in.AuthenticateUser, useCase in.Logout) Option {
	return func(mux *http.ServeMux) {
		mux.HandleFunc("POST "+BasePath+"/logout", requireAuthenticationEvenIfListIsDown(authenticator, logout(useCase)))
	}
}

// logoutRequest is the optional request body of logout in the auth-service contract.
type logoutRequest struct {
	RefreshToken string `json:"refreshToken"`
	AllDevices   bool   `json:"allDevices"`
}

func logout(useCase in.Logout) claimsHandler {
	return func(w http.ResponseWriter, r *http.Request, claims model.AccessClaims) {
		traceID := w.Header().Get(headerCorrelationID) // set by the guard, which wraps this handler

		var body logoutRequest
		if r.ContentLength != 0 {
			decoded, unreadable := decodeBody[logoutRequest](w, r)
			if len(unreadable) > 0 {
				writeValidation(w, traceID, unreadable)
				return
			}
			body = decoded
		}

		// A sign out always ends the refresh capability of the session (ADR-033), even if the browser leaves the page.
		ctx, cancel := detachedFromClient(r)
		defer cancel()
		err := useCase.Logout(ctx, in.LogoutCommand{
			UserID:       claims.Subject,
			TokenID:      claims.TokenID,
			ExpiresAt:    claims.ExpiresAt,
			RefreshToken: body.RefreshToken,
			AllDevices:   body.AllDevices,
		})
		if err != nil {
			translateLogoutError(w, traceID, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
