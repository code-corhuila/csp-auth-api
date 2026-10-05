// Package httpapi is the HTTP inbound adapter: routes, validation and response objects.
package httpapi

import (
	"encoding/json"
	"net/http"
)

// BasePath is the prefix of every route of the service (see the auth-service contract).
const BasePath = "/api/v1/auth"

// NewHandler returns the router of the service.
func NewHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+BasePath+"/health", health)
	mux.HandleFunc("GET "+BasePath+"/health/ready", ready)
	return mux
}

func health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ready reports no dependencies yet: the adapters that need PostgreSQL and Redis add theirs.
func ready(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ready",
		"dependencies": map[string]string{},
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
