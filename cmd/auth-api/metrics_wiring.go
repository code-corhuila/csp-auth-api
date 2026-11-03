package main

import (
	"net/http"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/in/httpapi"
	"github.com/code-corhuila/csp-auth-api/internal/config"
	"github.com/code-corhuila/csp-auth-api/internal/platform/metrics"
)

// newRouter returns the function that builds the router of the service. With APP_AUTH_METRICS_ENABLED it also publishes
// GET /metrics and reports every request to the metrics (ADR-061); the scrape is not part of the contract and the gateway
// does not route it.
func newRouter(cfg config.Config) func(options ...httpapi.Option) http.Handler {
	if !cfg.MetricsEnabled {
		return func(options ...httpapi.Option) http.Handler { return httpapi.NewHandler(options...) }
	}
	collected := metrics.NewHTTP()
	return func(options ...httpapi.Option) http.Handler {
		all := append([]httpapi.Option{httpapi.WithMetricsRoute(collected)}, options...)
		return httpapi.WithObserver(httpapi.NewHandler(all...), collected)
	}
}
