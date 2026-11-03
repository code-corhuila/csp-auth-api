package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/persistence"
)

func serveGet(t *testing.T, handler http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestTheServicePublishesAndCountsItsRequestsWhenMetricsAreEnabled(t *testing.T) {
	cfg := testConfig(t)
	if !cfg.MetricsEnabled {
		t.Fatal("metrics must be on by default: the platform scrapes them")
	}
	handler, release, err := newHandler(context.Background(), discardLogger(), cfg, persistence.NewPool)
	if err != nil {
		t.Fatalf("newHandler() error = %v", err)
	}
	defer release()

	serveGet(t, handler, "/api/v1/auth/health")
	scrape := serveGet(t, handler, "/metrics")

	if scrape.Code != http.StatusOK || !strings.Contains(scrape.Body.String(), `auth_http_requests_total{route="/api/v1/auth/health",method="GET",outcome="success"} 1`) {
		t.Errorf("GET /metrics = %d:\n%s\nwant the counted health request", scrape.Code, scrape.Body.String())
	}
}

func TestTheServiceHasNoMetricsRouteWhenTheyAreDisabled(t *testing.T) {
	cfg := testConfig(t)
	cfg.MetricsEnabled = false
	handler, release, err := newHandler(context.Background(), discardLogger(), cfg, persistence.NewPool)
	if err != nil {
		t.Fatalf("newHandler() error = %v", err)
	}
	defer release()

	if rec := serveGet(t, handler, "/metrics"); rec.Code != http.StatusNotFound {
		t.Errorf("GET /metrics = %d, want 404 with APP_AUTH_METRICS_ENABLED=false", rec.Code)
	}
}
