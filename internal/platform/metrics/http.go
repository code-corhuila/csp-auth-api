// Package metrics keeps the metrics of the HTTP routes and writes them in the Prometheus text format (version 0.0.4), with the
// Go standard library only. It is neutral on purpose, as internal/platform/logging: the http adapter observes, the
// composition root publishes the scrape.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// latencyBuckets are the limits, in seconds, of the latency histogram: the ones of the metric catalog of the week 11
// workshop. A password route hashes with bcrypt on purpose, so its first buckets are wider than a read's. The SLO of the
// credential routes (1 second) is one of the limits.
var latencyBuckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5}

type routeKey struct{ route, method string }

type outcomeKey struct {
	routeKey
	outcome string
}

type histogram struct {
	buckets []uint64
	count   uint64
	sum     float64
}

// HTTP counts the requests and times the answers of the routes of the service:
// auth_http_requests_total{route,method,outcome} and auth_http_request_duration_seconds{route,method}. Its labels are the
// pattern of the route, the method and the outcome class, so the series are as many as the routes and never grow with the
// users or the requests.
type HTTP struct {
	mu       sync.Mutex
	requests map[outcomeKey]uint64
	latency  map[routeKey]*histogram
}

var _ http.Handler = (*HTTP)(nil)

// NewHTTP creates empty metrics.
func NewHTTP() *HTTP {
	return &HTTP{requests: map[outcomeKey]uint64{}, latency: map[routeKey]*histogram{}}
}

// Outcome groups an HTTP status in the label values success (2xx and 3xx), client_error (4xx) and error (5xx). A 4xx is a
// correct answer of the service, so the availability SLO does not count it as an error.
func Outcome(status int) string {
	switch {
	case status >= 500:
		return "error"
	case status >= 400:
		return "client_error"
	}
	return "success"
}

// Observe records one answered request. route is the pattern of the route, never the raw path.
func (m *HTTP) Observe(route, method string, status int, duration time.Duration) {
	seconds := duration.Seconds()
	key := routeKey{route, method}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[outcomeKey{key, Outcome(status)}]++
	h := m.latency[key]
	if h == nil {
		h = &histogram{buckets: make([]uint64, len(latencyBuckets))}
		m.latency[key] = h
	}
	for i, limit := range latencyBuckets {
		if seconds <= limit {
			h.buckets[i]++
		}
	}
	h.count++
	h.sum += seconds
}

// ServeHTTP answers a scrape with the metrics in the Prometheus text format.
func (m *HTTP) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	var b strings.Builder
	m.writeRequests(&b)
	m.writeLatency(&b)
	m.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}

func (m *HTTP) writeRequests(b *strings.Builder) {
	b.WriteString("# HELP auth_http_requests_total Requests answered, by route pattern, method and outcome class.\n")
	b.WriteString("# TYPE auth_http_requests_total counter\n")
	keys := make([]outcomeKey, 0, len(m.requests))
	for k := range m.requests {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, c := keys[i], keys[j]
		if a.route != c.route {
			return a.route < c.route
		}
		if a.method != c.method {
			return a.method < c.method
		}
		return a.outcome < c.outcome
	})
	for _, k := range keys {
		fmt.Fprintf(b, "auth_http_requests_total{route=%q,method=%q,outcome=%q} %d\n", k.route, k.method, k.outcome, m.requests[k])
	}
}

func (m *HTTP) writeLatency(b *strings.Builder) {
	b.WriteString("# HELP auth_http_request_duration_seconds Time to answer a request, without the intentional waits of the service.\n")
	b.WriteString("# TYPE auth_http_request_duration_seconds histogram\n")
	keys := make([]routeKey, 0, len(m.latency))
	for k := range m.latency {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].route != keys[j].route {
			return keys[i].route < keys[j].route
		}
		return keys[i].method < keys[j].method
	})
	for _, k := range keys {
		h := m.latency[k]
		for i, limit := range latencyBuckets {
			fmt.Fprintf(b, "auth_http_request_duration_seconds_bucket{route=%q,method=%q,le=\"%g\"} %d\n", k.route, k.method, limit, h.buckets[i])
		}
		fmt.Fprintf(b, "auth_http_request_duration_seconds_bucket{route=%q,method=%q,le=\"+Inf\"} %d\n", k.route, k.method, h.count)
		fmt.Fprintf(b, "auth_http_request_duration_seconds_sum{route=%q,method=%q} %g\n", k.route, k.method, h.sum)
		fmt.Fprintf(b, "auth_http_request_duration_seconds_count{route=%q,method=%q} %d\n", k.route, k.method, h.count)
	}
}
