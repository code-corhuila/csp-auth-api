package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func lookupFrom(env map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := env[key]
		return value, ok
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func TestRunRejectsInvalidConfiguration(t *testing.T) {
	err := run(context.Background(), discardLogger(), lookupFrom(map[string]string{"PORT": "not-a-number"}))
	if err == nil {
		t.Fatal("run() error = nil, want a configuration error")
	}
}

func TestRunServesHealthAndStopsOnCancel(t *testing.T) {
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, discardLogger(), lookupFrom(map[string]string{"PORT": strconv.Itoa(port)}))
	}()

	url := "http://127.0.0.1:" + strconv.Itoa(port) + "/api/v1/auth/health"
	var status int
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			status = resp.StatusCode
			resp.Body.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if status != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200", url, status)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run() error = %v, want nil after a graceful shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run() did not return after the context was cancelled")
	}
}

func TestRunFailsWhenThePortIsTaken(t *testing.T) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = run(ctx, discardLogger(), lookupFrom(map[string]string{"PORT": strconv.Itoa(port)}))
	if err == nil {
		t.Fatal("run() error = nil, want a bind error")
	}
}
