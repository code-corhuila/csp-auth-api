// Command auth-api is the composition root of the auth service: the only place that
// knows every concrete type and every limit.
package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/persistence"
	"github.com/code-corhuila/csp-auth-api/internal/config"
	"github.com/code-corhuila/csp-auth-api/internal/platform/logging"
)

func main() {
	logger := newLogger(os.Stdout)
	slog.SetDefault(logger)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, logger, os.LookupEnv); err != nil {
		logger.Error("auth-api stopped", "error", err)
		os.Exit(1)
	}
}

// newLogger writes JSON lines, and adds the traceId of the request to every record logged with its context (Norma 5.3.9).
func newLogger(out io.Writer) *slog.Logger {
	return slog.New(logging.NewTraceHandler(slog.NewJSONHandler(out, nil)))
}

func run(ctx context.Context, logger *slog.Logger, lookup config.Lookup) error {
	cfg, err := config.Load(lookup)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(cfg.Port)))
	if err != nil {
		return err
	}
	return serve(ctx, logger, cfg, listener)
}

// serve answers on listener until ctx is cancelled or the server fails. Taking the listener
// lets a test bind its own port instead of guessing a free one.
func serve(ctx context.Context, logger *slog.Logger, cfg config.Config, listener net.Listener) error {
	handler, closeDatabase, err := newHandler(ctx, logger, cfg, persistence.NewPool)
	if err != nil {
		return err
	}
	defer closeDatabase()
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		MaxHeaderBytes:    int(cfg.MaxHeaderBytes),
		IdleTimeout:       cfg.IdleTimeout,
	}

	failed := make(chan error, 1)
	go func() {
		logger.Info("auth-api listening", "addr", listener.Addr().String())
		failed <- server.Serve(listener)
	}()

	select {
	case err := <-failed:
		return err
	case <-ctx.Done():
		logger.Info("shutting down", "timeout", cfg.ShutdownTimeout.String())
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
