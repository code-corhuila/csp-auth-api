package main

import (
	"github.com/code-corhuila/csp-auth-api/internal/adapter/in/httpapi"
	"github.com/code-corhuila/csp-auth-api/internal/config"
)

// limitsOf is the request limits of the configuration, which the handlers read from the request context.
func limitsOf(cfg config.Config) httpapi.Limits {
	return httpapi.Limits{
		RequestTimeout:            cfg.RequestTimeout,
		DetachedDeadline:          cfg.DetachedDeadline,
		MaxBodyBytes:              cfg.MaxBodyBytes,
		PasswordResetMaxBodyBytes: cfg.PasswordResetMaxBodyBytes,
	}
}
