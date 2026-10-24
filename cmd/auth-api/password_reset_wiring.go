package main

import (
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/in/httpapi"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/mail"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/persistence"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/security"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/system"
	"github.com/code-corhuila/csp-auth-api/internal/application/usecase"
	"github.com/code-corhuila/csp-auth-api/internal/config"
)

// passwordResetRoutes publishes POST /forgot-password and POST /reset-password (HU-AUTH-006, ADR-050) when the SMTP relay
// and the link of the portal are configured: the link is sent through that relay after the commit, by a queue the
// returned function stops. Without either, the two routes answer the 404 of the contract and the log says why, once.
func passwordResetRoutes(cfg config.Config, logger *slog.Logger, pool *pgxpool.Pool) (httpapi.Option, func(), error) {
	notEnabled := func(reason string) (httpapi.Option, func(), error) {
		logger.Info(reason + ": the password reset is not enabled")
		return httpapi.WithPasswordResetNotEnabled(), func() {}, nil
	}
	switch {
	case cfg.SMTPHost == "":
		return notEnabled("APP_AUTH_SMTP_HOST is not set")
	case cfg.PasswordResetURL == "":
		return notEnabled("APP_AUTH_PASSWORD_RESET_URL is not set")
	}
	forgotGate, err := httpapi.NewBulkhead(cfg.PasswordResetMaxConcurrency, cfg.PasswordResetQueueTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("password reset limit: %w", err)
	}
	resetGate, err := httpapi.NewBulkhead(cfg.PasswordResetMaxConcurrency, cfg.PasswordResetQueueTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("password reset limit: %w", err)
	}
	sender, err := mail.NewSMTPPasswordResetSender(mail.Settings{
		Host: cfg.SMTPHost, Port: cfg.SMTPPort, User: cfg.SMTPUser, Password: cfg.SMTPPassword,
		From: cfg.SMTPFrom, TLS: cfg.SMTPTLS, Timeout: cfg.SMTPTimeout,
	}, cfg.PasswordResetURL, logger)
	if err != nil {
		return nil, nil, err
	}
	users, transactions, clock := persistence.NewUserRepository(pool), persistence.NewTransactionManager(pool), system.Clock{}
	resets := persistence.NewPasswordResetRepository(pool)
	request := usecase.NewRequestPasswordReset(usecase.RequestPasswordResetPorts{
		Users: users, Resets: resets, Tokens: system.ResetTokenGenerator{}, Sender: sender,
		IDs: system.UUIDGenerator{}, Clock: clock, Transactions: transactions,
	})
	reset := usecase.NewResetPassword(usecase.ResetPasswordPorts{
		Resets: resets, Hasher: security.NewBcryptHasher(cfg.BcryptRounds), Current: users, Passwords: users,
		Sessions: persistence.NewRefreshTokenRepository(pool), Clock: clock, Transactions: transactions,
	})
	logger.Info("password reset routes enabled", "maxConcurrency", forgotGate.Limit(), "queueTimeout", forgotGate.Wait().String())
	return httpapi.WithPasswordReset(request, reset, forgotGate, resetGate), sender.Close, nil
}
