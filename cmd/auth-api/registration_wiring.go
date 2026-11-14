package main

import (
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/in/httpapi"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/mail"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/persistence"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/system"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/token"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/application/usecase"
	"github.com/code-corhuila/csp-auth-api/internal/config"
)

// registrationRoutes publishes POST /register and POST /register/confirm (HU-AUTH-001, issue csp-docs#282). The messages
// of the registration go through the SMTP relay after the commit, by a queue the returned function stops. Without the relay
// or the link of the portal the routes still answer as usual, because the answer must not tell whether an address has an
// account, and every delivery fails with a WARN: no registration can be confirmed until the relay is configured.
func registrationRoutes(cfg config.Config, logger *slog.Logger, pool *pgxpool.Pool, issuer *token.Issuer, hasher out.PasswordHasher, gate *httpapi.Bulkhead) (httpapi.Option, func(), error) {
	sender, closeSender, err := registrationSender(cfg, logger)
	if err != nil {
		return nil, nil, err
	}
	users, transactions, clock, ids := persistence.NewUserRepository(pool), persistence.NewTransactionManager(pool), system.Clock{}, system.UUIDGenerator{}
	registrations := persistence.NewRegistrationRequestRepository(pool)
	request := usecase.NewRequestRegistration(usecase.RequestRegistrationPorts{
		Users: users, Registrations: registrations, Hasher: hasher, Tokens: system.ResetTokenGenerator{}, Sender: sender,
		IDs: ids, Clock: clock, Transactions: transactions,
	})
	confirm := usecase.NewConfirmRegistration(usecase.ConfirmRegistrationPorts{
		Users: users, Registrations: registrations, Keys: persistence.NewIdempotencyKeyRepository(pool), Outbox: persistence.NewOutboxWriter(pool),
		IDs: ids, Clock: clock, Transactions: transactions, Tokens: issuer,
		Sessions: usecase.NewIssueRefreshToken(persistence.NewRefreshTokenRepository(pool), ids, clock, cfg.RefreshTokenTTL),
	})
	return httpapi.WithRegistration(request, confirm, gate), closeSender, nil
}

func registrationSender(cfg config.Config, logger *slog.Logger) (out.RegistrationSender, func(), error) {
	if cfg.SMTPHost == "" || cfg.RegistrationConfirmURL == "" {
		logger.Warn("APP_AUTH_SMTP_HOST or APP_AUTH_REGISTRATION_CONFIRM_URL is not set: registrations cannot be confirmed")
		return mail.UnconfiguredRegistrationSender{}, func() {}, nil
	}
	sender, err := mail.NewSMTPRegistrationSender(mail.Settings{
		Host: cfg.SMTPHost, Port: cfg.SMTPPort, User: cfg.SMTPUser, Password: cfg.SMTPPassword,
		From: cfg.SMTPFrom, TLS: cfg.SMTPTLS, Timeout: cfg.SMTPTimeout,
	}, cfg.RegistrationConfirmURL, logger)
	if err != nil {
		return nil, nil, err
	}
	return sender, sender.Close, nil
}
