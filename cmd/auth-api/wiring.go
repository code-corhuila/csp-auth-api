package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/in/httpapi"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/persistence"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/security"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/system"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/token"
	"github.com/code-corhuila/csp-auth-api/internal/application/usecase"
	"github.com/code-corhuila/csp-auth-api/internal/config"
)

// poolOpener opens the database pool. The tests replace it so the wiring decisions do not need a
// database.
type poolOpener func(ctx context.Context, settings persistence.PoolSettings) (*pgxpool.Pool, error)

// newHandler wires the routes and returns the function that releases what they hold open.
//
//   - No signing key: health only, exactly as before; with a database URL that is a startup error,
//     because registration issues tokens.
//   - A signing key: health and /jwks.
//   - A signing key and a database URL: also POST /register, served by the real use case.
//
// A configured key or database that cannot be used stops the service instead of degrading it.
func newHandler(ctx context.Context, logger *slog.Logger, cfg config.Config, open poolOpener) (http.Handler, func(), error) {
	noop := func() {}
	hasKey := cfg.JWTPrivateKey != "" || cfg.JWTPrivateKeyFile != ""
	if !hasKey {
		if cfg.DatabaseURL != "" {
			return nil, noop, errors.New("APP_AUTH_DATABASE_URL needs a signing key (APP_AUTH_JWT_PRIVATE_KEY or APP_AUTH_JWT_PRIVATE_KEY_FILE): registration issues tokens")
		}
		return httpapi.NewHandler(), noop, nil
	}
	key, err := token.LoadPrivateKey(cfg.JWTPrivateKey, cfg.JWTPrivateKeyFile)
	if err != nil {
		return nil, noop, err
	}
	issuer, err := token.NewIssuer(key, cfg.AccessTokenTTL, system.Clock{}, system.UUIDGenerator{})
	if err != nil {
		return nil, noop, err
	}
	options := []httpapi.Option{httpapi.WithPublicKeys(issuer)}
	if cfg.DatabaseURL == "" {
		return httpapi.NewHandler(options...), noop, nil
	}

	pool, err := open(ctx, persistence.PoolSettings{
		URL:            cfg.DatabaseURL,
		MaxConnections: cfg.DatabaseMaxConnections,
		MinConnections: cfg.DatabaseMinConnections,
		ConnectTimeout: cfg.DatabaseConnectTimeout,
		QueryTimeout:   cfg.DatabaseQueryTimeout,
	})
	if err != nil {
		return nil, noop, fmt.Errorf("connect to the auth database: %w", err)
	}
	options = append(options, httpapi.WithRegisterUser(newRegisterUser(cfg, pool, issuer)))
	logger.Info("register route enabled")
	return httpapi.NewHandler(options...), pool.Close, nil
}

func newRegisterUser(cfg config.Config, pool *pgxpool.Pool, issuer *token.Issuer) *usecase.RegisterUser {
	clock, ids := system.Clock{}, system.UUIDGenerator{}
	return usecase.NewRegisterUser(usecase.RegisterUserPorts{
		Users:        persistence.NewUserRepository(pool),
		Keys:         persistence.NewIdempotencyKeyRepository(pool),
		Outbox:       persistence.NewOutboxWriter(pool),
		Hasher:       security.NewBcryptHasher(cfg.BcryptRounds),
		IDs:          ids,
		Clock:        clock,
		Transactions: persistence.NewTransactionManager(pool),
		Tokens:       issuer,
		Sessions:     usecase.NewIssueRefreshToken(persistence.NewRefreshTokenRepository(pool), ids, clock, cfg.RefreshTokenTTL),
	})
}
