package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/in/httpapi"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/mail"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/persistence"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/redis"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/security"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/system"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/token"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/application/usecase"
	"github.com/code-corhuila/csp-auth-api/internal/config"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// poolOpener opens the database pool. The tests replace it so the wiring decisions do not need a
// database.
type poolOpener func(ctx context.Context, settings persistence.PoolSettings) (*pgxpool.Pool, error)

// newHandler wires the routes and returns the function that releases what they hold open.
//
//   - No signing key: health only, exactly as before; with a database URL that is a startup error,
//     because registration issues tokens.
//   - A signing key: health and /jwks.
//   - A signing key and a database URL: also POST /register, POST /login and POST /refresh, served by the real use cases,
//     GET /users and PATCH /users/{userId}/role, open to the access tokens that hold user:role:update, and
//     PATCH /me/email and POST /me/email/verify when APP_AUTH_SMTP_HOST is set (the verification code goes
//     to that SMTP relay, ADR-034; without it the two routes are not enabled), open to the access tokens that
//     hold profile:update:self, and
//     POST /internal/maintenance/purge, open only to the service tokens whose subject is in SERVICE_SUBJECTS.
//   - Also an APP_AUTH_REDIS_URL: POST /logout, which lists the revoked access tokens in Redis, and the check of
//     that list on POST /logout, GET /users, PATCH /users/{userId}/role and the email change. Without it the route is not enabled and
//     the other two work without the check. It also holds the
//     login attempt limit of POST /login (HU-AUTH-005), which is off without it.
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
	redisState, closeRedis, err := openRedisState(logger, cfg)
	if err != nil {
		pool.Close()
		return nil, noop, err
	}
	options = append(options, httpapi.WithLoginUser(newLoginUser(cfg, pool, issuer, redisState.attempts)))
	logger.Info("login route enabled")
	options = append(options, httpapi.WithRefreshSession(newRefreshSession(cfg, pool, issuer)))
	logger.Info("refresh route enabled")
	authorizer := newAuthorizeUser(issuer, redisState.revoked)
	options = append(options, httpapi.WithChangeUserRole(authorizer, newChangeUserRole(pool)))
	logger.Info("user role route enabled")
	options = append(options, httpapi.WithListUsers(authorizer, usecase.NewListUsers(persistence.NewUserReader(pool))))
	logger.Info("user list route enabled")
	if cfg.SMTPHost != "" {
		requestEmailChange, err := newRequestEmailChange(cfg, logger, pool)
		if err != nil {
			closeRedis()
			pool.Close()
			return nil, noop, err
		}
		gate, err := httpapi.NewBulkhead(cfg.EmailChangeMaxConcurrency, cfg.EmailChangeQueueTimeout)
		if err != nil {
			closeRedis()
			pool.Close()
			return nil, noop, fmt.Errorf("email change limit: %w", err)
		}
		options = append(options, httpapi.WithEmailChange(authorizer, requestEmailChange, newVerifyEmailChange(pool), gate))
		logger.Info("email change routes enabled", "maxConcurrency", gate.Limit(), "queueTimeout", gate.Wait().String())
	} else {
		logger.Info("APP_AUTH_SMTP_HOST is not set: the email change is not enabled")
	}
	options = append(options, httpapi.WithPurgeOldRecords(newAuthorizeService(cfg, issuer), newPurgeOldRecords(pool)))
	logger.Info("purge route enabled")
	if cfg.RedisURL != "" {
		options = append(options, httpapi.WithLogout(authorizer, newLogout(pool, redisState.revoked)))
		logger.Info("logout route enabled")
	}
	return httpapi.NewHandler(options...), func() {
		closeRedis()
		pool.Close()
	}, nil
}

// redisState is what the service keeps in the Redis of the auth state (ADR-028): the list of revoked
// access tokens (logout) and the counters and locks of the login attempt limit (HU-AUTH-005).
type redisState struct {
	revoked  out.RevokedTokens
	attempts out.LoginAttempts
}

// openRedisState connects the Redis of the auth state when APP_AUTH_REDIS_URL is set (the client does not
// connect until it is used). Without it there is no state: the routes that consult the revoked list work
// without the check, logout is not enabled and the login is not limited, which the log says once.
func openRedisState(logger *slog.Logger, cfg config.Config) (redisState, func(), error) {
	if cfg.RedisURL == "" {
		logger.Info("APP_AUTH_REDIS_URL is not set: logout is not enabled, revoked access tokens are not checked and the login is not limited")
		return redisState{revoked: noRevokedTokens{}, attempts: noLoginAttempts{}}, func() {}, nil
	}
	policy, err := model.NewLoginAttemptPolicy(cfg.LoginMaxAttempts, cfg.LoginWindow, cfg.LoginLock)
	if err != nil {
		return redisState{}, nil, fmt.Errorf("login attempt limit: %w", err)
	}
	if cfg.LoginLimitTimeout <= 0 || cfg.LoginLimitPause <= 0 {
		return redisState{}, nil, errors.New("login attempt limit: the timeout and the pause must be positive")
	}
	client, err := redis.NewClient(redis.ClientSettings{URL: cfg.RedisURL, Timeout: cfg.RedisTimeout})
	if err != nil {
		return redisState{}, nil, err
	}
	attempts := redis.NewBoundedLoginAttempts(redis.NewLoginAttempts(client, policy), cfg.LoginLimitTimeout, cfg.LoginLimitPause, system.Clock{})
	state := redisState{revoked: redis.NewRevokedTokens(client), attempts: attempts}
	return state, func() { _ = client.Close() }, nil
}

// noRevokedTokens is the list of a service without Redis: nothing is ever revoked.
type noRevokedTokens struct{}

func (noRevokedTokens) Revoke(context.Context, string, time.Duration) error { return nil }

func (noRevokedTokens) IsRevoked(context.Context, string) (bool, error) { return false, nil }

// noLoginAttempts is the login limit of a service without Redis: nothing is counted and nobody is locked.
type noLoginAttempts struct{}

func (noLoginAttempts) LockedFor(context.Context, string) (time.Duration, error) { return 0, nil }

func (noLoginAttempts) RecordFailure(context.Context, string) error { return nil }

func (noLoginAttempts) Clear(context.Context, string) error { return nil }

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

func newLoginUser(cfg config.Config, pool *pgxpool.Pool, issuer *token.Issuer, attempts out.LoginAttempts) *usecase.LoginUser {
	clock, ids := system.Clock{}, system.UUIDGenerator{}
	return usecase.NewLoginUser(
		persistence.NewUserRepository(pool),
		security.NewBcryptHasher(cfg.BcryptRounds),
		issuer,
		usecase.NewIssueRefreshToken(persistence.NewRefreshTokenRepository(pool), ids, clock, cfg.RefreshTokenTTL),
		clock,
		attempts,
	)
}

func newRefreshSession(cfg config.Config, pool *pgxpool.Pool, issuer *token.Issuer) *usecase.RefreshSession {
	clock, ids := system.Clock{}, system.UUIDGenerator{}
	tokens := persistence.NewRefreshTokenRepository(pool)
	return usecase.NewRefreshSession(
		tokens,
		persistence.NewUserRepository(pool),
		persistence.NewTransactionManager(pool),
		issuer,
		usecase.NewIssueRefreshToken(tokens, ids, clock, cfg.RefreshTokenTTL),
		clock,
		cfg.RefreshReuseGrace,
	)
}

func newLogout(pool *pgxpool.Pool, revoked out.RevokedTokens) *usecase.Logout {
	return usecase.NewLogout(
		persistence.NewRefreshTokenRepository(pool),
		revoked,
		persistence.NewTransactionManager(pool),
		system.Clock{},
	)
}

func newAuthorizeUser(issuer *token.Issuer, revoked out.RevokedTokens) *usecase.AuthorizeUser {
	return usecase.NewAuthorizeUser(token.NewAccessTokenVerifier(issuer.PublicKeys(), system.Clock{}), revoked)
}

func newChangeUserRole(pool *pgxpool.Pool) *usecase.ChangeUserRole {
	users := persistence.NewUserRepository(pool)
	return usecase.NewChangeUserRole(usecase.ChangeUserRolePorts{
		Users:        users,
		Roles:        users,
		Outbox:       persistence.NewOutboxWriter(pool),
		IDs:          system.UUIDGenerator{},
		Clock:        system.Clock{},
		Transactions: persistence.NewTransactionManager(pool),
	})
}

func newAuthorizeService(cfg config.Config, issuer *token.Issuer) *usecase.AuthorizeService {
	return usecase.NewAuthorizeService(token.NewServiceTokenVerifier(issuer.PublicKeys(), system.Clock{}), cfg.ServiceSubjects)
}

func newPurgeOldRecords(pool *pgxpool.Pool) *usecase.PurgeOldRecords {
	return usecase.NewPurgeOldRecords(
		persistence.NewOutboxPurger(pool),
		persistence.NewRefreshTokenPurger(pool),
		persistence.NewIdempotencyKeyPurger(pool),
		persistence.NewEmailVerificationPurger(pool),
		system.Clock{},
	)
}

// newRequestEmailChange delivers the verification code through the SMTP relay of the configuration (ADR-034).
func newRequestEmailChange(cfg config.Config, logger *slog.Logger, pool *pgxpool.Pool) (*usecase.RequestEmailChange, error) {
	sender, err := mail.NewSMTPVerificationCodeSender(mail.Settings{
		Host: cfg.SMTPHost, Port: cfg.SMTPPort, User: cfg.SMTPUser, Password: cfg.SMTPPassword,
		From: cfg.SMTPFrom, TLS: cfg.SMTPTLS, Timeout: cfg.SMTPTimeout,
	}, logger)
	if err != nil {
		return nil, err
	}
	return usecase.NewRequestEmailChange(usecase.RequestEmailChangePorts{
		Users:        persistence.NewUserRepository(pool),
		Requests:     persistence.NewEmailVerificationRepository(pool),
		Codes:        system.NewVerificationCodeGenerator(),
		Sender:       sender,
		IDs:          system.UUIDGenerator{},
		Clock:        system.Clock{},
		Transactions: persistence.NewTransactionManager(pool),
	}), nil
}

func newVerifyEmailChange(pool *pgxpool.Pool) *usecase.VerifyEmailChange {
	return usecase.NewVerifyEmailChange(usecase.VerifyEmailChangePorts{
		Requests:     persistence.NewEmailVerificationRepository(pool),
		Outbox:       persistence.NewOutboxWriter(pool),
		IDs:          system.UUIDGenerator{},
		Clock:        system.Clock{},
		Transactions: persistence.NewTransactionManager(pool),
	})
}
