# Changelog

All notable changes of `csp-auth-api` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Each change is recorded in the pull request that introduces it.

## [Unreleased]

Everything below is in `develop`; it is promoted to `qa` and `main` only when it is ordered.

### Added

- HU-AUTH-001, registration (`POST /api/v1/auth/register`):
  domain and use case ([#31](https://github.com/code-corhuila/csp-auth-api/pull/31)),
  PostgreSQL and bcrypt adapters ([#33](https://github.com/code-corhuila/csp-auth-api/pull/33)),
  idempotent registration with `Idempotency-Key` that returns the session
  ([#43](https://github.com/code-corhuila/csp-auth-api/pull/43)),
  the HTTP endpoint ([#44](https://github.com/code-corhuila/csp-auth-api/pull/44)) and
  its wiring to the database in the composition root ([#45](https://github.com/code-corhuila/csp-auth-api/pull/45)).
- HU-AUTH-002, tokens and sessions:
  RS256 access token issuer ([#35](https://github.com/code-corhuila/csp-auth-api/pull/35)),
  `GET /api/v1/auth/jwks` ([#36](https://github.com/code-corhuila/csp-auth-api/pull/36)),
  storage and issuing of refresh tokens ([#40](https://github.com/code-corhuila/csp-auth-api/pull/40)),
  the login use case ([#42](https://github.com/code-corhuila/csp-auth-api/pull/42)),
  `POST /api/v1/auth/login` ([#48](https://github.com/code-corhuila/csp-auth-api/pull/48)) and
  `POST /api/v1/auth/refresh` with single-use rotation ([#49](https://github.com/code-corhuila/csp-auth-api/pull/49)).
- CI job that runs the integration tests against the `csp-auth-db` schema
  ([#37](https://github.com/code-corhuila/csp-auth-api/pull/37)).
- `deploy/compose.yml` passes the service settings from the platform environment
  ([#47](https://github.com/code-corhuila/csp-auth-api/pull/47)).
- HU-AUTH-002, reuse detection of the refresh token (ADR-029, issue [#50](https://github.com/code-corhuila/csp-auth-api/issues/50)):
  a spent token presented again after `APP_AUTH_REFRESH_REUSE_GRACE` seconds (default 10, maximum 60) revokes every active
  refresh token of its user, the revocation is committed although the request fails, a warning is logged without the
  token and the answer stays the same `401 INVALID_REFRESH_TOKEN`.
- Contract tests that validate the real responses of `register`, `login`, `refresh` and `jwks` against `auth-service.yaml`
  (HU-AUTH-001, HU-AUTH-002); the CI job checks out `csp-docs` for the contract
  ([#52](https://github.com/code-corhuila/csp-auth-api/issues/52)).
- HU-AUTH-002, verification of the service credential for the internal operations (ADR-020, ADR-030, issue
  [#32](https://github.com/code-corhuila/csp-auth-api/issues/32)): `SERVICE_SUBJECTS`, the RS256 verifier of service
  tokens, the use case that authorizes a service and the guard that answers `401` and `403`. No route uses it yet.
- HU-AUTH-002, purge of old rows, use case and PostgreSQL adapters (ADR-030, issue
  [#32](https://github.com/code-corhuila/csp-auth-api/issues/32)): outbox events older than 30 days, refresh tokens
  expired or revoked more than 30 days ago and idempotency keys older than 7 days are deleted in that order, at most
  `batchSize` rows in total per call. It needs the `DELETE` grants of `csp-auth-db` V019
  ([#56](https://github.com/code-corhuila/csp-auth-api/pull/56)).
- HU-AUTH-004, the purge also deletes `auth.email_verification` rows whose `expires_at` is more than 7 days in the past,
  verified or not, after the idempotency keys and inside the same `batchSize`; the code is stored in clear, so it is
  not kept longer (ADR-034, ADR-030). It needs the `DELETE` grant of `csp-auth-db` V026; the request and the response do
  not change.
- HU-AUTH-002, `POST /api/v1/auth/internal/maintenance/purge` (ADR-030): the endpoint, protected by the service credential
  ([#54](https://github.com/code-corhuila/csp-auth-api/pull/54)), wired in the composition root.
- HU-AUTH-003, domain and persistence of the role change (ADR-031, issue
  [#60](https://github.com/code-corhuila/csp-auth-api/issues/60)): the user grants and revokes `ADMIN`, never the last
  active administrator (`LAST_ADMIN`); the `ChangeUserRole` use case writes the role and the `UserRoleChanged` outbox
  row in one transaction, only when something changed, and locks the active administrators before it counts them.
  No route uses it yet.
- HU-AUTH-003, authorization of the users by permission (Norma 5.3.7, issue
  [#61](https://github.com/code-corhuila/csp-auth-api/issues/61)): the RS256 verifier of access tokens (signature,
  expiration, issuer `csp-auth` and audience `csp-api`), the `AuthorizeUser` use case and the `requirePermission` guard
  that answers `401` for a missing or invalid token and `403` for a token without the permission. No route uses it yet.
- HU-AUTH-003, `PATCH /api/v1/auth/users/{userId}/role` (ADR-031, issue
  [#62](https://github.com/code-corhuila/csp-auth-api/issues/62)): the administrator grants or revokes `ADMIN`; `400`,
  `401`, `403`, `404` and `409 LAST_ADMIN` as the contract declares them, contract tests against `auth-service.yaml` 1.5.0
  and an end-to-end test that checks the effect at login and refresh. Revoking the only role of a user is
  `409 USER_WITHOUT_ROLES`; `LAST_ADMIN` wins when both rules apply.
- HU-AUTH-003, `GET /api/v1/auth/users` (ADR-031, issue [#63](https://github.com/code-corhuila/csp-auth-api/issues/63)): paged
  search of accounts by email prefix for the administrator, ordered by email and id, with the roles of each user and no
  permissions; contract tests against `auth-service.yaml` 1.5.0 and integration tests of the query. The queries are planned per execution so that the `text_pattern_ops` index
  `idx_app_user_email_pattern` (`csp-auth-db` V023) serves them, and a test checks the plan.
- HU-AUTH-003, list of revoked access tokens (ADR-028, issue
  [#86](https://github.com/code-corhuila/csp-auth-api/issues/86)): the `RevokedTokens` port and its Redis adapter, which
  writes `blacklist:{jti}` with the remaining life of the token and checks it with `EXISTS`; `APP_AUTH_REDIS_URL` and
  `APP_AUTH_REDIS_TIMEOUT` (default 2s, connect, read and write). Integration tests run against Redis 7 with the ACL of
  `auth_app`. No route uses it yet.
- HU-AUTH-003, `POST /api/v1/auth/logout` (ADR-033, issue [#87](https://github.com/code-corhuila/csp-auth-api/issues/87)): the
  `Logout` use case revokes the refresh tokens in PostgreSQL in one transaction (the presented one if it is the user's, or all
  with `allDevices`; an unknown, foreign or revoked one is not an error) and then lists the `jti` of the access token in Redis
  with the remaining life of the token; `204`, `401` and `500` as the contract declares them. The route is enabled only
  with `APP_AUTH_REDIS_URL`. The verified claims now carry the `jti` and the expiration, and a token without `jti` is
  invalid. Contract, integration and end-to-end tests against PostgreSQL and Redis.
- HU-AUTH-003, check of the revoked token list (ADR-033, issue [#88](https://github.com/code-corhuila/csp-auth-api/issues/88)):
  `POST /logout`, `GET /users` and `PATCH /users/{userId}/role` answer `401` for an access token that a logout revoked (before
  judging its permissions), and `GET /users` and `PATCH` role fail closed with `500 INTERNAL_ERROR` and a `WARN` without the token or the `jti` when Redis
  cannot be consulted; `POST /logout` goes on, revokes the refresh tokens and answers `500` when it cannot write the list. Without `APP_AUTH_REDIS_URL` the check is off, which the log says at start.
- This changelog ([#51](https://github.com/code-corhuila/csp-auth-api/pull/51)).
- HU-AUTH-004, domain and use cases of the email change (ADR-034, issue
  [#102](https://github.com/code-corhuila/csp-auth-api/issues/102)): `EmailChangeRequest` (six digits, 15 minutes, 5 wrong
  codes), `VerificationCode`, the `UserEmailChanged` event and the `RequestEmailChange` (3 requests per user per rolling
  hour, code handed to `VerificationCodeSender` inside the transaction) and `VerifyEmailChange` use cases. No route yet.
- HU-AUTH-004, adapters of the email change (ADR-034, issue [#103](https://github.com/code-corhuila/csp-auth-api/issues/103)):
  PostgreSQL repository of `auth.email_verification` (row lock per user, rolling-hour count, supersede, `FOR UPDATE`, savepoint
  for the duplicate email), `UserEmailChanged` outbox row, `crypto/rand` code generator and the first sender of
  the code (replaced by the SMTP sender, see below). No route yet.
- HU-AUTH-004, `PATCH /api/v1/auth/me/email` and `POST /api/v1/auth/me/email/verify` (ADR-034, issue [#104](https://github.com/code-corhuila/csp-auth-api/issues/104)):
  both steps of the email change with the guards of the protected routes (`profile:update:self`, revoked token `401`, list down `500`),
  `400`, `409`, `429` with `Retry-After` and one `400` for every rejected code; wired in the composition root. Contract tests against `auth-service.yaml` 1.6.0 and an end-to-end test against PostgreSQL and Redis.
- HU-AUTH-004, delivery of the email verification code by SMTP (ADR-034, issue [#109](https://github.com/code-corhuila/csp-auth-api/issues/109)):
  `SMTPVerificationCodeSender` (`net/smtp`, plain-text message in Spanish, STARTTLS required unless `APP_AUTH_SMTP_TLS=none`, timeout
  for the whole exchange) and the settings `APP_AUTH_SMTP_HOST`, `_PORT`, `_USER`, `_PASSWORD`, `_FROM`, `_TLS` and `_TIMEOUT`. Without
  `APP_AUTH_SMTP_HOST` the two email change routes are not enabled (`404`, one INFO line at start). A failure of the relay is a `500` and a
  `WARN` with the user id and the class of the error; the code and the address are never logged. `deploy/compose.yml` offers an
  optional Mailpit under the profile `mail`.

### Changed

- The log adapter of the verification code (`LogVerificationCodeSender`) is removed: the code is no longer written in the service log
  (HU-AUTH-004, issue [#109](https://github.com/code-corhuila/csp-auth-api/issues/109)).
- The end-to-end refresh test expires the token with one hour instead of one second, like the persistence tests: the database clock and the Go clock were compared with a one second margin (HU-AUTH-003, issue [#94](https://github.com/code-corhuila/csp-auth-api/issues/94)).
- The persistence integration tests no longer depend on the clock or on the table statistics: the tests that expire a refresh token use one hour instead of one second (the database clock and the Go clock were compared with a one second margin), the test of the email prefix index plans on a table with enough rows inside a rolled back transaction with `SET LOCAL`, and the role change test finds its events by identity instead of by the order of `created_at` (the clock of a database container can step backwards). Found running the suite repeatedly against a fresh PostgreSQL 16 (HU-AUTH-003, issue [#92](https://github.com/code-corhuila/csp-auth-api/issues/92)).
- The contract tests validate every response in full: `auth-service.yaml` 1.4.1 declares the `400`, `423` and `500`
  answers that were listed as undocumented, so the exception list is removed
  ([#52](https://github.com/code-corhuila/csp-auth-api/issues/52)).
- The password is limited to 72 bytes, the limit of bcrypt, and a longer one is a validation error
  ([#39](https://github.com/code-corhuila/csp-auth-api/pull/39)).
- `APP_AUTH_JWT_EXPIRY` and `APP_AUTH_REFRESH_TOKEN_EXPIRY` are integer seconds, as the platform documents
  ([#41](https://github.com/code-corhuila/csp-auth-api/pull/41), [#40](https://github.com/code-corhuila/csp-auth-api/pull/40)).
- A rejected refresh token leaves one warning in the log with the trace id and never the token; two fields of the
  refresh use case are renamed; the comments of `.env.example` and the compose header are corrected
  ([#51](https://github.com/code-corhuila/csp-auth-api/pull/51)).
- HU-AUTH-002, the purge deletes by primary key (ADR-030): `DELETE ... WHERE id = ANY(ARRAY(SELECT ... LIMIT n))`
  replaces `id IN (SELECT ...)`, whose generic plan did a Hash Semi Join with a Seq Scan of the whole table. The
  behaviour is the same (issue [#32](https://github.com/code-corhuila/csp-auth-api/issues/32)).
- HU-AUTH-004, the README says where the SMTP variables go per environment: the relay and its credentials are provided as secrets in qa and main, never versioned, and without `APP_AUTH_SMTP_HOST` the two email change routes answer `404`.

### Fixed

- The container restarts when the database is not ready at start: `restart: on-failure` in `deploy/compose.yml`; on the first `up` of the platform the service started before PostgreSQL answered and stayed stopped (HU-AUTH-003, issue [#84](https://github.com/code-corhuila/csp-auth-api/issues/84)).
- The container image builds again: `deploy/Dockerfile` copies `go.sum` together with `go.mod` before `go mod download`;
  without it `go build` failed with `missing go.sum entry` (HU-AUTH-003, issue
  [#81](https://github.com/code-corhuila/csp-auth-api/issues/81)).
- The email change no longer deadlocks when a request and a correct code race: the verification takes the account lock before the pending request, the order the request already used; an SMTP TLS mode other than `starttls` or `none` is rejected at startup instead of sending in clear (HU-AUTH-004, issue [#111](https://github.com/code-corhuila/csp-auth-api/issues/111)).
- The `429` of `PATCH /api/v1/auth/me/email` answers `Retry-After` with the exact seconds until the oldest request of the rolling hour leaves the window, rounded up and never under 1, instead of a fixed 3600 (HU-AUTH-004, ADR-034).
- An email of more than 255 characters is rejected with `400 VALIDATION_ERROR` on the field `email` (`PATCH /api/v1/auth/me/email` and `POST /api/v1/auth/register`) instead of `500` from the database CHECK; the limit lives in the `Email` value object, which login also uses and keeps answering `401` for it (HU-AUTH-004, issue [#132](https://github.com/code-corhuila/csp-auth-api/issues/132)).
- `PATCH /api/v1/auth/me/email` answers `401 UNAUTHORIZED` instead of `500` when the token is valid but its account does not exist or was deleted, and logs no error for it (HU-AUTH-004, issue [#133](https://github.com/code-corhuila/csp-auth-api/issues/133)).
- `PATCH /api/v1/auth/me/email` has a bulkhead: at most `APP_AUTH_EMAIL_CHANGE_MAX_CONCURRENCY` requests (default 4) run at once and a request waits at most `APP_AUTH_EMAIL_CHANGE_QUEUE_TIMEOUT` (default 1s) for a slot; otherwise it answers `429 RATE_LIMITED` with `Retry-After: 1` before opening a transaction, so a slow SMTP relay no longer starves the pool and the other routes (HU-AUTH-004, ADR-034, norm 5.3.10, issue [#134](https://github.com/code-corhuila/csp-auth-api/issues/134)).

## Before the changelog

- Base scaffold: governance files, Go module and hexagonal packages, CI workflow, Dockerfile and compose file, and the
  domain model (`User`, `Email`, `Role`).
  ([#1](https://github.com/code-corhuila/csp-auth-api/pull/1) to [#5](https://github.com/code-corhuila/csp-auth-api/pull/5))
- Phone and address contact data of the user aggregate
  ([#10](https://github.com/code-corhuila/csp-auth-api/pull/10)) and tests of the composition root and the user accessors
  ([#15](https://github.com/code-corhuila/csp-auth-api/pull/15), [#16](https://github.com/code-corhuila/csp-auth-api/pull/16)).
- Promotions to `qa`: [#6](https://github.com/code-corhuila/csp-auth-api/pull/6) to
  [#9](https://github.com/code-corhuila/csp-auth-api/pull/9), [#11](https://github.com/code-corhuila/csp-auth-api/pull/11),
  [#14](https://github.com/code-corhuila/csp-auth-api/pull/14) and [#17](https://github.com/code-corhuila/csp-auth-api/pull/17).
- Promotions to `main`: release `0.1.0` ([#12](https://github.com/code-corhuila/csp-auth-api/pull/12)) and release `0.1.1`
  ([#13](https://github.com/code-corhuila/csp-auth-api/pull/13)).
