# Changelog

All notable changes of `csp-auth-api` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Each change is recorded in the pull request that introduces it.

## [Unreleased]

## [3.0.0] - 2026-10-15

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

### Changed

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

### Fixed

- The container restarts when the database is not ready at start: `restart: on-failure` in `deploy/compose.yml`; on the first `up` of the platform the service started before PostgreSQL answered and stayed stopped (HU-AUTH-003, issue [#84](https://github.com/code-corhuila/csp-auth-api/issues/84)).
- The container image builds again: `deploy/Dockerfile` copies `go.sum` together with `go.mod` before `go mod download`;
  without it `go build` failed with `missing go.sum entry` (HU-AUTH-003, issue
  [#81](https://github.com/code-corhuila/csp-auth-api/issues/81)).

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
