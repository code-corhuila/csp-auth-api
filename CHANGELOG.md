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
- This changelog ([#51](https://github.com/code-corhuila/csp-auth-api/pull/51)).

### Changed

- The password is limited to 72 bytes, the limit of bcrypt, and a longer one is a validation error
  ([#39](https://github.com/code-corhuila/csp-auth-api/pull/39)).
- `APP_AUTH_JWT_EXPIRY` and `APP_AUTH_REFRESH_TOKEN_EXPIRY` are integer seconds, as the platform documents
  ([#41](https://github.com/code-corhuila/csp-auth-api/pull/41), [#40](https://github.com/code-corhuila/csp-auth-api/pull/40)).
- A rejected refresh token leaves one warning in the log with the trace id and never the token; two fields of the
  refresh use case are renamed; the comments of `.env.example` and the compose header are corrected
  ([#51](https://github.com/code-corhuila/csp-auth-api/pull/51)).

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
