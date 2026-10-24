# Changelog

All notable changes of `csp-auth-api` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Each change is recorded in the pull request that introduces it.

## [Unreleased]

Everything below is in `develop`; it is promoted to `qa` and `main` only when it is ordered.

### Changed

- The access token lives 15 minutes by default: `APP_AUTH_JWT_EXPIRY` defaults to 900 seconds (it was 3600; the range 1 to 3600 stays), so `expiresIn` is 900
  and a signed-out user or a demoted administrator keeps a valid token in the other services for at most 15 minutes (ADR-054, contract 1.12.0).
  `.env.example` and the README say so. Configuration test of the default.

### Added

- The `ADMIN` role holds `concessions:inventory:read`, the permission that `GET /stock/movements` of `concessions-service.yaml` requires (HU-CONCESSIONS-007);
  the token of an `ADMIN` carries it in `permissions` after the next login or refresh. Test of the permissions of each role.
- `GET /api/v1/auth/jwks` answers `Cache-Control: public, max-age=300` (contract 1.11.0, ADR-053): the key changes only in a coordinated
  rotation, so a copy kept by a browser, a proxy or a tool is stale for at most five minutes. Handler test and contract test (the contract
  declares the header and the test checks that the response carries it).

- HU-AUTH-007, change of the own password (ADR-051), the endpoint: `POST /api/v1/auth/me/password` (`profile:update:self`, no
  `Idempotency-Key`, body at most 4 KiB with no unknown property) answers `200` with the `AuthResponse` of a fresh session. A wrong current
  password is `400 VALIDATION_ERROR` on `currentPassword` (`The current password is incorrect`), never `401`; a new password equal to the current
  one is `400` on `newPassword` (`The new password must differ from the current one`); the 5th wrong password of a user in 15 minutes locks the
  change for 15 minutes (`429` with `Retry-After`, before the password is verified); a request without a free slot of the bulkhead is `429` with
  `Retry-After: 1`. No event is published. The bodies of the routes of the own account share one reader of their properties.
- HU-AUTH-007, change of the own password (ADR-051), adapters and settings: `PasswordChangeAttempts` over Redis under
  `attempts:pwd:{userId}` and `locked:pwd:{userId}`, bounded by the circuit breaker of ADR-048, which is now shared with the login limiter;
  `LockPasswordHashOf` on the user repository (`FOR NO KEY UPDATE`); and the settings `APP_AUTH_PASSWORD_CHANGE_MAX_ATTEMPTS`, `_WINDOW`,
  `_LOCK`, `_MAX_CONCURRENCY` and `_QUEUE_TIMEOUT`, validated at start-up (`.env.example`, `deploy/compose.yml`).
- HU-AUTH-007, change of the own password (ADR-051), domain and use case: `CheckPresentedPassword` (a current password is 1 to 72 bytes
  and is not judged by the password policy), `ErrWrongCurrentPassword`, the lock error `PasswordChangeRateLimitedError` and the policy of
  5 wrong passwords in 15 minutes, the `ChangePassword` use case and the output ports `PasswordChangeAttempts` and `PasswordHashLocker`. In one
  transaction it locks the account, verifies the current password, refuses a new password equal to it, replaces the hash, revokes every
  refresh token of the user and opens a new session; only a wrong current password counts against the limit, and the limit fails open when
  its store cannot be reached.
- HU-AUTH-007, own profile (ADR-051), the endpoints: `GET /api/v1/auth/me` (`profile:read:self`) returns `id`, `email`, `name`, `phone`,
  `address` and `roles` read from the database (`phone` and `address` are `null` for an account created before they existed) and
  `PATCH /api/v1/auth/me` (`profile:update:self`) edits `name`, `phone` and `address`: all optional, at least one, a `null` field, an empty body
  and an unknown field are `400 VALIDATION_ERROR` naming the field, and the accepted fields are written in one `UPDATE`. A token of an
  account that is gone or locked is `401`; the body is at most 4 KiB; no `Idempotency-Key`, no event. The user repository implements
  `ProfileUpdater` and the routes are wired in the composition root.
- HU-AUTH-007, own profile (ADR-051), domain and use cases: the `ProfileChange` value object, which applies the rules of
  registration to the fields that were sent (a field that was not sent keeps its value, an empty edit is refused and every invalid
  field is reported together), the inbound ports `GetProfile` and `UpdateProfile` with their use cases, and the output port
  `ProfileUpdater`. A locked account or one that is gone is refused with `ErrUserLocked` or `ErrUserNotFound`.
- HU-AUTH-003, scenario 4 (ADR-031, amendment 2026-10-24): removing the `ADMIN` role of a user ends their sessions. In the transaction of
  the role change `ChangeUserRole` revokes every active refresh token of the target; after the commit it writes
  `blacklist:user:{userId}` (epoch second of the revocation, `EX 3600`) through the new `UserSessionRevocations` port, implemented by the
  Redis revoked list. `AuthorizeUser` reads that marker on every protected route and answers `401` when the `iat` of the token is less
  than or equal to it; a failed read fails closed with `500`, a failed write answers `500` with an `ERROR` after the commit. The access token
  verifier now returns `iat` (`AccessClaims.IssuedAt`) and rejects a token without it; the issuer already wrote it. Granting, a no-op revoke and the
  `LAST_ADMIN` and `USER_WITHOUT_ROLES` refusals end nothing. No new event, no schema change, no change in the ACL of `auth_app`.
- HU-AUTH-006, password reset (ADR-050, amendment 2026-10-24): `POST /api/v1/auth/reset-password` refuses a new password equal to the
  current one with `400 VALIDATION_ERROR` (`details[0].field` `password`, message `The new password must differ from the current one`).
  The comparison runs inside the transaction through `PasswordHasher.Verify`, only after the token proved valid, so the `401 INVALID_TOKEN`
  cases do not depend on the password; the token is not consumed, no hash is written and no session is revoked. The new
  `CurrentPasswordReader` port reads the stored hash. Only the current password is checked: there is no password history.
- HU-AUTH-006, password reset (ADR-050), the endpoints: `POST /api/v1/auth/forgot-password` (always `202` without body, the same for an
  active, unknown, inactive or over-limit account) and `POST /api/v1/auth/reset-password` (`204`, or `401 INVALID_TOKEN`; it consumes the token,
  replaces the hash and revokes every refresh token in one transaction). Each route has its own bulkhead and a 4 KiB body limit, and without
  the SMTP host or `APP_AUTH_PASSWORD_RESET_URL` both answer the `404` of the contract. The three variables are in `.env.example`,
  `deploy/compose.yml` and the README.
- HU-AUTH-006, password reset (ADR-050), delivery and settings: `SMTPPasswordResetSender`, the adapter of the new `PasswordResetSender` port, which
  only queues the message (a bounded in-memory queue, two workers) so the latency or the failure of the relay cannot change the answer of
  the request, and sends the link `<APP_AUTH_PASSWORD_RESET_URL>#token=<token>` in a plain-text message in Spanish. The SMTP exchange and the
  message layout are now shared with the email verification code. New settings `APP_AUTH_PASSWORD_RESET_URL`,
  `APP_AUTH_PASSWORD_RESET_MAX_CONCURRENCY` and `APP_AUTH_PASSWORD_RESET_QUEUE_TIMEOUT`, validated at start-up.
- HU-AUTH-006, password reset (ADR-050), adapters: `PasswordResetRepository` over `auth.password_reset` (requests locked per user, a new
  request supersedes the pending one by soft delete, the token locked by its digest after the account), `UpdatePasswordHash` on the user
  repository, the `ResetTokenGenerator` and the purge of password resets that expired more than 7 days ago (ADR-030 extended).
- HU-AUTH-006, password reset (ADR-050), domain and use cases: the `ResetToken` value object (a UUID of which only the SHA-256
  digest is stored), the `PasswordReset` entity (one hour, single use, three requests per user in a rolling hour), the inbound
  ports `RequestPasswordReset` and `ResetPassword` and their use cases. A request does the same work for any email and sends the
  link after the commit; a reset consumes the token, replaces the hash and revokes every refresh token of the user in one transaction.
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
- HU-AUTH-005, domain and use case of the login attempt limit (issue [#126](https://github.com/code-corhuila/csp-auth-api/issues/126)):
  `LoginAttemptPolicy` (10 failures in 5 minutes, 5-minute lock), `LoginRateLimitedError` with the time left, the `LoginAttempts` port
  and `ClientIP` in the login command. The login rejects a locked address before checking the password, counts only wrong credentials,
  clears the count on success and goes on with a `WARN` when the store fails. Not reachable yet: the composition root passes a no-op
  store until the Redis adapter and the `429` answer arrive.
- HU-AUTH-005, Redis adapter of the login attempt limit (issue [#127](https://github.com/code-corhuila/csp-auth-api/issues/127)):
  `LoginAttempts` over `attempts:{ip}` (`INCR`, `EXPIRE` for the window) and `locked:{ip}` (`SET` with the lock time, `TTL`), `DEL` of the
  counter on success and when the lock is written; only commands of the `auth_app` ACL. Integration tests against Redis 7 with that ACL.
- HU-AUTH-005, `429 RATE_LIMITED` on `POST /api/v1/auth/login` (ADR-040, issue [#128](https://github.com/code-corhuila/csp-auth-api/issues/128)):
  10 failed logins from one client address in 5 minutes reject the next attempt, with `Retry-After` set to the seconds left of the 5-minute
  lock, even with the right credentials; the address is the last entry of `X-Forwarded-For`. New `APP_AUTH_LOGIN_MAX_ATTEMPTS`,
  `APP_AUTH_LOGIN_WINDOW` and `APP_AUTH_LOGIN_LOCK`. Without Redis the login is not limited and with Redis down it goes on with a `WARN`.
  Contract, end-to-end and wiring tests.
- HU-AUTH-005, bounded latency of the login limiter when Redis fails (ADR-048, issue [#139](https://github.com/code-corhuila/csp-auth-api/issues/139)):
  each call of the limiter waits at most `APP_AUTH_LOGIN_LIMIT_TIMEOUT` (300ms, at most 5s) and, after a failure, the limiter is not called
  for `APP_AUTH_LOGIN_LIMIT_PAUSE` (10s, at most 5m), so a login no longer takes 4 to 6 seconds while Redis is down. One `WARN` per pause;
  the Redis client now honours the deadline of a call (`ContextTimeoutEnabled`). Unit tests with a blocking store and a Redis that hangs.

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

- HU-AUTH-003, `PATCH /api/v1/auth/users/{userId}/role` (ADR-031) no longer loses the marker that ends the sessions of a user who lost `ADMIN`
  when the client disconnects after the commit: the change runs on the context detached from the cancellation of the request, with the
  10 second deadline shared with the sign out (`detachedFromClient`), so `blacklist:user:{userId}` is written and the old access tokens are `401`.

- HU-AUTH-003, `POST /api/v1/auth/logout` (ADR-033) no longer loses the revocation when the client disconnects: the browser that navigates away
  right after the click cancelled the request, the use case failed with `context canceled`, the refresh tokens stayed active and the session
  came back. The use case now runs on a context detached from the cancellation of the request, which keeps its values and is bounded by a
  10 second deadline; the answer on Redis down is unchanged (`500` after the commit, the retry is idempotent).

- The bulkhead unit tests no longer depend on the speed of the machine (HU-AUTH-004, issue [#134](https://github.com/code-corhuila/csp-auth-api/issues/134)): `TestRequestEmailChangeIsRefusedWith429BeforeTheUseCaseWhenNoSlotIsFree` failed under load because it asserted an answer in under 1 second, and the other two upper bounds of 1 second of the file had the same flaw. They now use a guard of 30 seconds that only catches a call that is stuck, and the contract check runs last so the other checks also run when the contract file is not set.
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
