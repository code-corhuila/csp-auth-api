# csp-auth-api

> auth bounded context: service API

Part of the **Cinesync Platform** distributed system — team `cinesync-platform`, Group 1.
Governance and documentation live in [`csp-docs`](https://github.com/code-corhuila/csp-docs).

## Purpose

`csp-auth-api` is the service of the **auth** domain: registration, login, JWT issuance (RS256), refresh tokens,
JWKS publication and roles. It is the authoritative owner of the `User` and `Role` entities; the other services
verify the tokens it issues on their own.

The repository currently holds the **base scaffold only**. The service has the health routes and a typed domain
skeleton, and is built in small steps; each step is a Pull Request that leaves the repository coherent.

## Stack

| Item | Decision | Record |
|---|---|---|
| Language | Go 1.22, module `github.com/code-corhuila/csp-auth-api`, standard library `net/http` router | [ADR-015](https://github.com/code-corhuila/csp-docs/blob/main/05-architecture/decisions/records/ADR-015-auth-go-postgresql-flyway.md) |
| Layout | Hexagonal, Annex C of the norm: `internal/domain`, `internal/application`, `internal/adapter`, `cmd/auth-api` | Norma 5.3 |
| Database | PostgreSQL, schema `auth`, owned by `csp-auth-db`; Redis for the token blacklist | ADR-015 |
| Events | The API writes the outbox; `csp-worker` relays it with read-only access | [ADR-019](https://github.com/code-corhuila/csp-docs/blob/main/05-architecture/decisions/records/ADR-019-outbox-relay-read-only-for-other-domains.md) |

## Rules of this repository

- **No migration here.** There is no migration library in this repository, and nothing runs at startup to change
  the database structure (Norma 5.2.1). Structure and migrations live in `csp-auth-db`.
- **The domain depends on nothing.** `internal/domain/model` imports only the standard library, never a framework
  or a driver. Dependencies point inward.
- **Only the approved contract is implemented.** The contract is `auth-service.yaml` in `csp-docs`; a route that is
  not in it is not added.
- **The API never connects to RabbitMQ.** `csp-worker` relays the outbox.
- **Explicit limits.** Server timeouts, pool sizes and expiries are configuration, with a default (Norma 5.3.10).

## Related repositories

| Repository | Relation |
|---|---|
| `csp-auth-db` | Owns the auth database structure and its migrations |
| `csp-auth-portal` | Portal that consumes this API |
| `csp-docs` | Governance, contracts, data model and ADRs |
| `csp-worker` | Relays the auth outbox |
| `csp-api-gateway` | The only entry point from outside the platform |

## Build, test and run

Requirements: Go 1.22 (or Docker).

```bash
go build ./...                       # compile every package
go vet ./...                         # static checks
test -z "$(gofmt -l .)"              # formatting: the list must be empty
go test ./...                        # run every test
go run ./cmd/auth-api                # starts on PORT, 8081 by default
```

The HTTP adapter has contract tests (`internal/adapter/in/httpapi/contract_test.go`): the real handlers answer through
fakes of the use cases and every response of `POST /register`, `/login`, `/refresh` and `GET /jwks` is validated against
`auth-service.yaml` (status, declared headers and body schema). The contract lives in `csp-docs`, so point
`AUTH_CONTRACT_FILE` at it. Without the variable they are skipped on a workstation; in CI (`CI` set) they fail instead:

```bash
AUTH_CONTRACT_FILE=../csp-docs/07-api/contracts/openapi/auth-service.yaml go test ./internal/adapter/in/httpapi/
```

Every status the service answers is declared by the contract (1.4.1 or later), so every response is validated in full.

The PostgreSQL adapter has integration tests behind the `integration` build tag. They need a database with the
`csp-auth-db` migrations applied and are skipped when `AUTH_TEST_DATABASE_URL` (login `auth_app`) is not set;
`AUTH_TEST_OUTBOX_READER_URL` (login `worker_app`) enables the outbox payload test. The tests that count or retire the
administrators take an advisory lock (key 3013), because the database is shared by all the packages:

```bash
go test -tags integration ./internal/adapter/out/persistence/
```

The Redis adapter (`internal/adapter/out/redis`) has integration tests with the same tag. They need the Redis 7 of
`csp-infra-redis` with its ACL (`auth_app`: `+get +set +exists +incr +expire +ttl +del +ping` on `~attempts:* ~locked:*
~blacklist:*`) and are skipped when `AUTH_TEST_REDIS_URL` is not set. They check that the list expires with the token, that
the key is `blacklist:{jti}`, that the login attempt store (`attempts:{ip}` for the window, `locked:{ip}` for the lock) counts, locks
and expires as the policy says, that the ACL allows exactly the commands the adapters use, and that an unreachable Redis is an error:

```bash
AUTH_TEST_REDIS_URL=redis://auth_app:<password>@localhost:6379/0 go test -tags integration ./internal/adapter/out/redis/
```

With the service running:

```bash
curl http://localhost:8081/api/v1/auth/health          # {"status":"ok"}
curl http://localhost:8081/api/v1/auth/health/ready    # {"status":"ready","dependencies":{}}
```

`POST /api/v1/auth/register` (HU-AUTH-001) is served by the real use case when **both** `APP_AUTH_DATABASE_URL`
and a signing key (`APP_AUTH_JWT_PRIVATE_KEY` or `APP_AUTH_JWT_PRIVATE_KEY_FILE`) are set. Without a database URL the
service starts as before (health, and `/jwks` when a key is set). A database URL without a signing key, an invalid pool
setting or a database that does not answer stops the service at startup. The pool is closed on shutdown.

`GET /api/v1/auth/jwks` publishes the public key that verifies the tokens, with the `kid` of their header. The services do not read it: they
receive the key as configuration (`JWT_PUBLIC_KEY`, norm 5.3.7). The response carries `Cache-Control: public, max-age=300`, so whoever caches
it holds a stale key for at most five minutes after a rotation (runbook of the auth service, section 4; ADR-053).

To run it with the database:

1. Start the PostgreSQL instance of `csp-infra-postgres` and apply the migrations with the executor of `csp-auth-db`
   (`docker compose -f deploy/compose.yml --env-file .env --profile tooling run --rm auth-db-migrate`, see its README).
   The service connects as `auth_app`, never as the executor user.
2. Export the variables (names only here, see `.env.example`; never commit values):
   `APP_AUTH_DATABASE_URL` (login `auth_app`, `search_path=auth`), `APP_AUTH_JWT_PRIVATE_KEY_FILE` (RSA key, PEM)
   and, optionally, `APP_AUTH_BCRYPT_ROUNDS`, `APP_AUTH_JWT_EXPIRY` (default 900 seconds, 15 minutes, ADR-054), `APP_AUTH_REFRESH_TOKEN_EXPIRY`, `APP_AUTH_REFRESH_REUSE_GRACE` and the
   `APP_AUTH_DATABASE_*` pool limits.
3. `go run ./cmd/auth-api` and register:

```bash
curl -i -X POST http://localhost:8081/api/v1/auth/register   -H 'Content-Type: application/json'   -H "Idempotency-Key: $(uuidgen)"   -d '{"email":"ada@example.com","password":"<a password of 8 to 72 bytes>","name":"Ada Lovelace"}'
```

It requires the `Idempotency-Key` header and a JSON body of at most 1 MiB; it answers `201` with the tokens and the
user, `200` with the user alone on a replay, `400` with one `details` entry per invalid field, and `409` when the
email is registered or the key was used by another request. `X-Correlation-Id` is echoed or generated.

`POST /api/v1/auth/login` (HU-AUTH-002) is enabled by the same two settings as `/register`:

```bash
curl -i -X POST http://localhost:8081/api/v1/auth/login   -H 'Content-Type: application/json'   -d '{"email":"ada@example.com","password":"<the password chosen at registration>"}'
```

It requires a JSON body of at most 1 MiB with `email` and `password`, and answers `200` with the tokens and the user
(`Cache-Control: no-store`). A missing or empty field is `400`; an unknown or malformed email and a wrong password get
the same `401` (`INVALID_CREDENTIALS`), and a locked account gets `423` (`ACCOUNT_LOCKED`) only when the password is
right. With Redis, 10 failed logins from the same client address in 5 minutes lock that address for 5 minutes (HU-AUTH-005, ADR-040):
the next attempt is `429` (`RATE_LIMITED`) with `Retry-After` set to the seconds left, **whether or not the credentials are right**, and
after the cooldown the right credentials authenticate normally. See "Login attempt limit".

`POST /api/v1/auth/refresh` (HU-AUTH-002) is enabled by the same two settings and renews a session:

```bash
curl -i -X POST http://localhost:8081/api/v1/auth/refresh   -H 'Content-Type: application/json'   -d '{"refreshToken":"<the refresh token of the last login or refresh>"}'
```

It requires a JSON body of at most 1 MiB with `refreshToken` and answers `200` with a new pair and the user
(`Cache-Control: no-store`). The presented token is spent in the same transaction that issues the new one, so a token
works once and a failure while issuing leaves it valid. An unknown, expired or already used token gets the same `401`
(`INVALID_REFRESH_TOKEN`). A locked account gets `423`, a missing or empty `refreshToken` gets `400`.

Reuse detection (ADR-029): a token that was already used and is presented again more than
`APP_AUTH_REFRESH_REUSE_GRACE` seconds after (default 10, maximum 60) ends every active session of its user. The
revocation is committed although the request fails, one `WARN` with the user id and the id of the token row is logged
(never the token), and the answer is the same `401` as for any other rejected token. Inside the window the presentation
is taken as a concurrent refresh and nothing else is revoked; unknown and expired tokens never revoke anything.

`PATCH /api/v1/auth/users/{userId}/role` (HU-AUTH-003, ADR-031) is enabled by the same two settings and lets an administrator
grant or revoke the `ADMIN` role. It is protected by the access token of the caller (RS256, `iss` `csp-auth`, `aud` `csp-api`, not
expired), which must hold the permission `user:role:update`:

```bash
curl -i -X PATCH http://localhost:8081/api/v1/auth/users/<userId>/role -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' -H "Idempotency-Key: $(uuidgen)" -d '{"role":"ADMIN","enabled":true}'
```

It answers `200` with the user after the change; a missing or invalid token is `401`, a token without the permission `403`, an
invalid `userId`, `Idempotency-Key` or body `400`, an unknown user `404` and the revoke of the last active administrator `409`
(`LAST_ADMIN`), as is revoking the only role of a user (`USER_WITHOUT_ROLES`; `LAST_ADMIN` wins when both apply). Asking for the state the user already has is a `200` that writes nothing and publishes no event, so the operation
is idempotent by itself; the `Idempotency-Key` is validated but not stored. A real change writes the `UserRoleChanged` outbox row in the
same transaction. The roles are read again from the database at login and at refresh, so a grant reaches the user at their next
token; a token already issued keeps its roles until it expires.

**Removing `ADMIN` ends the sessions of the user** (ADR-031, amendment 2026-10-24). When a revoke changes something (not a grant, not a
no-op, not a `LAST_ADMIN` or `USER_WITHOUT_ROLES` refusal) every active refresh token of the target is revoked in the same transaction
as the role and the outbox row, and after the commit the service writes `blacklist:user:{userId}` in Redis (see
[Revoked access tokens](#revoked-access-tokens)). From then the access tokens of the user issued at or before that second are `401` on
every route that reads the revoked list, and their refresh tokens are `401 INVALID_REFRESH_TOKEN`; a new login gives a session with
only `CLIENT`. An administrator who revokes their own `ADMIN` (while others exist) gets `200` and the next call is `401`. If the
marker cannot be written the answer is `500 INTERNAL_ERROR` and an `ERROR` is logged, although the role and the refresh tokens are
already changed; repeating the call is a no-op `200` that does not write the marker. Without `APP_AUTH_REDIS_URL` only the refresh
tokens are revoked. No new event is published.

The change does not depend on the client either: it runs on the same detached context as the sign out (bounded by `detachedDeadline`),
so a client that leaves between the commit and the write of the marker cannot leave the old access tokens of the user alive.

`GET /api/v1/auth/users` (HU-AUTH-003, ADR-031) is enabled by the same settings and has the same guard: the permission `user:role:update`.
It lists the accounts so an administrator can find the one to change:

```bash
curl -i "http://localhost:8081/api/v1/auth/users?email=maria&page=1&limit=20" -H "Authorization: Bearer $ACCESS_TOKEN"
```

`email` is a case-insensitive **prefix** of 1 to 254 characters (`%`, `_` and `\` are ordinary characters); `page` starts at 1 and `limit`
is 1 to 100 (default 20). The answer is `{data, meta}` with `id`, `email`, `name` and `roles` of each user, without permissions,
ordered by email and then id; soft-deleted accounts are not listed. An invalid parameter is `400`, a missing or invalid token `401` and a
token without the permission `403`. The prefix match is `LIKE 'prefix%'`, which a `text_pattern_ops` index on `auth.app_user (email)`
serves (`idx_app_user_email_pattern`, migration V023 of `csp-auth-db`, which the integration tests need). The two statements run with
`pgx.QueryExecModeExec`, so each one is planned with its prefix and a generic plan never replaces it.

`POST /api/v1/auth/logout` (HU-AUTH-003, ADR-033) ends the session of the caller. It needs a valid access token (any role) and
**`APP_AUTH_REDIS_URL`**: without it the route is not enabled (`404`, and the log says so). The body is optional:

```bash
curl -i -X POST http://localhost:8081/api/v1/auth/logout -H "Authorization: Bearer $ACCESS_TOKEN"   -H 'Content-Type: application/json' -d '{"refreshToken":"'"$REFRESH_TOKEN"'","allDevices":false}'
```

With `allDevices: true` every active refresh token of the user is revoked; otherwise only `refreshToken`, if it is sent and
belongs to the user. A refresh token that is unknown, another user's or already revoked does not fail the call and revokes
nothing. The refresh tokens are revoked in PostgreSQL in **one transaction that is committed first**; then `jti` of the access
token is written to Redis (`blacklist:{jti}`, `SET` with a ttl of its remaining life, at least one second) and the answer is `204`.
If Redis cannot be written the answer is `500 INTERNAL_ERROR` although the refresh tokens are already revoked: the client repeats
the call, which is idempotent. A missing or invalid access token is `401`. The list is read on the protected routes too (below).

The revocation survives the client: a browser that navigates away right after the click cancels its request, and the refresh tokens must
not stay alive for that. The use case runs on a context that keeps the values of the request (trace id) but not its cancellation, bounded by
a fixed deadline of 10 seconds (`detachedDeadline`, norm 5.3.10); the bearer token and the body are still read on the request context.

`PATCH /api/v1/auth/me/email` and `POST /api/v1/auth/me/email/verify` (HU-AUTH-004, ADR-034) change the email of the caller in two
steps. Both need an access token that holds `profile:update:self` (any signed-in user) and an `Idempotency-Key` of 8 to 128
characters. The request step stores its key (below); the verification only validates it, because it creates nothing. The account is always the one in the token, and the routes are enabled by the same
two settings as the other protected routes **and by `APP_AUTH_SMTP_HOST`**: without it the two routes answer `404` and the start-up
log says so once (see [Email delivery](#email-delivery-smtp)).

```bash
curl -i -X PATCH http://localhost:8081/api/v1/auth/me/email -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' -H "Idempotency-Key: $(uuidgen)" -d '{"email":"new.address@example.com"}'
curl -i -X POST http://localhost:8081/api/v1/auth/me/email/verify -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' -H "Idempotency-Key: $(uuidgen)" -d '{"verificationCode":"012345"}'
```

The request normalizes the address to lower case and answers `202` with no body: the code is never in the response. An invalid address
is `400`, an address used by any active account (the own one included) is `409 EMAIL_ALREADY_REGISTERED`, and the fourth request of a
user in a rolling hour (superseded ones count) is `429 RATE_LIMITED` with `Retry-After: 3600`; `429` with `Retry-After: 1` also means
that the service is busy sending other codes (bulkhead, see [Email delivery](#email-delivery-smtp)). A new request with a new key replaces the
pending one.

The key of the request is stored (Norma 5.3.8, ADR-034) in `auth.email_change_idempotency_key` with the SHA-256 of the user id and the normalised
new address, linked to the pending request and in the same transaction as it. It is recorded only when a request is really created: a `409
EMAIL_ALREADY_REGISTERED` or a `429` leaves no key. The same key with the same address, by the same user, is a replay: `202` again, nothing is
created or sent, and it does not count against the limit of three per hour. The same key with another address, or by another user, is `409
IDEMPOTENCY_KEY_CONFLICT`. The account row is locked first, so two concurrent requests of one user with the same key are one replay; the same key
from two users loses on the unique key before anything is sent and answers the conflict. Keys are purged after seven days.
The code has six digits (`crypto/rand`, leading zeros kept), lasts 15 minutes and is handed to the `VerificationCodeSender` port
inside the transaction of the request. The adapter is `SMTPVerificationCodeSender` (ADR-034): it sends one plain-text message in Spanish
through the SMTP relay and nowhere else. If the relay fails the request is rolled back and the answer is `500`; the user asks again.

The verification answers `204` when the code is right: in one transaction the email of the account changes, `email_verified` becomes
true, the request is consumed and `UserEmailChanged` (user id and new email only) is written to the outbox. A malformed code, no pending
request, an expired or exhausted request and a wrong code all answer the same `400 VALIDATION_ERROR`. Each wrong code is counted
and the count is committed although the answer is `400`; the fifth one retires the request. The comparison is in constant time. If
another account took the address meanwhile the answer is `409 EMAIL_ALREADY_REGISTERED`, the request is invalidated and no event is
written. No session is revoked by the change. The tables are those of `csp-auth-db` V024 and V025, and V036 to V040 for the key.

### Issuing a service credential (`cmd/auth-token`, ADR-052)

The credential of a service is issued by this service's own offline command, not by an endpoint. The owner of the environment runs it where the
private key already is, with the same variables as the service (`APP_AUTH_JWT_PRIVATE_KEY` or `APP_AUTH_JWT_PRIVATE_KEY_FILE`):

```bash
docker run --rm --entrypoint auth-token -e APP_AUTH_JWT_PRIVATE_KEY_FILE=/keys/jwt-private.pem   -v "$PWD/keys:/keys:ro" -v "$PWD/out:/out" csp-auth-api -subject csp-worker -lifetime 2160h -out /out/token.txt
```

The subject must be `csp-worker`, `booking-service` or `csp-workflow` (never a user id); the lifetime is at most 2160h (90 days, the default). The token
(`sub`, `iss` `csp-auth`, `aud` `csp-internal`, `iat`, `exp`, `jti`, and the `kid` in the header) is written only to the file, created with mode `0600`
and not replaced without `-force`. Stdout stays empty; one line on stderr records the subject, the `jti`, the expiry and the file, never the token or the key.

Internal operations (ADR-020) accept a **service credential**: an RS256 token signed with the key of this service,
with `exp` and a `sub` and sent as `Authorization: Bearer`. A missing or invalid token gets `401 UNAUTHORIZED` and a
valid token whose `sub` is not in `SERVICE_SUBJECTS` (comma-separated, empty by default so that no service is allowed)
gets `403 FORBIDDEN`. Issuer and audience are not required. The service has no endpoint that issues these tokens: the
owner issues them with `auth-token` (above) and loads them as environment secrets, and `csp-infra-postgres/scripts/dev-token.sh <sub> <minutes>` writes one for
development. The first internal operation is the purge of old rows.

The purge of old rows (ADR-030) deletes, in this order, outbox events older than 30 days, refresh tokens that expired
or were revoked more than 30 days ago, idempotency keys older than 7 days, email change requests (`auth.email_verification`)
that expired more than 7 days ago, verified or not, and the password resets that expired more than 7 days ago, then the keys of
`forgot-password` (`auth.password_reset_idempotency_key`) older than 7 days and those of the email change
(`auth.email_change_idempotency_key`) older than 7 days, at most `batchSize` rows (1 to 500) in total per call; it needs the
`DELETE` grants of migrations V019, V026, V035 and V040 of `csp-auth-db` for `auth_writer`.

`POST /api/v1/auth/internal/maintenance/purge` (HU-AUTH-002) runs it. It is enabled by the same two settings as
`/register`, is not routed by the gateway and is called by `csp-worker` with its service credential (`sub` in
`SERVICE_SUBJECTS`):

```bash
curl -i -X POST http://localhost:8081/api/v1/auth/internal/maintenance/purge   -H "Authorization: Bearer $(cat "$AUTH_SERVICE_TOKEN_FILE")"   -H 'Content-Type: application/json'   -d '{"batchSize":100}'
```

The body is optional and `batchSize` is 1 to 500 (default 100, otherwise `400`). It answers `200` with
`{"processedCount":N,"hasMore":true|false}`: the rows deleted in this call over the seven tables and whether any
eligible row is left, so the caller repeats it until `hasMore` is `false`. A repeated call is safe. After the purge of an
`Idempotency-Key`, the same registration answers `409 EMAIL_ALREADY_REGISTERED` instead of the `200` replay. A missing or
invalid token is `401` and a valid token of another subject is `403`.

The end-to-end tests of these routes (`cmd/auth-api`, tag `integration`) uses the same `AUTH_TEST_DATABASE_URL`:

```bash
go test -tags integration ./...
```

With Docker, from the root of the repository:

```bash
docker build -f deploy/Dockerfile -t csp-auth-api .
docker run --rm -p 8081:8081 csp-auth-api
```

The service stops gracefully on `SIGINT` and `SIGTERM`. In the platform, `csp-infra` includes `deploy/compose.yml`,
which exposes the port on the `platform` network without publishing it: only the gateway reaches the service.
Copy `.env.example` to `.env` for local values and never commit `.env`. The file lists first the variables the
service reads (HTTP, database, bcrypt, tokens and Redis).

## Own profile

`GET /api/v1/auth/me` and `PATCH /api/v1/auth/me` (HU-AUTH-007, ADR-051) read and edit the personal data of the caller. They need an
access token that holds `profile:read:self` and `profile:update:self` respectively (granted to `CLIENT` and `ADMIN`), take no
`Idempotency-Key` and are enabled by the same two settings as the other protected routes (a signing key and a database). The account is
always the one in the token: no id travels in the path or in the body.

```bash
curl -i http://localhost:8081/api/v1/auth/me -H "Authorization: Bearer $ACCESS_TOKEN"
curl -i -X PATCH http://localhost:8081/api/v1/auth/me -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' -d '{"name":"Maria Garcia","address":"Calle 1 # 2-3"}'
```

`GET` answers `200` with `id`, `email`, `name`, `phone`, `address` and `roles`, read from the database, not from the token; `phone`
and `address` are `null` for an account created before they existed. `PATCH` takes `name`, `phone` and `address`, all optional and at
least one, with the rules of registration; a field that is not sent keeps its value and a phone or an address cannot be cleared. A
`null` field, an empty body and an unknown field (`email`, `roles`, `id` included) are `400 VALIDATION_ERROR` with `details[].field`
naming the field, and nothing is changed. The accepted fields are written in one `UPDATE` and the answer is `200` with the profile after
the change. The body is at most 4 KiB. A revoked access token is `401` and, as on the other protected routes, a failure of the revoked
list is `500`; so is `401` the token of an account that no longer exists or is locked. No event is published and phone and address stay
out of tokens, `UserSummary` and events (ADR-024); the log never carries them.

## Change of the own password

`POST /api/v1/auth/me/password` (HU-AUTH-007, ADR-051) changes the password of the caller after checking the current one. It needs an access
token that holds `profile:update:self`, takes no `Idempotency-Key` and is enabled by the same two settings as the other protected routes.
The body is `{ "currentPassword", "newPassword" }` (at most 4 KiB, no other property).

```bash
curl -i -X POST http://localhost:8081/api/v1/auth/me/password -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' -d '{"currentPassword":"Secret123","newPassword":"NewSecret123"}'
```

Success is `200` with the `AuthResponse` of a fresh session. In **one transaction** the account row is locked (`FOR NO KEY UPDATE`), the
current password is verified, the hash is replaced (bcrypt, the cost of registration), every active refresh token of the user is revoked and a
new one is created; so the device that made the change stays signed in and every other device loses its refresh token. Access tokens already
issued live until they expire (at most one hour). No event is published.

A **wrong current password is `400 VALIDATION_ERROR`, never `401`** (the shell treats every `401` as an expired session): `details[0].field` is
`currentPassword` and the message `The current password is incorrect`. A new password equal to the current one is `400` on `newPassword` with
`The new password must differ from the current one` (compared only after the current password was verified), and one that breaks the rules of
registration is `400` on `newPassword`. A `currentPassword` of 0 or more than 72 bytes is a plain `400` that does not count as a failure. The token
of an account that is gone or locked is `401`.

Guessing the current password with a stolen token is bounded per **user** (the id in the token): with Redis, `APP_AUTH_PASSWORD_CHANGE_MAX_ATTEMPTS`
wrong current passwords inside `APP_AUTH_PASSWORD_CHANGE_WINDOW` write the lock (`APP_AUTH_PASSWORD_CHANGE_LOCK`) and the next attempt is
`429 RATE_LIMITED` with `Retry-After` set to the remaining seconds (rounded up, at least 1), **before** the password is verified, so even the
correct one is refused and no bcrypt work is done. Only wrong current passwords count; validation errors, the equal-password error and `500` do
not, and a success drops the counter. The keys are `attempts:pwd:{userId}` and `locked:pwd:{userId}`, inside the prefixes the ACL of the auth
Redis already grants. If the limit store cannot be consulted the limit **fails open** with a `WARN` that carries neither the password nor the
user id, and the wait is bounded by `APP_AUTH_LOGIN_LIMIT_TIMEOUT` and `APP_AUTH_LOGIN_LIMIT_PAUSE`, as for the login (ADR-048); the check of
the revoked token list still fails closed (`500`) when Redis is down. Without `APP_AUTH_REDIS_URL` the change is not limited. The route has a
bulkhead (Norma 5.3.10): at most `APP_AUTH_PASSWORD_CHANGE_MAX_CONCURRENCY` requests run at once, the next one waits at most
`APP_AUTH_PASSWORD_CHANGE_QUEUE_TIMEOUT` and is then answered `429` with `Retry-After: 1`, after the token and the body are validated and before
any transaction.

| Variable | Default | Meaning |
|---|---|---|
| `APP_AUTH_PASSWORD_CHANGE_MAX_ATTEMPTS` | `5` | Wrong current passwords inside the window that lock the change of a user (1 to 100) |
| `APP_AUTH_PASSWORD_CHANGE_WINDOW` | `15m` | Window in which they are counted (positive Go duration) |
| `APP_AUTH_PASSWORD_CHANGE_LOCK` | `15m` | How long a locked user is refused with `429` (positive Go duration) |
| `APP_AUTH_PASSWORD_CHANGE_MAX_CONCURRENCY` | `4` | Bulkhead of the route. At least 1 and, with a database, below `APP_AUTH_DATABASE_MAX_CONNECTIONS`; otherwise the service does not start. |
| `APP_AUTH_PASSWORD_CHANGE_QUEUE_TIMEOUT` | `1s` | Go duration (maximum `5s`) a request waits for a free slot before it is refused. |

## Password reset

`POST /api/v1/auth/forgot-password` and `POST /api/v1/auth/reset-password` (HU-AUTH-006, ADR-050) let a user who forgot the password
choose a new one with a link sent by email. Both are public. Only `forgot-password` takes the `Idempotency-Key` header, required, 8 to 128
characters (Norma 5.3.8); `reset-password` creates nothing and a replay of it is a `401`, so it takes none. They are enabled by the settings of the other routes,
**`APP_AUTH_SMTP_HOST` and `APP_AUTH_PASSWORD_RESET_URL`** (see [Email delivery](#email-delivery-smtp)); without either the two routes answer
`404` with the envelope of the contract and the start-up log says which one is missing.

```bash
curl -i -X POST http://localhost:8081/api/v1/auth/forgot-password -H 'Content-Type: application/json' -H "Idempotency-Key: $(uuidgen)" -d '{"email":"maria@example.com"}'
curl -i -X POST http://localhost:8081/api/v1/auth/reset-password -H 'Content-Type: application/json' -d '{"token":"<uuid of the link>","password":"NewSecret123"}'
```

`forgot-password` answers `202` with no body for an active account, an unknown email, a locked or deleted account and a user who
already asked three times in the rolling hour: the answer, its body and its duration do not tell which case it was. Only an active account
within its limit gets a token: a UUIDv4 (`crypto/rand`) of which only the SHA-256 digest is stored in `auth.password_reset`, valid for one
hour and for one use; a new request soft-deletes the previous pending one. The message is not sent inside the request: once the transaction
commits the `PasswordResetSender` port queues it (`SMTPPasswordResetSender`, a bounded in-memory queue of 64 messages and two workers), so
the latency or the failure of the relay cannot change the answer. A message that fails, or finds the queue full, is a `WARN` with the user id
and the class of the error, and the user asks again; messages not yet sent are lost if the process stops. The link is
`APP_AUTH_PASSWORD_RESET_URL` followed by `#token=<token>`: the token travels in the fragment, which browsers do not send to servers. The
token, its digest, the link and the address are never logged, and nothing is written to the outbox. A malformed or missing email, or a body
over 4 KiB, is `400 VALIDATION_ERROR`; a missing or malformed `Idempotency-Key` is the same `400` with a detail for the header.

The key is stored in `auth.password_reset_idempotency_key` with the SHA-256 of the normalised (lowercase, trimmed) email and nothing else. It is
recorded for every request that passes validation, whatever the account is: for an active account within its limit in the same transaction as
the token, linked to it, and in the other cases alone with no link, so a replay is indistinguishable. The same key and email again is the same
silent `202` and creates and sends nothing; the same key with another email is `409 IDEMPOTENCY_KEY_CONFLICT` (as in `/register`), which depends
only on the key and the email sent, never on the account. Two concurrent requests with the same key resolve on the primary key: the loser
re-reads the key and replays. Keys are purged after seven days (the purge above); the only `429` is the bulkhead below.

`reset-password` answers `204` and, in one transaction, consumes the token, replaces the password hash (bcrypt, the cost of registration)
and revokes every active refresh token of the user. An unknown, expired, used or superseded token, and the token of an account that is no
longer active, are the same `401 INVALID_TOKEN`; a malformed token or a password that breaks the rules of registration (8 to 72 bytes, one
uppercase letter, one digit) is `400` and does not consume the token. So is a password equal to the current one of the account (`400
VALIDATION_ERROR`, `details[0].field` `password`, message `The new password must differ from the current one`): it is compared, with the
same bcrypt check as the login, only after the token proved valid, so the `401` cases never depend on it; nothing changes and the token still
works with another password. Previous passwords are not remembered: only the current one is refused. Access tokens already issued last until they expire (at most one hour).

Each route has a bulkhead (Norma 5.3.10): at most `APP_AUTH_PASSWORD_RESET_MAX_CONCURRENCY` requests run at once and the next one waits at most
`APP_AUTH_PASSWORD_RESET_QUEUE_TIMEOUT` before it is answered `429 RATE_LIMITED` with `Retry-After: 1`, after the body is read and before any
transaction opens. It does not depend on the email. The retention purge also deletes the password resets that expired more than seven days ago.

## Redis

`APP_AUTH_REDIS_URL` (`redis://auth_app:<password>@redis:6379/0`, URL-safe password) points at the Redis of
`csp-infra-redis` (ADR-028). It holds the list of revoked access tokens, one key `blacklist:{jti}` per token that lives
as long as the token does. `APP_AUTH_REDIS_TIMEOUT` (default `2s`) bounds the connection, every read and every write
(Norma 5.3.10). The client does not connect at start: an unreachable Redis is an error of the first command that needs it.
When the variable is empty the features that need Redis are not enabled (`POST /logout`, with an INFO line in the log).

### Revoked access tokens

`POST /logout`, `GET /users`, `PATCH /users/{userId}/role` and the email change look up the `jti` of the
access token after verifying its signature and expiration: a token on the list is `401`, before its permissions are judged.
Only this service reads the list; the other services accept the token until it expires (ADR-028, ADR-033). If Redis cannot be
consulted `GET /users`, `PATCH /users/{userId}/role` and the email change **fail closed**: `500 INTERNAL_ERROR` and a `WARN` that never contains
the token or the `jti`. The same lookup also reads `blacklist:user:{sub}`, the marker that the removal of `ADMIN` writes
(`SET blacklist:user:{userId} <R> EX 3600`, `R` being the epoch second of the revocation, read from the server clock after the commit): a token
whose `iat` is less than or equal to `R` is `401`, one with a later `iat` is accepted, so a user who signs in after the revocation is not
rejected, and a token issued in the second of `R` is rejected. The marker lives one hour, the longest life of an access token, and uses
only `get` and `set` on `~blacklist:*`, which `auth_app` already holds. A Redis restart empties the markers: the access tokens of that
moment are accepted again until they expire, while the refresh tokens stay revoked. The other services verify signature and expiry
only, so an `ADMIN` token revoked this way is still accepted outside this service for up to one hour (ADR-031, accepted limit).
`POST /logout` does not stop at the lookup: it revokes the refresh tokens in PostgreSQL, commits, and
then fails with `500` when it writes the list, so during a Redis outage a sign out answers `500` but the refresh tokens are
already revoked, and the client repeats the call.
Without `APP_AUTH_REDIS_URL` the check is off (INFO line at start) and the routes work as before.

### Login attempt limit

With Redis, `POST /login` counts the failed logins of each client address (HU-AUTH-005, ADR-040). The address is the **last** entry of
`X-Forwarded-For`, the one the gateway appends; the entries before it come from the client and are ignored. Without that header the
address of the connection is used, and a request with no usable address is not limited. Only wrong credentials (unknown email or
wrong password) count; a locked account, an invalid body and server errors do not. The state is two keys per address with a TTL:
`attempts:{ip}` (the counter, which lives for the window) and `locked:{ip}` (the lock, which lives for the lock time). The failure that
reaches the maximum writes the lock and drops the counter; a successful login drops the counter. The lock is checked before the
password, so a locked address costs no bcrypt.

| Variable | Default | Meaning |
|---|---|---|
| `APP_AUTH_LOGIN_MAX_ATTEMPTS` | `10` | Failures inside the window that lock the address (1 to 1000) |
| `APP_AUTH_LOGIN_WINDOW` | `5m` | Window in which the failures are counted (Go duration) |
| `APP_AUTH_LOGIN_LOCK` | `5m` | How long a locked address is rejected with `429` (Go duration) |
| `APP_AUTH_LOGIN_LIMIT_TIMEOUT` | `300ms` | Most one call of the limiter waits for Redis (positive Go duration, at most `5s`); the revoked token list keeps `APP_AUTH_REDIS_TIMEOUT` |
| `APP_AUTH_LOGIN_LIMIT_PAUSE` | `10s` | How long the limiter is not called after a failure (positive Go duration, at most `5m`) |

If Redis cannot be consulted the login **goes on without the limit** and a `WARN` is logged; the per-IP limit of the gateway stays
active. The wait is bounded (ADR-048): each call of the limiter gives up after `APP_AUTH_LOGIN_LIMIT_TIMEOUT`, and after a failure the
limiter is not called for `APP_AUTH_LOGIN_LIMIT_PAUSE`, so only the first login of an outage waits (one timeout at most) and the
`WARN` is written once per pause. When the pause ends the next login tries Redis again. Without `APP_AUTH_REDIS_URL` the login is not
limited (INFO line at start).
## Email delivery (SMTP)

The code of the email change goes to the SMTP relay of the platform (`net/smtp`, ADR-034). All the settings are domain variables,
never versioned (Annex G):

| Variable | Default | Meaning |
|---|---|---|
| `APP_AUTH_SMTP_HOST` | empty | Relay host. Empty: `PATCH /me/email` and `POST /me/email/verify` are not registered (`404`). |
| `APP_AUTH_SMTP_PORT` | `587` | Relay port, 1 to 65535. |
| `APP_AUTH_SMTP_USER`, `APP_AUTH_SMTP_PASSWORD` | empty | Credentials (AUTH PLAIN, sent only over TLS or to a local catcher). Empty user: no authentication. |
| `APP_AUTH_SMTP_FROM` | none | Sender address, required when the host is set. |
| `APP_AUTH_SMTP_TLS` | `starttls` | `starttls` requires the relay to offer STARTTLS and fails otherwise; `none` is only for a local catcher. |
| `APP_AUTH_SMTP_TIMEOUT` | `5s` | Go duration that bounds the whole exchange, connection included. |
| `APP_AUTH_EMAIL_CHANGE_MAX_CONCURRENCY` | `4` | Bulkhead of `PATCH /me/email`: at most this many requests run at once. At least 1 and, with `APP_AUTH_SMTP_HOST` set, below `APP_AUTH_DATABASE_MAX_CONNECTIONS`, so the other routes always find a connection; otherwise the service does not start. |
| `APP_AUTH_EMAIL_CHANGE_QUEUE_TIMEOUT` | `1s` | Go duration (maximum `5s`) a request waits for a free slot before it is refused. |
| `APP_AUTH_PASSWORD_RESET_URL` | empty | Page of the portal that the link of the password reset opens: an absolute `http` or `https` URL without a fragment. Empty: `POST /forgot-password` and `POST /reset-password` answer `404`, with or without the SMTP host. |
| `APP_AUTH_PASSWORD_RESET_MAX_CONCURRENCY` | `4` | Bulkhead of each of the two password reset routes. At least 1 and, with `APP_AUTH_SMTP_HOST` set, below `APP_AUTH_DATABASE_MAX_CONNECTIONS`; otherwise the service does not start. |
| `APP_AUTH_PASSWORD_RESET_QUEUE_TIMEOUT` | `1s` | Go duration (maximum `5s`) a password reset request waits for a free slot before it is refused. |

Where the variables go: `deploy/compose.yml` passes the seven of them, the two of the bulkhead and the three of the password reset through from the platform environment (the `.env` of `csp-infra`;
in development its git-ignored `env/dev.env`, which may point at the local Mailpit below with `APP_AUTH_SMTP_TLS=none`), and `.env.example`
lists them with no value for the host, user, password and sender. In qa and main the SMTP relay and its credentials are provided by Oscar and
set per environment as secrets (`APP_AUTH_SMTP_HOST`, `_USER`, `_PASSWORD`, `_FROM`); they are never versioned. Without
`APP_AUTH_SMTP_HOST` the two email change routes answer `404`, and so do the two password reset routes (see [Password reset](#password-reset)).

A `404` on the two routes therefore means the service runs without `APP_AUTH_SMTP_HOST`, not that the route does not exist. A relay that
fails is a `500` with a `WARN` that carries the user id and the class of the error (`connect`, `tls`, `auth`, `rejected`, `timeout`,
`canceled`...); the code, the address and the credentials are never logged. The SMTP call runs inside the database transaction, so a slow
relay holds a connection for up to the timeout. That is why `PATCH /me/email` has a bulkhead (Norma 5.3.10): when
`APP_AUTH_EMAIL_CHANGE_MAX_CONCURRENCY` requests are in flight, the next one waits at most `APP_AUTH_EMAIL_CHANGE_QUEUE_TIMEOUT` and is
then answered `429 RATE_LIMITED` with `Retry-After: 1` **before a transaction is opened**, with a `WARN` (`email change request refused:
no free slot`, the limit and the wait, never the address). `POST /me/email/verify` sends nothing and is not limited.

To try it locally with Mailpit (a catcher that keeps the messages, never use it outside a developer machine):

```bash
docker compose -f deploy/compose.yml --profile mail up -d mailpit
APP_AUTH_SMTP_HOST=localhost APP_AUTH_SMTP_PORT=1025 APP_AUTH_SMTP_TLS=none APP_AUTH_SMTP_FROM=no-reply@cinesync.local go run ./cmd/auth-api
```

Inside the platform network the service uses `APP_AUTH_SMTP_HOST=mailpit` and port `1025`. Mailpit publishes SMTP (1025) and the web UI
on the loopback only; the message with the code appears at `http://localhost:8025` after `PATCH /me/email`.

## Branching

Three permanent branches. **None of them accepts a direct commit** — you enter through a child
branch and leave through a Pull Request.

```
develop  <--PR--  feat/... fix/... chore/...
qa       <--PR--  qa/...
main     <--PR--  release/...  hotfix/...
```

Promotion happens **by re-application** (`git cherry-pick -x`), never by merging one permanent
branch into another: `merge develop -> qa` and `merge qa -> main` do not exist in this model.

`main` requires **1 approval from `ariel5253`**. On `develop` and `qa` the team sets its own review
rule.

Full policy: `00-governance/branching-policy.md` in `csp-docs`.

## Pull Requests and commits

- Commits follow Conventional Commits: `<type>(<scope>): <description>`, in English, lowercase and imperative.
- A Pull Request has at most **400 changed lines** (additions plus deletions) and one logical goal.
- Every Pull Request targets the permanent branch that matches its prefix, according to the diagram above.
