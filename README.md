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

The PostgreSQL adapter has integration tests behind the `integration` build tag. They need a database with the
`csp-auth-db` migrations applied and are skipped when `AUTH_TEST_DATABASE_URL` (login `auth_app`) is not set;
`AUTH_TEST_OUTBOX_READER_URL` (login `worker_app`) enables the outbox payload test:

```bash
go test -tags integration ./internal/adapter/out/persistence/
```

With the service running:

```bash
curl http://localhost:8081/api/v1/auth/health          # {"status":"ok"}
curl http://localhost:8081/api/v1/auth/health/ready    # {"status":"ready","dependencies":{}}
```

With Docker, from the root of the repository:

```bash
docker build -f deploy/Dockerfile -t csp-auth-api .
docker run --rm -p 8081:8081 csp-auth-api
```

The service stops gracefully on `SIGINT` and `SIGTERM`. In the platform, `csp-infra` includes `deploy/compose.yml`,
which exposes the port on the `platform` network without publishing it: only the gateway reaches the service.
Copy `.env.example` to `.env` for local values and never commit `.env`. The file lists first the variables the
service reads today (`PORT` and the `APP_AUTH_HTTP_*` timeouts) and then, apart, the ones reserved for later features
(database, Redis, JWT, expiries, bcrypt), which the service does not read yet.

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
