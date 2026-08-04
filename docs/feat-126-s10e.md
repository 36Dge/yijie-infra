# FEAT-126 S10E isolated identity environment

## Scope and contract impact

- Slice: `FEAT-126 / S10E`.
- `contract-impact = additive` for the private deployment interface: this adds an explicit,
  default-off Compose profile and run commands without changing existing profiles, public wire,
  central contracts, Runtime, API, Host, or Desktop behavior.
- Authority: `docker-compose.local.yml`, the pinned image digests, and the S10E scripts in this
  repository. `yijie-contracts` is `N/A` because no business request, response, event, or SDK shape
  changes.
- Owner-approved decision: DESIGN-126-008 / DEC-126-038 Option B.
- S10P1, S10P2, S10P3, S10B, MiniMax, and all default feature activation remain out of scope.

## Isolation model

Every invocation requires one canonical lowercase UUIDv4 `RUN_ID`. The scripts derive the Compose
project name and ignored owner-only run directory from that value. The profile starts only:

- an empty API PostgreSQL 16.13 database on `127.0.0.1:5432`;
- an internal Keycloak PostgreSQL 16.13 database;
- Keycloak 26.7.0 with the existing reviewed synthetic-only realm mounted read-only;
- Caddy 2.11.4 on `127.0.0.1:8443` and `127.0.0.1:9443`.

The four named volumes and four networks are Compose-project scoped. The API database remains on
its private database network and is also attached to the project-scoped, non-internal host bridge
because Docker Desktop does not create its loopback publisher for an internal-only network. It is
still published only on `127.0.0.1`; it never uses host networking or a shared external network. No service sets
`container_name`. Redis, pgvector, the ordinary local PostgreSQL database, FEAT-125 volumes, real
identity, and system/user CA trust are not used. All three image references include exact versions
and SHA-256 digests; `up` uses `--pull never` and fails if any image is absent.

The Keycloak realm asset is reused as a configuration authority only. Its Desktop public client
uses Keycloak's built-in user-session-note mapper to project the numeric `AUTH_TIME` session value
as access-token `nbf`; this keeps the API's required-claim verifier unchanged and avoids a static
not-before value, script mapper, alternate signer, or hand-built bearer. Its database and Caddy state
are new run-scoped volumes. The fixed users and tenant material are synthetic; secrets are generated
locally into an ignored regular file with mode `0600`, are never printed, and are not written to Git.

## Commands

```bash
make feat-126-s10-init-secrets RUN_ID=<canonical-lowercase-uuidv4>
make feat-126-s10-config RUN_ID=<same-run-id>
make feat-126-s10-up RUN_ID=<same-run-id>
make feat-126-s10-status RUN_ID=<same-run-id>
make feat-126-s10-export-ca RUN_ID=<same-run-id>
make feat-126-s10-verify-runtime RUN_ID=<same-run-id>
make feat-126-s10-provision-users RUN_ID=<same-run-id>
make feat-126-s10-api-migrate RUN_ID=<same-run-id> API_REPO=../yijie-api
make feat-126-s10-stop RUN_ID=<same-run-id>
```

`config` is read-only. `up` starts only the four explicit services and waits for health; a profile-only
generic `docker compose up` is not an approved entry point. `export-ca` copies only the public Caddy
root certificate into the owner-only ignored run directory and rejects private-key, symlink, invalid,
or oversized input. It does not install trust.

`verify-runtime` checks the exact healthy container set, immutable image references, run labels,
security options, project-scoped networks and volumes, actual loopback publishers, public CA, OIDC
issuer and the Caddy Tasks 404 boundary. Docker inspection stays in-process and the verifier emits
only a content-free pass/fail result; it never prints container environments or secret values.

The provisioning command adapts this run's generated credentials to the single existing reviewed
synthetic realm authority and verifies the live Desktop audience/`nbf` mapper projection; it does
not create a second identity standard. The migration command
requires the exact approved API commit and a clean worktree, then applies the API-owned migrations
only to `yijie_api_feat126_s10`. Neither command prints credentials or copies application schema into
Infra.

`stop` removes this run's containers and networks but intentionally retains the four named volumes.
Deleting those volumes requires a separate explicit Owner authorization and an exact run manifest;
`docker compose down --volumes`, `docker volume rm`, and prune commands are not part of S10E.

## Readiness and failure rules

- The Docker CLI plugin must be the reviewed Compose v5.3.0 binary with the S10P0-recorded digest.
- Ports 5432, 8443, and 9443 must be loopback-only and available to this run.
- API migrations belong to `yijie-api`; S10E may run the pinned migration binary against only this
  run's empty API database, but Infra must not copy business migration SQL.
- A missing image, digest drift, noncanonical run ID, unsafe secrets file, unexpected port owner,
  unhealthy service, CA validation failure, or resource-label mismatch is a hard stop.
- A run whose evidence or credential handling is rejected must have an owner-only regular
  `REJECTED` marker in its run root. Compose start/config/export, provisioning, migration and
  runtime verification then fail closed; only status/stop remain available for containment.
- No curl fixture or empty row count may be presented as Desktop-to-Public-Tasks E2E evidence.
- S10E completion does not authorize S10P1 or S10B and does not change G3/G4/G6.

## Recovery

Stop only the exact derived Compose project. Preserve volumes unless the Owner separately authorizes
their exact deletion. The user-level Compose discovery link has an owner-only run-scoped backup and
can be restored without modifying the Docker Desktop application or a system directory. Never touch
ordinary local, FEAT-125, foreign-project, or real-data resources during recovery.
