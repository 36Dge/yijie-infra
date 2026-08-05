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
- S10BF1 adds only the separately authorized combined S10B-001 preflight runner described below.
  S10B-R5, S11, MiniMax, and all default feature activation remain out of scope.

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
and SHA-256 digests. Before `up`, a closed preflight derives each unique `repository@digest`
identity from those reviewed Compose pins and verifies the local Docker object and repository digest.
This avoids Docker 29's state-sensitive `version-tag@digest` inspect lookup without weakening the
Compose version labels or digest authority. `up` still uses `--pull never` and fails if any exact
digest is absent or mismatched; it never falls back to a floating tag or pulls an image.

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
make feat-126-s10-verify-images RUN_ID=<same-run-id>
make feat-126-s10-up RUN_ID=<same-run-id>
make feat-126-s10-status RUN_ID=<same-run-id>
make feat-126-s10-export-ca RUN_ID=<same-run-id>
make feat-126-s10-verify-runtime RUN_ID=<same-run-id>
make feat-126-s10-provision-users RUN_ID=<same-run-id>
make feat-126-s10-api-migrate RUN_ID=<same-run-id> API_REPO=../yijie-api API_SHA=<full-clean-commit-sha>
make feat-126-s10-api-bootstrap RUN_ID=<same-run-id> API_REPO=../yijie-api API_SHA=<full-clean-commit-sha>
make feat-126-s10-api-runtime-profile
make feat-126-s10b-api-continuation RUN_ID=<same-run-id> \
  GOVERNANCE_SHA=<full-sha> CONTRACTS_SHA=<full-sha> API_SHA=<full-sha> \
  HOST_SHA=<full-sha> DESKTOP_SHA=<full-sha> RUNTIME_SHA=<full-sha> INFRA_SHA=<full-sha>
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

The bootstrap command is the only authoritative FEAT-126 S10 identity/authorization bootstrap entry
point. It requires a caller-supplied full API commit SHA and a clean matching worktree, fixes the
closed profile to `feat-126-s10-local-lab`, fixes the issuer and database, and invokes exactly the four
already reviewed tracked synthetic manifests. The API-owned verifier proves migration v4 and a wholly
empty authorization/task state before manifest execution, then proves the exact two-user/two-tenant
matrix after two ordered, API-owned batch transactions. Each four-manifest pass is atomic, so a
failure cannot retain a partial user, tenant, membership, role, assignment, or bootstrap-audit
matrix. The second pass must be unchanged and revision-stable. Infra stores
only owner-only, run-scoped, content-free count/revision summaries; transient per-operation results
are removed. It neither contains business SQL nor offers profile, manifest, issuer, database, role,
or actor overrides. This additive local deployment/security profile has `contract-impact = none` on
public/private wire, durable schema, and the existing `feat-125-local-lab` profile semantics.

Migration and bootstrap share one run-scoped `api-candidate-authority.json`. The first command uses
create-new/O_EXCL and no-follow semantics to bind the canonical run ID to one full, clean API commit;
the other command must match it exactly. The owner-only closed document contains only schema version,
run ID, and full API commit—never a repository path, DSN, credential, manifest body, or conversation
content. Missing/short/wrong SHA, dirty worktree, symlink/hardlink, wrong mode/owner, corrupt document,
or cross-command candidate drift fails before reading the secret file or accessing PostgreSQL. The
caller cannot use a branch name or separate migration/bootstrap candidate identities.

This corrective change is intentionally breaking for the private FEAT-126 local migration helper:
the former two-argument invocation now fails closed and every caller must supply the same full
`API_SHA` already required by bootstrap. The repository-owned Make target is updated in the same
change. It does not alter a public wire contract, central source contract, production/default
configuration, durable business schema, or the existing `feat-125-local-lab` profile; G2A impact is
therefore `none` even though the local deployment helper interface is stricter.

`stop` removes this run's containers and networks but intentionally retains the four named volumes.
Deleting those volumes requires a separate explicit Owner authorization and an exact run manifest;
`docker compose down --volumes`, `docker volume rm`, and prune commands are not part of S10E.

## S10BF1 single combined preflight

`make feat-126-s10b-preflight` is the sole S10B-001 combined-preflight entry point. It requires a
fresh canonical run UUID and seven caller-reviewed full commit SHAs for Governance, Contracts, API,
Host, Desktop, Runtime, and Infra. It derives the seven sibling repositories from the workspace,
requires each exact worktree to be clean, checks all fixed loopback ports, and then composes the
accepted image resolver, S10E dependencies, TLS/OIDC runtime inventory, synthetic identity,
migration, closed bootstrap, API build/readiness, Host/fake build, and fake readiness gates.

The runner deliberately has no dataset or fixture command-line argument, environment variable, or
Make variable. It builds and invokes the Host-owned `feat126-fake-readiness` probe, which selects the
frozen case internally and returns a closed projection with separate `dataset_id` and
`fixture_case_id` fields plus the dataset digest. Infra validates the closed shape and run binding;
it does not copy either identity into a second authority or construct the fake request headers.

The command records only full candidate SHAs, closed step names, the Host-owned content-free
readiness identity, the SHA-256 of the verified preflight-built API binary, cleanup state, and the
explicit fact that S10B-R5 was not executed. The binary is opened without following symlinks and its
owner, mode, link count and bounded size are checked; a second identity/digest snapshot immediately
before preflight launch must match. API and fake logs are owner-only, bounded, and scanned against
the run's generated secrets. API/fake processes and Compose containers/networks are stopped before
the command returns; named volumes and the owner-only ignored run record remain under the existing
disclosure. Any mismatch creates a closed `REJECTED` marker and fails without printing child stderr,
secrets, DSN, token, source paths, or fixture content. This private deployment/test tooling has no
central-contract, IPC, durable-schema, Host business-wire, or Runtime-pin impact.

## S10B API runtime profile authority corrective

`scripts/feat-126-s10-api-runtime-profile.mjs` is the sole Infra-owned runtime authority for the
FEAT-126 API process. It exports a closed, versioned projection and a builder that fixes
`YIJIE_ENV=nonproduction`, `YIJIE_API_SERVICE_PROFILE=feat-126-s10-local-lab`, the loopback API and
PostgreSQL endpoints, the isolated database, issuer/JWKS, TLS verification, and the two accepted API
feature gates. `make feat-126-s10-api-runtime-profile` emits only that content-free projection for
machine inspection. It does not accept a profile, endpoint, database, issuer, or gate override.

The combined preflight imports this authority to construct the API child environment and records the
same closed projection in its summary. `make feat-126-s10b-api-continuation` is the only accepted API
continuation entry. It accepts only the canonical run ID and seven full candidate SHAs. The launcher
derives the summary, secrets, CA, preflight-built API binary and content-free log from fixed paths
inside that run; profile, endpoint, database, issuer, gate, binary and path overrides do not exist.
The launcher calls `readApiRuntimeAuthorityFromPreflightSummary`, binds the summary to the same run
and exact seven-SHA set, and only then passes the returned authority to `buildApiRuntimeEnvironment`.
Reconstructing the environment in shell, using
`feat-125-local-lab`, a generic/default/unknown profile, or accepting an operator-provided override
is a hard failure. The existing FEAT-125 runner and template remain unchanged.

Before spawning, the launcher verifies owner, mode, regular-file, no-symlink, link-count and bounded
size requirements for the run artifacts. It securely hashes the API binary, requires an exact match
with `api_binary_sha256` from the closed summary, then repeats the digest and inode/device metadata
snapshot immediately before spawn. An owner-side accidental replacement or metadata drift therefore
fails closed rather than running an unbound artifact. It executes only the fixed API binary as a
foreground child with the closed API environment, forwards termination signals, and propagates its
exit status. Raw child output is discarded with a strict capacity ceiling; only content-free
lifecycle records are written to the owner-only run log. This entry starts neither Compose nor
another component. Its presence and test-harness PASS do not claim that S10B-002 through S10B-012,
a fresh four-component run, G4, or G6 has executed or passed.

This corrective has `contract-impact = semantic` for the private FEAT-126 deployment interface:
previous FEAT-126 preflight behavior selected the FEAT-125 API runtime profile, whereas the corrected
chain selects the dedicated FEAT-126 runtime profile. Public HTTP/event contracts, central SDKs,
durable schema, private IPC, Host wire, Runtime pin, production/default configuration, immutable
image pins, `--pull never`, and cleanup semantics do not change; central G2A impact is `none`.

## S10BD1 capability and immutable resolver corrective

- Authorization: `LIA-126-017`, explicitly consumed for S10BD1 only.
- `contract-impact = semantic` for the private FEAT-126 local deployment interface. The existing
  public/private business wire, durable schema, Runtime pin and default/production behavior do not
  change; central G2A is N/A.
- The verifier checks Docker CLI/server capability in the same process and context before any image
  or container command. Failures are reduced to the reviewed closed classes; raw Docker stderr,
  socket/context paths and command payloads are never emitted.
- Each original Compose `version-tag@digest` remains the only authority. Two read-only snapshots
  must agree on image Id, mandatory Descriptor digest, RepoDigests, repository and Linux/server
  architecture. A tag-only lookup is diagnostic and can never satisfy the gate.
- After identity succeeds, the verifier performs one bounded `docker create --pull=never` probe per
  unique image. The probe uses `--network none`, run-scoped names and labels, overrides every image
  volume with tmpfs, never starts the container and removes only an exact owned identity. Unknown
  outcomes are reconciled before cleanup; a foreign or mismatched resource is never removed.
- The probe does not pull, retag, restart Docker, switch image stores, publish ports, create networks,
  delete existing volumes or weaken the immutable pins. S10BD1 completion is not S10B evidence and
  does not authorize S10B-R4 or S11.

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
