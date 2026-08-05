import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { chmod, link, lstat, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  FEAT_126_S10_IMAGES,
  FEAT_126_S10_PROFILE,
  FEAT_126_S10_SERVICES,
  loadCompose,
  validateCompose,
} from "../scripts/compose-model.mjs";
import {
  FEAT_126_S10_SECRET_KEYS,
  validateFeat126S10Secrets,
} from "../scripts/feat-126-s10-secrets.mjs";
import { validateBootstrapResults } from "../scripts/verify-feat-126-s10-bootstrap-results.mjs";
import {
  DockerPreflightError,
  expectedImmutableImages,
  parsePinnedImage,
  parseInspectOutput,
  validateImageSnapshot,
} from "../scripts/verify-feat-126-s10-images.mjs";
import {
  API_CANDIDATE_AUTHORITY_FILE,
  ensureApiCandidateAuthority,
} from "../scripts/feat-126-s10-api-candidate.mjs";

function hasDockerCode(code) {
  return (error) => error instanceof DockerPreflightError && error.code === code;
}

test("FEAT-126 S10E services are immutable, default-off, project-scoped, and synthetic-only", async () => {
  const compose = await loadCompose();
  assert.doesNotThrow(() => validateCompose(compose));

  for (const name of FEAT_126_S10_SERVICES) {
    const service = compose.services[name];
    assert.equal(service.image, FEAT_126_S10_IMAGES[name]);
    assert.deepEqual(service.profiles, [FEAT_126_S10_PROFILE]);
    assert.equal(service.container_name, undefined);
    assert.equal(service.labels["ai.yijie.feature"], "FEAT-126");
    assert.equal(service.labels["ai.yijie.slice"], "S10E");
    assert.equal(service.labels["ai.yijie.data-classification"], "synthetic-only");
  }

  assert.deepEqual(compose.services["feat126-s10-api-db"].ports, ["127.0.0.1:5432:5432"]);
  assert.deepEqual(compose.services["feat126-s10-api-db"].networks, [
    "feat126_s10_api_internal",
    "feat126_s10_host_bridge",
  ]);
  assert.equal(compose.services["feat126-s10-keycloak-db"].ports, undefined);
  assert.equal(compose.services["feat126-s10-keycloak"].ports, undefined);
  assert.deepEqual(compose.services["feat126-s10-caddy"].ports, [
    "127.0.0.1:8443:8443",
    "127.0.0.1:9443:9443",
  ]);
  assert.equal(compose.networks.feat126_s10_api_internal.internal, true);
  assert.equal(compose.networks.feat126_s10_identity_internal.internal, true);
  assert.equal(compose.networks.feat126_s10_proxy_internal.internal, true);
  assert.notEqual(compose.networks.feat126_s10_host_bridge?.internal, true);
});

test("FEAT-126 S10E static assets keep no-pull, no-volume-delete, and no-trust-install boundaries", async () => {
  const [script, runtimeVerifier, caddyfile, documentation] = await Promise.all([
    readFile("scripts/feat-126-s10-compose.sh", "utf8"),
    readFile("scripts/verify-feat-126-s10-runtime.mjs", "utf8"),
    readFile("config/feat-126-s10/Caddyfile", "utf8"),
    readFile("docs/feat-126-s10e.md", "utf8"),
  ]);

  assert.match(script, /--pull never/);
  assert.match(script, /verify-feat-126-s10-images\.mjs/);
  assert.doesNotMatch(script, /docker (image )?pull|docker image inspect/);
  assert.doesNotMatch(script, /down[^\n]*--volumes|docker volume rm|docker system prune/);
  assert.match(script, /canonical lowercase UUIDv4/);
  assert.match(script, /Refusing to use a rejected FEAT-126 S10E run/);
  assert.match(runtimeVerifier, /spawnSync/);
  assert.doesNotMatch(runtimeVerifier, /console\.(log|error)\([^\n]*environment/i);
  assert.doesNotMatch(runtimeVerifier, /\.Config\.Env/);
  assert.match(caddyfile, /skip_install_trust/);
  assert.doesNotMatch(caddyfile, /tls_insecure_skip_verify|0\.0\.0\.0|PRIVATE KEY/);
  assert.match(documentation, /contract-impact = additive/);
  assert.match(documentation, /separate explicit Owner authorization/);
});

test("FEAT-126 S10 image preflight derives repository digests from the reviewed Compose pins", () => {
  const postgres = parsePinnedImage(FEAT_126_S10_IMAGES["feat126-s10-api-db"]);
  assert.equal(postgres.repository, "postgres");
  assert.equal(postgres.tag, "16.13-alpine");
  assert.equal(
    postgres.digestReference,
    "postgres@sha256:4e6e670bb069649261c9c18031f0aded7bb249a5b6664ddec29c013a89310d50",
  );
  assert.equal(expectedImmutableImages().length, 3);
  assert.throws(() => parsePinnedImage("postgres:latest"), hasDockerCode("image_identity_invalid"));
  const digest = "sha256:4e6e670bb069649261c9c18031f0aded7bb249a5b6664ddec29c013a89310d50";
  assert.throws(
    () =>
      expectedImmutableImages({
        first: `postgres:16.13-alpine@${digest}`,
        second: `postgres:other-version@${digest}`,
      }),
    hasDockerCode("image_identity_invalid"),
  );
  assert.throws(() => parseInspectOutput(""), hasDockerCode("inspect_payload_invalid"));
  assert.throws(() => parseInspectOutput("{}\n{}"), hasDockerCode("inspect_payload_invalid"));
  assert.throws(() => parseInspectOutput("not-json"), hasDockerCode("inspect_payload_invalid"));
});

test("FEAT-126 S10 image identity requires exact digest, descriptor, and platform", () => {
  const image = parsePinnedImage(FEAT_126_S10_IMAGES["feat126-s10-api-db"]);
  const capability = { architecture: "arm64", os: "linux" };
  const snapshot = {
    Id: `sha256:${"1".repeat(64)}`,
    RepoDigests: [image.digestReference],
    Descriptor: { digest: image.digest },
    Os: "linux",
    Architecture: "arm64",
    Config: { Volumes: { "/var/lib/postgresql/data": {} } },
  };
  const identity = validateImageSnapshot(snapshot, image, capability);
  assert.deepEqual(identity.volumes, ["/var/lib/postgresql/data"]);
  assert.throws(
    () => validateImageSnapshot({ ...snapshot, RepoDigests: [] }, image, capability),
    hasDockerCode("image_repository_mismatch"),
  );
  assert.throws(
    () =>
      validateImageSnapshot(
        { ...snapshot, Descriptor: { digest: `sha256:${"0".repeat(64)}` } },
        image,
        capability,
      ),
    hasDockerCode("image_digest_mismatch"),
  );
  assert.throws(
    () => validateImageSnapshot({ ...snapshot, Architecture: "amd64" }, image, capability),
    hasDockerCode("image_platform_mismatch"),
  );
  assert.throws(
    () => validateImageSnapshot({ ...snapshot, Id: "invalid" }, image, capability),
    hasDockerCode("image_identity_invalid"),
  );
});

test("FEAT-126 S10E secret validator accepts only distinct owner-only generated values", async () => {
  const directory = await mkdtemp(join(tmpdir(), "feat126-s10-secrets-"));
  const path = join(directory, "infra-secrets.env");
  try {
    const text = FEAT_126_S10_SECRET_KEYS.map(
      (key, index) => `${key}=${String(index + 1).padStart(64, String(index + 1))}`,
    ).join("\n");
    await writeFile(path, `${text}\n`, { mode: 0o600 });
    await chmod(path, 0o600);
    const entries = await validateFeat126S10Secrets(path);
    assert.equal(entries.size, FEAT_126_S10_SECRET_KEYS.length);

    await chmod(path, 0o644);
    await assert.rejects(
      validateFeat126S10Secrets(path),
      /permissions must be 0600 or stricter/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("FEAT-126 S10E validation rejects fixed container names and non-loopback ports", async () => {
  const compose = structuredClone(await loadCompose());
  compose.services["feat126-s10-api-db"].container_name = "unsafe-fixed-name";
  assert.throws(() => validateCompose(compose), /must not set container_name/);

  const second = structuredClone(await loadCompose());
  second.services["feat126-s10-caddy"].ports[0] = "0.0.0.0:8443:8443";
  assert.throws(() => validateCompose(second), /published ports mismatch|IPv4 loopback/);
});

test("FEAT-126 S10 bootstrap wrapper fixes the closed profile, manifests, and API-owned verification", async () => {
  const [script, migration, candidate, makefile] = await Promise.all([
    readFile("scripts/feat-126-s10-api-bootstrap.sh", "utf8"),
    readFile("scripts/feat-126-s10-api-migration.sh", "utf8"),
    readFile("scripts/feat-126-s10-api-candidate.mjs", "utf8"),
    readFile("Makefile", "utf8"),
  ]);
  const manifestNames = [
    "user-a-tenant-a.json",
    "user-a-tenant-b.json",
    "user-b-tenant-a.json",
    "user-b-tenant-b.json",
  ];

  assert.match(script, /profile="feat-126-s10-local-lab"/);
  assert.match(script, /yijie_api_feat126_s10\?sslmode=disable/);
  assert.match(script, /feat-126-s10-api-candidate\.mjs.*"\$expected_api_sha"/);
  assert.match(migration, /feat-126-s10-api-candidate\.mjs.*"\$expected_api_sha"/);
  assert.match(migration, /expected_api_sha="\$\{3:-\}"/);
  assert.doesNotMatch(migration, /expected_api_sha="[a-f0-9]{40}"/);
  assert.match(makefile, /feat-126-s10-api-migrate:[\s\S]*API_SHA is required[\s\S]*feat-126-s10-api-migration\.sh[^\n]*"\$\(API_SHA\)"/);
  assert.match(candidate, /\["-C", apiRepository, "rev-parse", "HEAD"\]/);
  assert.match(candidate, /"status", "--porcelain", "--untracked-files=all"/);
  assert.match(candidate, /O_EXCL \| constants\.O_NOFOLLOW/);
  assert.doesNotMatch(candidate, /DSN|password|token|repository_path/);
  assert.match(script, /ls-files --error-unmatch/);
  assert.match(script, /verify-nonprod-authz --profile "\$profile" --expect empty/);
  assert.match(script, /verify-nonprod-authz --profile "\$profile" --expect complete/);
  assert.match(script, /go run \.\/cmd\/bootstrap-nonprod-authz-batch/);
  assert.doesNotMatch(script, /go run \.\/cmd\/bootstrap-nonprod-authz --/);
  assert.doesNotMatch(script, /set -a/);
  assert.doesNotMatch(script, /\bpsql\b|SELECT |INSERT |UPDATE |DELETE FROM/i);
  assert.doesNotMatch(script, /\*\.json|find .*manifest/);
  for (const name of manifestNames) {
    assert.equal(script.split(name).length - 1, 1);
  }
});

test("FEAT-126 S10 migration and bootstrap share one exact run-scoped API candidate", async () => {
  const runRoot = await realpath(await mkdtemp(join(tmpdir(), "feat126-api-candidate-")));
  const runId = "12600000-0000-4000-8000-000000000051";
  const fullCommit = "a".repeat(40);
  const inspectRepository = () => ({ head: fullCommit, dirty: false });
  try {
    await chmod(runRoot, 0o700);
    const first = await ensureApiCandidateAuthority({
      runId,
      apiRepository: "synthetic-api-worktree",
      apiFullCommit: fullCommit,
      runRoot,
      inspectRepository,
    });
    assert.deepEqual(first, {
      schema_version: 1,
      run_id: runId,
      api_full_commit: fullCommit,
    });
    const authorityPath = join(runRoot, API_CANDIDATE_AUTHORITY_FILE);
    const metadata = await lstat(authorityPath);
    assert.equal(metadata.mode & 0o777, 0o600);
    assert.equal(metadata.nlink, 1);

    assert.deepEqual(
      await ensureApiCandidateAuthority({
        runId,
        apiRepository: "synthetic-api-worktree",
        apiFullCommit: fullCommit,
        runRoot,
        inspectRepository,
      }),
      first,
    );
    const otherCommit = "b".repeat(40);
    await assert.rejects(
      ensureApiCandidateAuthority({
        runId,
        apiRepository: "synthetic-api-worktree",
        apiFullCommit: otherCommit,
        runRoot,
        inspectRepository: () => ({ head: otherCommit, dirty: false }),
      }),
      /authority is invalid/,
    );
    await assert.rejects(
      ensureApiCandidateAuthority({
        runId,
        apiRepository: "synthetic-api-worktree",
        apiFullCommit: fullCommit,
        runRoot,
        inspectRepository: () => ({ head: fullCommit, dirty: true }),
      }),
      /authority is invalid/,
    );
  } finally {
    await rm(runRoot, { recursive: true, force: true });
  }
});

test("FEAT-126 S10 API candidate authority rejects mode, hardlink, and symlink drift", async () => {
  const runId = "12600000-0000-4000-8000-000000000052";
  const fullCommit = "c".repeat(40);
  const inspectRepository = () => ({ head: fullCommit, dirty: false });
  for (const fault of ["mode", "hardlink", "symlink"]) {
    const runRoot = await realpath(await mkdtemp(join(tmpdir(), `feat126-api-candidate-${fault}-`)));
    try {
      await chmod(runRoot, 0o700);
      const authorityPath = join(runRoot, API_CANDIDATE_AUTHORITY_FILE);
      if (fault === "symlink") {
        const target = join(runRoot, "foreign.json");
        await writeFile(target, "{}\n", { mode: 0o600 });
        await symlink(target, authorityPath);
      } else {
        await ensureApiCandidateAuthority({
          runId,
          apiRepository: "synthetic-api-worktree",
          apiFullCommit: fullCommit,
          runRoot,
          inspectRepository,
        });
        if (fault === "mode") await chmod(authorityPath, 0o640);
        if (fault === "hardlink") await link(authorityPath, join(runRoot, "authority-link.json"));
      }
      await assert.rejects(
        ensureApiCandidateAuthority({
          runId,
          apiRepository: "synthetic-api-worktree",
          apiFullCommit: fullCommit,
          runRoot,
          inspectRepository,
        }),
        /authority is invalid/,
      );
    } finally {
      await rm(runRoot, { recursive: true, force: true });
    }
  }
});

test("FEAT-126 S10 bootstrap result verifier accepts only the exact two-pass matrix", () => {
  const expected = [
    ["12500000-0000-4000-8000-000000000001", "12500000-0000-4000-8000-100000000001", "tenant_owner"],
    ["12500000-0000-4000-8000-000000000001", "12500000-0000-4000-8000-100000000002", "tenant_member"],
    ["12500000-0000-4000-8000-000000000002", "12500000-0000-4000-8000-100000000001", "tenant_member"],
    ["12500000-0000-4000-8000-000000000002", "12500000-0000-4000-8000-100000000002", "tenant_owner"],
  ];
  const results = [];
  for (let pass = 0; pass < 2; pass += 1) {
    for (let index = 0; index < expected.length; index += 1) {
      results.push({
        request_id: `feat-125-bootstrap-${randomUUID()}`,
        state_changed: pass === 0,
        authorization_revision: pass === 0 && index < 2 ? 2 : 3,
        authorization_diff: pass === 0 ? ["synthetic.change"] : [],
        user_id: expected[index][0],
        tenant_id: expected[index][1],
        role: expected[index][2],
      });
    }
  }

  const valid = results.map((value) => JSON.stringify(value)).join("\n") + "\n";
  assert.deepEqual(validateBootstrapResults(valid), {
    schema_version: 1,
    profile: "feat-126-s10-local-lab",
    manifests: 4,
    executions: 8,
    changed: 4,
    unchanged: 4,
    final_authorization_revision: 3,
    content_classification: "synthetic_only",
  });

  const wrongOrder = structuredClone(results);
  [wrongOrder[0], wrongOrder[1]] = [wrongOrder[1], wrongOrder[0]];
  assert.throws(
    () => validateBootstrapResults(wrongOrder.map((value) => JSON.stringify(value)).join("\n") + "\n"),
    /results are invalid/,
  );

  const changedReplay = structuredClone(results);
  changedReplay[4].state_changed = true;
  assert.throws(
    () => validateBootstrapResults(changedReplay.map((value) => JSON.stringify(value)).join("\n") + "\n"),
    /results are invalid/,
  );
});
