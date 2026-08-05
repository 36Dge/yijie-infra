import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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
  expectedImmutableImages,
  parsePinnedImage,
  parseInspectOutput,
  verifyLocalImageAvailability,
} from "../scripts/verify-feat-126-s10-images.mjs";

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
  assert.throws(() => parsePinnedImage("postgres:latest"), /pin is malformed/);
  const digest = "sha256:4e6e670bb069649261c9c18031f0aded7bb249a5b6664ddec29c013a89310d50";
  assert.throws(
    () =>
      expectedImmutableImages({
        first: `postgres:16.13-alpine@${digest}`,
        second: `postgres:other-version@${digest}`,
      }),
    /conflicting version tags/,
  );
  assert.throws(() => parseInspectOutput(""), /invalid result/);
  assert.throws(() => parseInspectOutput("{}\n{}"), /invalid result/);
  assert.throws(() => parseInspectOutput("not-json"), /invalid JSON/);
});

test("FEAT-126 S10 image preflight accepts only exact local repository digests", () => {
  const inspected = [];
  assert.equal(
    verifyLocalImageAvailability({
      inspect: (digestReference) => {
        inspected.push(digestReference);
        return {
          Id: digestReference.slice(digestReference.indexOf("sha256:")),
          RepoDigests: [digestReference],
          Descriptor: { digest: digestReference.slice(digestReference.indexOf("sha256:")) },
        };
      },
    }),
    3,
  );
  assert.equal(inspected.length, 3);

  assert.throws(
    () =>
      verifyLocalImageAvailability({
        inspect: (digestReference) => ({
          Id: digestReference.slice(digestReference.indexOf("sha256:")),
          RepoDigests: [],
        }),
      }),
    /repository digest does not match/,
  );
  assert.throws(
    () =>
      verifyLocalImageAvailability({
        inspect: (digestReference) => ({
          Id: digestReference.slice(digestReference.indexOf("sha256:")),
          RepoDigests: [digestReference],
          Descriptor: { digest: `sha256:${"0".repeat(64)}` },
        }),
      }),
    /descriptor does not match/,
  );
  assert.throws(
    () =>
      verifyLocalImageAvailability({
        inspect: () => {
          throw new Error("unavailable");
        },
      }),
    /unavailable/,
  );
  assert.throws(
    () =>
      verifyLocalImageAvailability({
        inspect: (digestReference) => ({ Id: "invalid", RepoDigests: [digestReference] }),
      }),
    /identity is invalid/,
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
  const script = await readFile("scripts/feat-126-s10-api-bootstrap.sh", "utf8");
  const manifestNames = [
    "user-a-tenant-a.json",
    "user-a-tenant-b.json",
    "user-b-tenant-a.json",
    "user-b-tenant-b.json",
  ];

  assert.match(script, /profile="feat-126-s10-local-lab"/);
  assert.match(script, /yijie_api_feat126_s10\?sslmode=disable/);
  assert.match(script, /git -C "\$api_repo" rev-parse HEAD/);
  assert.match(script, /status --porcelain --untracked-files=all/);
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
