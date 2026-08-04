import assert from "node:assert/strict";
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
  assert.doesNotMatch(script, /down[^\n]*--volumes|docker volume rm|docker system prune/);
  assert.match(script, /canonical lowercase UUIDv4/);
  assert.match(runtimeVerifier, /spawnSync/);
  assert.doesNotMatch(runtimeVerifier, /console\.(log|error)\([^\n]*environment/i);
  assert.doesNotMatch(runtimeVerifier, /\.Config\.Env/);
  assert.match(caddyfile, /skip_install_trust/);
  assert.doesNotMatch(caddyfile, /tls_insecure_skip_verify|0\.0\.0\.0|PRIVATE KEY/);
  assert.match(documentation, /contract-impact = additive/);
  assert.match(documentation, /separate explicit Owner authorization/);
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
