import assert from "node:assert/strict";
import test from "node:test";
import {
  FEAT_125_LOCAL_IMAGES,
  FEAT_125_LOCAL_PROFILE,
  loadCompose,
  validateCompose,
} from "../scripts/compose-model.mjs";

test("local Compose model has isolated API and knowledge databases", async () => {
  const compose = await loadCompose();
  assert.doesNotThrow(() => validateCompose(compose));
  assert.deepEqual(compose.services.postgres.ports, ["127.0.0.1:5432:5432"]);
  assert.deepEqual(compose.services.redis.ports, ["127.0.0.1:6379:6379"]);
  assert.deepEqual(compose.services.pgvector.ports, ["127.0.0.1:5433:5432"]);
  assert.ok(compose.services.pgvector.volumes.some((volume) => volume.includes("001-enable-vector.sql")));
});

test("FEAT-125 local services are immutable, opt-in, isolated, and loopback-only", async () => {
  const compose = await loadCompose();

  for (const [name, image] of Object.entries(FEAT_125_LOCAL_IMAGES)) {
    assert.equal(compose.services[name].image, image);
    assert.deepEqual(compose.services[name].profiles, [FEAT_125_LOCAL_PROFILE]);
  }
  assert.equal(compose.services["feat125-keycloak-db"].ports, undefined);
  assert.equal(compose.services["feat125-keycloak"].ports, undefined);
  assert.deepEqual(compose.services["feat125-caddy"].ports, [
    "127.0.0.1:8443:8443",
    "127.0.0.1:9443:9443",
  ]);
  assert.deepEqual(compose.services["feat125-caddy"].cap_drop, ["ALL"]);
  assert.deepEqual(compose.services["feat125-caddy"].cap_add, ["NET_BIND_SERVICE"]);
  assert.equal(compose.networks.feat125_identity_internal.internal, true);
  assert.equal(compose.networks.feat125_proxy_internal.internal, true);
  assert.notEqual(compose.networks.feat125_host_bridge?.internal, true);
  assert.match(
    compose.services["feat125-keycloak"].healthcheck.test.join(" "),
    /\^HTTP\/1\\\.\[01\] 200/,
  );
  assert.deepEqual(compose.services["feat125-caddy"].healthcheck.test, [
    "CMD",
    "wget",
    "-qO-",
    "http://127.0.0.1:2019/config/",
  ]);
});

test("FEAT-125 Caddy healthcheck uses baseline BusyBox wget instead of an optional curl package", async () => {
  const compose = structuredClone(await loadCompose());
  compose.services["feat125-caddy"].healthcheck.test = [
    "CMD",
    "curl",
    "--fail",
    "http://127.0.0.1:2019/config/",
  ];
  assert.throws(
    () => validateCompose(compose),
    /must use Alpine BusyBox wget against its admin API/,
  );
});
