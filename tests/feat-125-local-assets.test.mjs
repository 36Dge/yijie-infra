import assert from "node:assert/strict";
import { test } from "node:test";

import {
  loadFeat125LocalAssets,
  validateCaddyfile,
  validateFeat125LocalAssets,
  validateRealm,
} from "../scripts/feat-125-local-assets.mjs";

test("committed FEAT-125 local realm and Caddyfile satisfy the security model", async () => {
  const assets = await loadFeat125LocalAssets();
  assert.doesNotThrow(() => validateFeat125LocalAssets(assets));
});

test("realm rejects a wildcard callback even on loopback", async () => {
  const { realm } = await loadFeat125LocalAssets();
  const changed = structuredClone(realm);
  const desktop = changed.clients.find(
    (client) => client.clientId === "yijie-desktop-feat-125-local",
  );
  desktop.redirectUris = ["http://127.0.0.1/*"];

  assert.throws(() => validateRealm(changed), /exact path-preserving loopback redirect/);
});

test("realm rejects committed credential material", async () => {
  const { realm } = await loadFeat125LocalAssets();
  const changed = structuredClone(realm);
  changed.clients[1].secret = "must-not-be-committed";

  assert.throws(() => validateRealm(changed), /forbidden credential field/);
});

test("realm rejects a missing or static Desktop nbf mapping", async () => {
  const { realm } = await loadFeat125LocalAssets();
  const missing = structuredClone(realm);
  const missingDesktop = missing.clients.find(
    (client) => client.clientId === "yijie-desktop-feat-125-local",
  );
  missingDesktop.protocolMappers = missingDesktop.protocolMappers.filter(
    (mapper) => mapper.name !== "yijie-api-not-before",
  );
  assert.throws(() => validateRealm(missing), /dynamic numeric nbf/);

  const hardcoded = structuredClone(realm);
  const hardcodedDesktop = hardcoded.clients.find(
    (client) => client.clientId === "yijie-desktop-feat-125-local",
  );
  const nbfMapper = hardcodedDesktop.protocolMappers.find(
    (mapper) => mapper.name === "yijie-api-not-before",
  );
  nbfMapper.protocolMapper = "oidc-hardcoded-claim-mapper";
  nbfMapper.config = {
    "claim.name": "nbf",
    "claim.value": "0",
    "jsonType.label": "long",
    "access.token.claim": "true",
  };
  assert.throws(() => validateRealm(hardcoded), /dynamic numeric nbf/);
});

test("Caddyfile rejects insecure upstream TLS bypass", async () => {
  const { caddyfile } = await loadFeat125LocalAssets();
  assert.throws(
    () => validateCaddyfile(`${caddyfile}\ntls_insecure_skip_verify`),
    /forbidden setting/,
  );
});

test("Caddyfile requires the Tasks denial before the API proxy", async () => {
  const { caddyfile } = await loadFeat125LocalAssets();
  const changed = caddyfile.replace("respond @legacy_tasks 404", "");
  assert.throws(() => validateCaddyfile(changed), /reject \/v1\/tasks/);
});
