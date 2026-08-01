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
