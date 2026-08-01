import assert from "node:assert/strict";
import { test } from "node:test";

import {
  loadFeat125NonprodConfig,
  validateFeat125NonprodConfig,
  verifyFeat125NonprodOnline,
} from "../scripts/feat-125-nonprod-config.mjs";

const templatePath = new URL(
  "../environments/nonproduction/feat-125.template.yaml",
  import.meta.url,
);

test("committed FEAT-125 template is safe and valid", async () => {
  const config = await loadFeat125NonprodConfig(templatePath);
  assert.equal(validateFeat125NonprodConfig(config, { mode: "template" }), config);
});

test("assigned vendor-neutral nonproduction configuration passes offline readiness", async () => {
  const config = await readyConfig();
  assert.equal(validateFeat125NonprodConfig(config, { mode: "ready" }), config);
});

test("readiness rejects unassigned hosts and client identifier", async () => {
  const config = await loadFeat125NonprodConfig(templatePath);
  assert.throws(
    () => validateFeat125NonprodConfig(config, { mode: "ready" }),
    /assigned nonproduction HTTPS hostname/,
  );
});

for (const [name, mutate, expected] of [
  [
    "feature flags enabled before activation",
    (config) => {
      config.api.permission_projection_enabled = true;
    },
    /api.permission_projection_enabled must equal false/,
  ],
  [
    "production environment",
    (config) => {
      config.environment = "production";
    },
    /environment must equal "nonproduction"/,
  ],
  [
    "real user data",
    (config) => {
      config.data_policy.real_users = true;
    },
    /data_policy.real_users must equal false/,
  ],
  [
    "client secret material",
    (config) => {
      config.identity.client_secret = "must-never-be-committed";
    },
    /identity contains unsupported field: client_secret/,
  ],
  [
    "non-HTTPS issuer",
    (config) => {
      config.identity.issuer = "http://identity.staging.yijie.ai/";
    },
    /identity.issuer must use HTTPS/,
  ],
  [
    "cross-origin token endpoint",
    (config) => {
      config.identity.token_endpoint = "https://other.staging.yijie.ai/oauth2/token";
    },
    /identity.token_endpoint must use the issuer origin/,
  ],
  [
    "wrong loopback callback",
    (config) => {
      config.identity.redirect_uri_template = "http://localhost/callback";
    },
    /identity.redirect_uri_template must equal/,
  ],
  [
    "wrong token audience",
    (config) => {
      config.contracts.access_token_audience = "https://staging-api.yijie.ai";
    },
    /contracts.access_token_audience must equal/,
  ],
  [
    "wrong contract candidate",
    (config) => {
      config.contracts.full_commit = "0000000000000000000000000000000000000000";
    },
    /contracts.full_commit must equal/,
  ],
  [
    "wrong migration version",
    (config) => {
      config.api.postgres.migration_version = 1;
    },
    /api.postgres.migration_version must equal 2/,
  ],
]) {
  test(`readiness rejects ${name}`, async () => {
    const config = await readyConfig();
    mutate(config);
    assert.throws(() => validateFeat125NonprodConfig(config, { mode: "ready" }), expected);
  });
}

test("online preflight verifies RSA signing key, health, readiness, and disabled projection", async () => {
  const config = await readyConfig();
  const calls = [];
  const responses = [
    jsonResponse(discovery(config)),
    jsonResponse({ keys: [{ kty: "RSA", kid: "nonprod-1", use: "sig", alg: "RS256" }] }),
    jsonResponse({
      service: "yijie-api",
      environment: "nonproduction",
      status: "ok",
      database: "connected",
    }),
    jsonResponse({ status: "ready" }),
    new Response("not found", { status: 404 }),
  ];

  await verifyFeat125NonprodOnline(config, {
    fetchImpl: async (url, options) => {
      calls.push({ url: String(url), options });
      return responses.shift();
    },
  });

  assert.deepEqual(
    calls.map(({ url }) => new URL(url).pathname),
    [
      "/.well-known/openid-configuration",
      "/.well-known/jwks.json",
      "/healthz",
      "/readyz",
      "/v1/me/tenants",
    ],
  );
  assert.ok(calls.every(({ options }) => options.redirect === "error"));
});

test("online preflight rejects activation before the permission endpoint is hidden", async () => {
  const config = await readyConfig();
  const responses = [
    jsonResponse(discovery(config)),
    jsonResponse({ keys: [{ kty: "RSA", kid: "nonprod-1", alg: "RS256" }] }),
    jsonResponse({
      service: "yijie-api",
      environment: "nonproduction",
      status: "ok",
      database: "connected",
    }),
    jsonResponse({ status: "ready" }),
    jsonResponse({ code: "unauthorized" }, { status: 401 }),
  ];

  await assert.rejects(
    verifyFeat125NonprodOnline(config, {
      fetchImpl: async () => responses.shift(),
    }),
    /must remain disabled before activation; expected 404, got 401/,
  );
});

test("online preflight rejects discovery drift before trusting JWKS or API", async () => {
  const config = await readyConfig();
  const metadata = discovery(config);
  metadata.token_endpoint = "https://identity.staging.yijie.ai/oauth2/unapproved-token";

  await assert.rejects(
    verifyFeat125NonprodOnline(config, {
      fetchImpl: async () => jsonResponse(metadata),
    }),
    /OIDC discovery token_endpoint must match the approved configuration/,
  );
});

test("online preflight rejects an API that is not the approved nonproduction service", async () => {
  const config = await readyConfig();
  const responses = [
    jsonResponse(discovery(config)),
    jsonResponse({ keys: [{ kty: "RSA", kid: "nonprod-1", alg: "RS256" }] }),
    jsonResponse({
      service: "yijie-api",
      environment: "production",
      status: "ok",
      database: "connected",
    }),
  ];

  await assert.rejects(
    verifyFeat125NonprodOnline(config, {
      fetchImpl: async () => responses.shift(),
    }),
    /must identify a connected yijie-api nonproduction instance/,
  );
});

test("online preflight rejects oversized streaming responses", async () => {
  const config = await readyConfig();
  const oversized = new Response(new Uint8Array(262_145), {
    headers: { "content-type": "application/json" },
  });

  await assert.rejects(
    verifyFeat125NonprodOnline(config, {
      fetchImpl: async () => oversized,
    }),
    /OIDC discovery response exceeds 256 KiB/,
  );
});

async function readyConfig() {
  const config = structuredClone(await loadFeat125NonprodConfig(templatePath));
  const identityOrigin = "https://identity.staging.yijie.ai";
  config.identity.issuer = `${identityOrigin}/`;
  config.identity.authorization_endpoint = `${identityOrigin}/oauth2/authorize`;
  config.identity.token_endpoint = `${identityOrigin}/oauth2/token`;
  config.identity.jwks_uri = `${identityOrigin}/.well-known/jwks.json`;
  config.identity.revocation_endpoint = `${identityOrigin}/oauth2/revoke`;
  config.identity.public_client_id = "yijie-desktop-feat-125-staging";
  config.api.origin = "https://api.staging.yijie.ai/";
  return config;
}

function jsonResponse(body, init = {}) {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: { "content-type": "application/json", ...init.headers },
  });
}

function discovery(config) {
  return {
    issuer: config.identity.issuer,
    authorization_endpoint: config.identity.authorization_endpoint,
    token_endpoint: config.identity.token_endpoint,
    jwks_uri: config.identity.jwks_uri,
    revocation_endpoint: config.identity.revocation_endpoint,
    response_types_supported: ["code"],
    code_challenge_methods_supported: ["S256"],
    id_token_signing_alg_values_supported: ["RS256"],
  };
}
