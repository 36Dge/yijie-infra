import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  loadFeat125LocalLabConfig,
  inspectCaCertificate,
  validateFeat125LocalLabConfig,
  verifyFeat125LocalLabOnline,
} from "../scripts/feat-125-local-config.mjs";

const templatePath = new URL(
  "../environments/local/feat-125.local-lab.template.yaml",
  import.meta.url,
);
const apiCommit = "360a526b679147472e7cc82ca7ac9db9d18a371d";
const desktopCommit = "3798c67d260237928730758c7ec4c1fbe6fcf7d2";
const caDigest = "a".repeat(64);
const committedRepositoryEvidence = {
  apiRepository: "api-repository",
  desktopRepository: "desktop-repository",
  worktreeReferenceImpl: async (repository) =>
    repository === "api-repository" ? `commit:${apiCommit}` : `commit:${desktopCommit}`,
};

test("committed FEAT-125 local-lab template is safe and valid", async () => {
  const config = await loadFeat125LocalLabConfig(templatePath);
  assert.equal(
    await validateFeat125LocalLabConfig(config, { mode: "template" }),
    config,
  );
});

test("local-lab ready mode requires exact commits, loopback DNS, and the pinned CA", async () => {
  const config = await readyConfig();
  assert.equal(await validateReady(config), config);
});

test("local-lab requires exact localhost and rejects a loopback-resolved .test alias", async () => {
  const config = await readyConfig();
  setIdentityHost(config, "identity.yijie.test");
  let lookupCalled = false;

  await assert.rejects(
    validateReady(config, {
      lookupImpl: async () => {
        lookupCalled = true;
        return [{ address: "127.0.0.1" }];
      },
    }),
    /identity.issuer hostname must equal localhost/,
  );
  assert.equal(lookupCalled, false);
});

for (const [name, mutate, expected] of [
  [
    "insecure TLS bypass",
    (config) => {
      config.tls.insecure_skip_verify = true;
    },
    /tls.insecure_skip_verify must equal false/,
  ],
  [
    "production activation",
    (config) => {
      config.activation.production = true;
    },
    /activation.production must equal false/,
  ],
  [
    "disabled local activation",
    (config) => {
      config.activation.local = false;
    },
    /activation.local must equal true/,
  ],
  [
    "disabled local permission projection",
    (config) => {
      config.api.permission_projection_enabled = false;
    },
    /api.permission_projection_enabled must equal true/,
  ],
  [
    "default API service profile",
    (config) => {
      config.api.service_profile = "default";
    },
    /api.service_profile must equal "feat-125-local-lab"/,
  ],
  [
    "real tenants",
    (config) => {
      config.data_policy.real_tenants = true;
    },
    /data_policy.real_tenants must equal false/,
  ],
  [
    "shared or unreviewed API database",
    (config) => {
      config.api.postgres.database = "yijie_api";
    },
    /api.postgres.database must equal "yijie_api_feat125_local"/,
  ],
  [
    "generic bootstrap profile",
    (config) => {
      config.api.postgres.bootstrap_profile = "default";
    },
    /api.postgres.bootstrap_profile must equal "feat-125-local-lab"/,
  ],
  [
    "client secret material",
    (config) => {
      config.identity.client_secret = "forbidden";
    },
    /identity contains unsupported field: client_secret/,
  ],
  [
    "wrong callback path",
    (config) => {
      config.identity.redirect_uri_template = "http://127.0.0.1:{ephemeral-port}/callback";
    },
    /identity.redirect_uri_template must equal/,
  ],
  [
    "floating Keycloak image",
    (config) => {
      config.runtime.keycloak_image = "quay.io/keycloak/keycloak:latest";
    },
    /runtime.keycloak_image must equal/,
  ],
]) {
  test(`local-lab rejects ${name}`, async () => {
    const config = await readyConfig();
    mutate(config);
    await assert.rejects(validateReady(config), expected);
  });
}

test("local-lab rejects a CA digest that does not match the file", async () => {
  const config = await readyConfig();
  await assert.rejects(
    validateReady(config, {
      inspectCaImpl: async () => ({
        sha256: "b".repeat(64),
        isCertificateAuthority: true,
      }),
    }),
    /does not match/,
  );
});

test("local-lab CA inspection rejects a group-readable certificate before parsing", async () => {
  const directory = await mkdtemp(join(tmpdir(), "yijie-feat125-ca-"));
  const path = join(directory, "root.crt");
  try {
    await writeFile(path, "not-a-certificate", { mode: 0o600 });
    await chmod(path, 0o640);
    await assert.rejects(inspectCaCertificate(path), /owner-only 0400 or 0600/);
  } finally {
    await rm(directory, { recursive: true });
  }
});

test("local-lab CA inspection rejects a PEM certificate bundle", async () => {
  const directory = await mkdtemp(join(tmpdir(), "yijie-feat125-ca-"));
  const path = join(directory, "root.crt");
  const certificate = "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n";
  try {
    await writeFile(path, certificate.repeat(2), { mode: 0o600 });
    await assert.rejects(inspectCaCertificate(path), /exactly one public PEM certificate/);
  } finally {
    await rm(directory, { recursive: true });
  }
});

test("local-lab accepts and pins an explicit reviewed worktree candidate reference", async () => {
  const config = await readyConfig();
  const apiReference = setCandidateEvidence(config.api, "b".repeat(40), "c".repeat(64));
  const desktopReference = setCandidateEvidence(config.desktop, "d".repeat(40), "e".repeat(64));

  assert.equal(
    await validateFeat125LocalLabConfig(config, {
      mode: "local-lab",
      expectedApiReference: apiReference,
      expectedDesktopReference: desktopReference,
      apiRepository: "api-repository",
      desktopRepository: "desktop-repository",
      worktreeReferenceImpl: async (repository) =>
        repository === "api-repository" ? apiReference : desktopReference,
      lookupImpl: loopbackLookup,
      inspectCaImpl: validCa,
    }),
    config,
  );
  await assert.rejects(
    validateFeat125LocalLabConfig(config, {
      mode: "local-lab",
      expectedApiReference: `candidate:${"b".repeat(40)}:${"f".repeat(64)}`,
      expectedDesktopReference: desktopReference,
      apiRepository: "api-repository",
      desktopRepository: "desktop-repository",
      worktreeReferenceImpl: async (repository) =>
        repository === "api-repository" ? apiReference : desktopReference,
      lookupImpl: loopbackLookup,
      inspectCaImpl: validCa,
    }),
    /api.implementation_evidence must equal/,
  );
  await assert.rejects(
    validateFeat125LocalLabConfig(config, {
      mode: "local-lab",
      expectedApiReference: apiReference,
      expectedDesktopReference: desktopReference,
      apiRepository: "api-repository",
      desktopRepository: "desktop-repository",
      worktreeReferenceImpl: async (repository) =>
        repository === "api-repository"
          ? `candidate:${"b".repeat(40)}:${"f".repeat(64)}`
          : desktopReference,
      lookupImpl: loopbackLookup,
      inspectCaImpl: validCa,
    }),
    /api implementation evidence no longer matches the repository snapshot/,
  );
});

test("online preflight checks callback registration, active projection, and both Tasks boundaries", async () => {
  const config = await readyConfig();
  const calls = [];
  const responses = [
    ...successfulOnlinePreamble(config),
    ...notFoundResponses(6),
  ];

  await verifyFeat125LocalLabOnline(config, {
    expectedApiCommit: apiCommit,
    expectedDesktopCommit: desktopCommit,
    ...committedRepositoryEvidence,
    lookupImpl: loopbackLookup,
    inspectCaImpl: validCa,
    enforceProcessCa: false,
    fetchImpl: async (url, options) => {
      calls.push({ url: String(url), method: options.method ?? "GET", redirect: options.redirect });
      return responses.shift();
    },
  });

  assert.deepEqual(
    calls.map(({ method, url }) => `${method} ${new URL(url).pathname}`),
    [
      "GET /realms/yijie-local/.well-known/openid-configuration",
      "GET /realms/yijie-local/protocol/openid-connect/certs",
      "GET /realms/yijie-local/protocol/openid-connect/auth",
      "GET /realms/yijie-local/protocol/openid-connect/auth",
      "GET /healthz",
      "GET /readyz",
      "GET /v1/me/tenants",
      "GET /v1/me/capabilities",
      "GET /v1/tasks",
      "POST /v1/tasks",
      "GET /v1/tasks/synthetic-never-exists",
      "GET /v1/tasks",
      "POST /v1/tasks",
      "GET /v1/tasks/synthetic-never-exists",
    ],
  );
  assert.equal(new URL(calls[2].url).searchParams.get("redirect_uri"), "http://127.0.0.1:49152/oauth/callback");
  assert.equal(
    new URL(calls[3].url).searchParams.get("redirect_uri"),
    "http://127.0.0.1:49152/oauth/not-callback",
  );
  assert.deepEqual(calls.map(({ redirect }) => redirect), [
    "error",
    "error",
    "manual",
    "manual",
    "error",
    "error",
    "error",
    "error",
    "error",
    "error",
    "error",
    "error",
    "error",
    "error",
  ]);
  assert.deepEqual(
    calls.slice(8).map(({ url }) => new URL(url).origin),
    [
      "https://localhost:9443",
      "https://localhost:9443",
      "https://localhost:9443",
      "http://127.0.0.1:18080",
      "http://127.0.0.1:18080",
      "http://127.0.0.1:18080",
    ],
  );
  assert.equal(responses.length, 0);
  assert.equal(calls[7].method, "GET");
  assert.equal(calls[7].url.includes("/v1/me/capabilities"), true);
});

test("online preflight requires stable unauthenticated capabilities semantics", async () => {
  const config = await readyConfig();
  const responses = successfulOnlinePreamble(config);
  responses[responses.length - 1] = jsonResponse(
    { code: "tenant_context_invalid", message: "wrong order" },
    { status: 400 },
  );

  await assert.rejects(
    verifyFeat125LocalLabOnline(config, {
      expectedApiCommit: apiCommit,
      expectedDesktopCommit: desktopCommit,
      ...committedRepositoryEvidence,
      lookupImpl: loopbackLookup,
      inspectCaImpl: validCa,
      enforceProcessCa: false,
      fetchImpl: async () => responses.shift(),
    }),
    /unauthenticated \/v1\/me\/capabilities must require bearer authentication/,
  );
});

test("online preflight fails closed when Caddy Tasks reaches an application handler", async () => {
  const config = await readyConfig();
  const responses = [
    ...successfulOnlinePreamble(config),
    jsonResponse({ code: "unauthorized" }, { status: 401 }),
  ];

  await assert.rejects(
    verifyFeat125LocalLabOnline(config, {
      expectedApiCommit: apiCommit,
      expectedDesktopCommit: desktopCommit,
      ...committedRepositoryEvidence,
      lookupImpl: loopbackLookup,
      inspectCaImpl: validCa,
      enforceProcessCa: false,
      fetchImpl: async () => responses.shift(),
    }),
    /Caddy edge legacy Tasks boundary must return 404/,
  );
});

test("online preflight fails closed when the direct API profile registers Tasks", async () => {
  const config = await readyConfig();
  const responses = [
    ...successfulOnlinePreamble(config),
    ...notFoundResponses(3),
    jsonResponse({ code: "unauthorized" }, { status: 401 }),
  ];

  await assert.rejects(
    verifyFeat125LocalLabOnline(config, {
      expectedApiCommit: apiCommit,
      expectedDesktopCommit: desktopCommit,
      ...committedRepositoryEvidence,
      lookupImpl: loopbackLookup,
      inspectCaImpl: validCa,
      enforceProcessCa: false,
      fetchImpl: async () => responses.shift(),
    }),
    /direct local-lab API profile legacy Tasks boundary must return 404/,
  );
});

test("online callback rejection evidence never leaks query credentials", async () => {
  const config = await readyConfig();
  const responses = [
    jsonResponse(discovery(config)),
    jsonResponse({ keys: [{ kty: "RSA", kid: "local-1", alg: "RS256" }] }),
    new Response("login", { status: 200, headers: { "content-type": "text/html" } }),
    new Response(null, {
      status: 302,
      headers: {
        location: "http://127.0.0.1:49152/oauth/not-callback?code=secret-token&state=secret-state",
      },
    }),
  ];

  await assert.rejects(
    verifyFeat125LocalLabOnline(config, {
      expectedApiCommit: apiCommit,
      expectedDesktopCommit: desktopCommit,
      ...committedRepositoryEvidence,
      lookupImpl: loopbackLookup,
      inspectCaImpl: validCa,
      enforceProcessCa: false,
      fetchImpl: async () => responses.shift(),
    }),
    (error) => {
      assert.match(error.message, /location=http:\/\/127\.0\.0\.1:49152\/oauth\/not-callback/);
      assert.doesNotMatch(error.message, /secret-token|secret-state|\?/);
      return true;
    },
  );
});

async function readyConfig() {
  const config = structuredClone(await loadFeat125LocalLabConfig(templatePath));
  config.tls.ca_certificate_sha256 = caDigest;
  return config;
}

function validateReady(config, overrides = {}) {
  return validateFeat125LocalLabConfig(config, {
    mode: "local-lab",
    expectedApiCommit: apiCommit,
    expectedDesktopCommit: desktopCommit,
    ...committedRepositoryEvidence,
    lookupImpl: loopbackLookup,
    inspectCaImpl: validCa,
    ...overrides,
  });
}

function loopbackLookup() {
  return Promise.resolve([{ address: "127.0.0.1" }, { address: "::1" }]);
}

function validCa() {
  return Promise.resolve({ sha256: caDigest, isCertificateAuthority: true });
}

function setIdentityHost(config, hostname) {
  const oldOrigin = "https://localhost:8443";
  const newOrigin = `https://${hostname}:8443`;
  for (const field of [
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "jwks_uri",
    "revocation_endpoint",
  ]) {
    config.identity[field] = config.identity[field].replace(oldOrigin, newOrigin);
  }
}

function setCandidateEvidence(section, baseCommit, digest) {
  section.implementation_evidence = {
    state: "reviewed_worktree_candidate",
    full_commit: null,
    base_commit: baseCommit,
    candidate_tree_sha256: digest,
  };
  return `candidate:${baseCommit}:${digest}`;
}

function successfulOnlinePreamble(config) {
  return [
    jsonResponse(discovery(config)),
    jsonResponse({ keys: [{ kty: "RSA", kid: "local-1", use: "sig", alg: "RS256" }] }),
    new Response("login", { status: 200, headers: { "content-type": "text/html" } }),
    new Response("invalid redirect", { status: 400 }),
    jsonResponse({
      service: "yijie-api",
      environment: "nonproduction",
      status: "ok",
      database: "connected",
    }),
    jsonResponse({ status: "ready" }),
    jsonResponse(
      { code: "unauthorized", message: "valid bearer authentication is required" },
      {
        status: 401,
        headers: { "www-authenticate": "Bearer", "cache-control": "no-store" },
      },
    ),
    jsonResponse(
      { code: "unauthorized", message: "valid bearer authentication is required" },
      {
        status: 401,
        headers: { "www-authenticate": "Bearer", "cache-control": "no-store" },
      },
    ),
  ];
}

function notFoundResponses(count) {
  return Array.from({ length: count }, () => new Response("not found", { status: 404 }));
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
