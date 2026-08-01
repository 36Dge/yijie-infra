import { readFile } from "node:fs/promises";

import { parse } from "yaml";

export const FEAT_125 = Object.freeze({
  feature: "FEAT-125-authoritative-permission-projection",
  contractVersion: "0.3.0-candidate",
  contractCommit: "9ec34abd6e7dfb5a23b0154d467694167224ebbb",
  audience: "https://api.yijie.ai",
  apiCommit: "360a526b679147472e7cc82ca7ac9db9d18a371d",
  desktopCommit: "3798c67d260237928730758c7ec4c1fbe6fcf7d2",
  redirectUriTemplate: "http://127.0.0.1:{ephemeral-port}/oauth/callback",
});

const RESERVED_HOST_SUFFIXES = [
  ".example",
  ".invalid",
  ".localhost",
  ".test",
];

const EXPECTED_KEYS = Object.freeze({
  root: [
    "schema_version",
    "feature",
    "environment",
    "data_policy",
    "contracts",
    "identity",
    "api",
    "desktop",
    "activation",
  ],
  data_policy: ["classification", "real_users", "real_tenants", "merchant_data"],
  contracts: ["version", "full_commit", "access_token_audience"],
  identity: [
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "jwks_uri",
    "revocation_endpoint",
    "public_client_id",
    "redirect_uri_template",
    "authorization_code_flow",
    "pkce_method",
    "id_token_alg",
    "access_token_alg",
    "access_token_ttl_seconds",
    "refresh_rotation",
    "refresh_reuse_revokes_family",
  ],
  api: ["origin", "implementation_full_commit", "permission_projection_enabled", "postgres"],
  postgres: ["major_version", "migration_version", "data", "bootstrap"],
  desktop: [
    "implementation_full_commit",
    "native_auth_enabled",
    "permission_consumer_enabled",
  ],
  activation: ["production", "release", "requires_online_preflight"],
});

export async function loadFeat125NonprodConfig(path) {
  const raw = await readFile(path, "utf8");
  const value = parse(raw);
  if (!isRecord(value)) {
    throw new Error("configuration root must be a YAML mapping");
  }
  return value;
}

export function validateFeat125NonprodConfig(config, { mode = "template" } = {}) {
  if (!isRecord(config)) {
    throw new Error("configuration root must be an object");
  }
  if (!new Set(["template", "ready"]).has(mode)) {
    throw new Error(`unsupported validation mode: ${mode}`);
  }

  const errors = [];
  exactKeys(config, EXPECTED_KEYS.root, "configuration", errors);
  expectEqual(config.schema_version, 1, "schema_version", errors);
  expectEqual(config.feature, FEAT_125.feature, "feature", errors);
  expectEqual(config.environment, "nonproduction", "environment", errors);

  const dataPolicy = expectRecord(config.data_policy, "data_policy", errors);
  exactKeys(dataPolicy, EXPECTED_KEYS.data_policy, "data_policy", errors);
  expectEqual(dataPolicy.classification, "synthetic_only", "data_policy.classification", errors);
  expectEqual(dataPolicy.real_users, false, "data_policy.real_users", errors);
  expectEqual(dataPolicy.real_tenants, false, "data_policy.real_tenants", errors);
  expectEqual(dataPolicy.merchant_data, false, "data_policy.merchant_data", errors);

  const contracts = expectRecord(config.contracts, "contracts", errors);
  exactKeys(contracts, EXPECTED_KEYS.contracts, "contracts", errors);
  expectEqual(contracts.version, FEAT_125.contractVersion, "contracts.version", errors);
  expectEqual(contracts.full_commit, FEAT_125.contractCommit, "contracts.full_commit", errors);
  expectEqual(
    contracts.access_token_audience,
    FEAT_125.audience,
    "contracts.access_token_audience",
    errors,
  );

  const identity = expectRecord(config.identity, "identity", errors);
  exactKeys(identity, EXPECTED_KEYS.identity, "identity", errors);
  expectEqual(
    identity.redirect_uri_template,
    FEAT_125.redirectUriTemplate,
    "identity.redirect_uri_template",
    errors,
  );
  expectEqual(identity.authorization_code_flow, true, "identity.authorization_code_flow", errors);
  expectEqual(identity.pkce_method, "S256", "identity.pkce_method", errors);
  expectEqual(identity.id_token_alg, "RS256", "identity.id_token_alg", errors);
  expectEqual(identity.access_token_alg, "RS256", "identity.access_token_alg", errors);
  expectEqual(identity.access_token_ttl_seconds, 600, "identity.access_token_ttl_seconds", errors);
  expectEqual(identity.refresh_rotation, "required", "identity.refresh_rotation", errors);
  expectEqual(
    identity.refresh_reuse_revokes_family,
    "required",
    "identity.refresh_reuse_revokes_family",
    errors,
  );

  const issuer = expectHttpsUrl(identity.issuer, "identity.issuer", errors, { rootPath: false });
  const identityEndpoints = [
    ["authorization_endpoint", identity.authorization_endpoint],
    ["token_endpoint", identity.token_endpoint],
    ["jwks_uri", identity.jwks_uri],
    ["revocation_endpoint", identity.revocation_endpoint],
  ];
  for (const [name, value] of identityEndpoints) {
    const endpoint = expectHttpsUrl(value, `identity.${name}`, errors, { rootPath: false });
    if (issuer && endpoint && issuer.origin !== endpoint.origin) {
      errors.push(`identity.${name} must use the issuer origin`);
    }
  }

  if (typeof identity.public_client_id !== "string" || identity.public_client_id.length < 3) {
    errors.push("identity.public_client_id must be a non-empty public-client identifier");
  }

  const api = expectRecord(config.api, "api", errors);
  exactKeys(api, EXPECTED_KEYS.api, "api", errors);
  expectEqual(api.implementation_full_commit, FEAT_125.apiCommit, "api.implementation_full_commit", errors);
  expectEqual(api.permission_projection_enabled, false, "api.permission_projection_enabled", errors);
  const apiOrigin = expectHttpsUrl(api.origin, "api.origin", errors, { rootPath: true });

  const postgres = expectRecord(api.postgres, "api.postgres", errors);
  exactKeys(postgres, EXPECTED_KEYS.postgres, "api.postgres", errors);
  expectEqual(postgres.major_version, 16, "api.postgres.major_version", errors);
  expectEqual(postgres.migration_version, 2, "api.postgres.migration_version", errors);
  expectEqual(postgres.data, "synthetic_only", "api.postgres.data", errors);
  expectEqual(
    postgres.bootstrap,
    "synthetic_audited_idempotent_required",
    "api.postgres.bootstrap",
    errors,
  );

  const desktop = expectRecord(config.desktop, "desktop", errors);
  exactKeys(desktop, EXPECTED_KEYS.desktop, "desktop", errors);
  expectEqual(
    desktop.implementation_full_commit,
    FEAT_125.desktopCommit,
    "desktop.implementation_full_commit",
    errors,
  );
  expectEqual(desktop.native_auth_enabled, false, "desktop.native_auth_enabled", errors);
  expectEqual(desktop.permission_consumer_enabled, false, "desktop.permission_consumer_enabled", errors);

  const activation = expectRecord(config.activation, "activation", errors);
  exactKeys(activation, EXPECTED_KEYS.activation, "activation", errors);
  expectEqual(activation.production, false, "activation.production", errors);
  expectEqual(activation.release, false, "activation.release", errors);
  expectEqual(activation.requires_online_preflight, true, "activation.requires_online_preflight", errors);

  const issuerHost = issuer?.hostname.toLowerCase();
  const apiHost = apiOrigin?.hostname.toLowerCase();
  const placeholderClient = identity.public_client_id === "replace-with-nonproduction-public-client-id";
  if (mode === "template") {
    if (!isReservedHost(issuerHost)) {
      errors.push("template identity.issuer must use a reserved non-routable hostname");
    }
    if (!isReservedHost(apiHost)) {
      errors.push("template api.origin must use a reserved non-routable hostname");
    }
    if (!placeholderClient) {
      errors.push("template identity.public_client_id must retain the documented placeholder");
    }
  } else {
    if (isReservedHost(issuerHost)) {
      errors.push("ready identity.issuer must use the assigned nonproduction HTTPS hostname");
    }
    if (isReservedHost(apiHost)) {
      errors.push("ready api.origin must use the assigned nonproduction HTTPS hostname");
    }
    if (placeholderClient) {
      errors.push("ready identity.public_client_id must be assigned by the nonproduction IdP");
    }
  }

  if (errors.length > 0) {
    throw new Error(errors.join("\n"));
  }
  return config;
}

export async function verifyFeat125NonprodOnline(config, { fetchImpl = globalThis.fetch } = {}) {
  if (typeof fetchImpl !== "function") {
    throw new Error("online preflight requires a Fetch API implementation");
  }

  validateFeat125NonprodConfig(config, { mode: "ready" });

  const discovery = await fetchJson(
    oidcDiscoveryUrl(config.identity.issuer),
    "OIDC discovery",
    fetchImpl,
  );
  for (const [field, expected] of [
    ["issuer", config.identity.issuer],
    ["authorization_endpoint", config.identity.authorization_endpoint],
    ["token_endpoint", config.identity.token_endpoint],
    ["jwks_uri", config.identity.jwks_uri],
    ["revocation_endpoint", config.identity.revocation_endpoint],
  ]) {
    if (discovery[field] !== expected) {
      throw new Error(`OIDC discovery ${field} must match the approved configuration`);
    }
  }
  if (!Array.isArray(discovery.response_types_supported) || !discovery.response_types_supported.includes("code")) {
    throw new Error("OIDC discovery must support authorization code response type");
  }
  if (
    !Array.isArray(discovery.code_challenge_methods_supported) ||
    !discovery.code_challenge_methods_supported.includes("S256")
  ) {
    throw new Error("OIDC discovery must support PKCE S256");
  }
  if (
    !Array.isArray(discovery.id_token_signing_alg_values_supported) ||
    !discovery.id_token_signing_alg_values_supported.includes("RS256")
  ) {
    throw new Error("OIDC discovery must support RS256 ID token signing");
  }

  const jwks = await fetchJson(config.identity.jwks_uri, "identity JWKS", fetchImpl);
  if (!Array.isArray(jwks.keys)) {
    throw new Error("identity JWKS response must contain a keys array");
  }
  const rsaSigningKey = jwks.keys.some(
    (key) =>
      isRecord(key) &&
      key.kty === "RSA" &&
      typeof key.kid === "string" &&
      key.kid.length > 0 &&
      (key.use === undefined || key.use === "sig") &&
      (key.alg === undefined || key.alg === "RS256"),
  );
  if (!rsaSigningKey) {
    throw new Error("identity JWKS must expose at least one keyed RSA/RS256 signing key");
  }

  const health = await fetchJson(new URL("/healthz", config.api.origin), "API /healthz", fetchImpl);
  if (
    !isRecord(health) ||
    health.service !== "yijie-api" ||
    health.environment !== "nonproduction" ||
    health.status !== "ok" ||
    health.database !== "connected"
  ) {
    throw new Error("API /healthz must identify a connected yijie-api nonproduction instance");
  }
  const readiness = await fetchJson(new URL("/readyz", config.api.origin), "API /readyz", fetchImpl);
  if (!isRecord(readiness) || readiness.status !== "ready") {
    throw new Error("API /readyz must report ready");
  }

  const disabledEndpoint = new URL("/v1/me/tenants", config.api.origin);
  const disabledResponse = await fetchWithDeadline(disabledEndpoint, fetchImpl);
  if (disabledResponse.status !== 404) {
    throw new Error(
      `API permission projection must remain disabled before activation; expected 404, got ${disabledResponse.status}`,
    );
  }
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function expectRecord(value, name, errors) {
  if (!isRecord(value)) {
    errors.push(`${name} must be a mapping`);
    return {};
  }
  return value;
}

function exactKeys(value, expected, name, errors) {
  if (!isRecord(value)) {
    return;
  }
  const expectedSet = new Set(expected);
  for (const key of Object.keys(value)) {
    if (!expectedSet.has(key)) {
      errors.push(`${name} contains unsupported field: ${key}`);
    }
  }
  for (const key of expected) {
    if (!Object.hasOwn(value, key)) {
      errors.push(`${name} is missing required field: ${key}`);
    }
  }
}

function expectEqual(actual, expected, name, errors) {
  if (actual !== expected) {
    errors.push(`${name} must equal ${JSON.stringify(expected)}`);
  }
}

function expectHttpsUrl(value, name, errors, { rootPath }) {
  if (typeof value !== "string") {
    errors.push(`${name} must be an HTTPS URL`);
    return undefined;
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    errors.push(`${name} must be an absolute HTTPS URL`);
    return undefined;
  }
  if (url.protocol !== "https:") {
    errors.push(`${name} must use HTTPS`);
  }
  if (url.username || url.password) {
    errors.push(`${name} must not contain user information`);
  }
  if (url.search || url.hash) {
    errors.push(`${name} must not contain a query or fragment`);
  }
  if (rootPath && url.pathname !== "/") {
    errors.push(`${name} must be an origin URL with root path`);
  }
  return url;
}

function isReservedHost(hostname) {
  if (typeof hostname !== "string") {
    return false;
  }
  return RESERVED_HOST_SUFFIXES.some(
    (suffix) => hostname === suffix.slice(1) || hostname.endsWith(suffix),
  );
}

async function fetchJson(url, label, fetchImpl) {
  const response = await fetchWithDeadline(url, fetchImpl);
  if (!response.ok) {
    throw new Error(`${label} returned HTTP ${response.status}`);
  }
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().includes("json")) {
    throw new Error(`${label} must return JSON`);
  }
  const contentLength = Number(response.headers.get("content-length") ?? "0");
  if (Number.isFinite(contentLength) && contentLength > 262_144) {
    throw new Error(`${label} response exceeds 256 KiB`);
  }
  const bytes = await readBoundedBody(response, label, 262_144);
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new Error(`${label} returned invalid JSON`);
  }
}

function oidcDiscoveryUrl(issuer) {
  const url = new URL(issuer);
  const issuerPath = url.pathname.endsWith("/") ? url.pathname.slice(0, -1) : url.pathname;
  url.pathname = `${issuerPath}/.well-known/openid-configuration`;
  url.search = "";
  url.hash = "";
  return url;
}

async function readBoundedBody(response, label, limit) {
  if (!response.body) {
    return new Uint8Array();
  }
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      throw new Error(`${label} response exceeds 256 KiB`);
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

async function fetchWithDeadline(url, fetchImpl) {
  try {
    return await fetchImpl(url, {
      redirect: "error",
      signal: AbortSignal.timeout(5_000),
      headers: { accept: "application/json" },
    });
  } catch (error) {
    throw new Error(`nonproduction online preflight request failed: ${error.message}`);
  }
}
