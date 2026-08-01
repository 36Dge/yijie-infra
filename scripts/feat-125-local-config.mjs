import { X509Certificate, createHash } from "node:crypto";
import { lookup as dnsLookup } from "node:dns/promises";
import { lstat, readFile } from "node:fs/promises";
import { isIP } from "node:net";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { parse } from "yaml";

import {
  FEAT_125_LOCAL_AUDIENCE,
  FEAT_125_LOCAL_CLIENT_ID,
} from "./feat-125-local-assets.mjs";
import {
  FEAT_125_LOCAL_IMAGES,
  FEAT_125_LOCAL_PROFILE,
} from "./compose-model.mjs";
import { FEAT_125 } from "./feat-125-nonprod-config.mjs";
import { computeWorktreeReference } from "./feat-125-worktree-evidence.mjs";

const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const TEMPLATE_CA_DIGEST = "replace-with-exported-caddy-root-ca-sha256";
const LOCAL_CA_PATH = "environments/local/generated/feat-125-caddy-root.crt";
const SHA_PATTERN = /^[a-f0-9]{40}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const MAX_JSON_BYTES = 262_144;
const SYNTHETIC_TENANT_ID = "12500000-0000-4000-8000-100000000001";

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
    "tls",
    "runtime",
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
  api: [
    "origin",
    "service_profile",
    "implementation_evidence",
    "health_environment",
    "permission_projection_enabled",
    "postgres",
  ],
  postgres: [
    "major_version",
    "host",
    "port",
    "database",
    "sslmode",
    "migration_version",
    "data",
    "bootstrap_profile",
    "bootstrap",
  ],
  desktop: [
    "implementation_evidence",
    "native_auth_enabled",
    "permission_consumer_enabled",
  ],
  tls: ["ca_certificate_path", "ca_certificate_sha256", "insecure_skip_verify"],
  runtime: [
    "compose_profile",
    "identity_https_port",
    "api_https_port",
    "api_upstream",
    "api_direct_origin",
    "legacy_tasks_ingress",
    "keycloak_image",
    "keycloak_postgres_image",
    "caddy_image",
  ],
  activation: ["local", "production", "release", "requires_online_preflight"],
  implementation_evidence: ["state", "full_commit", "base_commit", "candidate_tree_sha256"],
});

export async function loadFeat125LocalLabConfig(path) {
  const raw = await readFile(path, "utf8");
  const value = parse(raw);
  if (!isRecord(value)) {
    throw new Error("local-lab configuration root must be a YAML mapping");
  }
  return value;
}

export async function validateFeat125LocalLabConfig(
  config,
  {
    mode = "template",
    expectedApiCommit,
    expectedDesktopCommit,
    expectedApiReference,
    expectedDesktopReference,
    apiRepository,
    desktopRepository,
    worktreeReferenceImpl = computeWorktreeReference,
    lookupImpl = dnsLookup,
    inspectCaImpl = inspectCaCertificate,
  } = {},
) {
  if (!isRecord(config)) {
    throw new Error("local-lab configuration root must be an object");
  }
  if (!new Set(["template", "local-lab"]).has(mode)) {
    throw new Error(`unsupported local-lab validation mode: ${mode}`);
  }

  const errors = [];
  exactKeys(config, EXPECTED_KEYS.root, "configuration", errors);
  expectEqual(config.schema_version, 1, "schema_version", errors);
  expectEqual(config.feature, FEAT_125.feature, "feature", errors);
  expectEqual(config.environment, "local_lab", "environment", errors);

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
    FEAT_125_LOCAL_AUDIENCE,
    "contracts.access_token_audience",
    errors,
  );

  const identity = expectRecord(config.identity, "identity", errors);
  exactKeys(identity, EXPECTED_KEYS.identity, "identity", errors);
  expectEqual(identity.public_client_id, FEAT_125_LOCAL_CLIENT_ID, "identity.public_client_id", errors);
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
    "provider_limit_documented",
    "identity.refresh_reuse_revokes_family",
    errors,
  );

  const issuer = expectHttpsUrl(identity.issuer, "identity.issuer", errors, {
    path: "/realms/yijie-local",
    port: "8443",
  });
  const expectedIdentityEndpoints = issuer
    ? new Map([
        ["authorization_endpoint", `${issuer.origin}${issuer.pathname}/protocol/openid-connect/auth`],
        ["token_endpoint", `${issuer.origin}${issuer.pathname}/protocol/openid-connect/token`],
        ["jwks_uri", `${issuer.origin}${issuer.pathname}/protocol/openid-connect/certs`],
        ["revocation_endpoint", `${issuer.origin}${issuer.pathname}/protocol/openid-connect/revoke`],
      ])
    : new Map();
  for (const [field, expected] of expectedIdentityEndpoints) {
    expectEqual(identity[field], expected, `identity.${field}`, errors);
    expectHttpsUrl(identity[field], `identity.${field}`, errors, { origin: issuer.origin });
  }

  const api = expectRecord(config.api, "api", errors);
  exactKeys(api, EXPECTED_KEYS.api, "api", errors);
  const apiOrigin = expectHttpsUrl(api.origin, "api.origin", errors, {
    path: "/",
    port: "9443",
  });
  expectEqual(api.service_profile, "feat-125-local-lab", "api.service_profile", errors);
  expectEqual(api.health_environment, "nonproduction", "api.health_environment", errors);
  expectEqual(api.permission_projection_enabled, true, "api.permission_projection_enabled", errors);
  const postgres = expectRecord(api.postgres, "api.postgres", errors);
  exactKeys(postgres, EXPECTED_KEYS.postgres, "api.postgres", errors);
  expectEqual(postgres.major_version, 16, "api.postgres.major_version", errors);
  expectEqual(postgres.host, "127.0.0.1", "api.postgres.host", errors);
  expectEqual(postgres.port, 5432, "api.postgres.port", errors);
  expectEqual(postgres.database, "yijie_api_feat125_local", "api.postgres.database", errors);
  expectEqual(postgres.sslmode, "disable", "api.postgres.sslmode", errors);
  expectEqual(postgres.migration_version, 2, "api.postgres.migration_version", errors);
  expectEqual(postgres.data, "synthetic_only", "api.postgres.data", errors);
  expectEqual(
    postgres.bootstrap_profile,
    "feat-125-local-lab",
    "api.postgres.bootstrap_profile",
    errors,
  );
  expectEqual(
    postgres.bootstrap,
    "synthetic_audited_idempotent_required",
    "api.postgres.bootstrap",
    errors,
  );

  const desktop = expectRecord(config.desktop, "desktop", errors);
  exactKeys(desktop, EXPECTED_KEYS.desktop, "desktop", errors);
  expectEqual(desktop.native_auth_enabled, false, "desktop.native_auth_enabled", errors);
  expectEqual(desktop.permission_consumer_enabled, false, "desktop.permission_consumer_enabled", errors);

  validateImplementationPins(
    config,
    mode,
    expectedApiReference ?? referenceFromLegacyCommit(expectedApiCommit),
    expectedDesktopReference ?? referenceFromLegacyCommit(expectedDesktopCommit),
    errors,
  );

  const tls = expectRecord(config.tls, "tls", errors);
  exactKeys(tls, EXPECTED_KEYS.tls, "tls", errors);
  expectEqual(tls.ca_certificate_path, LOCAL_CA_PATH, "tls.ca_certificate_path", errors);
  expectEqual(tls.insecure_skip_verify, false, "tls.insecure_skip_verify", errors);
  if (mode === "template") {
    expectEqual(
      tls.ca_certificate_sha256,
      TEMPLATE_CA_DIGEST,
      "tls.ca_certificate_sha256",
      errors,
    );
  } else if (!SHA256_PATTERN.test(tls.ca_certificate_sha256)) {
    errors.push("tls.ca_certificate_sha256 must be a lowercase 64-character SHA-256 digest");
  }

  const runtime = expectRecord(config.runtime, "runtime", errors);
  exactKeys(runtime, EXPECTED_KEYS.runtime, "runtime", errors);
  expectEqual(runtime.compose_profile, FEAT_125_LOCAL_PROFILE, "runtime.compose_profile", errors);
  expectEqual(runtime.identity_https_port, 8443, "runtime.identity_https_port", errors);
  expectEqual(runtime.api_https_port, 9443, "runtime.api_https_port", errors);
  expectEqual(runtime.api_upstream, "http://host.docker.internal:18080", "runtime.api_upstream", errors);
  expectEqual(runtime.api_direct_origin, "http://127.0.0.1:18080/", "runtime.api_direct_origin", errors);
  expectEqual(
    runtime.legacy_tasks_ingress,
    "edge_404_and_api_handler_absent_required",
    "runtime.legacy_tasks_ingress",
    errors,
  );
  expectEqual(
    runtime.keycloak_image,
    FEAT_125_LOCAL_IMAGES["feat125-keycloak"],
    "runtime.keycloak_image",
    errors,
  );
  expectEqual(
    runtime.keycloak_postgres_image,
    FEAT_125_LOCAL_IMAGES["feat125-keycloak-db"],
    "runtime.keycloak_postgres_image",
    errors,
  );
  expectEqual(
    runtime.caddy_image,
    FEAT_125_LOCAL_IMAGES["feat125-caddy"],
    "runtime.caddy_image",
    errors,
  );

  const activation = expectRecord(config.activation, "activation", errors);
  exactKeys(activation, EXPECTED_KEYS.activation, "activation", errors);
  expectEqual(activation.local, true, "activation.local", errors);
  expectEqual(activation.production, false, "activation.production", errors);
  expectEqual(activation.release, false, "activation.release", errors);
  expectEqual(activation.requires_online_preflight, true, "activation.requires_online_preflight", errors);

  const issuerHost = issuer?.hostname.toLowerCase();
  const apiHost = apiOrigin?.hostname.toLowerCase();
  for (const [label, host] of [
    ["identity.issuer", issuerHost],
    ["api.origin", apiHost],
  ]) {
    if (host !== "localhost") {
      errors.push(`${label} hostname must equal localhost`);
    }
  }

  if (errors.length > 0) {
    throw new Error(errors.join("\n"));
  }

  if (mode === "local-lab") {
    await verifyImplementationWorktree(
      config.api.implementation_evidence,
      "api",
      apiRepository,
      worktreeReferenceImpl,
    );
    await verifyImplementationWorktree(
      config.desktop.implementation_evidence,
      "desktop",
      desktopRepository,
      worktreeReferenceImpl,
    );
    await verifyLoopbackResolution(new Set([issuerHost, apiHost]), lookupImpl);
    const ca = await inspectCaImpl(resolveRepositoryPath(tls.ca_certificate_path));
    if (ca.sha256 !== tls.ca_certificate_sha256) {
      throw new Error("tls.ca_certificate_sha256 does not match the configured CA certificate file");
    }
    if (ca.isCertificateAuthority !== true) {
      throw new Error("tls.ca_certificate_path must contain a CA certificate");
    }
  }

  return config;
}

export async function verifyFeat125LocalLabOnline(
  config,
  {
    expectedApiCommit,
    expectedDesktopCommit,
    expectedApiReference,
    expectedDesktopReference,
    apiRepository,
    desktopRepository,
    worktreeReferenceImpl = computeWorktreeReference,
    fetchImpl = globalThis.fetch,
    lookupImpl = dnsLookup,
    inspectCaImpl = inspectCaCertificate,
    enforceProcessCa = true,
  } = {},
) {
  if (typeof fetchImpl !== "function") {
    throw new Error("local-lab online preflight requires a Fetch API implementation");
  }
  await validateFeat125LocalLabConfig(config, {
    mode: "local-lab",
    expectedApiCommit,
    expectedDesktopCommit,
    expectedApiReference,
    expectedDesktopReference,
    apiRepository,
    desktopRepository,
    worktreeReferenceImpl,
    lookupImpl,
    inspectCaImpl,
  });

  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
    throw new Error("NODE_TLS_REJECT_UNAUTHORIZED=0 is forbidden");
  }
  if (enforceProcessCa) {
    const expectedCa = resolveRepositoryPath(config.tls.ca_certificate_path);
    const configuredCa = process.env.NODE_EXTRA_CA_CERTS;
    if (!configuredCa || resolve(configuredCa) !== expectedCa) {
      throw new Error("NODE_EXTRA_CA_CERTS must equal the validated local-lab CA certificate path");
    }
  }

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
      throw new Error(`OIDC discovery ${field} must match the approved local-lab configuration`);
    }
  }
  if (!discovery.response_types_supported?.includes("code")) {
    throw new Error("OIDC discovery must support authorization code response type");
  }
  if (!discovery.code_challenge_methods_supported?.includes("S256")) {
    throw new Error("OIDC discovery must support PKCE S256");
  }
  if (!discovery.id_token_signing_alg_values_supported?.includes("RS256")) {
    throw new Error("OIDC discovery must support RS256 ID token signing");
  }

  const jwks = await fetchJson(config.identity.jwks_uri, "identity JWKS", fetchImpl);
  if (
    !Array.isArray(jwks.keys) ||
    !jwks.keys.some(
      (key) =>
        isRecord(key) &&
        key.kty === "RSA" &&
        typeof key.kid === "string" &&
        key.kid.length > 0 &&
        (key.use === undefined || key.use === "sig") &&
        (key.alg === undefined || key.alg === "RS256"),
    )
  ) {
    throw new Error("identity JWKS must expose at least one keyed RSA/RS256 signing key");
  }

  await verifyNativeRedirectRegistration(config, fetchImpl);

  const health = await fetchJson(new URL("/healthz", config.api.origin), "API /healthz", fetchImpl);
  if (
    !isRecord(health) ||
    health.service !== "yijie-api" ||
    health.environment !== config.api.health_environment ||
    health.status !== "ok" ||
    health.database !== "connected"
  ) {
    throw new Error("API /healthz must identify the connected approved local-lab yijie-api instance");
  }
  const readiness = await fetchJson(new URL("/readyz", config.api.origin), "API /readyz", fetchImpl);
  if (!isRecord(readiness) || readiness.status !== "ready") {
    throw new Error("API /readyz must report ready");
  }

  await verifyUnauthenticatedProjection(
    new URL("/v1/me/tenants", config.api.origin),
    "unauthenticated /v1/me/tenants",
    fetchImpl,
  );
  await verifyUnauthenticatedProjection(
    new URL("/v1/me/capabilities", config.api.origin),
    "unauthenticated /v1/me/capabilities",
    fetchImpl,
    {
      accept: "application/json",
      "x-yijie-tenant-id": SYNTHETIC_TENANT_ID,
    },
  );

  for (const [boundary, origin] of [
    ["Caddy edge", config.api.origin],
    ["direct local-lab API profile", config.runtime.api_direct_origin],
  ]) {
    for (const [method, path] of [
      ["GET", "/v1/tasks"],
      ["POST", "/v1/tasks"],
      ["GET", "/v1/tasks/synthetic-never-exists"],
    ]) {
      const response = await fetchWithDeadline(new URL(path, origin), fetchImpl, { method });
      if (response.status !== 404) {
        throw new Error(`${boundary} legacy Tasks boundary must return 404 for ${method} ${path}`);
      }
      await response.body?.cancel();
    }
  }
}

async function verifyUnauthenticatedProjection(url, label, fetchImpl, headers = undefined) {
  const response = await fetchWithDeadline(url, fetchImpl, headers ? { headers } : {});
  if (response.status !== 401) {
    throw new Error(
      `${label} must require bearer authentication; expected 401, got ${response.status}`,
    );
  }
  const challenge = response.headers.get("www-authenticate");
  const cacheControl = response.headers.get("cache-control");
  const body = await readJsonResponse(response, label);
  if (
    challenge !== "Bearer" ||
    cacheControl !== "no-store" ||
    body.code !== "unauthorized" ||
    body.message !== "valid bearer authentication is required"
  ) {
    throw new Error(`${label} must return the stable contract 401 semantics`);
  }
}

async function verifyNativeRedirectRegistration(config, fetchImpl) {
  const acceptedRedirect = "http://127.0.0.1:49152/oauth/callback";
  const rejectedRedirect = "http://127.0.0.1:49152/oauth/not-callback";
  const accepted = await fetchWithDeadline(
    authorizeUrl(config, acceptedRedirect),
    fetchImpl,
    { redirect: "manual", headers: { accept: "text/html" } },
  );
  const acceptedLocation = accepted.headers.get("location");
  if (accepted.status === 200) {
    if (!(accepted.headers.get("content-type") ?? "").toLowerCase().includes("text/html")) {
      throw new Error("accepted native redirect must make the Keycloak login HTML reachable");
    }
  } else if (new Set([302, 303]).has(accepted.status) && acceptedLocation) {
    const location = new URL(acceptedLocation, config.identity.authorization_endpoint);
    if (
      location.origin !== new URL(config.identity.issuer).origin ||
      !location.pathname.startsWith("/realms/yijie-local/")
    ) {
      throw new Error("accepted native redirect may only continue inside the approved Keycloak realm");
    }
  } else {
    throw new Error(
      `accepted dynamic-port exact callback did not reach login; status=${accepted.status} location=${sanitizedLocation(acceptedLocation, config.identity.authorization_endpoint)}`,
    );
  }
  await accepted.body?.cancel();

  const rejected = await fetchWithDeadline(
    authorizeUrl(config, rejectedRedirect),
    fetchImpl,
    { redirect: "manual", headers: { accept: "text/html" } },
  );
  const rejectedLocation = rejected.headers.get("location");
  if (rejected.status !== 400 || rejectedLocation !== null) {
    throw new Error(
      `wrong native callback path must be rejected without redirect; status=${rejected.status} location=${sanitizedLocation(rejectedLocation, config.identity.authorization_endpoint)}`,
    );
  }
  await rejected.body?.cancel();
}

function authorizeUrl(config, redirectUri) {
  const url = new URL(config.identity.authorization_endpoint);
  url.searchParams.set("client_id", config.identity.public_client_id);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid");
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("code_challenge", "A".repeat(43));
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("state", "feat125-local-preflight-state");
  url.searchParams.set("nonce", "feat125-local-preflight-nonce");
  url.searchParams.set("prompt", "login");
  return url;
}

function sanitizedLocation(location, base) {
  if (!location) {
    return "none";
  }
  try {
    const parsed = new URL(location, base);
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return "invalid";
  }
}

export async function inspectCaCertificate(path) {
  const stats = await lstat(path);
  if (!stats.isFile() || stats.isSymbolicLink()) {
    throw new Error("local-lab CA certificate must be a regular non-symlink file");
  }
  if (stats.size === 0 || stats.size > 65_536) {
    throw new Error("local-lab CA certificate must be between 1 byte and 64 KiB");
  }
  if (!new Set([0o400, 0o600]).has(stats.mode & 0o777)) {
    throw new Error("local-lab CA certificate permissions must be owner-only 0400 or 0600");
  }
  const bytes = await readFile(path);
  const text = bytes.toString("utf8");
  if (
    countOccurrences(text, "-----BEGIN CERTIFICATE-----") !== 1 ||
    countOccurrences(text, "-----END CERTIFICATE-----") !== 1 ||
    text.includes("PRIVATE KEY")
  ) {
    throw new Error("local-lab CA file must contain exactly one public PEM certificate");
  }
  let certificate;
  try {
    certificate = new X509Certificate(bytes);
  } catch {
    throw new Error("local-lab CA file must contain a valid X.509 certificate");
  }
  return {
    sha256: createHash("sha256").update(bytes).digest("hex"),
    isCertificateAuthority: certificate.ca,
  };
}

export function resolveRepositoryPath(path) {
  if (typeof path !== "string" || path.length === 0 || isAbsolute(path)) {
    throw new Error("local-lab file paths must be repository-relative");
  }
  const resolved = resolve(REPOSITORY_ROOT, path);
  const fromRoot = relative(REPOSITORY_ROOT, resolved);
  if (fromRoot.startsWith("..") || isAbsolute(fromRoot)) {
    throw new Error("local-lab file paths must remain inside the repository");
  }
  return resolved;
}

function validateImplementationPins(config, mode, expectedApiReference, expectedDesktopReference, errors) {
  const apiReference = validateImplementationEvidence(
    config.api?.implementation_evidence,
    "api.implementation_evidence",
    errors,
  );
  const desktopReference = validateImplementationEvidence(
    config.desktop?.implementation_evidence,
    "desktop.implementation_evidence",
    errors,
  );
  if (mode === "template") {
    expectEqual(
      apiReference,
      `commit:${FEAT_125.apiCommit}`,
      "api.implementation_evidence",
      errors,
    );
    expectEqual(
      desktopReference,
      `commit:${FEAT_125.desktopCommit}`,
      "desktop.implementation_evidence",
      errors,
    );
    return;
  }
  if (!isImplementationReference(expectedApiReference)) {
    errors.push(
      "local-lab validation requires --expected-api-reference with commit:<sha> or candidate:<base-sha>:<tree-sha256>",
    );
  } else {
    expectEqual(
      apiReference,
      expectedApiReference,
      "api.implementation_evidence",
      errors,
    );
  }
  if (!isImplementationReference(expectedDesktopReference)) {
    errors.push(
      "local-lab validation requires --expected-desktop-reference with commit:<sha> or candidate:<base-sha>:<tree-sha256>",
    );
  } else {
    expectEqual(
      desktopReference,
      expectedDesktopReference,
      "desktop.implementation_evidence",
      errors,
    );
  }
}

function validateImplementationEvidence(value, label, errors) {
  const evidence = expectRecord(value, label, errors);
  exactKeys(evidence, EXPECTED_KEYS.implementation_evidence, label, errors);
  if (evidence.state === "committed") {
    if (!SHA_PATTERN.test(evidence.full_commit ?? "")) {
      errors.push(`${label}.full_commit must be a lowercase 40-character SHA when state is committed`);
    }
    expectEqual(evidence.base_commit, null, `${label}.base_commit`, errors);
    expectEqual(evidence.candidate_tree_sha256, null, `${label}.candidate_tree_sha256`, errors);
    return SHA_PATTERN.test(evidence.full_commit ?? "") ? `commit:${evidence.full_commit}` : undefined;
  }
  if (evidence.state === "reviewed_worktree_candidate") {
    expectEqual(evidence.full_commit, null, `${label}.full_commit`, errors);
    if (!SHA_PATTERN.test(evidence.base_commit ?? "")) {
      errors.push(`${label}.base_commit must be a lowercase 40-character SHA for a worktree candidate`);
    }
    if (!SHA256_PATTERN.test(evidence.candidate_tree_sha256 ?? "")) {
      errors.push(`${label}.candidate_tree_sha256 must be a lowercase 64-character SHA-256 digest`);
    }
    if (
      SHA_PATTERN.test(evidence.base_commit ?? "") &&
      SHA256_PATTERN.test(evidence.candidate_tree_sha256 ?? "")
    ) {
      return `candidate:${evidence.base_commit}:${evidence.candidate_tree_sha256}`;
    }
    return undefined;
  }
  errors.push(`${label}.state must equal committed or reviewed_worktree_candidate`);
  return undefined;
}

function isImplementationReference(value) {
  return (
    new RegExp(`^commit:${SHA_PATTERN.source.slice(1, -1)}$`).test(value ?? "") ||
    new RegExp(
      `^candidate:${SHA_PATTERN.source.slice(1, -1)}:${SHA256_PATTERN.source.slice(1, -1)}$`,
    ).test(value ?? "")
  );
}

function referenceFromLegacyCommit(value) {
  return SHA_PATTERN.test(value ?? "") ? `commit:${value}` : undefined;
}

async function verifyImplementationWorktree(evidence, label, repository, worktreeReferenceImpl) {
  if (typeof repository !== "string" || repository.length === 0) {
    throw new Error(`${label} implementation evidence requires its repository path`);
  }
  const expected =
    evidence?.state === "committed"
      ? `commit:${evidence.full_commit}`
      : `candidate:${evidence?.base_commit}:${evidence?.candidate_tree_sha256}`;
  const actual = await worktreeReferenceImpl(repository);
  if (actual !== expected) {
    throw new Error(`${label} implementation evidence no longer matches the repository snapshot`);
  }
}

async function verifyLoopbackResolution(hosts, lookupImpl) {
  for (const host of hosts) {
    const addresses = isIP(host)
      ? [{ address: host }]
      : await lookupImpl(host, { all: true, verbatim: true });
    if (!Array.isArray(addresses) || addresses.length === 0) {
      throw new Error(`local-lab hostname did not resolve: ${host}`);
    }
    for (const { address } of addresses) {
      if (!isLoopbackAddress(address)) {
        throw new Error(`local-lab hostname ${host} resolved outside loopback: ${address}`);
      }
    }
  }
}

function isLoopbackAddress(address) {
  return /^127(?:\.\d{1,3}){3}$/.test(address) || address === "::1" || address === "0:0:0:0:0:0:0:1";
}

function countOccurrences(value, needle) {
  return value.split(needle).length - 1;
}

function expectHttpsUrl(value, name, errors, { path, port, origin } = {}) {
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
  if (url.username || url.password || url.search || url.hash) {
    errors.push(`${name} must not contain user information, query, or fragment`);
  }
  if (path !== undefined && url.pathname !== path) {
    errors.push(`${name} path must equal ${path}`);
  }
  if (port !== undefined && url.port !== port) {
    errors.push(`${name} port must equal ${port}`);
  }
  if (origin !== undefined && url.origin !== origin) {
    errors.push(`${name} must use the approved identity origin`);
  }
  return url;
}

async function fetchJson(url, label, fetchImpl) {
  const response = await fetchWithDeadline(url, fetchImpl);
  if (!response.ok) {
    throw new Error(`${label} returned HTTP ${response.status}`);
  }
  return readJsonResponse(response, label);
}

async function readJsonResponse(response, label) {
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().includes("json")) {
    throw new Error(`${label} must return JSON`);
  }
  const contentLength = Number(response.headers.get("content-length") ?? "0");
  if (Number.isFinite(contentLength) && contentLength > MAX_JSON_BYTES) {
    throw new Error(`${label} response exceeds 256 KiB`);
  }
  const bytes = await readBoundedBody(response, label, MAX_JSON_BYTES);
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new Error(`${label} returned invalid JSON`);
  }
}

function oidcDiscoveryUrl(issuer) {
  const url = new URL(issuer);
  url.pathname = `${url.pathname.replace(/\/$/, "")}/.well-known/openid-configuration`;
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

async function fetchWithDeadline(url, fetchImpl, init = {}) {
  try {
    return await fetchImpl(url, {
      redirect: "error",
      signal: AbortSignal.timeout(5_000),
      headers: { accept: "application/json" },
      ...init,
    });
  } catch (error) {
    throw new Error(`local-lab online preflight request failed: ${error.message}`);
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
