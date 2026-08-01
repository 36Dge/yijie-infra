import { readFile } from "node:fs/promises";

export const FEAT_125_LOCAL_REALM_PATH =
  "config/feat-125-local/keycloak/realm.json";
export const FEAT_125_LOCAL_CADDYFILE_PATH =
  "config/feat-125-local/Caddyfile";
export const FEAT_125_LOCAL_REDIRECT_URI =
  "http://127.0.0.1/oauth/callback";
export const FEAT_125_LOCAL_AUDIENCE = "https://api.yijie.ai";
export const FEAT_125_LOCAL_CLIENT_ID = "yijie-desktop-feat-125-local";

export async function loadFeat125LocalAssets() {
  const [realmText, caddyfile] = await Promise.all([
    readFile(FEAT_125_LOCAL_REALM_PATH, "utf8"),
    readFile(FEAT_125_LOCAL_CADDYFILE_PATH, "utf8"),
  ]);
  return { realm: JSON.parse(realmText), caddyfile };
}

export function validateFeat125LocalAssets({ realm, caddyfile }) {
  validateRealm(realm);
  validateCaddyfile(caddyfile);
}

export function validateRealm(realm) {
  if (!isRecord(realm)) {
    throw new Error("FEAT-125 Keycloak realm must be a JSON object.");
  }
  for (const [field, expected] of [
    ["realm", "yijie-local"],
    ["enabled", true],
    ["sslRequired", "external"],
    ["registrationAllowed", false],
    ["defaultSignatureAlgorithm", "RS256"],
    ["accessTokenLifespan", 600],
    ["revokeRefreshToken", true],
    ["refreshTokenMaxReuse", 0],
  ]) {
    if (realm[field] !== expected) {
      throw new Error(`Keycloak realm ${field} must equal ${JSON.stringify(expected)}.`);
    }
  }
  validateSyntheticUsers(realm.users);
  rejectCredentialMaterial(realm);

  if (!Array.isArray(realm.clients) || realm.clients.length !== 2) {
    throw new Error("Keycloak realm must contain only the native client and API audience marker.");
  }
  const api = realm.clients.find((client) => client.clientId === FEAT_125_LOCAL_AUDIENCE);
  if (!api || api.bearerOnly !== true || api.enabled !== true) {
    throw new Error("Keycloak realm must define the exact bearer-only API audience client.");
  }
  for (const field of [
    "standardFlowEnabled",
    "implicitFlowEnabled",
    "directAccessGrantsEnabled",
    "serviceAccountsEnabled",
  ]) {
    if (api[field] !== false) {
      throw new Error(`API audience marker ${field} must remain false.`);
    }
  }

  const desktop = realm.clients.find((client) => client.clientId === FEAT_125_LOCAL_CLIENT_ID);
  if (!desktop || desktop.enabled !== true || desktop.publicClient !== true) {
    throw new Error("Keycloak realm must define the exact enabled public Desktop client.");
  }
  for (const [field, expected] of [
    ["bearerOnly", false],
    ["standardFlowEnabled", true],
    ["implicitFlowEnabled", false],
    ["directAccessGrantsEnabled", false],
    ["serviceAccountsEnabled", false],
    ["fullScopeAllowed", false],
  ]) {
    if (desktop[field] !== expected) {
      throw new Error(`Desktop client ${field} must equal ${expected}.`);
    }
  }
  if (
    !Array.isArray(desktop.redirectUris) ||
    desktop.redirectUris.length !== 1 ||
    desktop.redirectUris[0] !== FEAT_125_LOCAL_REDIRECT_URI ||
    desktop.redirectUris[0].includes("*")
  ) {
    throw new Error(
      `Desktop client must register only the exact path-preserving loopback redirect ${FEAT_125_LOCAL_REDIRECT_URI}.`,
    );
  }
  if (desktop.attributes?.["pkce.code.challenge.method"] !== "S256") {
    throw new Error("Desktop public client must require PKCE S256.");
  }
  const audienceMapper = desktop.protocolMappers?.find(
    (mapper) => mapper.protocolMapper === "oidc-audience-mapper",
  );
  if (
    audienceMapper?.config?.["included.client.audience"] !== FEAT_125_LOCAL_AUDIENCE ||
    audienceMapper.config["access.token.claim"] !== "true" ||
    audienceMapper.config["id.token.claim"] !== "false"
  ) {
    throw new Error("Desktop access tokens must contain only the exact FEAT-125 API audience mapping.");
  }
}

function validateSyntheticUsers(users) {
  const expected = new Map([
    ["feat125-synthetic-user-a", "12500000-0000-4000-8000-000000000001"],
    ["feat125-synthetic-user-b", "12500000-0000-4000-8000-000000000002"],
  ]);
  if (!Array.isArray(users) || users.length !== expected.size) {
    throw new Error("Keycloak realm must contain exactly the two approved synthetic users.");
  }
  for (const user of users) {
    if (
      !isRecord(user) ||
      expected.get(user.username) !== user.id ||
      user.enabled !== true ||
      user.emailVerified !== true ||
      !String(user.email).endsWith(".synthetic.invalid") ||
      JSON.stringify(user.attributes?.data_classification) !== JSON.stringify(["synthetic_only"])
    ) {
      throw new Error("Keycloak realm contains an unapproved or non-synthetic user record.");
    }
  }
}

export function validateCaddyfile(caddyfile) {
  if (typeof caddyfile !== "string") {
    throw new Error("FEAT-125 Caddyfile must be text.");
  }
  for (const forbidden of [
    "tls_insecure_skip_verify",
    "0.0.0.0",
    "identity.yijie",
    "api.yijie",
  ]) {
    if (caddyfile.includes(forbidden)) {
      throw new Error(`FEAT-125 Caddyfile contains forbidden setting: ${forbidden}`);
    }
  }
  if (!caddyfile.includes("skip_install_trust")) {
    throw new Error("Caddy must not silently mutate the host trust store.");
  }
  if ((caddyfile.match(/\btls internal\b/g) ?? []).length !== 2) {
    throw new Error("Both FEAT-125 HTTPS listeners must use the persisted Caddy internal CA.");
  }
  if (!caddyfile.includes("https://localhost:8443")) {
    throw new Error("Caddy must expose the local IdP at https://localhost:8443.");
  }
  if (!caddyfile.includes("reverse_proxy feat125-keycloak:8080")) {
    throw new Error("Caddy must proxy the local IdP only over its private Docker network.");
  }
  if (!caddyfile.includes("https://localhost:9443")) {
    throw new Error("Caddy must expose the local API at https://localhost:9443.");
  }
  if (!caddyfile.includes("reverse_proxy host.docker.internal:18080")) {
    throw new Error("Caddy must proxy the API only through the explicit host gateway upstream.");
  }
  const matcher = "@legacy_tasks path /v1/tasks /v1/tasks/*";
  const response = "respond @legacy_tasks 404";
  const matcherIndex = caddyfile.indexOf(matcher);
  const responseIndex = caddyfile.indexOf(response);
  const apiProxyIndex = caddyfile.indexOf("reverse_proxy host.docker.internal:18080");
  if (
    matcherIndex === -1 ||
    responseIndex <= matcherIndex ||
    apiProxyIndex <= responseIndex
  ) {
    throw new Error("Caddy must reject /v1/tasks and every child path before the API proxy.");
  }
}

function rejectCredentialMaterial(value, path = "realm") {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => rejectCredentialMaterial(entry, `${path}[${index}]`));
    return;
  }
  if (!isRecord(value)) {
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    if (["secret", "clientSecret", "credentials", "password"].includes(key)) {
      throw new Error(`Committed Keycloak realm contains forbidden credential field: ${path}.${key}`);
    }
    rejectCredentialMaterial(child, `${path}.${key}`);
  }
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
