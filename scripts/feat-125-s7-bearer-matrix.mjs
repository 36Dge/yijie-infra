#!/usr/bin/env node

import { execFile } from "node:child_process";
import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
const IDENTITY_ORIGIN = "https://localhost:8443";
const ISSUER = `${IDENTITY_ORIGIN}/realms/yijie-local`;
const AUTHORIZATION_ENDPOINT = `${ISSUER}/protocol/openid-connect/auth`;
const TOKEN_ENDPOINT = `${ISSUER}/protocol/openid-connect/token`;
const JWKS_ENDPOINT = `${ISSUER}/protocol/openid-connect/certs`;
const REVOCATION_ENDPOINT = `${ISSUER}/protocol/openid-connect/revoke`;
const CLIENT_ID = "yijie-desktop-feat-125-local";
const API_AUDIENCE = "https://api.yijie.ai";
const API_ORIGIN = "https://localhost:9443";
const CALLBACK_PATH = "/oauth/callback";
const MAX_BODY_BYTES = 256 * 1024;
const MAX_TOKEN_BYTES = 16 * 1024;
const EXPECTED_CA_PATH = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../environments/local/generated/feat-125-caddy-root.crt",
);
const TENANT_A = "12500000-0000-4000-8000-100000000001";
const TENANT_B = "12500000-0000-4000-8000-100000000002";
const OWNER_CAPABILITIES = Object.freeze([
  "knowledge.read",
  "plugin.read",
  "schedule.read",
  "store.read",
  "task.create",
  "task.read",
  "workspace.use",
]);
const MEMBER_CAPABILITIES = Object.freeze(["task.create", "task.read"]);
const EXPECTED_TENANTS = Object.freeze([
  Object.freeze({ tenant_id: TENANT_A, display_name: "Synthetic FEAT-125 Tenant A" }),
  Object.freeze({ tenant_id: TENANT_B, display_name: "Synthetic FEAT-125 Tenant B" }),
]);
const IDENTITIES = Object.freeze([
  Object.freeze({
    label: "user-a",
    username: "feat125-synthetic-user-a",
    subject: "12500000-0000-4000-8000-000000000001",
    capabilities: Object.freeze({ [TENANT_A]: OWNER_CAPABILITIES, [TENANT_B]: MEMBER_CAPABILITIES }),
  }),
  Object.freeze({
    label: "user-b",
    username: "feat125-synthetic-user-b",
    subject: "12500000-0000-4000-8000-000000000002",
    capabilities: Object.freeze({ [TENANT_A]: MEMBER_CAPABILITIES, [TENANT_B]: OWNER_CAPABILITIES }),
  }),
]);

if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
  throw new Error("NODE_TLS_REJECT_UNAUTHORIZED=0 is forbidden");
}
if (process.env.NODE_EXTRA_CA_CERTS !== EXPECTED_CA_PATH) {
  throw new Error("S7 bearer matrix requires the fixed exported local CA");
}

const jwks = await getJson(JWKS_ENDPOINT, {}, "JWKS");
if (!Array.isArray(jwks.keys) || jwks.keys.length === 0) {
  throw new Error("S7 JWKS is unavailable");
}

const results = [];
for (const identity of IDENTITIES) {
  const tokens = await authorize(identity);
  try {
    verifyJwt(tokens.id_token, jwks, {
      audience: CLIENT_ID,
      issuer: ISSUER,
      nonce: tokens.nonce,
      subject: identity.subject,
    });
    verifyJwt(tokens.access_token, jwks, {
      audience: API_AUDIENCE,
      issuer: ISSUER,
      requireNotBefore: true,
      subject: identity.subject,
    });
    results.push(await verifyIdentityMatrix(identity, tokens.access_token));
  } finally {
    await revoke(tokens.refresh_token);
    tokens.access_token = "";
    tokens.refresh_token = "";
    tokens.id_token = "";
  }
}

for (const result of results) {
  console.log(
    `S7 ${result.label} PASS: tenants=2, owner=7, member=2, ` +
      `concurrent=50, throughput=${result.throughput.toFixed(1)}rps, p95=${result.p95.toFixed(1)}ms`,
  );
}
console.log("FEAT-125 S7 real bearer 2 roles x 2 tenants matrix passed (Keychain evidence is separate).");

async function authorize(identity) {
  const verifier = base64Url(randomBytes(64));
  const challenge = base64Url(createHash("sha256").update(verifier).digest());
  const state = base64Url(randomBytes(32));
  const nonce = base64Url(randomBytes(32));
  const callback = await createCallback(state);
  const redirectUri = `http://127.0.0.1:${callback.port}${CALLBACK_PATH}`;
  const authorizationUrl = new URL(AUTHORIZATION_ENDPOINT);
  for (const [name, value] of Object.entries({
    client_id: CLIENT_ID,
    code_challenge: challenge,
    code_challenge_method: "S256",
    login_hint: identity.username,
    nonce,
    prompt: "login",
    redirect_uri: redirectUri,
    response_mode: "query",
    response_type: "code",
    scope: "openid",
    state,
  })) {
    authorizationUrl.searchParams.set(name, value);
  }

  try {
    await execFileAsync("open", [authorizationUrl.toString()]);
    console.log(`S7_BROWSER_LOGIN_READY ${identity.label}`);
    const code = await callback.waitForCode;
    const token = await postForm(TOKEN_ENDPOINT, {
      client_id: CLIENT_ID,
      code,
      code_verifier: verifier,
      grant_type: "authorization_code",
      redirect_uri: redirectUri,
    });
    if (
      token.token_type !== "Bearer" ||
      typeof token.access_token !== "string" ||
      typeof token.refresh_token !== "string" ||
      typeof token.id_token !== "string" ||
      token.access_token.length === 0 ||
      token.refresh_token.length === 0 ||
      token.id_token.length === 0 ||
      Buffer.byteLength(token.access_token) > MAX_TOKEN_BYTES ||
      Buffer.byteLength(token.refresh_token) > MAX_TOKEN_BYTES ||
      Buffer.byteLength(token.id_token) > MAX_TOKEN_BYTES
    ) {
      throw new Error("S7 token response is incomplete");
    }
    return { ...token, nonce };
  } finally {
    await callback.close();
  }
}

async function createCallback(expectedState) {
  let resolveCode;
  let rejectCode;
  const waitForCode = new Promise((resolve, reject) => {
    resolveCode = resolve;
    rejectCode = reject;
  });
  const server = createServer((request, response) => {
    try {
      const address = server.address();
      if (
        request.method !== "GET" ||
        request.socket.remoteAddress !== "127.0.0.1" ||
        typeof address !== "object" ||
        address === null ||
        request.headers.host !== `127.0.0.1:${address.port}`
      ) {
        throw new Error("callback transport rejected");
      }
      const requestUrl = new URL(request.url ?? "", `http://${request.headers.host}`);
      const allowed = new Set(["code", "iss", "session_state", "state"]);
      if (
        requestUrl.pathname !== CALLBACK_PATH ||
        [...requestUrl.searchParams.keys()].some((key) => !allowed.has(key)) ||
        requestUrl.searchParams.getAll("code").length !== 1 ||
        requestUrl.searchParams.getAll("iss").length !== 1 ||
        requestUrl.searchParams.getAll("session_state").length > 1 ||
        requestUrl.searchParams.getAll("state").length !== 1 ||
        requestUrl.searchParams.get("state") !== expectedState ||
        requestUrl.searchParams.get("iss") !== ISSUER
      ) {
        throw new Error("callback parameters rejected");
      }
      const code = requestUrl.searchParams.get("code");
      if (!code || code.length > 4096) {
        throw new Error("callback code rejected");
      }
      response.writeHead(200, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
      response.end("Yijie synthetic S7 login completed. You may close this tab.");
      resolveCode(code);
    } catch {
      response.writeHead(400, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
      response.end("Yijie synthetic S7 callback rejected.");
      rejectCode(new Error("S7 loopback callback rejected"));
    }
  });
  server.on("error", rejectCode);
  await new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", resolve);
    server.once("error", reject);
  });
  const address = server.address();
  if (typeof address !== "object" || address === null) {
    throw new Error("S7 loopback listener did not bind TCP");
  }
  const timeout = setTimeout(() => rejectCode(new Error("S7 browser login timed out")), 120_000);
  return {
    port: address.port,
    waitForCode: waitForCode.finally(() => clearTimeout(timeout)),
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

async function verifyIdentityMatrix(identity, accessToken) {
  const tenants = await apiGet("/v1/me/tenants", accessToken);
  requireNoStore(tenants);
  if (tenants.status !== 200 || JSON.stringify(tenants.body?.tenants) !== JSON.stringify(EXPECTED_TENANTS)) {
    const safeTenants = Array.isArray(tenants.body?.tenants)
      ? tenants.body.tenants.map(({ tenant_id, display_name }) => ({ tenant_id, display_name }))
      : typeof tenants.body?.tenants;
    throw new Error(
      `${identity.label} tenant discovery failed closed: ` +
        `status=${tenants.status}, tenants=${JSON.stringify(safeTenants)}`,
    );
  }

  for (const tenantId of [TENANT_A, TENANT_B]) {
    const projection = await apiGet("/v1/me/capabilities", accessToken, {
      "X-Yijie-Tenant-ID": tenantId,
    });
    requireNoStore(projection);
    validateProjection(identity, tenantId, projection);
  }

  const missing = await apiGet("/v1/me/capabilities", accessToken);
  requireNoStore(missing);
  if (missing.status !== 400 || missing.body?.code !== "invalid_tenant_context") {
    throw new Error(`${identity.label} missing tenant did not fail closed`);
  }
  const denied = await apiGet("/v1/me/capabilities", accessToken, {
    "X-Yijie-Tenant-ID": "12500000-0000-4000-8000-100000000099",
  });
  requireNoStore(denied);
  if (denied.status !== 403 || denied.body?.code !== "tenant_access_denied") {
    throw new Error(`${identity.label} cross-tenant denial failed closed`);
  }

  const calls = Array.from({ length: 50 }, (_, index) => {
    const tenantId = index % 2 === 0 ? TENANT_A : TENANT_B;
    return timedProjection(identity, tenantId, accessToken);
  });
  const started = performance.now();
  const durations = await Promise.all(calls);
  const elapsed = performance.now() - started;
  durations.sort((left, right) => left - right);
  const p95 = durations[Math.ceil(durations.length * 0.95) - 1];
  const throughput = durations.length / (elapsed / 1000);
  if (p95 > 300 || throughput < 50) {
    throw new Error(`${identity.label} local performance threshold failed closed`);
  }
  return { label: identity.label, p95, throughput };
}

async function timedProjection(identity, tenantId, accessToken) {
  const started = performance.now();
  const projection = await apiGet("/v1/me/capabilities", accessToken, {
    "X-Yijie-Tenant-ID": tenantId,
  });
  validateProjection(identity, tenantId, projection);
  return performance.now() - started;
}

function validateProjection(identity, tenantId, response) {
  const expected = identity.capabilities[tenantId];
  const expiresAt = Date.parse(response.body?.expires_at);
  const remaining = expiresAt - Date.now();
  if (
    response.status !== 200 ||
    response.body?.schema_version !== 1 ||
    response.body?.tenant_id !== tenantId ||
    response.body?.authorization_revision !== 3 ||
    JSON.stringify(response.body?.capabilities) !== JSON.stringify(expected) ||
    !Number.isFinite(expiresAt) ||
    remaining <= 0 ||
    remaining > 301_000
  ) {
    throw new Error(`${identity.label} capability projection failed closed`);
  }
  requireNoStore(response);
}

async function apiGet(path, accessToken, extraHeaders = {}) {
  return requestJson(new URL(path, API_ORIGIN), {
    headers: { accept: "application/json", authorization: `Bearer ${accessToken}`, ...extraHeaders },
    method: "GET",
    redirect: "error",
  });
}

async function revoke(refreshToken) {
  const response = await fetch(REVOCATION_ENDPOINT, {
    body: new URLSearchParams({ client_id: CLIENT_ID, token: refreshToken, token_type_hint: "refresh_token" }),
    headers: { "content-type": "application/x-www-form-urlencoded" },
    method: "POST",
    redirect: "error",
  });
  await response.body?.cancel();
  if (response.status !== 200) {
    throw new Error("S7 refresh-token cleanup failed closed");
  }
}

async function postForm(url, fields) {
  return getJson(url, {
    body: new URLSearchParams(fields),
    headers: { "content-type": "application/x-www-form-urlencoded" },
    method: "POST",
  }, "token endpoint");
}

async function getJson(url, init, label) {
  const response = await requestJson(url, { ...init, redirect: "error" });
  if (response.status !== 200) {
    throw new Error(`S7 ${label} returned an unexpected status`);
  }
  return response.body;
}

async function requestJson(url, init) {
  const response = await fetch(url, init);
  const declaredLength = Number(response.headers.get("content-length") ?? "0");
  if (declaredLength > MAX_BODY_BYTES) {
    await response.body?.cancel();
    throw new Error("S7 response exceeded the body limit");
  }
  const text = await response.text();
  if (Buffer.byteLength(text) > MAX_BODY_BYTES) {
    throw new Error("S7 response exceeded the body limit");
  }
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error("S7 response was not JSON");
  }
  return { body, headers: response.headers, status: response.status };
}

function requireNoStore(response) {
  if (response.headers.get("cache-control") !== "no-store") {
    throw new Error("S7 API response did not require no-store");
  }
}

function verifyJwt(token, keySet, expected) {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("S7 JWT shape is invalid");
  }
  let header;
  let payload;
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url"));
    payload = JSON.parse(Buffer.from(parts[1], "base64url"));
  } catch {
    throw new Error("S7 JWT encoding is invalid");
  }
  const matchingKeys = keySet.keys.filter(
    (candidate) => candidate.kid === header.kid && candidate.kty === "RSA",
  );
  const key = matchingKeys.length === 1 ? matchingKeys[0] : undefined;
  const audience = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  const failedClaims = [];
  if (header.alg !== "RS256") failedClaims.push("alg");
  if (!key || key.alg !== "RS256") failedClaims.push("kid");
  if (payload.iss !== expected.issuer) failedClaims.push("issuer");
  if (typeof payload.sub !== "string" || payload.sub.length === 0) {
    failedClaims.push("subject_missing");
  } else if (payload.sub !== expected.subject) {
    failedClaims.push("subject_mismatch");
  }
  if (audience.length !== 1 || audience[0] !== expected.audience) {
    failedClaims.push(`audience=${JSON.stringify(audience)}`);
  }
  if (expected.nonce !== undefined && payload.nonce !== expected.nonce) failedClaims.push("nonce");
  if (typeof payload.iat !== "number") failedClaims.push("issued_at_missing");
  if (expected.requireNotBefore && typeof payload.nbf !== "number") {
    failedClaims.push("not_before_missing");
  }
  if (typeof payload.exp !== "number" || payload.exp <= Math.floor(Date.now() / 1000)) {
    failedClaims.push("expiry");
  }
  if (
    typeof payload.iat === "number" &&
    typeof payload.exp === "number" &&
    payload.exp - payload.iat > 600
  ) {
    failedClaims.push("lifetime");
  }
  if (failedClaims.length > 0) {
    throw new Error(`S7 JWT claims failed closed: ${failedClaims.join(",")}`);
  }
  const verified = verify(
    "RSA-SHA256",
    Buffer.from(`${parts[0]}.${parts[1]}`),
    createPublicKey({ key, format: "jwk" }),
    Buffer.from(parts[2], "base64url"),
  );
  if (!verified) {
    throw new Error("S7 JWT signature failed closed");
  }
}

function base64Url(value) {
  return Buffer.from(value).toString("base64url");
}
