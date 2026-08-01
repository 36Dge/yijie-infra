import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  loadFeat125LocalLabConfig,
  resolveRepositoryPath,
  validateFeat125LocalLabConfig,
} from "./feat-125-local-config.mjs";
import { validateFeat125LocalSecrets } from "./feat-125-local-secrets.mjs";

const REPOSITORY_ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const CONFIG_PATH = resolve(REPOSITORY_ROOT, "environments/local/feat-125.local-lab.yaml");
const SECRETS_PATH = resolve(REPOSITORY_ROOT, "environments/local/feat-125.secrets.env");
const CA_PATH = resolve(REPOSITORY_ROOT, "environments/local/generated/feat-125-caddy-root.crt");
const IDENTITY_ORIGIN = "https://localhost:8443";
const TOKEN_ENDPOINT = `${IDENTITY_ORIGIN}/realms/master/protocol/openid-connect/token`;
const REVOCATION_ENDPOINT = `${IDENTITY_ORIGIN}/realms/master/protocol/openid-connect/revoke`;
const ADMIN_CLIENT_ID = "admin-cli";
const DESKTOP_CLIENT_ID = "yijie-desktop-feat-125-local";
const API_AUDIENCE_CLIENT_ID = "https://api.yijie.ai";
const MAX_JSON_BYTES = 65_536;
const USER_PROFILE_ENDPOINT = new URL("/admin/realms/yijie-local/users/profile", IDENTITY_ORIGIN);

const REVIEWED_REALM_PROJECTION = Object.freeze({
  realm: "yijie-local",
  displayName: "Yijie FEAT-125 Local Lab",
  enabled: true,
  sslRequired: "external",
  registrationAllowed: false,
  registrationEmailAsUsername: false,
  rememberMe: false,
  verifyEmail: false,
  loginWithEmailAllowed: false,
  duplicateEmailsAllowed: false,
  resetPasswordAllowed: false,
  editUsernameAllowed: false,
  bruteForceProtected: true,
  permanentLockout: false,
  maxFailureWaitSeconds: 900,
  minimumQuickLoginWaitSeconds: 60,
  waitIncrementSeconds: 60,
  quickLoginCheckMilliSeconds: 1_000,
  maxDeltaTimeSeconds: 43_200,
  failureFactor: 5,
  defaultSignatureAlgorithm: "RS256",
  accessTokenLifespan: 600,
  accessTokenLifespanForImplicitFlow: 0,
  ssoSessionIdleTimeout: 1_800,
  ssoSessionMaxLifespan: 36_000,
  revokeRefreshToken: true,
  refreshTokenMaxReuse: 0,
});

const BASE_USER_PROFILE = Object.freeze({
  // Keycloak 26.7 represents the strict DISABLED unmanaged-attribute policy
  // by omitting the wire field. The REST enum accepts only the three enabled
  // variants, so sending the string "DISABLED" is invalid JSON for this API.
  attributes: [
    {
      name: "username",
      displayName: "${username}",
      validations: {
        length: { min: 3, max: 255 },
        "username-prohibited-characters": {},
        "up-username-not-idn-homograph": {},
      },
      permissions: { view: ["admin", "user"], edit: ["admin", "user"] },
      multivalued: false,
    },
    {
      name: "email",
      displayName: "${email}",
      validations: { email: {}, length: { max: 255 } },
      required: { roles: ["user"] },
      permissions: { view: ["admin", "user"], edit: ["admin", "user"] },
      multivalued: false,
    },
    {
      name: "firstName",
      displayName: "${firstName}",
      validations: {
        length: { max: 255 },
        "person-name-prohibited-characters": {},
      },
      required: { roles: ["user"] },
      permissions: { view: ["admin", "user"], edit: ["admin", "user"] },
      multivalued: false,
    },
    {
      name: "lastName",
      displayName: "${lastName}",
      validations: {
        length: { max: 255 },
        "person-name-prohibited-characters": {},
      },
      required: { roles: ["user"] },
      permissions: { view: ["admin", "user"], edit: ["admin", "user"] },
      multivalued: false,
    },
  ],
  groups: [
    {
      name: "user-metadata",
      displayHeader: "User metadata",
      displayDescription: "Attributes, which refer to user metadata",
    },
  ],
});

export const REVIEWED_USER_PROFILE = Object.freeze({
  ...BASE_USER_PROFILE,
  attributes: [
    ...BASE_USER_PROFILE.attributes,
    {
      name: "data_classification",
      displayName: "Data classification",
      validations: {
        length: { min: 14, max: 14 },
        options: { options: ["synthetic_only"] },
      },
      required: { roles: ["admin"] },
      permissions: { view: ["admin"], edit: ["admin"] },
      multivalued: false,
      group: "user-metadata",
    },
  ],
});

export const SYNTHETIC_USERS = Object.freeze([
  Object.freeze({
    id: "12500000-0000-4000-8000-000000000001",
    username: "feat125-synthetic-user-a",
    email: "user-a@feat-125.synthetic.invalid",
    passwordKey: "FEAT125_SYNTHETIC_USER_A_PASSWORD",
  }),
  Object.freeze({
    id: "12500000-0000-4000-8000-000000000002",
    username: "feat125-synthetic-user-b",
    email: "user-b@feat-125.synthetic.invalid",
    passwordKey: "FEAT125_SYNTHETIC_USER_B_PASSWORD",
  }),
]);

export async function provisionFeat125LocalUsers({ secrets, fetchImpl = globalThis.fetch }) {
  if (!(secrets instanceof Map) || typeof fetchImpl !== "function") {
    throw new Error("local synthetic user provisioning requires validated secrets and Fetch API");
  }

  const administratorPassword = requiredSecret(secrets, "FEAT125_KEYCLOAK_ADMIN_PASSWORD");
  let accessToken;
  let refreshToken;
  let primaryFailure;
  let provisionedUsers = 0;

  try {
    const tokenResponse = await postForm(
      TOKEN_ENDPOINT,
      new URLSearchParams({
        client_id: ADMIN_CLIENT_ID,
        grant_type: "password",
        username: "feat125-admin",
        password: administratorPassword,
      }),
      "bootstrap admin token",
      fetchImpl,
    );
    const token = await readJson(tokenResponse, "bootstrap admin token");
    if (
      token.token_type !== "Bearer" ||
      typeof token.access_token !== "string" ||
      token.access_token.length === 0 ||
      typeof token.refresh_token !== "string" ||
      token.refresh_token.length === 0
    ) {
      throw new Error("bootstrap admin token response is incomplete");
    }
    accessToken = token.access_token;
    refreshToken = token.refresh_token;

    const adminHeaders = {
      accept: "application/json",
      authorization: `Bearer ${accessToken}`,
    };
    const realm = await getJson(
      new URL("/admin/realms/yijie-local", IDENTITY_ORIGIN),
      adminHeaders,
      "live synthetic realm",
      fetchImpl,
    );
    if (!matchesLiveRealm(realm)) {
      throw new Error("live synthetic realm security settings drifted from the reviewed profile");
    }

    const desktopClient = await getExactClient(DESKTOP_CLIENT_ID, adminHeaders, fetchImpl);
    if (!matchesDesktopClient(desktopClient)) {
      throw new Error("live Desktop OIDC client drifted from the reviewed public-client profile");
    }
    const mappers = await getJson(
      new URL(
        `/admin/realms/yijie-local/clients/${encodeURIComponent(desktopClient.id)}/protocol-mappers/models`,
        IDENTITY_ORIGIN,
      ),
      adminHeaders,
      "live Desktop audience mapper",
      fetchImpl,
    );
    if (!matchesAudienceMapper(mappers)) {
      throw new Error("live Desktop audience mapper drifted from the reviewed API audience");
    }

    const apiAudienceClient = await getExactClient(
      API_AUDIENCE_CLIENT_ID,
      adminHeaders,
      fetchImpl,
    );
    if (!matchesApiAudienceClient(apiAudienceClient)) {
      throw new Error("live API audience client drifted from the reviewed bearer-only profile");
    }

    const usersUrl = new URL(`/admin/realms/yijie-local/users`, IDENTITY_ORIGIN);
    usersUrl.searchParams.set("max", String(SYNTHETIC_USERS.length + 1));
    usersUrl.searchParams.set("briefRepresentation", "false");
    const usersResponse = await request(
      usersUrl,
      { headers: adminHeaders },
      "synthetic realm user inventory",
      fetchImpl,
    );
    const liveUsers = await readJson(usersResponse, "synthetic realm user inventory");
    if (!matchesFixedSyntheticInventory(liveUsers)) {
      throw new Error("live realm user inventory did not match the two fixed synthetic identities");
    }

    const liveUserStates = [];
    for (const user of SYNTHETIC_USERS) {
      const liveUser = await getJson(
        new URL(`/admin/realms/yijie-local/users/${encodeURIComponent(user.id)}`, IDENTITY_ORIGIN),
        adminHeaders,
        "fixed synthetic user",
        fetchImpl,
      );
      if (!matchesFixedSyntheticUserCore(liveUser, user)) {
        throw new Error("live synthetic user metadata drifted from the reviewed identity");
      }
      const attributeState = syntheticAttributeState(liveUser);
      if (attributeState === "drifted") {
        throw new Error("live synthetic user metadata drifted from the reviewed identity");
      }
      liveUserStates.push({ user, attributeState });
    }

    // Do not mutate even the local realm profile until both the complete
    // inventory and each fixed synthetic identity have passed read-only
    // checks. This keeps the known default-to-reviewed migration fail closed.
    await ensureReviewedUserProfile(adminHeaders, fetchImpl);

    for (const { user, attributeState } of liveUserStates) {
      if (attributeState !== "legacy-empty") {
        continue;
      }
      const updateResponse = await request(
        new URL(`/admin/realms/yijie-local/users/${encodeURIComponent(user.id)}`, IDENTITY_ORIGIN),
        {
          method: "PUT",
          headers: { ...adminHeaders, "content-type": "application/json" },
          body: JSON.stringify(reviewedSyntheticUser(user)),
        },
        "synthetic user metadata reconciliation",
        fetchImpl,
      );
      if (updateResponse.status !== 204) {
        await updateResponse.body?.cancel();
        throw new Error(`synthetic user metadata reconciliation returned HTTP ${updateResponse.status}`);
      }
      await updateResponse.body?.cancel();

      const reconciledUser = await getJson(
        new URL(`/admin/realms/yijie-local/users/${encodeURIComponent(user.id)}`, IDENTITY_ORIGIN),
        adminHeaders,
        "reconciled synthetic user",
        fetchImpl,
      );
      if (!matchesFixedSyntheticUser(reconciledUser, user)) {
        throw new Error("reconciled synthetic user metadata did not match the reviewed identity");
      }
    }

    for (const user of SYNTHETIC_USERS) {
      const password = requiredSecret(secrets, user.passwordKey);
      const resetResponse = await request(
        new URL(`/admin/realms/yijie-local/users/${encodeURIComponent(user.id)}/reset-password`, IDENTITY_ORIGIN),
        {
          method: "PUT",
          headers: {
            ...adminHeaders,
            "content-type": "application/json",
          },
          body: JSON.stringify({ type: "password", value: password, temporary: false }),
        },
        "synthetic user password reset",
        fetchImpl,
      );
      if (resetResponse.status !== 204) {
        await resetResponse.body?.cancel();
        throw new Error(`synthetic user password reset returned HTTP ${resetResponse.status}`);
      }
      await resetResponse.body?.cancel();
      provisionedUsers += 1;
    }
  } catch {
    primaryFailure = new Error("local synthetic user provisioning failed closed");
  }

  let revocationFailure;
  if (refreshToken) {
    try {
      const response = await postForm(
        REVOCATION_ENDPOINT,
        new URLSearchParams({
          client_id: ADMIN_CLIENT_ID,
          token: refreshToken,
          token_type_hint: "refresh_token",
        }),
        "bootstrap admin refresh-token revocation",
        fetchImpl,
      );
      await response.body?.cancel();
      await requireRevokedRefreshToken(refreshToken, fetchImpl);
    } catch {
      revocationFailure = new Error("bootstrap admin refresh-token revocation failed closed");
    }
  }

  accessToken = undefined;
  refreshToken = undefined;
  if (primaryFailure && revocationFailure) {
    throw new Error("local synthetic user provisioning and admin-session revocation both failed closed");
  }
  if (primaryFailure) {
    throw primaryFailure;
  }
  if (revocationFailure) {
    throw revocationFailure;
  }
  return Object.freeze({ provisionedUsers, validatedClients: 2 });
}

async function main() {
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
    throw new Error("NODE_TLS_REJECT_UNAUTHORIZED=0 is forbidden");
  }
  if (!process.env.NODE_EXTRA_CA_CERTS || resolve(process.env.NODE_EXTRA_CA_CERTS) !== CA_PATH) {
    throw new Error("NODE_EXTRA_CA_CERTS must equal the exported FEAT-125 Caddy root CA path");
  }

  const config = await loadFeat125LocalLabConfig(CONFIG_PATH);
  const expectedApiReference = evidenceReference(config.api?.implementation_evidence);
  const expectedDesktopReference = evidenceReference(config.desktop?.implementation_evidence);
  await validateFeat125LocalLabConfig(config, {
    mode: "local-lab",
    expectedApiReference,
    expectedDesktopReference,
    apiRepository: resolve(REPOSITORY_ROOT, "../yijie-api"),
    desktopRepository: resolve(REPOSITORY_ROOT, "../yijie-desktop"),
  });
  if (resolveRepositoryPath(config.tls.ca_certificate_path) !== CA_PATH) {
    throw new Error("local-lab configuration must use the fixed exported Caddy root CA path");
  }

  const secrets = await validateFeat125LocalSecrets(SECRETS_PATH);
  const result = await provisionFeat125LocalUsers({ secrets });
  console.log(
    `Validated the live FEAT-125 realm and ${result.validatedClients} clients, then provisioned ${result.provisionedUsers} fixed synthetic identities over pinned HTTPS.`,
  );
}

function evidenceReference(evidence) {
  if (evidence?.state === "committed") {
    return `commit:${evidence.full_commit}`;
  }
  if (evidence?.state === "reviewed_worktree_candidate") {
    return `candidate:${evidence.base_commit}:${evidence.candidate_tree_sha256}`;
  }
  return undefined;
}

function requiredSecret(secrets, key) {
  const value = secrets.get(key);
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error("validated local secret is unavailable");
  }
  return value;
}

function matchesFixedSyntheticInventory(liveUsers) {
  if (!Array.isArray(liveUsers) || liveUsers.length !== SYNTHETIC_USERS.length) {
    return false;
  }
  const byId = new Map(liveUsers.map((user) => [user?.id, user]));
  return SYNTHETIC_USERS.every((expected) => {
    const actual = byId.get(expected.id);
    return (
      actual?.id === expected.id &&
      actual?.username === expected.username &&
      actual?.email === expected.email &&
      actual?.enabled === true &&
      actual?.emailVerified === true
    );
  });
}

function matchesFixedSyntheticUser(actual, expected) {
  return exactProjection(
    {
      id: actual?.id,
      username: actual?.username,
      email: actual?.email,
      enabled: actual?.enabled,
      emailVerified: actual?.emailVerified,
      requiredActions: actual?.requiredActions,
      attributes: actual?.attributes ?? {},
    },
    {
      id: expected.id,
      username: expected.username,
      email: expected.email,
      enabled: true,
      emailVerified: true,
      requiredActions: [],
      attributes: { data_classification: ["synthetic_only"] },
    },
  );
}

function matchesFixedSyntheticUserCore(actual, expected) {
  return exactProjection(
    {
      id: actual?.id,
      username: actual?.username,
      email: actual?.email,
      enabled: actual?.enabled,
      emailVerified: actual?.emailVerified,
      requiredActions: actual?.requiredActions,
    },
    {
      id: expected.id,
      username: expected.username,
      email: expected.email,
      enabled: true,
      emailVerified: true,
      requiredActions: [],
    },
  );
}

function syntheticAttributeState(actual) {
  const attributes = actual?.attributes ?? {};
  if (exactProjection(attributes, { data_classification: ["synthetic_only"] })) {
    return "ready";
  }
  if (exactProjection(attributes, {})) {
    return "legacy-empty";
  }
  return "drifted";
}

function reviewedSyntheticUser(user) {
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    enabled: true,
    emailVerified: true,
    requiredActions: [],
    attributes: { data_classification: ["synthetic_only"] },
  };
}

function matchesLiveRealm(realm) {
  return exactProjection(projectKeys(realm, Object.keys(REVIEWED_REALM_PROJECTION)), REVIEWED_REALM_PROJECTION);
}

async function getExactClient(clientId, headers, fetchImpl) {
  const url = new URL("/admin/realms/yijie-local/clients", IDENTITY_ORIGIN);
  url.searchParams.set("clientId", clientId);
  const matches = await getJson(url, headers, "live realm client", fetchImpl);
  if (!Array.isArray(matches) || matches.length !== 1 || matches[0]?.clientId !== clientId) {
    throw new Error("live realm client lookup did not return one exact reviewed client");
  }
  return matches[0];
}

function matchesDesktopClient(client) {
  return (
    typeof client?.id === "string" &&
    client.id.length > 0 &&
    exactProjection(
      {
        clientId: client?.clientId,
        name: client?.name,
        description: client?.description,
        enabled: client?.enabled,
        protocol: client?.protocol,
        bearerOnly: client?.bearerOnly,
        publicClient: client?.publicClient,
        consentRequired: client?.consentRequired,
        standardFlowEnabled: client?.standardFlowEnabled,
        implicitFlowEnabled: client?.implicitFlowEnabled,
        directAccessGrantsEnabled: client?.directAccessGrantsEnabled,
        serviceAccountsEnabled: client?.serviceAccountsEnabled,
        frontchannelLogout: client?.frontchannelLogout,
        fullScopeAllowed: client?.fullScopeAllowed,
        redirectUris: client?.redirectUris,
        webOrigins: client?.webOrigins,
        attributes: {
          "pkce.code.challenge.method": client?.attributes?.["pkce.code.challenge.method"],
          "oauth2.device.authorization.grant.enabled":
            client?.attributes?.["oauth2.device.authorization.grant.enabled"],
          "oidc.ciba.grant.enabled": client?.attributes?.["oidc.ciba.grant.enabled"],
        },
        // Keycloak returns client scopes in storage order, while the OIDC
        // semantics are an unordered set. Canonicalize only these two fields
        // so the projection remains exact without treating harmless order
        // changes as configuration drift.
        defaultClientScopes: canonicalStringSet(client?.defaultClientScopes),
        optionalClientScopes: canonicalStringSet(client?.optionalClientScopes),
      },
      {
        clientId: DESKTOP_CLIENT_ID,
        name: "Yijie Desktop FEAT-125 local native client",
        description: "Synthetic-only public native client; no client secret is permitted.",
        enabled: true,
        protocol: "openid-connect",
        bearerOnly: false,
        publicClient: true,
        consentRequired: false,
        standardFlowEnabled: true,
        implicitFlowEnabled: false,
        directAccessGrantsEnabled: false,
        serviceAccountsEnabled: false,
        frontchannelLogout: false,
        fullScopeAllowed: false,
        redirectUris: ["http://127.0.0.1/oauth/callback"],
        webOrigins: [],
        attributes: {
          "pkce.code.challenge.method": "S256",
          "oauth2.device.authorization.grant.enabled": "false",
          "oidc.ciba.grant.enabled": "false",
        },
        defaultClientScopes: ["email", "profile", "roles"],
        optionalClientScopes: ["offline_access"],
      },
    )
  );
}

function matchesApiAudienceClient(client) {
  return exactProjection(
    {
      clientId: client?.clientId,
      name: client?.name,
      description: client?.description,
      enabled: client?.enabled,
      protocol: client?.protocol,
      bearerOnly: client?.bearerOnly,
      publicClient: client?.publicClient,
      standardFlowEnabled: client?.standardFlowEnabled,
      implicitFlowEnabled: client?.implicitFlowEnabled,
      directAccessGrantsEnabled: client?.directAccessGrantsEnabled,
      serviceAccountsEnabled: client?.serviceAccountsEnabled,
      fullScopeAllowed: client?.fullScopeAllowed,
      redirectUris: client?.redirectUris,
      webOrigins: client?.webOrigins,
    },
    {
      clientId: API_AUDIENCE_CLIENT_ID,
      name: "Yijie API audience",
      description: "Bearer-only audience marker for the FEAT-125 contract.",
      enabled: true,
      protocol: "openid-connect",
      bearerOnly: true,
      publicClient: false,
      standardFlowEnabled: false,
      implicitFlowEnabled: false,
      directAccessGrantsEnabled: false,
      serviceAccountsEnabled: false,
      fullScopeAllowed: false,
      redirectUris: [],
      webOrigins: [],
    },
  );
}

function matchesAudienceMapper(mappers) {
  if (!Array.isArray(mappers) || mappers.length !== 1) {
    return false;
  }
  const mapper = mappers[0];
  return exactProjection(
    {
      name: mapper?.name,
      protocol: mapper?.protocol,
      protocolMapper: mapper?.protocolMapper,
      consentRequired: mapper?.consentRequired,
      config: mapper?.config,
    },
    {
      name: "yijie-api-audience",
      protocol: "openid-connect",
      protocolMapper: "oidc-audience-mapper",
      consentRequired: false,
      config: {
        "included.client.audience": API_AUDIENCE_CLIENT_ID,
        "id.token.claim": "false",
        "access.token.claim": "true",
        "introspection.token.claim": "true",
        "userinfo.token.claim": "false",
      },
    },
  );
}

async function ensureReviewedUserProfile(headers, fetchImpl) {
  const current = await getJson(
    USER_PROFILE_ENDPOINT,
    headers,
    "live realm user profile",
    fetchImpl,
  );
  if (matchesUserProfile(current, REVIEWED_USER_PROFILE)) {
    return;
  }
  if (!matchesUserProfile(current, BASE_USER_PROFILE)) {
    throw new Error("live realm user profile drifted from the reviewed or migratable profile");
  }

  const response = await request(
    USER_PROFILE_ENDPOINT,
    {
      method: "PUT",
      headers: { ...headers, "content-type": "application/json" },
      body: JSON.stringify(REVIEWED_USER_PROFILE),
    },
    "reviewed realm user profile reconciliation",
    fetchImpl,
  );
  const reconciled = await readJson(response, "reviewed realm user profile reconciliation");
  if (!matchesUserProfile(reconciled, REVIEWED_USER_PROFILE)) {
    throw new Error("reconciled realm user profile did not match the reviewed profile");
  }
}

function matchesUserProfile(actual, expected) {
  return exactProjection(normalizeUserProfile(actual), normalizeUserProfile(expected));
}

function normalizeUserProfile(profile) {
  return {
    unmanagedAttributePolicy: profile?.unmanagedAttributePolicy ?? "DISABLED",
    attributes: Array.isArray(profile?.attributes)
      ? [...profile.attributes].sort((left, right) => String(left?.name).localeCompare(String(right?.name)))
      : profile?.attributes,
    groups: Array.isArray(profile?.groups)
      ? [...profile.groups].sort((left, right) => String(left?.name).localeCompare(String(right?.name)))
      : profile?.groups,
  };
}

function projectKeys(actual, keys) {
  return Object.fromEntries(keys.map((key) => [key, actual?.[key]]));
}

function canonicalStringSet(values) {
  if (!Array.isArray(values) || values.some((value) => typeof value !== "string")) {
    return values;
  }
  return [...values].sort();
}

function exactProjection(actual, expected) {
  if (Array.isArray(expected)) {
    return (
      Array.isArray(actual) &&
      actual.length === expected.length &&
      expected.every((value, index) => exactProjection(actual[index], value))
    );
  }
  if (expected !== null && typeof expected === "object") {
    if (actual === null || typeof actual !== "object" || Array.isArray(actual)) {
      return false;
    }
    const expectedKeys = Object.keys(expected);
    return (
      Object.keys(actual).length === expectedKeys.length &&
      expectedKeys.every(
        (key) => Object.hasOwn(actual, key) && exactProjection(actual[key], expected[key]),
      )
    );
  }
  return Object.is(actual, expected);
}

async function getJson(url, headers, label, fetchImpl) {
  const response = await request(url, { headers }, label, fetchImpl);
  return readJson(response, label);
}

async function postForm(url, body, label, fetchImpl) {
  return request(
    url,
    {
      method: "POST",
      headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
      body,
    },
    label,
    fetchImpl,
  );
}

async function requireRevokedRefreshToken(refreshToken, fetchImpl) {
  let response;
  try {
    response = await fetchImpl(TOKEN_ENDPOINT, {
      method: "POST",
      headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: ADMIN_CLIENT_ID,
        grant_type: "refresh_token",
        refresh_token: refreshToken,
      }),
      redirect: "error",
      signal: AbortSignal.timeout(5_000),
    });
  } catch {
    throw new Error("revoked bootstrap admin refresh token probe failed closed");
  }
  if (response.status !== 400) {
    await response.body?.cancel();
    throw new Error("revoked bootstrap admin refresh token was unexpectedly reusable");
  }
  const payload = await readJson(response, "revoked bootstrap admin refresh token probe");
  if (!exactProjection({ error: payload?.error }, { error: "invalid_grant" })) {
    throw new Error("revoked bootstrap admin refresh token did not return invalid_grant");
  }
}

async function request(url, init, label, fetchImpl) {
  let response;
  try {
    response = await fetchImpl(url, {
      redirect: "error",
      signal: AbortSignal.timeout(5_000),
      ...init,
    });
  } catch {
    throw new Error(`${label} request failed closed`);
  }
  if (!response.ok) {
    await response.body?.cancel();
    throw new Error(`${label} returned HTTP ${response.status}`);
  }
  return response;
}

async function readJson(response, label) {
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().includes("json")) {
    await response.body?.cancel();
    throw new Error(`${label} must return JSON`);
  }
  const announcedLength = Number(response.headers.get("content-length") ?? "0");
  if (Number.isFinite(announcedLength) && announcedLength > MAX_JSON_BYTES) {
    await response.body?.cancel();
    throw new Error(`${label} response exceeds 64 KiB`);
  }
  const bytes = await readBoundedBody(response, label);
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new Error(`${label} returned invalid JSON`);
  }
}

async function readBoundedBody(response, label) {
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
    if (size > MAX_JSON_BYTES) {
      await reader.cancel();
      throw new Error(`${label} response exceeds 64 KiB`);
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

const invokedAsScript = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedAsScript) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
