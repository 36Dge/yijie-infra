import assert from "node:assert/strict";
import { test } from "node:test";

import {
  REVIEWED_USER_PROFILE,
  SYNTHETIC_USERS,
  provisionFeat125LocalUsers,
} from "../scripts/feat-125-local-provision.mjs";

const secretValues = new Map([
  ["FEAT125_KEYCLOAK_ADMIN_PASSWORD", "a".repeat(64)],
  ["FEAT125_SYNTHETIC_USER_A_PASSWORD", "b".repeat(64)],
  ["FEAT125_SYNTHETIC_USER_B_PASSWORD", "c".repeat(64)],
]);

test("local provisioner uses fixed HTTPS identities and revokes its admin refresh token", async () => {
  const requests = [];
  const result = await provisionFeat125LocalUsers({
    secrets: secretValues,
    fetchImpl: successfulFetch(requests),
  });

  assert.deepEqual(result, { provisionedUsers: 2, validatedClients: 2 });
  assert.equal(requests.length, 15);
  assert.deepEqual(
    requests.map(({ url, method }) => [url.origin, url.pathname, method]),
    [
      ["https://localhost:8443", "/realms/master/protocol/openid-connect/token", "POST"],
      ["https://localhost:8443", "/admin/realms/yijie-local", "GET"],
      ["https://localhost:8443", "/admin/realms/yijie-local/clients", "GET"],
      ["https://localhost:8443", "/admin/realms/yijie-local/client-scopes", "GET"],
      [
        "https://localhost:8443",
        "/admin/realms/yijie-local/client-scopes/basic-scope-id/protocol-mappers/models",
        "GET",
      ],
      [
        "https://localhost:8443",
        "/admin/realms/yijie-local/clients/desktop-client-id/protocol-mappers/models",
        "GET",
      ],
      ["https://localhost:8443", "/admin/realms/yijie-local/clients", "GET"],
      ["https://localhost:8443", "/admin/realms/yijie-local/users", "GET"],
      [
        "https://localhost:8443",
        `/admin/realms/yijie-local/users/${SYNTHETIC_USERS[0].id}`,
        "GET",
      ],
      [
        "https://localhost:8443",
        `/admin/realms/yijie-local/users/${SYNTHETIC_USERS[1].id}`,
        "GET",
      ],
      ["https://localhost:8443", "/admin/realms/yijie-local/users/profile", "GET"],
      [
        "https://localhost:8443",
        `/admin/realms/yijie-local/users/${SYNTHETIC_USERS[0].id}/reset-password`,
        "PUT",
      ],
      [
        "https://localhost:8443",
        `/admin/realms/yijie-local/users/${SYNTHETIC_USERS[1].id}/reset-password`,
        "PUT",
      ],
      ["https://localhost:8443", "/realms/master/protocol/openid-connect/revoke", "POST"],
      ["https://localhost:8443", "/realms/master/protocol/openid-connect/token", "POST"],
    ],
  );
  for (const request of requests) {
    assert.equal(request.redirect, "error");
  }
  assert.equal(JSON.stringify(result).includes("access-token"), false);
  assert.equal(JSON.stringify(result).includes("refresh-token"), false);
  assert.equal(JSON.stringify(result).includes("a".repeat(64)), false);
});

test("local provisioner rejects identity drift and still revokes the admin session", async () => {
  const requests = [];
  const fetchImpl = successfulFetch(requests, { wrongFirstUserId: true });

  await assert.rejects(
    provisionFeat125LocalUsers({ secrets: secretValues, fetchImpl }),
    (error) => {
      assert.equal(error.message, "local synthetic user provisioning failed closed");
      assert.equal(error.message.includes("access-token"), false);
      assert.equal(error.message.includes("a".repeat(64)), false);
      return true;
    },
  );
  assert.equal(requests.some(({ method }) => method === "PUT"), false);
  assert.equal(requests.some(({ url }) => url.pathname.endsWith("/revoke")), true);
  assert.equal(requests.at(-1).url.pathname, "/realms/master/protocol/openid-connect/token");
});

test("local provisioner rejects live client drift before changing user credentials", async () => {
  const requests = [];
  const fetchImpl = successfulFetch(requests, { desktopDirectGrantEnabled: true });

  await assert.rejects(
    provisionFeat125LocalUsers({ secrets: secretValues, fetchImpl }),
    /local synthetic user provisioning failed closed/,
  );
  assert.equal(requests.some(({ url }) => url.pathname.endsWith("/reset-password")), false);
  assert.equal(requests.some(({ url }) => url.pathname.endsWith("/revoke")), true);
  assert.equal(requests.at(-1).url.pathname, "/realms/master/protocol/openid-connect/token");
});

test("local provisioner treats exact client scope sets as order-independent", async () => {
  const requests = [];
  const result = await provisionFeat125LocalUsers({
    secrets: secretValues,
    fetchImpl: successfulFetch(requests, {
      desktopDefaultScopes: ["roles", "basic", "profile", "email"],
    }),
  });

  assert.deepEqual(result, { provisionedUsers: 2, validatedClients: 2 });
  assert.equal(requests.some(({ url }) => url.pathname.endsWith("/reset-password")), true);
});

test("local provisioner migrates only the exact legacy Desktop scope set missing basic", async () => {
  const requests = [];
  const result = await provisionFeat125LocalUsers({
    secrets: secretValues,
    fetchImpl: successfulFetch(requests, {
      desktopDefaultScopes: ["profile", "email", "roles"],
    }),
  });

  assert.deepEqual(result, { provisionedUsers: 2, validatedClients: 2 });
  assert.equal(
    requests.some(
      ({ url, method }) =>
        url.pathname.endsWith("/default-client-scopes/basic-scope-id") && method === "PUT",
    ),
    true,
  );
});

test("local provisioner migrates only the exact default profile and empty synthetic attributes", async () => {
  const requests = [];
  const result = await provisionFeat125LocalUsers({
    secrets: secretValues,
    fetchImpl: successfulFetch(requests, {
      defaultUserProfile: true,
      userAttributesMissing: true,
      userNamesMissing: true,
    }),
  });

  assert.deepEqual(result, { provisionedUsers: 2, validatedClients: 2 });
  assert.equal(
    requests.some(
      ({ url, method }) => url.pathname.endsWith("/users/profile") && method === "PUT",
    ),
    true,
  );
  assert.equal(
    requests.filter(
      ({ url, method }) =>
        /^\/admin\/realms\/yijie-local\/users\/[^/]+$/.test(url.pathname) &&
        !url.pathname.endsWith("/users/profile") &&
        method === "PUT",
    ).length,
    2,
  );
});

test("local provisioner reconciles only the exact legacy-empty synthetic names", async () => {
  const requests = [];
  const result = await provisionFeat125LocalUsers({
    secrets: secretValues,
    fetchImpl: successfulFetch(requests, { userNamesMissing: true }),
  });

  assert.deepEqual(result, { provisionedUsers: 2, validatedClients: 2 });
  assert.equal(
    requests.filter(
      ({ url, method }) =>
        /^\/admin\/realms\/yijie-local\/users\/[^/]+$/.test(url.pathname) &&
        method === "PUT",
    ).length,
    2,
  );
});

test("local provisioner rejects user-profile drift before any realm or user mutation", async () => {
  const requests = [];
  await assert.rejects(
    provisionFeat125LocalUsers({
      secrets: secretValues,
      fetchImpl: successfulFetch(requests, { profileDrift: true }),
    }),
    /local synthetic user provisioning failed closed/,
  );

  assert.equal(
    requests.some(
      ({ url, method }) =>
        method === "PUT" || url.pathname.endsWith("/reset-password"),
    ),
    false,
  );
  assert.equal(requests.some(({ url }) => url.pathname.endsWith("/revoke")), true);
});

test("local provisioner rejects reviewed realm client scope and user metadata drift", async (t) => {
  for (const [name, options] of [
    ["realm brute-force policy", { realmFailureFactor: 6 }],
    ["client protocol", { desktopProtocol: "saml" }],
    ["client scopes", { desktopDefaultScopes: ["profile", "email"] }],
    ["client mapper", { desktopMapperDrift: true }],
    ["user required action", { userRequiredActions: ["UPDATE_PASSWORD"] }],
    ["user classification", { userDataClassification: ["internal"] }],
    ["user name", { userFirstName: "Unexpected" }],
  ]) {
    await t.test(name, async () => {
      const requests = [];
      await assert.rejects(
        provisionFeat125LocalUsers({
          secrets: secretValues,
          fetchImpl: successfulFetch(requests, options),
        }),
        /local synthetic user provisioning failed closed/,
      );
      assert.equal(requests.some(({ url }) => url.pathname.endsWith("/reset-password")), false);
      assert.equal(requests.some(({ url }) => url.pathname.endsWith("/revoke")), true);
    });
  }
});

test("local provisioner fails closed when admin-session revocation fails", async () => {
  const fetchImpl = successfulFetch([], { revocationStatus: 503 });
  await assert.rejects(
    provisionFeat125LocalUsers({ secrets: secretValues, fetchImpl }),
    /bootstrap admin refresh-token revocation failed closed/,
  );
});

test("local provisioner proves the revoked admin refresh token returns invalid_grant", async () => {
  const fetchImpl = successfulFetch([], { revokedRefreshStatus: 200 });
  await assert.rejects(
    provisionFeat125LocalUsers({ secrets: secretValues, fetchImpl }),
    /bootstrap admin refresh-token revocation failed closed/,
  );
});

function successfulFetch(
  requests,
  {
    wrongFirstUserId = false,
    desktopDirectGrantEnabled = false,
    desktopProtocol = "openid-connect",
    desktopDefaultScopes = ["basic", "profile", "email", "roles"],
    desktopMapperDrift = false,
    defaultUserProfile = false,
    profileDrift = false,
    realmFailureFactor = 5,
    userAttributesMissing = false,
    userNamesMissing = false,
    userFirstName,
    userRequiredActions = [],
    userDataClassification = ["synthetic_only"],
    revocationStatus = 200,
    revokedRefreshStatus = 400,
  } = {},
) {
  let reviewedProfileApplied = !defaultUserProfile;
  let activeDesktopDefaultScopes = [...desktopDefaultScopes];
  const reconciledUsers = new Set();
  return async (input, init = {}) => {
    const url = new URL(input);
    const method = init.method ?? "GET";
    requests.push({ url, method, redirect: init.redirect });

    if (url.pathname.endsWith("/token")) {
      const form = new URLSearchParams(init.body);
      if (form.get("grant_type") === "refresh_token") {
        return jsonResponse(
          revokedRefreshStatus === 400
            ? { error: "invalid_grant", error_description: "synthetic revoked token" }
            : {
                token_type: "Bearer",
                access_token: "unexpected-access-token-never-log",
                refresh_token: "unexpected-refresh-token-never-log",
              },
          { status: revokedRefreshStatus },
        );
      }
      assert.equal(form.get("grant_type"), "password");
      return jsonResponse({
        token_type: "Bearer",
        access_token: "access-token-never-log",
        refresh_token: "refresh-token-never-log",
      });
    }
    if (url.pathname.endsWith("/revoke")) {
      return new Response(null, { status: revocationStatus });
    }
    if (url.pathname === "/admin/realms/yijie-local") {
      return jsonResponse({
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
        failureFactor: realmFailureFactor,
        defaultSignatureAlgorithm: "RS256",
        accessTokenLifespan: 600,
        accessTokenLifespanForImplicitFlow: 0,
        ssoSessionIdleTimeout: 1_800,
        ssoSessionMaxLifespan: 36_000,
        revokeRefreshToken: true,
        refreshTokenMaxReuse: 0,
      });
    }
    if (url.pathname.endsWith("/clients")) {
      const clientId = url.searchParams.get("clientId");
      if (clientId === "yijie-desktop-feat-125-local") {
        return jsonResponse([
          desktopClient({
            directAccessGrantsEnabled: desktopDirectGrantEnabled,
            protocol: desktopProtocol,
            defaultClientScopes: activeDesktopDefaultScopes,
          }),
        ]);
      }
      assert.equal(clientId, "https://api.yijie.ai");
      return jsonResponse([apiAudienceClient()]);
    }
    if (url.pathname.endsWith("/client-scopes")) {
      return jsonResponse([
        {
          id: "basic-scope-id",
          name: "basic",
          protocol: "openid-connect",
          attributes: {
            "include.in.token.scope": "false",
            "display.on.consent.screen": "false",
          },
        },
      ]);
    }
    if (url.pathname.endsWith("/default-client-scopes/basic-scope-id")) {
      assert.equal(method, "PUT");
      activeDesktopDefaultScopes = [...activeDesktopDefaultScopes, "basic"];
      return new Response(null, { status: 204 });
    }
    if (url.pathname.endsWith("/protocol-mappers/models")) {
      if (url.pathname.includes("/client-scopes/basic-scope-id/")) {
        return jsonResponse(basicClientScopeMappers());
      }
      const mappers = desktopTokenMappers();
      if (desktopMapperDrift) {
        mappers[0].config["included.client.audience"] = "https://drifted.example.invalid";
      }
      return jsonResponse(mappers);
    }
    if (url.pathname.endsWith("/users/profile")) {
      if (method === "PUT") {
        assert.deepEqual(JSON.parse(init.body), REVIEWED_USER_PROFILE);
        reviewedProfileApplied = true;
        return jsonResponse(REVIEWED_USER_PROFILE);
      }
      if (profileDrift) {
        return jsonResponse(driftedProfile());
      }
      return jsonResponse(reviewedProfileApplied ? REVIEWED_USER_PROFILE : defaultProfile());
    }
    if (url.pathname.endsWith("/users")) {
      assert.equal(url.searchParams.get("max"), "3");
      assert.equal(url.searchParams.get("briefRepresentation"), "false");
      return jsonResponse(
        SYNTHETIC_USERS.map((user, index) => ({
          id: wrongFirstUserId && index === 0 ? "drifted-user-id" : user.id,
          username: user.username,
          email: user.email,
          firstName: userNamesMissing ? undefined : user.firstName,
          lastName: userNamesMissing ? undefined : user.lastName,
          enabled: true,
          emailVerified: true,
        })),
      );
    }
    const fixedUser = SYNTHETIC_USERS.find(
      (user) => url.pathname === `/admin/realms/yijie-local/users/${user.id}`,
    );
    if (fixedUser) {
      if (method === "PUT") {
        assert.deepEqual(JSON.parse(init.body), reviewedSyntheticUser(fixedUser));
        reconciledUsers.add(fixedUser.id);
        return new Response(null, { status: 204 });
      }
      return jsonResponse({
        id: fixedUser.id,
        username: fixedUser.username,
        email: fixedUser.email,
        firstName:
          userNamesMissing && !reconciledUsers.has(fixedUser.id)
            ? undefined
            : (userFirstName ?? fixedUser.firstName),
        lastName:
          userNamesMissing && !reconciledUsers.has(fixedUser.id)
            ? undefined
            : fixedUser.lastName,
        enabled: true,
        emailVerified: true,
        requiredActions: userRequiredActions,
        attributes:
          userAttributesMissing && !reconciledUsers.has(fixedUser.id)
            ? undefined
            : { data_classification: userDataClassification },
      });
    }
    if (url.pathname.endsWith("/reset-password")) {
      assert.equal(init.headers.authorization, "Bearer access-token-never-log");
      const body = JSON.parse(init.body);
      assert.equal(body.type, "password");
      assert.equal(body.temporary, false);
      assert.match(body.value, /^[a-f0-9]{64}$/);
      return new Response(null, { status: 204 });
    }
    throw new Error(`unexpected mock request: ${url.pathname}`);
  };
}

function defaultProfile() {
  return {
    ...REVIEWED_USER_PROFILE,
    attributes: REVIEWED_USER_PROFILE.attributes.filter(
      ({ name }) => name !== "data_classification",
    ),
  };
}

function driftedProfile() {
  return {
    ...REVIEWED_USER_PROFILE,
    attributes: [
      ...REVIEWED_USER_PROFILE.attributes,
      {
        name: "unexpected_attribute",
        permissions: { view: ["admin"], edit: ["admin"] },
        multivalued: false,
      },
    ],
  };
}

function reviewedSyntheticUser(user) {
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
    enabled: true,
    emailVerified: true,
    requiredActions: [],
    attributes: { data_classification: ["synthetic_only"] },
  };
}

function desktopClient({
  directAccessGrantsEnabled = false,
  protocol = "openid-connect",
  defaultClientScopes = ["basic", "profile", "email", "roles"],
} = {}) {
  return {
    id: "desktop-client-id",
    clientId: "yijie-desktop-feat-125-local",
    name: "Yijie Desktop FEAT-125 local native client",
    description: "Synthetic-only public native client; no client secret is permitted.",
    enabled: true,
    protocol,
    bearerOnly: false,
    publicClient: true,
    consentRequired: false,
    standardFlowEnabled: true,
    implicitFlowEnabled: false,
    directAccessGrantsEnabled,
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
    defaultClientScopes,
    optionalClientScopes: ["offline_access"],
  };
}

function desktopTokenMappers() {
  return [
    {
      name: "yijie-api-audience",
      protocol: "openid-connect",
      protocolMapper: "oidc-audience-mapper",
      consentRequired: false,
      config: {
        "included.client.audience": "https://api.yijie.ai",
        "id.token.claim": "false",
        "access.token.claim": "true",
        "introspection.token.claim": "true",
        "userinfo.token.claim": "false",
      },
    },
    {
      name: "yijie-api-not-before",
      protocol: "openid-connect",
      protocolMapper: "oidc-usersessionmodel-note-mapper",
      consentRequired: false,
      config: {
        "user.session.note": "AUTH_TIME",
        "introspection.token.claim": "true",
        "userinfo.token.claim": "false",
        "id.token.claim": "false",
        "access.token.claim": "true",
        "claim.name": "nbf",
        "jsonType.label": "long",
      },
    },
  ];
}

function basicClientScopeMappers() {
  return [
    {
      name: "auth_time",
      protocol: "openid-connect",
      protocolMapper: "oidc-usersessionmodel-note-mapper",
      consentRequired: false,
      config: {
        "user.session.note": "AUTH_TIME",
        "introspection.token.claim": "true",
        "userinfo.token.claim": "true",
        "id.token.claim": "true",
        "access.token.claim": "true",
        "claim.name": "auth_time",
        "jsonType.label": "long",
      },
    },
    {
      name: "sub",
      protocol: "openid-connect",
      protocolMapper: "oidc-sub-mapper",
      consentRequired: false,
      config: {
        "introspection.token.claim": "true",
        "access.token.claim": "true",
      },
    },
  ];
}

function apiAudienceClient() {
  return {
    id: "api-audience-client-id",
    clientId: "https://api.yijie.ai",
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
  };
}

function jsonResponse(value, init = {}) {
  return new Response(JSON.stringify(value), {
    ...init,
    headers: { "content-type": "application/json", ...init.headers },
  });
}
