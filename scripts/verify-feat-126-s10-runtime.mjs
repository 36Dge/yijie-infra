#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { lstat, readFile } from "node:fs/promises";
import https from "node:https";
import net from "node:net";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { FEAT_126_S10_IMAGES, FEAT_126_S10_SERVICES } from "./compose-model.mjs";
import { validateFeat126S10Secrets } from "./feat-126-s10-secrets.mjs";

const runId = process.argv[2];
if (
  process.argv.length !== 3 ||
  !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
    runId ?? "",
  )
) {
  throw new Error("usage: verify-feat-126-s10-runtime.mjs CANONICAL_LOWERCASE_UUIDV4");
}

const repositoryRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const compactRunId = runId.replaceAll("-", "");
const project = `yijie-feat126-s10-${compactRunId}`;
const caPath = resolve(
  repositoryRoot,
  "environments/local/generated/feat-126-s10",
  runId,
  "caddy-root.crt",
);
const secretsPath = resolve(
  repositoryRoot,
  "environments/local/generated/feat-126-s10",
  runId,
  "infra-secrets.env",
);

function exactSet(actual, expected, label) {
  if (actual.size !== expected.size || [...actual].some((value) => !expected.has(value))) {
    throw new Error(`${label} mismatch`);
  }
}

function runDocker(arguments_) {
  const result = spawnSync("docker", arguments_, {
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.status !== 0 || result.error) {
    throw new Error("Docker runtime query failed");
  }
  return `${result.stdout ?? ""}${result.stderr ?? ""}`;
}

function request(url, ca) {
  return new Promise((resolveRequest, rejectRequest) => {
    const request_ = https.get(url, { ca, rejectUnauthorized: true, timeout: 5_000 }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => {
        body += chunk;
        if (body.length > 65_536) {
          request_.destroy(new Error("HTTPS response exceeded the S10E capacity limit"));
        }
      });
      response.on("end", () => resolveRequest({ statusCode: response.statusCode, body }));
    });
    request_.on("timeout", () => request_.destroy(new Error("HTTPS readiness timeout")));
    request_.on("error", rejectRequest);
  });
}

function requireTcpListener(port) {
  return new Promise((resolveConnection, rejectConnection) => {
    const socket = net.createConnection({ host: "127.0.0.1", port });
    socket.setTimeout(3_000);
    socket.once("connect", () => {
      socket.destroy();
      resolveConnection();
    });
    socket.once("timeout", () => socket.destroy(new Error(`loopback port ${port} timed out`)));
    socket.once("error", rejectConnection);
  });
}

const caStats = await lstat(caPath);
if (!caStats.isFile() || caStats.isSymbolicLink() || (caStats.mode & 0o077) !== 0) {
  throw new Error("public CA must be an owner-only regular non-symlink file");
}
const ca = await readFile(caPath, "utf8");
const secrets = await validateFeat126S10Secrets(secretsPath);
if (
  ca.length === 0 ||
  ca.length > 65_536 ||
  ca.includes("PRIVATE KEY") ||
  (ca.match(/-----BEGIN CERTIFICATE-----/g) ?? []).length !== 1 ||
  (ca.match(/-----END CERTIFICATE-----/g) ?? []).length !== 1
) {
  throw new Error("public CA must contain exactly one bounded certificate and no private key");
}

const containerNames = FEAT_126_S10_SERVICES.map((service) => `${project}-${service}-1`);
const containers = JSON.parse(runDocker(["inspect", ...containerNames]));
if (!Array.isArray(containers) || containers.length !== FEAT_126_S10_SERVICES.length) {
  throw new Error("container inventory mismatch");
}

const expectedNetworks = {
  "feat126-s10-api-db": new Set(["feat126_s10_api_internal", "feat126_s10_host_bridge"]),
  "feat126-s10-keycloak-db": new Set(["feat126_s10_identity_internal"]),
  "feat126-s10-keycloak": new Set([
    "feat126_s10_identity_internal",
    "feat126_s10_proxy_internal",
  ]),
  "feat126-s10-caddy": new Set(["feat126_s10_proxy_internal", "feat126_s10_host_bridge"]),
};
const expectedPorts = {
  "feat126-s10-api-db": new Set(["5432/tcp@127.0.0.1:5432"]),
  "feat126-s10-keycloak-db": new Set(),
  "feat126-s10-keycloak": new Set(),
  "feat126-s10-caddy": new Set([
    "8443/tcp@127.0.0.1:8443",
    "9443/tcp@127.0.0.1:9443",
  ]),
};

for (const container of containers) {
  const labels = container.Config?.Labels ?? {};
  const service = labels["com.docker.compose.service"];
  if (!FEAT_126_S10_SERVICES.includes(service)) {
    throw new Error("unexpected Compose service in runtime inventory");
  }
  if (
    container.Config?.Image !== FEAT_126_S10_IMAGES[service] ||
    container.State?.Running !== true ||
    container.State?.Health?.Status !== "healthy"
  ) {
    throw new Error(`${service} image or health mismatch`);
  }
  if (
    labels["ai.yijie.feature"] !== "FEAT-126" ||
    labels["ai.yijie.slice"] !== "S10E" ||
    labels["ai.yijie.run-id"] !== runId ||
    labels["ai.yijie.data-classification"] !== "synthetic-only"
  ) {
    throw new Error(`${service} closed run labels mismatch`);
  }
  if (
    container.HostConfig?.Privileged !== false ||
    container.HostConfig?.NetworkMode === "host" ||
    !(container.HostConfig?.SecurityOpt ?? []).includes("no-new-privileges:true") ||
    (container.Mounts ?? []).some((mount) => mount.Destination === "/var/run/docker.sock")
  ) {
    throw new Error(`${service} runtime security boundary mismatch`);
  }

  const networkSuffixes = new Set(
    Object.keys(container.NetworkSettings?.Networks ?? {}).map((name) =>
      name.startsWith(`${project}_`) ? name.slice(project.length + 1) : name,
    ),
  );
  exactSet(networkSuffixes, expectedNetworks[service], `${service} networks`);

  const publishedPorts = new Set();
  for (const [containerPort, bindings] of Object.entries(container.NetworkSettings?.Ports ?? {})) {
    for (const binding of bindings ?? []) {
      publishedPorts.add(`${containerPort}@${binding.HostIp}:${binding.HostPort}`);
    }
  }
  exactSet(publishedPorts, expectedPorts[service], `${service} published ports`);

  const logs = runDocker(["logs", container.Name.slice(1)]);
  if ([...secrets.values()].some((value) => logs.includes(value))) {
    throw new Error(`${service} logs contain generated credential material`);
  }
}

const expectedVolumeNames = new Set(
  [
    "feat126_s10_api_postgres_data",
    "feat126_s10_keycloak_postgres_data",
    "feat126_s10_caddy_data",
    "feat126_s10_caddy_config",
  ].map((name) => `${project}_${name}`),
);
const actualVolumeNames = new Set(
  runDocker(["volume", "ls", "--filter", `label=com.docker.compose.project=${project}`, "--format", "{{.Name}}"])
    .trim()
    .split("\n")
    .filter(Boolean),
);
exactSet(actualVolumeNames, expectedVolumeNames, "project volume inventory");

const expectedNetworkNames = new Set(
  [
    "feat126_s10_api_internal",
    "feat126_s10_identity_internal",
    "feat126_s10_proxy_internal",
    "feat126_s10_host_bridge",
  ].map((name) => `${project}_${name}`),
);
const actualNetworkNames = new Set(
  runDocker([
    "network",
    "ls",
    "--filter",
    `label=com.docker.compose.project=${project}`,
    "--format",
    "{{.Name}}",
  ])
    .trim()
    .split("\n")
    .filter(Boolean),
);
exactSet(actualNetworkNames, expectedNetworkNames, "project network inventory");

await requireTcpListener(5432);
const discovery = await request(
  "https://localhost:8443/realms/yijie-local/.well-known/openid-configuration",
  ca,
);
if (
  discovery.statusCode !== 200 ||
  JSON.parse(discovery.body).issuer !== "https://localhost:8443/realms/yijie-local"
) {
  throw new Error("OIDC discovery or issuer mismatch");
}
const tasksBoundary = await request("https://localhost:9443/v1/tasks", ca);
if (tasksBoundary.statusCode !== 404) {
  throw new Error("Caddy Tasks denial boundary mismatch");
}

console.log("Verified FEAT-126 S10E runtime inventory, isolation, TLS, OIDC, and Tasks denial.");
