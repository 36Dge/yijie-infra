import { readFile } from "node:fs/promises";

import YAML from "yaml";

export const BASE_SERVICES = Object.freeze(["postgres", "redis", "pgvector"]);
export const FEAT_125_LOCAL_SERVICES = Object.freeze([
  "feat125-keycloak-db",
  "feat125-keycloak",
  "feat125-caddy",
]);
export const FEAT_125_LOCAL_PROFILE = "feat-125-local";
export const FEAT_125_LOCAL_IMAGES = Object.freeze({
  "feat125-keycloak-db":
    "postgres:16.13-alpine@sha256:4e6e670bb069649261c9c18031f0aded7bb249a5b6664ddec29c013a89310d50",
  "feat125-keycloak":
    "quay.io/keycloak/keycloak:26.7.0@sha256:0f198be292568439d700cdbfb893e69a6009bb43a94a06a945b1d3d506c76b13",
  "feat125-caddy":
    "caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648",
});

const EXPECTED_VOLUMES = new Set([
  "yijie_postgres_data",
  "yijie_redis_data",
  "yijie_pgvector_data",
  "yijie_feat125_keycloak_postgres_data",
  "yijie_feat125_caddy_data",
  "yijie_feat125_caddy_config",
]);
const EXPECTED_NETWORKS = new Set([
  "feat125_identity_internal",
  "feat125_proxy_internal",
  "feat125_host_bridge",
]);

export async function loadCompose() {
  const compose = YAML.parse(await readFile("docker-compose.local.yml", "utf8"));
  if (!compose?.services || !compose?.volumes) {
    throw new Error("Compose file must define services and volumes.");
  }
  return compose;
}

export function validateCompose(compose) {
  const allowedServices = new Set([...BASE_SERVICES, ...FEAT_125_LOCAL_SERVICES]);
  const serviceNames = Object.keys(compose.services);
  exactSet(new Set(serviceNames), allowedServices, "local Compose services");

  for (const name of BASE_SERVICES) {
    const service = compose.services[name];
    requireTaggedImage(service, name);
    requireHealthcheck(service, name);
    if (!Array.isArray(service.volumes) || service.volumes.length === 0) {
      throw new Error(`${name} must use a persistent volume.`);
    }
    if (service.profiles !== undefined) {
      throw new Error(`${name} must remain available without an opt-in profile.`);
    }
  }

  validateBasePortsAndPgvector(compose);
  validateFeat125LocalServices(compose);
  validatePublishedPorts(compose);
  validateTopLevelResources(compose);
  validateCommonContainerBoundaries(compose);
}

function validateBasePortsAndPgvector(compose) {
  if (!compose.services.postgres.ports.includes("127.0.0.1:5432:5432")) {
    throw new Error("postgres must be exposed on loopback host port 5432.");
  }
  if (!compose.services.redis.ports.includes("127.0.0.1:6379:6379")) {
    throw new Error("redis must be exposed on loopback host port 6379.");
  }
  if (!compose.services.pgvector.ports.includes("127.0.0.1:5433:5432")) {
    throw new Error("pgvector must be exposed on loopback host port 5433.");
  }
  const pgvectorVolumes = compose.services.pgvector.volumes.map(String);
  if (!pgvectorVolumes.some((volume) => volume.includes("001-enable-vector.sql"))) {
    throw new Error("pgvector must initialize the vector extension.");
  }
  if (!compose.services.pgvector.healthcheck.test.join(" ").includes("pg_extension")) {
    throw new Error("pgvector healthcheck must verify the vector extension.");
  }
}

function validateFeat125LocalServices(compose) {
  for (const name of FEAT_125_LOCAL_SERVICES) {
    const service = compose.services[name];
    if (service.image !== FEAT_125_LOCAL_IMAGES[name]) {
      throw new Error(`${name} must use its reviewed immutable image pin.`);
    }
    if (!/^.+:[^@]+@sha256:[a-f0-9]{64}$/.test(service.image)) {
      throw new Error(`${name} image must contain both an exact version and digest.`);
    }
    if (JSON.stringify(service.profiles) !== JSON.stringify([FEAT_125_LOCAL_PROFILE])) {
      throw new Error(`${name} must be disabled by default behind ${FEAT_125_LOCAL_PROFILE}.`);
    }
    requireHealthcheck(service, name);
  }

  const database = compose.services["feat125-keycloak-db"];
  if ((database.ports ?? []).length !== 0) {
    throw new Error("feat125-keycloak-db must not publish a host port.");
  }
  exactSet(
    new Set(database.networks ?? []),
    new Set(["feat125_identity_internal"]),
    "feat125-keycloak-db networks",
  );
  if (!database.volumes.includes("yijie_feat125_keycloak_postgres_data:/var/lib/postgresql/data")) {
    throw new Error("feat125-keycloak-db must use its dedicated named volume.");
  }
  if (String(database.environment?.POSTGRES_PASSWORD) !== "${FEAT125_KEYCLOAK_DB_PASSWORD:-}") {
    throw new Error("feat125-keycloak-db password must come from the required ignored secrets file.");
  }

  const keycloak = compose.services["feat125-keycloak"];
  if ((keycloak.ports ?? []).length !== 0) {
    throw new Error("feat125-keycloak must only be reachable through the internal proxy network.");
  }
  exactSet(
    new Set(keycloak.networks ?? []),
    new Set(["feat125_identity_internal", "feat125_proxy_internal"]),
    "feat125-keycloak networks",
  );
  if (JSON.stringify(keycloak.command) !== JSON.stringify(["start", "--import-realm"])) {
    throw new Error("feat125-keycloak must use production-mode start with deterministic realm import.");
  }
  for (const [name, expected] of [
    ["KC_HOSTNAME", "https://localhost:8443"],
    ["KC_HTTP_ENABLED", "true"],
    ["KC_PROXY_HEADERS", "xforwarded"],
    ["KC_HEALTH_ENABLED", "true"],
  ]) {
    if (String(keycloak.environment?.[name]) !== expected) {
      throw new Error(`feat125-keycloak ${name} must equal ${expected}.`);
    }
  }
  if (String(keycloak.environment?.KC_DB_PASSWORD) !== "${FEAT125_KEYCLOAK_DB_PASSWORD:-}") {
    throw new Error("feat125-keycloak database password must come from the ignored secrets file.");
  }
  if (String(keycloak.environment?.KC_BOOTSTRAP_ADMIN_PASSWORD) !== "${FEAT125_KEYCLOAK_ADMIN_PASSWORD:-}") {
    throw new Error("feat125-keycloak admin password must come from the ignored secrets file.");
  }
  const realmMount = "./config/feat-125-local/keycloak/realm.json:/opt/keycloak/data/import/yijie-local-realm.json:ro";
  if (!keycloak.volumes?.includes(realmMount)) {
    throw new Error("feat125-keycloak must mount the reviewed realm read-only.");
  }
  const keycloakHealthcheck = keycloak.healthcheck?.test?.join(" ") ?? "";
  if (
    !keycloakHealthcheck.includes("/health/ready") ||
    !keycloakHealthcheck.includes("^HTTP/1\\.[01] 200([[:space:]]|$)")
  ) {
    throw new Error("feat125-keycloak healthcheck must require an HTTP/1.0 or HTTP/1.1 200 readiness status line.");
  }

  const caddy = compose.services["feat125-caddy"];
  exactSet(
    new Set(caddy.ports ?? []),
    new Set(["127.0.0.1:8443:8443", "127.0.0.1:9443:9443"]),
    "feat125-caddy published ports",
  );
  exactSet(
    new Set(caddy.networks ?? []),
    new Set(["feat125_proxy_internal", "feat125_host_bridge"]),
    "feat125-caddy networks",
  );
  if (JSON.stringify(caddy.extra_hosts) !== JSON.stringify(["host.docker.internal:host-gateway"])) {
    throw new Error("feat125-caddy may reach the host API only through host.docker.internal.");
  }
  for (const volume of [
    "./config/feat-125-local/Caddyfile:/etc/caddy/Caddyfile:ro",
    "yijie_feat125_caddy_data:/data",
    "yijie_feat125_caddy_config:/config",
  ]) {
    if (!caddy.volumes?.includes(volume)) {
      throw new Error(`feat125-caddy is missing required volume: ${volume}`);
    }
  }
  if (
    caddy.read_only !== true ||
    JSON.stringify(caddy.cap_drop) !== JSON.stringify(["ALL"]) ||
    JSON.stringify(caddy.cap_add) !== JSON.stringify(["NET_BIND_SERVICE"])
  ) {
    throw new Error(
      "feat125-caddy must use a read-only root filesystem, drop all capabilities, and add back only NET_BIND_SERVICE.",
    );
  }
  if (
    JSON.stringify(caddy.healthcheck?.test) !==
    JSON.stringify(["CMD", "wget", "-qO-", "http://127.0.0.1:2019/config/"])
  ) {
    throw new Error("feat125-caddy healthcheck must use Alpine BusyBox wget against its admin API.");
  }
}

function validatePublishedPorts(compose) {
  const publishedPorts = Object.values(compose.services)
    .flatMap((service) => service.ports ?? [])
    .map(String);
  for (const port of publishedPorts) {
    if (!port.startsWith("127.0.0.1:")) {
      throw new Error("Local service ports must bind to the IPv4 loopback interface.");
    }
  }
  const hostPorts = publishedPorts.map((port) => port.split(":").at(-2));
  if (new Set(hostPorts).size !== hostPorts.length) {
    throw new Error("Local service host ports must be unique.");
  }
}

function validateTopLevelResources(compose) {
  exactSet(new Set(Object.keys(compose.volumes ?? {})), EXPECTED_VOLUMES, "named volumes");
  exactSet(new Set(Object.keys(compose.networks ?? {})), EXPECTED_NETWORKS, "local networks");
  for (const name of ["feat125_identity_internal", "feat125_proxy_internal"]) {
    if (compose.networks[name]?.internal !== true) {
      throw new Error(`${name} must be an internal-only Docker network.`);
    }
  }
  if (compose.networks.feat125_host_bridge?.internal === true) {
    throw new Error("feat125_host_bridge must permit Caddy to reach the host-only API upstream.");
  }
}

function validateCommonContainerBoundaries(compose) {
  for (const [name, service] of Object.entries(compose.services)) {
    if (service.privileged === true || service.network_mode === "host") {
      throw new Error(`${name} must not use privileged or host-network mode.`);
    }
    for (const volume of service.volumes ?? []) {
      if (String(volume).includes("/var/run/docker.sock")) {
        throw new Error(`${name} must not mount the Docker socket.`);
      }
    }
  }
}

function requireTaggedImage(service, name) {
  if (!service?.image || service.image.endsWith(":latest")) {
    throw new Error(`${name} must use a tagged image.`);
  }
}

function requireHealthcheck(service, name) {
  if (!service?.healthcheck?.test) {
    throw new Error(`${name} must define a healthcheck.`);
  }
}

function exactSet(actual, expected, label) {
  const missing = [...expected].filter((value) => !actual.has(value));
  const unexpected = [...actual].filter((value) => !expected.has(value));
  if (missing.length > 0 || unexpected.length > 0) {
    throw new Error(
      `${label} mismatch; missing=${JSON.stringify(missing)} unexpected=${JSON.stringify(unexpected)}`,
    );
  }
}
