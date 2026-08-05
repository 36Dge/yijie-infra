import { pathToFileURL } from "node:url";

const AUTHORITY_KEYS = Object.freeze([
  "api_port",
  "database_host",
  "database_name",
  "database_port",
  "database_sslmode",
  "environment",
  "issuer",
  "jwks_url",
  "permission_projection_enabled",
  "schema_version",
  "secure_tasks_enabled",
  "service_profile",
]);
const RUN_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/**
 * The single Infra-owned, versioned authority for every FEAT-126 S10 API
 * process. The combined preflight and any subsequent full-run orchestration
 * must consume this projection instead of reconstructing profile values.
 */
export const FEAT_126_S10_API_RUNTIME_AUTHORITY = Object.freeze({
  schema_version: 1,
  environment: "nonproduction",
  service_profile: "feat-126-s10-local-lab",
  api_port: 18080,
  database_host: "127.0.0.1",
  database_port: 5432,
  database_name: "yijie_api_feat126_s10",
  database_sslmode: "disable",
  issuer: "https://localhost:8443/realms/yijie-local",
  jwks_url: "https://localhost:8443/realms/yijie-local/protocol/openid-connect/certs",
  permission_projection_enabled: true,
  secure_tasks_enabled: true,
});

export class Feat126S10ApiRuntimeProfileError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function fail() {
  throw new Feat126S10ApiRuntimeProfileError("api_runtime_profile_authority_invalid");
}

export function validateApiRuntimeAuthority(value) {
  if (
    value === null ||
    Array.isArray(value) ||
    typeof value !== "object" ||
    JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(AUTHORITY_KEYS) ||
    AUTHORITY_KEYS.some((key) => value[key] !== FEAT_126_S10_API_RUNTIME_AUTHORITY[key])
  ) {
    fail();
  }
  return Object.freeze({ ...value });
}

export function readApiRuntimeAuthorityFromPreflightSummary(summary, expectedRunId) {
  if (
    !RUN_ID_PATTERN.test(expectedRunId ?? "") ||
    summary === null ||
    Array.isArray(summary) ||
    typeof summary !== "object" ||
    summary.schema_version !== 1 ||
    summary.status !== "passed" ||
    summary.scope !== "S10B-001-combined-preflight" ||
    summary.run_id !== expectedRunId
  ) {
    fail();
  }
  return validateApiRuntimeAuthority(summary.api_runtime_authority);
}

function requireRuntimeInput(value, pattern) {
  if (typeof value !== "string" || !pattern.test(value)) fail();
  return value;
}

export function buildApiRuntimeEnvironment({
  authority = FEAT_126_S10_API_RUNTIME_AUTHORITY,
  databasePassword,
  localCaPemPath,
  localCaSha256,
} = {}) {
  const closed = validateApiRuntimeAuthority(authority);
  const password = requireRuntimeInput(databasePassword, /^[A-Za-z0-9_-]{32,256}$/);
  const caPath = requireRuntimeInput(localCaPemPath, /^\/.{1,4095}$/);
  const caSha256 = requireRuntimeInput(localCaSha256, /^[0-9a-f]{64}$/);
  const username = "yijie";
  const encodedUsername = encodeURIComponent(username);
  const encodedPassword = encodeURIComponent(password);

  return Object.freeze({
    YIJIE_ENV: closed.environment,
    YIJIE_API_SERVICE_PROFILE: closed.service_profile,
    YIJIE_API_PORT: String(closed.api_port),
    YIJIE_API_POSTGRES_DSN:
      `postgres://${encodedUsername}:${encodedPassword}@${closed.database_host}:` +
      `${closed.database_port}/${closed.database_name}?sslmode=${closed.database_sslmode}`,
    YIJIE_API_DB_MIN_CONNS: "1",
    YIJIE_API_DB_MAX_CONNS: "4",
    YIJIE_API_PERMISSION_PROJECTION_ENABLED: String(closed.permission_projection_enabled),
    YIJIE_API_SECURE_TASKS_ENABLED: String(closed.secure_tasks_enabled),
    YIJIE_API_ACCESS_ISSUER: closed.issuer,
    YIJIE_API_ACCESS_JWKS_URL: closed.jwks_url,
    YIJIE_API_LOCAL_CA_PEM_PATH: caPath,
    YIJIE_API_LOCAL_CA_SHA256: caSha256,
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv.length === 2) {
    process.stdout.write(`${JSON.stringify(FEAT_126_S10_API_RUNTIME_AUTHORITY)}\n`);
  } else if (process.argv.length === 3 && process.argv[2] === "--service-profile") {
    process.stdout.write(`${FEAT_126_S10_API_RUNTIME_AUTHORITY.service_profile}\n`);
  } else {
    process.stderr.write(
      `${JSON.stringify({ schema_version: 1, status: "failed", failure_class: "api_runtime_profile_arguments_invalid" })}\n`,
    );
    process.exitCode = 1;
  }
}
