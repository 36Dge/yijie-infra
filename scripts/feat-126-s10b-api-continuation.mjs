#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readFile, realpath } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  buildApiRuntimeEnvironment,
  readApiRuntimeAuthorityFromPreflightSummary,
} from "./feat-126-s10-api-runtime-profile.mjs";
import { inspectApiBinary, sameApiBinarySnapshot } from "./feat-126-s10-api-binary.mjs";
import { parseFeat126S10Secrets } from "./feat-126-s10-secrets.mjs";
import {
  readExpectedSHAs,
  validateHostRuntimeArtifactGateEvidence,
  validateProbeResult,
} from "./feat-126-s10b-preflight.mjs";

const INFRA_ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const RUN_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SUMMARY_KEYS = Object.freeze([
  "api_binary_sha256",
  "api_runtime_authority",
  "cleanup",
  "completed",
  "fake_readiness",
  "host_runtime_artifact_gate",
  "repositories",
  "run_id",
  "s10b_r5_executed",
  "schema_version",
  "scope",
  "status",
]);
const REPOSITORY_KEYS = Object.freeze([
  "api",
  "contracts",
  "desktop",
  "governance",
  "host",
  "infra",
  "runtime",
]);
const REQUIRED_COMPLETED = Object.freeze([
  "authority",
  "ports",
  "host_runtime_artifact",
  "secret_init",
  "compose",
  "images",
  "dependencies",
  "tls_oidc",
  "identity",
  "migration",
  "bootstrap",
  "api_binary",
  "host_binary",
  "fake_binary",
  "probe_binary",
  "api_health",
  "api_readiness",
  "host_owned_fake_authority",
  "fake_readiness",
  "content_free_logs",
]);
const FORBIDDEN_OVERRIDE_ENV = Object.freeze([
  "YIJIE_ENV",
  "YIJIE_API_SERVICE_PROFILE",
  "YIJIE_API_PORT",
  "YIJIE_API_POSTGRES_DSN",
  "YIJIE_API_REDIS_URL",
  "YIJIE_API_DB_MIN_CONNS",
  "YIJIE_API_DB_MAX_CONNS",
  "YIJIE_API_PERMISSION_PROJECTION_ENABLED",
  "YIJIE_API_SECURE_TASKS_ENABLED",
  "YIJIE_API_ACCESS_ISSUER",
  "YIJIE_API_ACCESS_JWKS_URL",
  "YIJIE_API_LOCAL_CA_PEM_PATH",
  "YIJIE_API_LOCAL_CA_SHA256",
  "FEAT126_S10B_API_BINARY",
  "FEAT126_S10B_API_ENDPOINT",
  "FEAT126_S10B_API_PROFILE",
  "FEAT126_S10B_RUN_ROOT",
  "FEAT126_S10B_SUMMARY_PATH",
  "FEAT126_S10B_SECRETS_PATH",
  "FEAT126_S10B_CA_PATH",
  "FEAT126_S10B_LOG_PATH",
]);
const MAX_SUMMARY_BYTES = 64 * 1024;
const MAX_CA_BYTES = 64 * 1024;
const MAX_CHILD_OUTPUT_BYTES = 1024 * 1024;

export class S10BApiContinuationError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function fail(code) {
  throw new S10BApiContinuationError(code);
}

function ownedByCurrentUser(metadata) {
  return typeof process.getuid !== "function" || metadata.uid === process.getuid();
}

async function requireOwnerDirectory(path) {
  let metadata;
  try {
    metadata = await lstat(path);
    if (
      !metadata.isDirectory() ||
      metadata.isSymbolicLink() ||
      !ownedByCurrentUser(metadata) ||
      (metadata.mode & 0o777) !== 0o700 ||
      (await realpath(path)) !== path
    ) {
      fail("continuation_artifact_invalid");
    }
  } catch (error) {
    if (error instanceof S10BApiContinuationError) throw error;
    fail("continuation_artifact_invalid");
  }
}

async function readSecureFile(path, { maximumBytes, modes }) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = await handle.stat();
    if (
      !metadata.isFile() ||
      metadata.isSymbolicLink() ||
      !ownedByCurrentUser(metadata) ||
      metadata.nlink !== 1 ||
      !modes.includes(metadata.mode & 0o777) ||
      metadata.size < 1 ||
      metadata.size > maximumBytes ||
      (await realpath(path)) !== path
    ) {
      fail("continuation_artifact_invalid");
    }
    return await handle.readFile();
  } catch (error) {
    if (error instanceof S10BApiContinuationError) throw error;
    fail("continuation_artifact_invalid");
  } finally {
    await handle?.close();
  }
}

function requireNoOverrides(environment) {
  if (FORBIDDEN_OVERRIDE_ENV.some((key) => Object.hasOwn(environment, key))) {
    fail("continuation_override_forbidden");
  }
}

function readRepositoryAuthority(environment) {
  try {
    return readExpectedSHAs(environment);
  } catch {
    fail("continuation_repository_authority_invalid");
  }
}

export function validateContinuationSummary(summary, runId, expectedRepositories) {
  if (
    summary === null ||
    Array.isArray(summary) ||
    typeof summary !== "object" ||
    JSON.stringify(Object.keys(summary).sort()) !== JSON.stringify(SUMMARY_KEYS) ||
    summary.schema_version !== 1 ||
    summary.status !== "passed" ||
    summary.scope !== "S10B-001-combined-preflight" ||
    summary.run_id !== runId ||
    summary.cleanup !== "passed" ||
    summary.s10b_r5_executed !== false ||
    !/^[0-9a-f]{64}$/.test(summary.api_binary_sha256 ?? "") ||
    !Array.isArray(summary.completed) ||
    JSON.stringify(summary.completed) !== JSON.stringify(REQUIRED_COMPLETED) ||
    summary.repositories === null ||
    Array.isArray(summary.repositories) ||
    typeof summary.repositories !== "object" ||
    JSON.stringify(Object.keys(summary.repositories).sort()) !== JSON.stringify(REPOSITORY_KEYS) ||
    REPOSITORY_KEYS.some((key) => summary.repositories[key] !== expectedRepositories[key])
  ) {
    fail("continuation_preflight_summary_invalid");
  }
  try {
    validateProbeResult(summary.fake_readiness, runId);
    validateHostRuntimeArtifactGateEvidence(
      summary.host_runtime_artifact_gate,
      expectedRepositories,
    );
    return Object.freeze({
      authority: readApiRuntimeAuthorityFromPreflightSummary(summary, runId),
      apiBinarySha256: summary.api_binary_sha256,
    });
  } catch {
    fail("continuation_preflight_summary_invalid");
  }
}

async function loadContinuation(runId, environment) {
  if (!RUN_ID_PATTERN.test(runId ?? "")) fail("continuation_run_id_invalid");
  requireNoOverrides(environment);
  const repositories = readRepositoryAuthority(environment);
  const runRoot = resolve(
    INFRA_ROOT,
    "environments/local/generated/feat-126-s10",
    runId,
  );
  const evidenceRoot = resolve(runRoot, "preflight-evidence");
  const binRoot = resolve(runRoot, "bin");
  const logRoot = resolve(runRoot, "logs");
  const summaryPath = resolve(evidenceRoot, "summary.json");
  const secretsPath = resolve(runRoot, "infra-secrets.env");
  const caPath = resolve(runRoot, "caddy-root.crt");
  const binaryPath = resolve(binRoot, "yijie-api");
  const logPath = resolve(logRoot, "api-continuation.log");

  for (const directory of [runRoot, evidenceRoot, binRoot, logRoot]) {
    await requireOwnerDirectory(directory);
  }
  const summaryBytes = await readSecureFile(summaryPath, {
    maximumBytes: MAX_SUMMARY_BYTES,
    modes: [0o600],
  });
  let summary;
  try {
    summary = JSON.parse(summaryBytes.toString("utf8"));
  } catch {
    fail("continuation_preflight_summary_invalid");
  }
  const continuationAuthority = validateContinuationSummary(summary, runId, repositories);

  const secretBytes = await readSecureFile(secretsPath, { maximumBytes: 4096, modes: [0o600] });
  let secrets;
  try {
    secrets = parseFeat126S10Secrets(secretBytes.toString("utf8"));
  } catch {
    fail("continuation_secret_store_invalid");
  }
  const ca = await readSecureFile(caPath, {
    maximumBytes: MAX_CA_BYTES,
    modes: [0o400, 0o600],
  });
  const caText = ca.toString("utf8");
  if (
    (caText.match(/-----BEGIN CERTIFICATE-----/g) ?? []).length !== 1 ||
    (caText.match(/-----END CERTIFICATE-----/g) ?? []).length !== 1 ||
    /PRIVATE KEY/.test(caText)
  ) {
    fail("continuation_ca_invalid");
  }
  let apiBinarySnapshot;
  try {
    apiBinarySnapshot = await inspectApiBinary(binaryPath);
  } catch {
    fail("continuation_api_binary_invalid");
  }
  if (apiBinarySnapshot.sha256 !== continuationAuthority.apiBinarySha256) {
    fail("continuation_api_binary_digest_mismatch");
  }

  let apiEnvironment;
  try {
    apiEnvironment = buildApiRuntimeEnvironment({
      authority: continuationAuthority.authority,
      databasePassword: secrets.get("FEAT126_S10_API_DB_PASSWORD"),
      localCaPemPath: caPath,
      localCaSha256: createHash("sha256").update(ca).digest("hex"),
    });
  } catch {
    fail("continuation_runtime_environment_invalid");
  }
  return {
    apiEnvironment,
    apiBinarySha256: continuationAuthority.apiBinarySha256,
    apiBinarySnapshot,
    binaryPath,
    logPath,
    runId,
  };
}

async function runForeground({
  apiEnvironment,
  apiBinarySha256,
  apiBinarySnapshot,
  binaryPath,
  logPath,
  runId,
}) {
  let launchBinarySnapshot;
  try {
    launchBinarySnapshot = await inspectApiBinary(binaryPath);
  } catch {
    fail("continuation_api_binary_invalid");
  }
  if (
    launchBinarySnapshot.sha256 !== apiBinarySha256 ||
    !sameApiBinarySnapshot(apiBinarySnapshot, launchBinarySnapshot)
  ) {
    fail("continuation_api_binary_digest_mismatch");
  }
  let logHandle;
  try {
    logHandle = await open(
      logPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    await logHandle.appendFile(
      `${JSON.stringify({ schema_version: 1, event: "api_continuation_started", run_id: runId })}\n`,
    );
  } catch {
    await logHandle?.close();
    fail("continuation_log_invalid");
  }

  let child;
  let outputBytes = 0;
  let outputExceeded = false;
  const signals = ["SIGHUP", "SIGINT", "SIGTERM"];
  const handlers = new Map();
  try {
    child = spawn(binaryPath, [], {
      cwd: INFRA_ROOT,
      env: apiEnvironment,
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const discard = (chunk) => {
      outputBytes += chunk.length;
      if (outputBytes > MAX_CHILD_OUTPUT_BYTES && !outputExceeded) {
        outputExceeded = true;
        child.kill("SIGKILL");
      }
    };
    child.stdout.on("data", discard);
    child.stderr.on("data", discard);
    for (const signal of signals) {
      const handler = () => {
        if (child.exitCode === null && child.signalCode === null) child.kill(signal);
      };
      handlers.set(signal, handler);
      process.on(signal, handler);
    }
    const result = await new Promise((resolveChild, rejectChild) => {
      child.once("error", () => rejectChild(new S10BApiContinuationError("continuation_api_spawn_failed")));
      child.once("exit", (code, signal) => resolveChild({ code, signal }));
    });
    if (outputExceeded) fail("continuation_api_output_capacity_exceeded");
    await logHandle.appendFile(
      `${JSON.stringify({
        schema_version: 1,
        event: "api_continuation_exited",
        exit_code: result.code,
        signal: result.signal,
      })}\n`,
    );
    if (result.code !== null) return result.code;
    return { SIGHUP: 129, SIGINT: 130, SIGTERM: 143 }[result.signal] ?? 1;
  } finally {
    for (const [signal, handler] of handlers) process.off(signal, handler);
    await logHandle?.close();
  }
}

export async function executeApiContinuation(runId, environment = process.env) {
  return runForeground(await loadContinuation(runId, environment));
}

async function main() {
  if (process.argv.length !== 3) fail("continuation_arguments_invalid");
  return executeApiContinuation(process.argv[2]);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main()
    .then((exitCode) => {
      process.exitCode = exitCode;
    })
    .catch((error) => {
      const failureClass =
        error instanceof S10BApiContinuationError ? error.code : "continuation_internal_failure";
      process.stderr.write(
        `${JSON.stringify({ schema_version: 1, status: "failed", failure_class: failureClass })}\n`,
      );
      process.exitCode = 1;
    });
}
