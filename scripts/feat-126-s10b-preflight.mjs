#!/usr/bin/env node

import { spawn, spawnSync } from "node:child_process";
import { constants, closeSync, openSync } from "node:fs";
import { chmod, lstat, mkdir, open, readFile, realpath, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import http from "node:http";
import net from "node:net";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { validateFeat126S10Secrets } from "./feat-126-s10-secrets.mjs";
import { inspectApiBinary, sameApiBinarySnapshot } from "./feat-126-s10-api-binary.mjs";
import {
  buildApiRuntimeEnvironment,
  FEAT_126_S10_API_RUNTIME_AUTHORITY,
  validateApiRuntimeAuthority,
} from "./feat-126-s10-api-runtime-profile.mjs";
import * as resolverProtocol from "./verify-feat-126-s10-images.mjs";
import { FEAT_126_S10_PROFILE, FEAT_126_S10_SERVICES } from "./compose-model.mjs";

const INFRA_ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const WORKSPACE_ROOT = resolve(INFRA_ROOT, "..");
const RUN_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const FULL_SHA_PATTERN = /^[0-9a-f]{40}$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const FIXED_PORTS = Object.freeze([5432, 8443, 9443, 18080, 18082, 1420, 1421]);
const IMAGE_RESOLVER_SCRIPT = resolve(INFRA_ROOT, "scripts/verify-feat-126-s10-images.mjs");
const IMAGE_RESOLVER_EVIDENCE_FILE = "image-resolver-result.v1.json";
const S10_COMPOSE_FILE = resolve(INFRA_ROOT, "docker-compose.local.yml");
const {
  CLOSED_RESOLVER_RESULT_MAX_BYTES,
  CLOSED_RESOLVER_SPAWN_BUFFER_BYTES,
  CLOSED_RESOLVER_TIMEOUT_MS,
  ClosedResolverResultError,
  mapClosedResolverFailure,
  parseClosedResolverResult,
} = resolverProtocol;
// The legacy feat-126-s10-verify-images Make gate remains unchanged; this
// parent uses the private closed mode for its one authoritative child call.
export const IMAGE_RESOLVER_PARENT_FAILURE_CLASSES = Object.freeze([
  "preflight_image_resolver_process_failed",
  "preflight_image_resolver_timeout",
  "preflight_image_resolver_result_invalid",
  "preflight_image_resolver_result_oversize",
  "preflight_image_resolver_evidence_failed",
]);
const REPOSITORIES = Object.freeze({
  governance: resolve(WORKSPACE_ROOT, "yijie"),
  contracts: resolve(WORKSPACE_ROOT, "yijie-contracts"),
  api: resolve(WORKSPACE_ROOT, "yijie-api"),
  host: resolve(WORKSPACE_ROOT, "yijie-agent-host"),
  desktop: resolve(WORKSPACE_ROOT, "yijie-desktop"),
  runtime: resolve(WORKSPACE_ROOT, "yijie-codex"),
  infra: INFRA_ROOT,
});
const SHA_ENV = Object.freeze({
  governance: "FEAT126_S10B_GOVERNANCE_SHA",
  contracts: "FEAT126_S10B_CONTRACTS_SHA",
  api: "FEAT126_S10B_API_SHA",
  host: "FEAT126_S10B_HOST_SHA",
  desktop: "FEAT126_S10B_DESKTOP_SHA",
  runtime: "FEAT126_S10B_RUNTIME_SHA",
  infra: "FEAT126_S10B_INFRA_SHA",
});
const PROBE_KEYS = Object.freeze([
  "dataset_id",
  "dataset_sha256",
  "fixture_case_id",
  "run_id",
  "schema_version",
  "status",
]);

export class S10BPreflightError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function fail(code) {
  throw new S10BPreflightError(code);
}

const IMAGE_RESOLVER_PARENT_FAILURE_SET = new Set(IMAGE_RESOLVER_PARENT_FAILURE_CLASSES);

function resolverParentFail(code) {
  if (!IMAGE_RESOLVER_PARENT_FAILURE_SET.has(code)) {
    throw new TypeError("unknown parent resolver failure class");
  }
  fail(code);
}

export function validateResolverProtocolExports(protocol = resolverProtocol) {
  if (
    typeof protocol?.parseClosedResolverResult !== "function" ||
    typeof protocol?.mapClosedResolverFailure !== "function" ||
    typeof protocol?.ClosedResolverResultError !== "function" ||
    !Number.isInteger(protocol?.CLOSED_RESOLVER_RESULT_MAX_BYTES) ||
    !Number.isInteger(protocol?.CLOSED_RESOLVER_SPAWN_BUFFER_BYTES) ||
    !Number.isInteger(protocol?.CLOSED_RESOLVER_TIMEOUT_MS)
  ) {
    resolverParentFail("preflight_image_resolver_result_invalid");
  }
  return true;
}

function requireResolverProtocol() {
  validateResolverProtocolExports();
}

export function validateProbeResult(value, runId) {
  if (
    value === null ||
    Array.isArray(value) ||
    typeof value !== "object" ||
    JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(PROBE_KEYS) ||
    value.schema_version !== 1 ||
    value.status !== "ready" ||
    value.run_id !== runId ||
    typeof value.dataset_id !== "string" ||
    value.dataset_id.length < 1 ||
    value.dataset_id.length > 128 ||
    typeof value.fixture_case_id !== "string" ||
    value.fixture_case_id.length < 1 ||
    value.fixture_case_id.length > 128 ||
    value.dataset_id === value.fixture_case_id ||
    !DIGEST_PATTERN.test(value.dataset_sha256 ?? "")
  ) {
    fail("fake_readiness_authority_invalid");
  }
  return Object.freeze({ ...value });
}

export function readExpectedSHAs(environment = process.env) {
  const expected = {};
  for (const [role, key] of Object.entries(SHA_ENV)) {
    const value = environment[key];
    if (!FULL_SHA_PATTERN.test(value ?? "")) fail("preflight_authority_invalid");
    expected[role] = value;
  }
  return Object.freeze(expected);
}

function commandEnvironment(extra = {}) {
  const allowed = {};
  for (const key of ["PATH", "HOME", "TMPDIR", "DOCKER_HOST", "DOCKER_CONTEXT", "GOPATH", "GOMODCACHE"]) {
    if (process.env[key]) allowed[key] = process.env[key];
  }
  return { ...allowed, ...extra };
}

function runCommand(label, command, arguments_, options = {}) {
  const result = spawnSync(command, arguments_, {
    cwd: options.cwd ?? INFRA_ROOT,
    env: options.env ?? commandEnvironment(),
    encoding: "utf8",
    shell: false,
    windowsHide: true,
    maxBuffer: 16 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error || result.status !== 0) fail(`preflight_${label}_failed`);
  return result.stdout ?? "";
}

function inspectRepository(role, path, expectedSHA) {
  const head = runCommand("repository", "git", ["-C", path, "rev-parse", "HEAD"]);
  const status = runCommand("repository", "git", ["-C", path, "status", "--porcelain", "--untracked-files=all"]);
  if (head.trim() !== expectedSHA) fail(`preflight_${role}_sha_mismatch`);
  if (status.length !== 0) fail(`preflight_${role}_worktree_dirty`);
}

function portIsAvailable(port) {
  return new Promise((resolveAvailability) => {
    const server = net.createServer();
    server.unref();
    server.once("error", () => resolveAvailability(false));
    server.listen({ host: "127.0.0.1", port, exclusive: true }, () => {
      server.close(() => resolveAvailability(true));
    });
  });
}

async function requirePortsAvailable(ports = FIXED_PORTS) {
  for (const port of ports) {
    if (!(await portIsAvailable(port))) fail("preflight_port_unavailable");
  }
}

function boundedJSONRequest(path, expectedStatus) {
  return new Promise((resolveRequest, rejectRequest) => {
    const request = http.get(
      { hostname: "127.0.0.1", port: 18080, path, timeout: 1000, agent: false },
      (response) => {
        let body = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => {
          body += chunk;
          if (body.length > 64 * 1024) request.destroy(new Error("capacity"));
        });
        response.on("end", () => {
          try {
            const payload = JSON.parse(body);
            if (response.statusCode !== 200 || payload.status !== expectedStatus) {
              rejectRequest(new Error("not ready"));
              return;
            }
            resolveRequest();
          } catch (error) {
            rejectRequest(error);
          }
        });
      },
    );
    request.on("timeout", () => request.destroy(new Error("timeout")));
    request.on("error", rejectRequest);
  });
}

async function waitForAPI(child) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    if (child.exitCode !== null) fail("preflight_api_process_failed");
    try {
      await boundedJSONRequest("/healthz", "ok");
      await boundedJSONRequest("/readyz", "ready");
      return;
    } catch {
      await new Promise((resolveWait) => setTimeout(resolveWait, 200));
    }
  }
  fail("preflight_api_not_ready");
}

function startProcess(binary, environment, logPath) {
  const descriptor = openSync(
    logPath,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    return spawn(binary, [], {
      cwd: INFRA_ROOT,
      env: commandEnvironment(environment),
      shell: false,
      windowsHide: true,
      stdio: ["ignore", descriptor, descriptor],
    });
  } finally {
    closeSync(descriptor);
  }
}

async function stopProcess(child) {
  if (!child || child.exitCode !== null) return;
  child.kill("SIGTERM");
  const stopped = await Promise.race([
    new Promise((resolveExit) => child.once("exit", () => resolveExit(true))),
    new Promise((resolveTimeout) => setTimeout(() => resolveTimeout(false), 5000)),
  ]);
  if (!stopped && child.exitCode === null) {
    child.kill("SIGKILL");
    await new Promise((resolveExit) => child.once("exit", resolveExit));
  }
}

function sha256(content) {
  return createHash("sha256").update(content).digest("hex");
}

async function scanLogs(paths, secretValues) {
  for (const path of paths) {
    const content = await readFile(path);
    if (content.length > 1024 * 1024) fail("preflight_log_capacity_exceeded");
    const text = content.toString("utf8");
    if (secretValues.some((secret) => text.includes(secret))) fail("preflight_secret_leak_detected");
  }
}

async function writeClosedJSON(path, value) {
  await writeFile(path, `${JSON.stringify(value)}\n`, { flag: "wx", mode: 0o600 });
  await chmod(path, 0o600);
}

function resolverProcessOutput(value) {
  if (Buffer.isBuffer(value)) return value;
  if (typeof value === "string") return Buffer.from(value, "utf8");
  return Buffer.alloc(0);
}

export function validateImageResolverProcessResult(result, runId) {
  requireResolverProtocol();
  if (result?.error?.code === "ETIMEDOUT") {
    resolverParentFail("preflight_image_resolver_timeout");
  }
  if (result?.error?.code === "ENOBUFS") {
    resolverParentFail("preflight_image_resolver_result_oversize");
  }
  if (result?.error || result?.signal !== null && result?.signal !== undefined) {
    resolverParentFail("preflight_image_resolver_process_failed");
  }

  const stdout = resolverProcessOutput(result?.stdout);
  const stderr = resolverProcessOutput(result?.stderr);
  if (stdout.length + stderr.length > CLOSED_RESOLVER_SPAWN_BUFFER_BYTES) {
    resolverParentFail("preflight_image_resolver_result_oversize");
  }
  if (stderr.length !== 0) {
    // A legacy/human child can still exit non-zero, but its text is not a
    // versioned result. Treat it as a protocol mismatch, never as a leaf.
    resolverParentFail("preflight_image_resolver_result_invalid");
  }
  if (stdout.length > CLOSED_RESOLVER_RESULT_MAX_BYTES) {
    resolverParentFail("preflight_image_resolver_result_oversize");
  }

  let envelope;
  try {
    envelope = parseClosedResolverResult(stdout, runId);
  } catch (error) {
    if (
      error instanceof ClosedResolverResultError &&
      error.code === "result_oversize"
    ) {
      resolverParentFail("preflight_image_resolver_result_oversize");
    }
    resolverParentFail("preflight_image_resolver_result_invalid");
  }

  if (
    (envelope.status === "passed" && result.status !== 0) ||
    (envelope.status === "failed" && result.status !== 1)
  ) {
    resolverParentFail("preflight_image_resolver_process_failed");
  }
  return Object.freeze({
    envelope,
    failureClass:
      envelope.status === "failed"
        ? mapClosedResolverFailure(envelope.failure_class)
        : null,
  });
}

export async function writeImageResolverEvidence(path, envelope) {
  requireResolverProtocol();
  let handle;
  try {
    const validated = parseClosedResolverResult(
      Buffer.from(`${JSON.stringify(envelope)}\n`, "utf8"),
      envelope?.run_id,
    );
    handle = await open(
      path,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        constants.O_NOFOLLOW,
      0o600,
    );
    await handle.writeFile(`${JSON.stringify(validated)}\n`, { encoding: "utf8" });
    await handle.chmod(0o600);
    await handle.sync();
    await handle.close();
    handle = undefined;

    const metadata = await lstat(path);
    if (
      !metadata.isFile() ||
      metadata.isSymbolicLink() ||
      metadata.uid !== process.getuid() ||
      metadata.nlink !== 1 ||
      (metadata.mode & 0o777) !== 0o600
    ) {
      resolverParentFail("preflight_image_resolver_evidence_failed");
    }
  } catch {
    if (handle) {
      try {
        await handle.close();
      } catch {
        // The create-new artifact remains a fail-closed marker.
      }
    }
    resolverParentFail("preflight_image_resolver_evidence_failed");
  }
}

export async function runClosedImageResolver(
  runId,
  evidenceRoot,
  { spawnResolver = spawnSync, writeEvidence = writeImageResolverEvidence } = {},
) {
  requireResolverProtocol();
  let processResult;
  try {
    processResult = spawnResolver(
      process.execPath,
      [IMAGE_RESOLVER_SCRIPT, "--closed-result-v1", runId],
      {
        cwd: INFRA_ROOT,
        env: commandEnvironment(),
        encoding: null,
        shell: false,
        windowsHide: true,
        timeout: CLOSED_RESOLVER_TIMEOUT_MS,
        killSignal: "SIGTERM",
        maxBuffer: CLOSED_RESOLVER_SPAWN_BUFFER_BYTES,
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
  } catch {
    resolverParentFail("preflight_image_resolver_process_failed");
  }

  const outcome = validateImageResolverProcessResult(processResult, runId);
  try {
    await writeEvidence(
      resolve(evidenceRoot, IMAGE_RESOLVER_EVIDENCE_FILE),
      outcome.envelope,
    );
  } catch {
    resolverParentFail("preflight_image_resolver_evidence_failed");
  }
  if (outcome.failureClass) fail(outcome.failureClass);
  return outcome.envelope;
}

export function buildPrevalidatedDependencyArguments(runId, secretsPath) {
  const expectedSecretsPath = resolve(
    INFRA_ROOT,
    "environments/local/generated/feat-126-s10",
    runId ?? "",
    "infra-secrets.env",
  );
  if (
    !RUN_ID_PATTERN.test(runId ?? "") ||
    resolve(secretsPath ?? "") !== expectedSecretsPath
  ) {
    fail("preflight_dependencies_authority_invalid");
  }
  return Object.freeze([
    "compose",
    "--project-name",
    "yijie-feat126-s10-" + runId.replaceAll("-", ""),
    "--env-file",
    expectedSecretsPath,
    "-f",
    S10_COMPOSE_FILE,
    "--profile",
    FEAT_126_S10_PROFILE,
    "up",
    "--detach",
    "--wait",
    "--pull",
    "never",
    ...FEAT_126_S10_SERVICES,
  ]);
}

function startPrevalidatedDependencies(runId, secretsPath) {
  runCommand(
    "dependencies",
    "docker",
    buildPrevalidatedDependencyArguments(runId, secretsPath),
    { env: commandEnvironment({ FEAT126_S10_RUN_ID: runId }) },
  );
}

async function execute(runId, expectedSHAs) {
  if (!RUN_ID_PATTERN.test(runId ?? "")) fail("preflight_run_id_invalid");
  let apiRuntimeAuthority;
  try {
    apiRuntimeAuthority = validateApiRuntimeAuthority(FEAT_126_S10_API_RUNTIME_AUTHORITY);
  } catch {
    fail("preflight_api_runtime_profile_authority_invalid");
  }
  for (const [role, repository] of Object.entries(REPOSITORIES)) {
    inspectRepository(role, repository, expectedSHAs[role]);
  }
  await requirePortsAvailable();

  const runRoot = resolve(INFRA_ROOT, "environments/local/generated/feat-126-s10", runId);
  const binRoot = resolve(runRoot, "bin");
  const logRoot = resolve(runRoot, "logs");
  const evidenceRoot = resolve(runRoot, "preflight-evidence");
  const secretsPath = resolve(runRoot, "infra-secrets.env");
  const caPath = resolve(runRoot, "caddy-root.crt");
  let dependenciesStarted = false;
  let apiProcess;
  let fakeProcess;
  let failure;
  const completed = [];

  try {
    try {
      await lstat(runRoot);
      fail("preflight_run_not_fresh");
    } catch (error) {
      if (error instanceof S10BPreflightError || error?.code !== "ENOENT") throw error;
    }
    runCommand("secret_init", "make", ["feat-126-s10-init-secrets", `RUN_ID=${runId}`]);
    const runRootMetadata = await lstat(runRoot);
    if (
      !runRootMetadata.isDirectory() ||
      runRootMetadata.isSymbolicLink() ||
      runRootMetadata.uid !== process.getuid() ||
      (runRootMetadata.mode & 0o777) !== 0o700 ||
      (await realpath(runRoot)) !== runRoot
    ) {
      fail("preflight_run_root_invalid");
    }
    await mkdir(binRoot, { mode: 0o700 });
    await mkdir(logRoot, { mode: 0o700 });
    await mkdir(evidenceRoot, { mode: 0o700 });
    completed.push("authority", "ports", "secret_init");

    runCommand("compose_config", "make", ["feat-126-s10-config", `RUN_ID=${runId}`]);
    completed.push("compose");
    await runClosedImageResolver(runId, evidenceRoot);
    completed.push("images");
    // Reuse the reviewed wrapper immediately before the direct fixed Compose
    // start to close the version/secret/rejected-marker TOCTOU window. Its
    // config action has no image resolver side effect.
    runCommand("dependencies", "make", [
      "feat-126-s10-config",
      `RUN_ID=${runId}`,
    ]);
    // The public `make feat-126-s10-up` path retains its human resolver for
    // compatibility. The parent starts dependencies from a fixed authority so
    // the closed resolver is not repeated through that human path.
    startPrevalidatedDependencies(runId, secretsPath);
    dependenciesStarted = true;
    runCommand("dependency_status", "make", ["feat-126-s10-status", `RUN_ID=${runId}`]);
    runCommand("ca_export", "make", ["feat-126-s10-export-ca", `RUN_ID=${runId}`]);
    runCommand("runtime_inventory", "make", ["feat-126-s10-verify-runtime", `RUN_ID=${runId}`]);
    runCommand("synthetic_identity", "make", ["feat-126-s10-provision-users", `RUN_ID=${runId}`]);
    runCommand("migration", "make", [
      "feat-126-s10-api-migrate",
      `RUN_ID=${runId}`,
      `API_REPO=${REPOSITORIES.api}`,
      `API_SHA=${expectedSHAs.api}`,
    ]);
    runCommand("bootstrap", "make", [
      "feat-126-s10-api-bootstrap",
      `RUN_ID=${runId}`,
      `API_REPO=${REPOSITORIES.api}`,
      `API_SHA=${expectedSHAs.api}`,
    ]);
    completed.push("dependencies", "tls_oidc", "identity", "migration", "bootstrap");

    const buildEnvironment = commandEnvironment({ GOCACHE: resolve(runRoot, "go-build-cache") });
    runCommand("api_build", "go", ["build", "-trimpath", "-o", resolve(binRoot, "yijie-api"), "./cmd/api-server"], {
      cwd: REPOSITORIES.api,
      env: buildEnvironment,
    });
    runCommand("host_build", "go", ["build", "-trimpath", "-o", resolve(binRoot, "yijie-agent-host"), "./cmd/desktop-host"], {
      cwd: REPOSITORIES.host,
      env: buildEnvironment,
    });
    runCommand("fake_build", "go", ["build", "-trimpath", "-o", resolve(binRoot, "feat126-fake-responses"), "./cmd/feat126-fake-responses"], {
      cwd: REPOSITORIES.host,
      env: buildEnvironment,
    });
    runCommand("probe_build", "go", ["build", "-trimpath", "-o", resolve(binRoot, "feat126-fake-readiness"), "./cmd/feat126-fake-readiness"], {
      cwd: REPOSITORIES.host,
      env: buildEnvironment,
    });
    const apiBinaryPath = resolve(binRoot, "yijie-api");
    let apiBinarySnapshot;
    try {
      apiBinarySnapshot = await inspectApiBinary(apiBinaryPath);
    } catch {
      fail("preflight_api_binary_invalid");
    }
    completed.push("api_binary", "host_binary", "fake_binary", "probe_binary");

    const secrets = await validateFeat126S10Secrets(secretsPath);
    const ca = await readFile(caPath);
    const caPin = sha256(ca);
    let apiEnvironment;
    try {
      apiEnvironment = buildApiRuntimeEnvironment({
        authority: apiRuntimeAuthority,
        databasePassword: secrets.get("FEAT126_S10_API_DB_PASSWORD"),
        localCaPemPath: caPath,
        localCaSha256: caPin,
      });
    } catch {
      fail("preflight_api_runtime_profile_authority_invalid");
    }
    let launchBinarySnapshot;
    try {
      launchBinarySnapshot = await inspectApiBinary(apiBinaryPath);
    } catch {
      fail("preflight_api_binary_invalid");
    }
    if (!sameApiBinarySnapshot(apiBinarySnapshot, launchBinarySnapshot)) {
      fail("preflight_api_binary_drift");
    }
    apiProcess = startProcess(
      apiBinaryPath,
      apiEnvironment,
      resolve(logRoot, "api.log"),
    );
    await waitForAPI(apiProcess);
    completed.push("api_health", "api_readiness");

    fakeProcess = startProcess(
      resolve(binRoot, "feat126-fake-responses"),
      {
        YIJIE_FEAT126_S10_TEST_PROFILE_ENABLED: "true",
        YIJIE_FEAT126_S10_RUN_ID: runId,
      },
      resolve(logRoot, "fake.log"),
    );
    let probeOutput;
    for (let attempt = 0; attempt < 30; attempt += 1) {
      const result = spawnSync(resolve(binRoot, "feat126-fake-readiness"), [], {
        cwd: INFRA_ROOT,
        env: commandEnvironment({
          YIJIE_FEAT126_S10_TEST_PROFILE_ENABLED: "true",
          YIJIE_FEAT126_S10_RUN_ID: runId,
        }),
        encoding: "utf8",
        shell: false,
        windowsHide: true,
        maxBuffer: 64 * 1024,
        stdio: ["ignore", "pipe", "pipe"],
      });
      if (!result.error && result.status === 0) {
        probeOutput = result.stdout;
        break;
      }
      if (fakeProcess.exitCode !== null) fail("preflight_fake_process_failed");
      await new Promise((resolveWait) => setTimeout(resolveWait, 100));
    }
    if (!probeOutput || probeOutput.length > 4096) fail("preflight_fake_not_ready");
    let probeValue;
    try {
      probeValue = JSON.parse(probeOutput);
    } catch {
      fail("fake_readiness_authority_invalid");
    }
    const readiness = validateProbeResult(probeValue, runId);
    completed.push("host_owned_fake_authority", "fake_readiness");

    await scanLogs(
      [resolve(logRoot, "api.log"), resolve(logRoot, "fake.log")],
      [...secrets.values()],
    );
    completed.push("content_free_logs");
    return {
      readiness,
      apiRuntimeAuthority,
      apiBinarySha256: launchBinarySnapshot.sha256,
      completed,
      runRoot,
      logRoot,
      evidenceRoot,
    };
  } catch (error) {
    failure = error instanceof S10BPreflightError ? error : new S10BPreflightError("preflight_internal_failure");
    throw failure;
  } finally {
    await stopProcess(fakeProcess);
    await stopProcess(apiProcess);
    if (dependenciesStarted) {
      try {
        runCommand("cleanup", "make", ["feat-126-s10-stop", `RUN_ID=${runId}`]);
      } catch (cleanupError) {
        if (!failure) failure = cleanupError;
      }
    }
    for (let attempt = 0; attempt < 30; attempt += 1) {
      const available = await Promise.all(FIXED_PORTS.map((port) => portIsAvailable(port)));
      if (available.every(Boolean)) break;
      if (attempt === 29 && !failure) failure = new S10BPreflightError("preflight_cleanup_incomplete");
      await new Promise((resolveWait) => setTimeout(resolveWait, 100));
    }
    if (failure) {
      try {
        await writeClosedJSON(resolve(runRoot, "REJECTED"), {
          schema_version: 1,
          run_id: runId,
          failure_class: failure.code,
        });
      } catch {
        // A pre-existing or unavailable run root remains fail-closed.
      }
      throw failure;
    }
  }
}

async function main() {
  if (process.argv.length !== 3) fail("preflight_arguments_invalid");
  const runId = process.argv[2];
  const expectedSHAs = readExpectedSHAs();
  const result = await execute(runId, expectedSHAs);
  for (const [role, repository] of Object.entries(REPOSITORIES)) {
    inspectRepository(role, repository, expectedSHAs[role]);
  }
  const summary = {
    schema_version: 1,
    status: "passed",
    scope: "S10B-001-combined-preflight",
    run_id: runId,
    repositories: expectedSHAs,
    api_binary_sha256: result.apiBinarySha256,
    api_runtime_authority: result.apiRuntimeAuthority,
    fake_readiness: result.readiness,
    completed: result.completed,
    cleanup: "passed",
    s10b_r5_executed: false,
  };
  await writeClosedJSON(resolve(result.evidenceRoot, "summary.json"), summary);
  process.stdout.write(`${JSON.stringify(summary)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    const code = error instanceof S10BPreflightError ? error.code : "preflight_internal_failure";
    process.stderr.write(`${JSON.stringify({ schema_version: 1, status: "failed", failure_class: code })}\n`);
    process.exitCode = 1;
  });
}
