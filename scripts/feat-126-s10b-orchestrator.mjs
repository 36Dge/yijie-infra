#!/usr/bin/env node

import { spawn, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { constants, createReadStream } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
} from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import { isAbsolute, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import YAML from "yaml";

import { inspectApiBinary } from "./feat-126-s10-api-binary.mjs";
import {
  buildApiRuntimeEnvironment,
  readApiRuntimeAuthorityFromPreflightSummary,
} from "./feat-126-s10-api-runtime-profile.mjs";
import { parseFeat126S10Secrets } from "./feat-126-s10-secrets.mjs";
import {
  buildPrevalidatedDependencyArguments,
  PREFLIGHT_FAILURE_EVIDENCE_FILE,
  readExpectedSHAs,
  validatePreflightFailureEvidence,
  validateProbeResult,
} from "./feat-126-s10b-preflight.mjs";

const INFRA_ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const WORKSPACE_ROOT = resolve(INFRA_ROOT, "..");
const GENERATED_ROOT = resolve(INFRA_ROOT, "environments/local/generated/feat-126-s10");
const ATTEMPT_ROOT = resolve(GENERATED_ROOT, ".orchestrator-attempts");
const DESKTOP_ROOT = resolve(WORKSPACE_ROOT, "yijie-desktop");
const RUNTIME_ROOT = resolve(WORKSPACE_ROOT, "yijie-codex");
const REPOSITORIES = Object.freeze({
  governance: resolve(WORKSPACE_ROOT, "yijie"),
  contracts: resolve(WORKSPACE_ROOT, "yijie-contracts"),
  api: resolve(WORKSPACE_ROOT, "yijie-api"),
  host: resolve(WORKSPACE_ROOT, "yijie-agent-host"),
  desktop: DESKTOP_ROOT,
  runtime: RUNTIME_ROOT,
  infra: INFRA_ROOT,
});
const RUN_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const FULL_SHA_PATTERN = /^[0-9a-f]{40}$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const CONTROL_KEYS = Object.freeze(["kind", "nonce", "run_id", "schema_version", "sequence"]);
const CONTROL_MAX_BYTES = 1024;
const CONTROL_TIMEOUT_MS = 60_000;
const GUARDED_CONTROL_WRITERS = new WeakSet();
const PROCESS_STOP_TIMEOUT_MS = 8_000;
const CHILD_OUTPUT_MAX_BYTES = 1024 * 1024;
const FIXED_PORTS = Object.freeze([5432, 8443, 9443, 18080, 18081, 18082]);
const REPOSITORY_KEYS = Object.freeze(["api", "contracts", "desktop", "governance", "host", "infra", "runtime"]);
const PREFLIGHT_MAKE_SHA_KEYS = Object.freeze([
  ["governance", "GOVERNANCE_SHA"],
  ["contracts", "CONTRACTS_SHA"],
  ["api", "API_SHA"],
  ["host", "HOST_SHA"],
  ["desktop", "DESKTOP_SHA"],
  ["runtime", "RUNTIME_SHA"],
  ["infra", "INFRA_SHA"],
]);
const ATTEMPT_PRECLAIM_KEYS = Object.freeze([
  "kind",
  "pid",
  "ppid",
  "repositories",
  "run_id",
  "schema_version",
  "s10b_r8_executed",
  "status",
]);
const ATTEMPT_PRECLAIM_FAILURE_KEYS = Object.freeze([
  "failure_class",
  "preclaim_sha256",
  "run_id",
  "schema_version",
  "s10b_r8_executed",
  "status",
]);
const ATTEMPT_MARKER_KEYS = Object.freeze([
  "binary_sha256",
  "kind",
  "pid",
  "ppid",
  "repositories",
  "run_id",
  "schema_version",
  "script_sha256",
  "s10b_r8_executed",
  "start_identity",
  "status",
]);
const ATTEMPT_FAILURE_KEYS = Object.freeze([
  "attempt_marker_sha256",
  "business_failure_class",
  "cleanup_failure_class",
  "compose_attempted",
  "compose_cleanup_required",
  "failure_class",
  "no_log_required",
  "parent_failure_class",
  "phase",
  "process_roles",
  "retained_volume_keys",
  "run_id",
  "run_root_present",
  "schema_version",
  "s10b_r8_executed",
  "status",
]);
const ATTEMPT_CLOSURE_KEYS = Object.freeze([
  "attempt_marker_sha256",
  "business_failure_class",
  "business_status",
  "cleanup_failure_class",
  "cleanup_scope",
  "closure_kind",
  "evidence_failure_class",
  "failure_class",
  "no_log_failure_class",
  "no_log_scope",
  "parent_failure_class",
  "run_id",
  "schema_version",
  "s10b_r8_executed",
  "status",
]);
const ATTEMPT_RECONCILE_KEYS = Object.freeze([
  "attempt_marker_sha256",
  "business_status",
  "cleanup_failure_class",
  "cleanup_scope",
  "failure_class",
  "no_log_failure_class",
  "no_log_scope",
  "run_id",
  "schema_version",
  "s10b_r8_executed",
  "status",
]);
const CLEANUP_RESULT_KEYS = Object.freeze([
  "containers",
  "listeners",
  "named_volume_after_count",
  "named_volume_baseline_count",
  "named_volumes_preserved",
  "networks",
  "processes",
  "prune_executed",
  "schema_version",
  "scope",
  "status",
  "temporary_volumes",
  "volume_delete_executed",
]);
const NO_LOG_RESULT_KEYS = Object.freeze([
  "coverage",
  "external_row_count",
  "external_source_count",
  "external_source_set_sha256",
  "file_count",
  "hit_count",
  "pattern_set_sha256",
  "row_count",
  "schema_version",
  "scope",
]);
const RUNTIME_LOG_SCAN_KEYS = Object.freeze([
  "hit_count",
  "row_count",
  "run_id",
  "schema_version",
  "source_count",
  "source_set_sha256",
  "status",
]);
const BUSINESS_BOUNDARY_KEYS = Object.freeze([
  "api_after_sha256",
  "api_before_sha256",
  "fake_accepted_calls",
  "fake_rejected_calls",
  "run_id",
  "s10b_r8_executed",
  "schema_version",
  "scope",
  "status",
]);
const SUMMARY_KEYS = Object.freeze([
  "api_binary_sha256",
  "api_runtime_authority",
  "cleanup",
  "completed",
  "fake_readiness",
  "repositories",
  "run_id",
  "s10b_r5_executed",
  "schema_version",
  "scope",
  "status",
]);
const REQUIRED_COMPLETED = Object.freeze([
  "authority",
  "ports",
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
const PROCESS_RECORD_KEYS = Object.freeze([
  "binary_sha256",
  "pid",
  "ppid",
  "role",
  "run_id",
  "schema_version",
  "start_identity",
]);
const HOST_PROCESS_EVIDENCE_KEYS = Object.freeze([
  "binarySha256",
  "endedAtUnixMs",
  "exitCode",
  "instanceNonce",
  "logLimitBytes",
  "pid",
  "ppid",
  "role",
  "runId",
  "schemaVersion",
  "startedAtUnixMs",
  "state",
  "stderrBytes",
  "stderrTruncated",
  "stdoutBytes",
  "stdoutTruncated",
]);
const RUNTIME_PROCESS_EVIDENCE_KEYS = Object.freeze([
  "binary_sha256",
  "manifest_sha256",
  "nonce",
  "pid",
  "ppid",
  "profile",
  "ready",
  "role",
  "run_id",
  "schema_version",
  "state",
]);
const EXISTING_PROCESS_ROLES = Object.freeze(["api", "desktop", "fake", "host", "runtime"]);
const INFRA_CONTROL_KINDS = Object.freeze(["abort"]);
const DESKTOP_CONTROL_KINDS = Object.freeze(["abort_complete", "component_ready"]);
const S10_NAMED_VOLUME_KEYS = Object.freeze([
  "feat126_s10_api_postgres_data",
  "feat126_s10_keycloak_postgres_data",
  "feat126_s10_caddy_data",
  "feat126_s10_caddy_config",
]);
const SYNTHETIC_OWNER_ID = "12500000-0000-4000-8000-000000000001";
const SYNTHETIC_TENANT_ID = "12500000-0000-4000-8000-100000000001";
const FORBIDDEN_ENV = Object.freeze([
  "FEAT126_S10B_ORCHESTRATOR_PATH",
  "FEAT126_S10B_ORCHESTRATOR_PORT",
  "FEAT126_S10B_ORCHESTRATOR_PROFILE",
  "FEAT126_S10B_ORCHESTRATOR_BINARY",
  "FEAT126_S10B_ORCHESTRATOR_FIXTURE",
  "FEAT126_S10B_ORCHESTRATOR_MODE",
  "FEAT126_S10B_ORCHESTRATOR_CASE",
  "FEAT126_S10B_ORCHESTRATOR_RESUME",
  "FEAT126_S10B_ORCHESTRATOR_RETRY",
  "FEAT126_S10B_ORCHESTRATOR_CLEANUP",
  "VITE_FEAT126_S10_DRIVER",
  "YIJIE_FEAT126_S10_TEST_PROFILE_ENABLED",
  "YIJIE_FEAT126_S10_DRIVER_ENABLED",
  "YIJIE_FEAT126_S10_DRIVER_NONCE",
  "YIJIE_FEAT126_S10_RUN_ID",
  "YIJIE_FEAT126_S10_RUN_ROOT",
  "YIJIE_FEAT126_S10P3_REAL_MAIN_CHAIN",
  "YIJIE_FEAT126_S10_SECURE_STORAGE_ENABLED",
  "YIJIE_FEAT126_S10_EPHEMERAL_SECRET_BACKEND_ENABLED",
  "YIJIE_FEAT126_S10_INFRA_SECRETS_PATH",
  "YIJIE_FEAT126_FAKE_RESPONSES_BASE_URL",
  "YIJIE_FEAT126_FAKE_RESPONSES_MODE",
  "YIJIE_FEAT126_FAKE_RESPONSES_MAX_CALLS",
  "YIJIE_FEAT126_S10_FAKE_GENERATION",
  "YIJIE_CHAT_LOCAL_ENABLED",
  "YIJIE_CHAT_LOCAL_HOST_ENABLED",
  "YIJIE_CHAT_LOCAL_OWNER_USER_ID",
  "YIJIE_CHAT_LOCAL_TENANT_ID",
  "YIJIE_AGENT_HOST_BINARY",
  "YIJIE_AGENT_HOST_HOME",
  "YIJIE_AGENT_HOST_PORT",
  "YIJIE_CODEX_BINARY",
  "YIJIE_CODEX_MANIFEST",
  "YIJIE_CODEX_HOME",
  "YIJIE_DESKTOP_NATIVE_AUTH_ENABLED",
  "YIJIE_DESKTOP_AUTH_ENVIRONMENT",
  "YIJIE_DESKTOP_OIDC_ISSUER",
  "YIJIE_DESKTOP_OIDC_AUTHORIZATION_ENDPOINT",
  "YIJIE_DESKTOP_OIDC_TOKEN_ENDPOINT",
  "YIJIE_DESKTOP_OIDC_JWKS_URI",
  "YIJIE_DESKTOP_OIDC_REVOCATION_ENDPOINT",
  "YIJIE_DESKTOP_OIDC_CLIENT_ID",
  "YIJIE_DESKTOP_API_ORIGIN",
  "YIJIE_DESKTOP_LOCAL_CA_PEM_PATH",
  "YIJIE_DESKTOP_LOCAL_CA_SHA256",
  "YIJIE_ENV",
]);

export const S10BO1_CASES = Object.freeze([
  "s10b_002",
  "s10b_003",
  "s10b_004",
  "s10b_005_planned_restart",
  "s10b_006",
  "s10b_007",
  "s10b_008",
  "s10b_009",
  "s10b_010",
  "s10b_011",
  "cleanup",
]);

export const S10BO1_TARGETED_MATRIX = Object.freeze(
  Array.from({ length: 14 }, (_, index) => `S10BO1-${String(index + 1).padStart(3, "0")}`),
);

export const S10BO2_TARGETED_MATRIX = Object.freeze(
  Array.from({ length: 14 }, (_, index) => `S10BO2-${String(index + 1).padStart(3, "0")}`),
);

export const S10BO3_TARGETED_MATRIX = Object.freeze(
  Array.from({ length: 20 }, (_, index) => `S10BO3-${String(index + 1).padStart(3, "0")}`),
);

export const S10BO1_CONTROL_KINDS = Object.freeze([
  "component_ready",
  "mode_transition",
  "planned_restart",
  "case_result",
  "abort",
]);

export const S10BO1_STATES = Object.freeze([
  "created",
  "preflight_running",
  "preflight_passed",
  "dependencies_ready",
  "api_ready",
  "fake_ready",
  "desktop_ready",
  "host_ready",
  "runtime_ready",
  ...S10BO1_CASES,
  "closed_pass",
]);

export const S10BO2_STATES = Object.freeze([
  "created",
  "preflight_running",
  "preflight_passed",
  "desktop_built",
  "dependencies_ready",
  "api_ready",
  "fake_ready",
  "desktop_spawned",
  "component_ready",
  "abort_sent",
  "abort_complete",
  "desktop_exited",
  "cleanup_passed",
  "closed_pass",
]);

const ATTEMPT_PHASES = new Set([
  "preflight_not_started",
  "preflight_running",
  "preflight_failed",
  "preflight_context_invalid",
  "desktop_building",
  "dependencies_starting",
  "api_starting",
  "fake_starting",
  "desktop_starting",
  ...S10BO2_STATES,
]);

const S10BO1_STATE_INDEX = new Map(S10BO1_STATES.map((state, index) => [state, index]));
const S10BO2_STATE_INDEX = new Map(S10BO2_STATES.map((state, index) => [state, index]));

export class S10BO1OrchestratorError extends Error {
  constructor(code, closure = undefined) {
    super(code);
    this.name = "S10BO1OrchestratorError";
    this.code = code;
    if (closure) this.closure = Object.freeze({ ...closure });
  }
}

function fail(code) {
  throw new S10BO1OrchestratorError(code);
}

function exactKeys(value, expected) {
  return JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}

function ownedByCurrentUser(metadata) {
  return typeof process.getuid !== "function" || metadata.uid === process.getuid();
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function commandEnvironment(extra = {}) {
  const allowed = {};
  for (const key of ["PATH", "HOME", "TMPDIR", "DOCKER_HOST", "DOCKER_CONTEXT", "LANG", "LC_ALL"]) {
    if (process.env[key]) allowed[key] = process.env[key];
  }
  return { ...allowed, ...extra };
}

export function createParentIdentityGuard({
  parentPid = process.ppid,
  readParentPid = () => process.ppid,
  probeParent = (pid) => {
    try {
      process.kill(pid, 0);
      return true;
    } catch (error) {
      return error?.code === "EPERM";
    }
  },
} = {}) {
  const validParentPid = Number.isSafeInteger(parentPid) && parentPid > 1;
  return Object.freeze({
    parentPid,
    isAlive() {
      if (!validParentPid || readParentPid() !== parentPid) return false;
      try {
        return probeParent(parentPid) === true;
      } catch {
        return false;
      }
    },
  });
}

export async function runCommand(label, command, arguments_, options = {}) {
  const timeoutMs = options.timeout ?? 10 * 60_000;
  const maximumBytes = options.maxBuffer ?? 16 * 1024 * 1024;
  if (
    !Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 ||
    !Number.isSafeInteger(maximumBytes) || maximumBytes <= 0
  ) fail(`orchestrator_${label}_failed`);
  if (options.signal?.aborted) fail("orchestrator_parent_death");
  try {
    return await new Promise((resolveCommand, rejectCommand) => {
      let settled = false;
      let timeout;
      let killTimeout;
      let outputBytes = 0;
      let errorBytes = 0;
      const output = [];
      const errorOutput = [];
      let failure;
      let child;
      const cleanup = () => {
        clearTimeout(timeout);
        clearTimeout(killTimeout);
        options.signal?.removeEventListener("abort", onAbort);
      };
      const settle = (error, value) => {
        if (settled) return;
        settled = true;
        cleanup();
        if (error) rejectCommand(error);
        else resolveCommand(value);
      };
      const signalOwnedCommand = (signal, ignoreMissing = false) => {
        try {
          if (process.platform === "win32") child.kill(signal);
          else process.kill(-child.pid, signal);
        } catch (error) {
          if (ignoreMissing && error?.code === "ESRCH") return;
          throw error;
        }
      };
      const stop = (error) => {
        if (failure) return;
        failure = error;
        if (child?.pid && child.exitCode === null && child.signalCode === null) {
          try {
            signalOwnedCommand("SIGTERM");
          } catch (killError) {
            settle(killError);
            return;
          }
          killTimeout = setTimeout(() => {
            if (process.platform !== "win32" ||
              (child.exitCode === null && child.signalCode === null)) {
              try {
                signalOwnedCommand("SIGKILL", true);
              } catch (killError) {
                settle(killError);
              }
            }
          }, 1_000);
        }
      };
      const onAbort = () => stop(new S10BO1OrchestratorError("orchestrator_parent_death"));
      try {
        child = spawn(command, arguments_, {
          cwd: options.cwd ?? INFRA_ROOT,
          env: options.env ?? commandEnvironment(),
          detached: process.platform !== "win32",
          shell: false,
          windowsHide: true,
          stdio: ["ignore", "pipe", "pipe"],
        });
      } catch (error) {
        settle(error);
        return;
      }
      child.once("error", (error) => settle(error));
      child.stdout.on("data", (chunk) => {
        outputBytes += chunk.length;
        if (outputBytes + errorBytes > maximumBytes) {
          stop(new Error("command output capacity exceeded"));
          return;
        }
        output.push(chunk);
      });
      child.stderr.on("data", (chunk) => {
        errorBytes += chunk.length;
        if (outputBytes + errorBytes > maximumBytes) {
          stop(new Error("command error capacity exceeded"));
          return;
        }
        errorOutput.push(chunk);
      });
      child.once("close", (code, signal) => {
        if (failure) {
          if (process.platform !== "win32") {
            try {
              signalOwnedCommand("SIGKILL", true);
            } catch (error) {
              settle(error);
              return;
            }
          }
          settle(failure);
          return;
        }
        if (code !== 0 || signal !== null) {
          if (typeof options.failureParser === "function") {
            try {
              const failureCode = options.failureParser(Buffer.concat(errorOutput));
              settle(new S10BO1OrchestratorError(failureCode));
              return;
            } catch {
              // A malformed child failure frame maps to the step-level class.
            }
          }
          settle(new Error("command failed"));
          return;
        }
        if (options.captureAllOutput === true) {
          settle(undefined, Buffer.concat([...output, ...errorOutput]));
          return;
        }
        settle(undefined, Buffer.concat(output).toString("utf8"));
      });
      options.signal?.addEventListener("abort", onAbort, { once: true });
      if (options.signal?.aborted) onAbort();
      timeout = setTimeout(
        () => stop(new Error("command timeout")),
        timeoutMs,
      );
    });
  } catch (error) {
    if (error instanceof S10BO1OrchestratorError) throw error;
    fail(`orchestrator_${label}_failed`);
  }
}

export function buildPreflightMakeInvocation(authority) {
  if (
    !RUN_ID_PATTERN.test(authority?.runId ?? "") ||
    authority?.repositories === null || Array.isArray(authority?.repositories) ||
    typeof authority?.repositories !== "object" ||
    !exactKeys(authority.repositories, REPOSITORY_KEYS) ||
    REPOSITORY_KEYS.some((role) => !FULL_SHA_PATTERN.test(authority.repositories[role] ?? ""))
  ) {
    fail("orchestrator_preflight_authority_invalid");
  }
  return Object.freeze([
    "--silent",
    "--no-print-directory",
    "feat-126-s10b-preflight",
    `RUN_ID=${authority.runId}`,
    ...PREFLIGHT_MAKE_SHA_KEYS.map(([role, name]) => `${name}=${authority.repositories[role]}`),
  ]);
}

export function parsePreflightFailureFrame(output) {
  const bytes = Buffer.isBuffer(output) ? output : Buffer.from(output ?? "", "utf8");
  if (bytes.length === 0 || bytes.length > 2048) fail("orchestrator_preflight_failed");
  let framed;
  try {
    framed = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail("orchestrator_preflight_failed");
  }
  if (framed.includes("\0") || framed.includes("\r") || !framed.endsWith("\n")) {
    fail("orchestrator_preflight_failed");
  }
  const lines = framed.slice(0, -1).split("\n");
  if (
    ![1, 2].includes(lines.length) || lines.some((line) => line !== line.trim()) ||
    (lines.length === 2 && lines[1] !== "make: *** [feat-126-s10b-preflight] Error 1")
  ) fail("orchestrator_preflight_failed");
  let value;
  try {
    const [body] = lines;
    YAML.parse(body, { version: "1.2", uniqueKeys: true });
    value = JSON.parse(body);
  } catch {
    fail("orchestrator_preflight_failed");
  }
  if (
    value === null || Array.isArray(value) || typeof value !== "object" ||
    !exactKeys(value, ["failure_class", "schema_version", "status"]) ||
    value.schema_version !== 1 || value.status !== "failed" ||
    !/^[a-z][a-z0-9_]{0,127}$/.test(value.failure_class ?? "")
  ) {
    fail("orchestrator_preflight_failed");
  }
  return value.failure_class;
}

function validFailureClass(value) {
  return value === null || /^[a-z][a-z0-9_]{0,127}$/.test(value ?? "");
}

export function buildOrchestratorFailureEnvelope(error) {
  const failureClass = error instanceof S10BO1OrchestratorError
    ? error.code
    : "orchestrator_internal_failure";
  const closure = error instanceof S10BO1OrchestratorError ? error.closure : undefined;
  const value = {
    schema_version: 1,
    status: "failed",
    failure_class: failureClass,
    business_failure_class: closure?.business_failure_class ?? null,
    cleanup_failure_class: closure?.cleanup_failure_class ?? null,
    evidence_failure_class: closure?.evidence_failure_class ?? null,
    no_log_failure_class: closure?.no_log_failure_class ?? null,
    parent_failure_class: closure?.parent_failure_class ?? null,
  };
  if (
    !validFailureClass(value.failure_class) || value.failure_class === null ||
    !validFailureClass(value.business_failure_class) ||
    !validFailureClass(value.cleanup_failure_class) ||
    !validFailureClass(value.evidence_failure_class) ||
    !validFailureClass(value.no_log_failure_class) ||
    !validFailureClass(value.parent_failure_class)
  ) {
    return Object.freeze({
      schema_version: 1,
      status: "failed",
      failure_class: "orchestrator_internal_failure",
      business_failure_class: null,
      cleanup_failure_class: null,
      evidence_failure_class: null,
      no_log_failure_class: null,
      parent_failure_class: null,
    });
  }
  return Object.freeze(value);
}

export function validateOrchestratorInput(runId, environment = process.env, arguments_ = []) {
  if (!RUN_ID_PATTERN.test(runId ?? "")) fail("orchestrator_run_id_invalid");
  if (arguments_.length !== 0) fail("orchestrator_arguments_invalid");
  if (FORBIDDEN_ENV.some((key) => Object.hasOwn(environment, key))) {
    fail("orchestrator_override_forbidden");
  }
  let repositories;
  try {
    repositories = readExpectedSHAs(environment);
  } catch {
    fail("orchestrator_repository_authority_invalid");
  }
  return Object.freeze({ runId, repositories });
}

export function validateRepositorySummary(summary, runId, repositories) {
  if (
    summary === null || Array.isArray(summary) || typeof summary !== "object" ||
    !exactKeys(summary, SUMMARY_KEYS) ||
    summary.schema_version !== 1 || summary.status !== "passed" ||
    summary.scope !== "S10B-001-combined-preflight" || summary.run_id !== runId ||
    summary.cleanup !== "passed" || summary.s10b_r5_executed !== false ||
    !DIGEST_PATTERN.test(summary.api_binary_sha256 ?? "") ||
    !Array.isArray(summary.completed) ||
    JSON.stringify(summary.completed) !== JSON.stringify(REQUIRED_COMPLETED) ||
    summary.repositories === null || Array.isArray(summary.repositories) ||
    typeof summary.repositories !== "object" ||
    !exactKeys(summary.repositories, REPOSITORY_KEYS) ||
    REPOSITORY_KEYS.some((key) => summary.repositories[key] !== repositories[key])
  ) {
    fail("orchestrator_preflight_authority_invalid");
  }
  try {
    validateProbeResult(summary.fake_readiness, runId);
    readApiRuntimeAuthorityFromPreflightSummary(summary, runId);
  } catch {
    fail("orchestrator_preflight_authority_invalid");
  }
  return Object.freeze({ runId, repositories, apiBinarySha256: summary.api_binary_sha256 });
}

function createOrderedStateMachine(states, index) {
  let current = states[0];
  let aborted = false;
  return Object.freeze({
    get state() { return current; },
    transition(next) {
      if (aborted || !index.has(next) || index.get(next) !== index.get(current) + 1) {
        fail("orchestrator_state_transition_invalid");
      }
      current = next;
      return current;
    },
    abort() {
      if (aborted || current === "closed_pass") fail("orchestrator_abort_invalid");
      aborted = true;
      current = "aborting";
      return current;
    },
    closeFailure(cleanupPassed = true) {
      if (!aborted || current !== "aborting") fail("orchestrator_abort_invalid");
      current = cleanupPassed ? "cleanup_passed" : "cleanup_incomplete";
      current = "closed_fail";
      return current;
    },
  });
}

export function createStateMachine() {
  return createOrderedStateMachine(S10BO1_STATES, S10BO1_STATE_INDEX);
}

export function createStartupAbortStateMachine() {
  return createOrderedStateMachine(S10BO2_STATES, S10BO2_STATE_INDEX);
}

export function validateControlFrame(
  frame,
  runId,
  nonce,
  previousSequence = 0,
  allowedKinds = S10BO1_CONTROL_KINDS,
) {
  if (
    frame === null || typeof frame !== "object" || Array.isArray(frame) ||
    !exactKeys(frame, CONTROL_KEYS) ||
    frame.schema_version !== 1 || frame.run_id !== runId || frame.nonce !== nonce ||
    !Number.isSafeInteger(frame.sequence) || frame.sequence !== previousSequence + 1 ||
    !allowedKinds.includes(frame.kind)
  ) {
    fail("orchestrator_control_frame_invalid");
  }
  return Object.freeze({
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence: frame.sequence,
    kind: frame.kind,
  });
}

export function parseControlFrame(output, authority) {
  const bytes = Buffer.isBuffer(output) ? output : Buffer.from(output ?? "", "utf8");
  if (bytes.length === 0) fail("orchestrator_control_frame_invalid");
  if (bytes.length > CONTROL_MAX_BYTES) fail("orchestrator_control_frame_oversize");
  let framed;
  try {
    framed = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail("orchestrator_control_frame_invalid");
  }
  if (
    framed.includes("\0") || framed.includes("\r") || !framed.endsWith("\n") ||
    framed.slice(0, -1).includes("\n") || framed.slice(0, -1) !== framed.slice(0, -1).trim()
  ) {
    fail("orchestrator_control_frame_invalid");
  }
  const body = framed.slice(0, -1);
  if (body.length === 0) fail("orchestrator_control_frame_invalid");
  let frame;
  try {
    YAML.parse(body, { version: "1.2", uniqueKeys: true });
    frame = JSON.parse(body);
  } catch {
    fail("orchestrator_control_frame_invalid");
  }
  return validateControlFrame(
    frame,
    authority.runId,
    authority.nonce,
    authority.previousSequence,
    authority.allowedKinds,
  );
}

export function encodeControlFrame(frame, authority) {
  const validated = validateControlFrame(
    frame,
    authority.runId,
    authority.nonce,
    authority.previousSequence,
    authority.allowedKinds,
  );
  const encoded = Buffer.from(`${JSON.stringify(validated)}\n`, "utf8");
  if (encoded.length > CONTROL_MAX_BYTES) fail("orchestrator_control_frame_oversize");
  return encoded;
}

export function createControlFrameReader(stream, authority) {
  const iterator = stream[Symbol.asyncIterator]();
  let buffered = Buffer.alloc(0);
  let previousSequence = 0;
  let closed = false;
  return Object.freeze({
    get sequence() { return previousSequence; },
    async next(expectedKind, timeoutMs = CONTROL_TIMEOUT_MS) {
      if (closed) fail("orchestrator_control_eof");
      while (buffered.indexOf(0x0a) === -1) {
        const result = await withTimeout(iterator.next(), timeoutMs, "orchestrator_control_timeout");
        if (result.done) {
          closed = true;
          if (buffered.length !== 0) fail("orchestrator_control_frame_invalid");
          fail("orchestrator_control_eof");
        }
        buffered = Buffer.concat([buffered, Buffer.from(result.value)]);
        if (buffered.length > CONTROL_MAX_BYTES && buffered.indexOf(0x0a) === -1) {
          fail("orchestrator_control_frame_oversize");
        }
      }
      const newline = buffered.indexOf(0x0a);
      const framed = buffered.subarray(0, newline + 1);
      buffered = buffered.subarray(newline + 1);
      const frame = parseControlFrame(framed, {
        runId: authority.runId,
        nonce: authority.nonce,
        previousSequence,
        allowedKinds: DESKTOP_CONTROL_KINDS,
      });
      if (frame.kind !== expectedKind) fail("orchestrator_control_order_invalid");
      previousSequence = frame.sequence;
      return frame;
    },
    async expectEof(timeoutMs = CONTROL_TIMEOUT_MS) {
      if (buffered.length !== 0) fail("orchestrator_control_trailing_frame");
      if (closed) return true;
      while (true) {
        let result;
        try {
          result = await withTimeout(iterator.next(), timeoutMs, "orchestrator_control_timeout");
        } catch (error) {
          if (error instanceof S10BO1OrchestratorError) throw error;
          fail("orchestrator_control_eof");
        }
        if (result.done) {
          closed = true;
          if (buffered.length !== 0) fail("orchestrator_control_trailing_frame");
          return true;
        }
        const chunk = Buffer.from(result.value ?? "");
        if (chunk.length !== 0) fail("orchestrator_control_trailing_frame");
      }
    },
    destroy() {
      closed = true;
      stream.destroy();
    },
  });
}

async function withTimeout(promise, timeoutMs, code) {
  let timeout;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timeout = setTimeout(() => reject(new S10BO1OrchestratorError(code)), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timeout);
  }
}

export function validateContentFreeEvidence(evidence, authority) {
  if (
    evidence === null || typeof evidence !== "object" || Array.isArray(evidence) ||
    evidence.schema_version !== 1 || evidence.run_id !== authority.runId ||
    evidence.role !== authority.role || !Number.isInteger(evidence.pid) || evidence.pid <= 0 ||
    !Number.isInteger(evidence.ppid) || evidence.ppid <= 0 ||
    !DIGEST_PATTERN.test(evidence.binary_sha256 ?? "") ||
    !DIGEST_PATTERN.test(evidence.manifest_sha256 ?? "") || evidence.nonce !== authority.nonce ||
    evidence.profile !== authority.profile || typeof evidence.state !== "string" ||
    Object.keys(evidence).some((key) => ["path", "argv", "env", "payload", "secret", "bearer", "dsn"].includes(key))
  ) {
    fail("orchestrator_evidence_invalid");
  }
  return true;
}

export function validateFakeAuthority(value, authority) {
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    value.schema_version !== 1 || value.status !== "ready" || value.run_id !== authority.runId ||
    value.mode !== authority.mode || value.generation !== authority.generation || value.call_cap !== authority.callCap ||
    !Number.isSafeInteger(value.generation) || value.generation < 1 ||
    !Number.isSafeInteger(value.call_cap) || value.call_cap < 1 || value.call_cap > 64
  ) {
    fail("orchestrator_fake_authority_invalid");
  }
  return true;
}

export function validateClosedFakeAuthorityProjection(value, context, requireZero = true) {
  const expectedKeys = [
    "accepted_calls",
    "call_cap",
    "dataset_id",
    "dataset_sha256",
    "fixture_case_id",
    "generation",
    "mode",
    "rejected_calls",
    "run_id",
    "schema_version",
    "status",
  ];
  if (
    value === null || Array.isArray(value) || typeof value !== "object" ||
    !exactKeys(value, expectedKeys) ||
    !Number.isSafeInteger(value.accepted_calls) || value.accepted_calls < 0 ||
    !Number.isSafeInteger(value.rejected_calls) || value.rejected_calls < 0 ||
    (requireZero && (value.accepted_calls !== 0 || value.rejected_calls !== 0)) ||
    value.dataset_id !== context?.summary?.fake_readiness?.dataset_id ||
    value.fixture_case_id !== context?.summary?.fake_readiness?.fixture_case_id ||
    value.dataset_sha256 !== context?.summary?.fake_readiness?.dataset_sha256
  ) fail("orchestrator_fake_authority_invalid");
  validateFakeAuthority(value, {
    runId: context.runId,
    mode: "complete",
    generation: 1,
    callCap: 1,
  });
  return Object.freeze({ ...value });
}

export function validateApiVerifierProjection(value, runId) {
  const validCounts = (entry) => entry && Number.isSafeInteger(entry.count) && entry.count >= 0 &&
    Array.isArray(entry.enums) && entry.enums.every((item) => typeof item === "string") &&
    DIGEST_PATTERN.test(entry.canonical_hash ?? "");
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    !exactKeys(value, [
      "audit",
      "canonical_hash",
      "denylist_hit_count",
      "idempotency",
      "profile",
      "run_id",
      "schema_version",
      "status",
      "tasks",
    ]) ||
    value.schema_version !== 1 || value.status !== "passed" || value.run_id !== runId ||
    value.profile !== "feat-126-s10-local-lab" || value.denylist_hit_count !== 0 ||
    !validCounts(value.tasks) || !validCounts(value.audit) || !validCounts(value.idempotency) ||
    !DIGEST_PATTERN.test(value.canonical_hash ?? "")
  ) {
    fail("orchestrator_api_projection_invalid");
  }
  return true;
}

export function validatePreflightFailureBinding(primaryFailureClass, evidence) {
  if (
    !/^[a-z][a-z0-9_]{0,127}$/.test(primaryFailureClass ?? "") ||
    evidence === null || Array.isArray(evidence) || typeof evidence !== "object" ||
    evidence.failure_class !== primaryFailureClass
  ) fail("orchestrator_preflight_failure_evidence_invalid");
  return true;
}

export function validateBusinessBoundaryEvidence(value, runId) {
  const apiRequired = ["api_only", "api_and_fake"].includes(value?.scope);
  const fakeRequired = value?.scope === "api_and_fake";
  if (
    value === null || Array.isArray(value) || typeof value !== "object" ||
    !exactKeys(value, BUSINESS_BOUNDARY_KEYS) || value.schema_version !== 1 ||
    value.status !== "passed" || value.run_id !== runId ||
    !["not_started", "api_only", "api_and_fake"].includes(value.scope) ||
    (apiRequired
      ? (!DIGEST_PATTERN.test(value.api_before_sha256 ?? "") ||
        value.api_after_sha256 !== value.api_before_sha256)
      : (value.api_before_sha256 !== null || value.api_after_sha256 !== null)) ||
    (fakeRequired
      ? (value.fake_accepted_calls !== 0 || value.fake_rejected_calls !== 0)
      : (value.fake_accepted_calls !== null || value.fake_rejected_calls !== null)) ||
    value.s10b_r8_executed !== false
  ) fail("orchestrator_business_boundary_invalid");
  return Object.freeze({ ...value });
}

export function validateDesktopDriverProjection(value, authority) {
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    value.schema_version !== 1 || value.message_kind !== "component_ready" ||
    value.run_id !== authority.runId || value.nonce !== authority.nonce || value.sequence !== 1 ||
    value.profile !== "feat-126-s10-local-lab" || value.project?.capability !== "local_only" ||
    value.authorization?.flow !== "authorization_code" || value.authorization?.method !== "S256" ||
    typeof value.authorization?.code_challenge !== "string" || value.authorization.code_challenge.length < 32
  ) {
    fail("orchestrator_desktop_projection_invalid");
  }
  return true;
}

export function validateCleanupClosure(value) {
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    !exactKeys(value, CLEANUP_RESULT_KEYS) || value.schema_version !== 1 || value.status !== "passed" ||
    !["pre_run_absence", "preflight_artifacts", "run_artifacts"].includes(value.scope) ||
    value.containers !== 0 || value.networks !== 0 || value.processes !== 0 || value.listeners !== 0 ||
    value.temporary_volumes !== 0 || value.named_volumes_preserved !== true ||
    !Number.isSafeInteger(value.named_volume_baseline_count) || value.named_volume_baseline_count < 0 ||
    !Number.isSafeInteger(value.named_volume_after_count) || value.named_volume_after_count < 0 ||
    value.named_volume_baseline_count !== value.named_volume_after_count ||
    (value.scope === "pre_run_absence" && value.named_volume_baseline_count !== 0) ||
    (value.scope === "run_artifacts" &&
      value.named_volume_baseline_count !== S10_NAMED_VOLUME_KEYS.length) ||
    value.prune_executed !== false || value.volume_delete_executed !== false
  ) {
    fail("orchestrator_cleanup_incomplete");
  }
  return true;
}

export function shouldRunComposeCleanup(context) {
  return context?.composeCleanupRequired === true;
}

export function validateNoLogResult(value) {
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    !exactKeys(value, NO_LOG_RESULT_KEYS) || value.schema_version !== 1 ||
    !["attempt_only", "preflight_artifacts", "run_artifacts"].includes(value.scope) ||
    ![
      "attempt_marker_and_failure",
      "attempt_ledger",
      "attempt_marker_only",
      "preclaim_and_marker",
      "preclaim_marker_and_failure",
      "preclaim_attempt_ledger",
      "all_preflight_log_and_evidence_sources",
      "all_run_log_and_evidence_sources",
    ].includes(value.coverage) ||
    (value.scope === "attempt_only" && (
      ![
        "attempt_marker_only",
        "attempt_marker_and_failure",
        "attempt_ledger",
        "preclaim_and_marker",
        "preclaim_marker_and_failure",
        "preclaim_attempt_ledger",
      ].includes(value.coverage) ||
      value.file_count !== ({
        attempt_marker_only: 1,
        attempt_marker_and_failure: 2,
        attempt_ledger: 3,
        preclaim_and_marker: 2,
        preclaim_marker_and_failure: 3,
        preclaim_attempt_ledger: 4,
      })[value.coverage]
    )) ||
    (value.scope === "preflight_artifacts" &&
      value.coverage !== "all_preflight_log_and_evidence_sources") ||
    (value.scope === "run_artifacts" &&
      value.coverage !== "all_run_log_and_evidence_sources") ||
    !Number.isSafeInteger(value.file_count) || value.file_count <= 0 ||
    !Number.isSafeInteger(value.row_count) || value.row_count < 0 || value.hit_count !== 0 ||
    !Number.isSafeInteger(value.external_source_count) || value.external_source_count < 0 ||
    !Number.isSafeInteger(value.external_row_count) || value.external_row_count < 0 ||
    !DIGEST_PATTERN.test(value.external_source_set_sha256 ?? "") ||
    (value.scope !== "run_artifacts" &&
      (value.external_source_count !== 0 || value.external_row_count !== 0 ||
        value.external_source_set_sha256 !== sha256(""))) ||
    (value.scope === "run_artifacts" && value.external_source_count <= 0) ||
    !DIGEST_PATTERN.test(value.pattern_set_sha256 ?? "")
  ) {
    fail("orchestrator_no_log_invalid");
  }
  return true;
}

export function validateRuntimeLogScan(value, runId) {
  if (
    value === null || Array.isArray(value) || typeof value !== "object" ||
    !exactKeys(value, RUNTIME_LOG_SCAN_KEYS) || value.schema_version !== 1 ||
    value.status !== (value.hit_count === 0 ? "passed" : "failed") ||
    value.run_id !== runId || !Number.isSafeInteger(value.source_count) ||
    value.source_count <= 0 || !Number.isSafeInteger(value.row_count) || value.row_count < 0 ||
    !Number.isSafeInteger(value.hit_count) || value.hit_count < 0 ||
    !DIGEST_PATTERN.test(value.source_set_sha256 ?? "")
  ) fail("orchestrator_no_log_invalid");
  return Object.freeze({ ...value });
}

export function validateOwnership(manifests) {
  const expected = Object.freeze({ infra: ["api", "fake", "desktop"], desktop: ["host"], host: ["runtime"] });
  if (
    manifests === null || typeof manifests !== "object" || Array.isArray(manifests) ||
    !exactKeys(manifests, Object.keys(expected).sort())
  ) fail("orchestrator_manifest_invalid");
  for (const [owner, children] of Object.entries(expected)) {
    if (
      manifests[owner] === null || typeof manifests[owner] !== "object" ||
      Array.isArray(manifests[owner]) || !exactKeys(manifests[owner], ["children"]) ||
      !Array.isArray(manifests[owner].children) ||
      JSON.stringify(manifests[owner].children) !== JSON.stringify(children)
    ) {
      fail("orchestrator_ownership_invalid");
    }
  }
  if (manifests.infra.children.includes("host") || manifests.infra.children.includes("runtime")) {
    fail("orchestrator_ownership_invalid");
  }
  return true;
}

export function classifyProjectVolumes(project, names) {
  if (typeof project !== "string" || !Array.isArray(names)) {
    fail("orchestrator_volume_inventory_invalid");
  }
  const expected = new Set(S10_NAMED_VOLUME_KEYS.map((key) => `${project}_${key}`));
  const observed = names.filter((name) => typeof name === "string" && name.length > 0);
  if (new Set(observed).size !== observed.length) fail("orchestrator_volume_inventory_invalid");
  const namedVolumes = observed.filter((name) => expected.has(name)).length;
  const temporaryVolumes = observed.filter((name) => !expected.has(name)).length;
  return Object.freeze({ namedVolumes, temporaryVolumes });
}

function projectName(runId) {
  return `yijie-feat126-s10-${runId.replaceAll("-", "")}`;
}

function retainedVolumeKeys(runId, names) {
  const project = projectName(runId);
  const prefix = `${project}_`;
  const keys = names
    .filter((name) => name.startsWith(prefix))
    .map((name) => name.slice(prefix.length))
    .filter((key) => S10_NAMED_VOLUME_KEYS.includes(key));
  return Object.freeze(S10_NAMED_VOLUME_KEYS.filter((key) => keys.includes(key)));
}

function volumeNamesFromKeys(runId, keys) {
  const project = projectName(runId);
  return Object.freeze(keys.map((key) => `${project}_${key}`));
}

function sameStringSet(left, right) {
  if (!Array.isArray(left) || !Array.isArray(right)) return false;
  const leftSorted = [...left].sort();
  const rightSorted = [...right].sort();
  return new Set(leftSorted).size === leftSorted.length &&
    new Set(rightSorted).size === rightSorted.length &&
    JSON.stringify(leftSorted) === JSON.stringify(rightSorted);
}

async function projectVolumeNames(runId) {
  return Object.freeze((await dockerList([
    "volume",
    "ls",
    "-q",
    "--filter",
    `label=com.docker.compose.project=${projectName(runId)}`,
  ])).sort());
}

export function buildOrchestratorPlan(input) {
  const authority = validateOrchestratorInput(input?.runId, input?.environment ?? {}, input?.arguments_ ?? []);
  return Object.freeze({
    schema_version: 2,
    kind: "feat126-s10b-startup-abort-plan",
    run_id: authority.runId,
    repositories: authority.repositories,
    ownership: Object.freeze({ infra: ["api", "fake", "desktop"], desktop: ["host"], host: ["runtime"] }),
    states: S10BO2_STATES,
    business_cases: "disabled",
    s10b_r8_executed: false,
    execution: "separately-authorized-isolated-live-only",
  });
}

export function validateProcessRecord(record, runId, role) {
  if (
    record === null || Array.isArray(record) || typeof record !== "object" ||
    !exactKeys(record, PROCESS_RECORD_KEYS) || record.schema_version !== 1 ||
    record.run_id !== runId || record.role !== role ||
    !Number.isSafeInteger(record.pid) || record.pid <= 1 ||
    !Number.isSafeInteger(record.ppid) || record.ppid <= 0 ||
    !DIGEST_PATTERN.test(record.binary_sha256 ?? "") ||
    !DIGEST_PATTERN.test(record.start_identity ?? "")
  ) {
    fail("orchestrator_process_record_invalid");
  }
  return Object.freeze({ ...record });
}

function canonicalUuid(value) {
  return typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
}

export function validateHostProcessEvidence(value, authority) {
  const ready = authority.expectedState === "ready";
  const stopped = authority.expectedState === "stopped";
  if (
    value === null || Array.isArray(value) || typeof value !== "object" ||
    !exactKeys(value, HOST_PROCESS_EVIDENCE_KEYS) ||
    (!ready && !stopped) ||
    value.schemaVersion !== 1 || value.runId !== authority.runId ||
    value.role !== "agent_host_child" ||
    !Number.isSafeInteger(value.pid) || value.pid <= 1 ||
    value.ppid !== authority.desktopPid ||
    !DIGEST_PATTERN.test(value.binarySha256 ?? "") ||
    value.binarySha256 !== authority.binarySha256 ||
    !canonicalUuid(value.instanceNonce) ||
    (authority.expectedPid !== undefined && value.pid !== authority.expectedPid) ||
    (authority.expectedNonce !== undefined && value.instanceNonce !== authority.expectedNonce) ||
    (authority.expectedStartedAtUnixMs !== undefined &&
      value.startedAtUnixMs !== authority.expectedStartedAtUnixMs) ||
    !Number.isSafeInteger(value.startedAtUnixMs) || value.startedAtUnixMs <= 0 ||
    !Number.isSafeInteger(value.stdoutBytes) || value.stdoutBytes < 0 ||
    !Number.isSafeInteger(value.stderrBytes) || value.stderrBytes < 0 ||
    value.stdoutBytes > 256 * 1024 || value.stderrBytes > 256 * 1024 ||
    value.stdoutTruncated !== false || value.stderrTruncated !== false ||
    value.logLimitBytes !== 256 * 1024 || value.state !== authority.expectedState ||
    (ready && (value.endedAtUnixMs !== null || value.exitCode !== null)) ||
    (stopped && (
      !Number.isSafeInteger(value.endedAtUnixMs) ||
      value.endedAtUnixMs < value.startedAtUnixMs ||
      (value.exitCode !== null && !Number.isSafeInteger(value.exitCode))
    ))
  ) {
    fail("orchestrator_host_evidence_invalid");
  }
  return Object.freeze({ ...value });
}

export function validateRuntimeProcessEvidence(value, authority) {
  if (
    value === null || Array.isArray(value) || typeof value !== "object" ||
    !exactKeys(value, RUNTIME_PROCESS_EVIDENCE_KEYS) ||
    value.schema_version !== 1 || value.run_id !== authority.runId || value.role !== "runtime" ||
    !Number.isSafeInteger(value.pid) || value.pid <= 1 || value.ppid !== authority.hostPid ||
    !DIGEST_PATTERN.test(value.binary_sha256 ?? "") || value.binary_sha256 !== authority.binarySha256 ||
    !DIGEST_PATTERN.test(value.manifest_sha256 ?? "") || value.manifest_sha256 !== authority.manifestSha256 ||
    value.nonce !== authority.nonce || value.profile !== authority.profile ||
    value.state !== "ready" || value.ready !== true
  ) {
    fail("orchestrator_runtime_evidence_invalid");
  }
  return Object.freeze({ ...value });
}

export function validateExistingProcessRecordSet(records, expectedRoles = EXISTING_PROCESS_ROLES) {
  if (
    !Array.isArray(expectedRoles) || new Set(expectedRoles).size !== expectedRoles.length ||
    JSON.stringify(expectedRoles) !== JSON.stringify(
      EXISTING_PROCESS_ROLES.filter((role) => expectedRoles.includes(role)),
    ) || !Array.isArray(records) || records.length !== expectedRoles.length
  ) {
    fail("orchestrator_existing_evidence_incomplete");
  }
  const roles = records.map((record) => record?.role);
  if (JSON.stringify(roles) !== JSON.stringify(expectedRoles)) {
    fail("orchestrator_existing_evidence_incomplete");
  }
  if (records.length === 0) return true;
  const runIds = new Set(records.map((record) => record?.run_id));
  const pids = records.map((record) => record?.pid);
  if (
    runIds.size !== 1 || [...runIds][0] === undefined || new Set(pids).size !== pids.length ||
    records.some((record) => (
      record?.schema_version !== 1 || !Number.isSafeInteger(record.pid) || record.pid <= 1 ||
      !Number.isSafeInteger(record.ppid) || record.ppid <= 0 ||
      !DIGEST_PATTERN.test(record.binary_sha256 ?? "") ||
      !DIGEST_PATTERN.test(record.start_identity ?? "")
    ))
  ) {
    fail("orchestrator_existing_evidence_incomplete");
  }
  const byRole = new Map(records.map((record) => [record.role, record]));
  const infraOwned = ["api", "fake", "desktop"].map((role) => byRole.get(role)).filter(Boolean);
  const infraPid = infraOwned[0]?.ppid;
  if (
    (infraOwned.length > 0 && (
      infraOwned.some((record) => record.ppid !== infraPid) || pids.includes(infraPid)
    )) ||
    (byRole.has("host") && (
      !byRole.has("desktop") || byRole.get("host").ppid !== byRole.get("desktop").pid
    )) ||
    (byRole.has("runtime") && (
      !byRole.has("host") || byRole.get("runtime").ppid !== byRole.get("host").pid
    ))
  ) {
    fail("orchestrator_existing_evidence_incomplete");
  }
  return true;
}

export function sameProcessIdentity(record, current) {
  return Boolean(
    record && current && DIGEST_PATTERN.test(record.start_identity ?? "") &&
    DIGEST_PATTERN.test(current.start_identity ?? "") &&
    DIGEST_PATTERN.test(record.binary_sha256 ?? "") &&
    DIGEST_PATTERN.test(current.binary_sha256 ?? "") &&
    record.pid === current.pid && record.ppid === current.ppid &&
    record.start_identity === current.start_identity &&
    record.binary_sha256 === current.binary_sha256,
  );
}

export async function reconcileProcess(record, operations) {
  let current;
  try {
    current = await operations.inspect(record.pid);
  } catch {
    return "unknown";
  }
  if (current === null) return "absent";
  if (!sameProcessIdentity(record, current)) return "foreign_identity_preserved";
  try {
    await operations.stop(record);
    current = await operations.inspect(record.pid);
  } catch {
    return "unknown";
  }
  if (current === null || !sameProcessIdentity(record, current)) return "stopped";
  return "unknown";
}

export async function assessProcessCleanup(records, inspect) {
  let processes = 0;
  let identityUnknown = false;
  for (const record of records) {
    let current;
    try {
      current = await inspect(record.pid);
    } catch {
      identityUnknown = true;
      continue;
    }
    if (current === null) continue;
    if (sameProcessIdentity(record, current)) processes += 1;
    else identityUnknown = true;
  }
  return Object.freeze({ processes, identityUnknown });
}

export async function runStartupAbortFlow(authority, operations) {
  const machine = createStartupAbortStateMachine();
  let primaryFailure;
  let cleanupPassed = false;
  try {
    machine.transition("preflight_running");
    const summary = await operations.runPreflight();
    validateRepositorySummary(summary, authority.runId, authority.repositories);
    machine.transition("preflight_passed");
    await operations.buildDesktop();
    machine.transition("desktop_built");
    await operations.startDependencies();
    machine.transition("dependencies_ready");
    await operations.startApi();
    machine.transition("api_ready");
    await operations.startFake();
    machine.transition("fake_ready");
    await operations.startDesktop();
    machine.transition("desktop_spawned");
    const ready = await operations.readDesktopFrame("component_ready");
    if (ready.kind !== "component_ready" || ready.sequence !== 1) fail("orchestrator_control_order_invalid");
    validateOwnership(await operations.readOwnership());
    machine.transition("component_ready");
    await operations.sendAbort();
    machine.transition("abort_sent");
    const complete = await operations.readDesktopFrame("abort_complete");
    if (complete.kind !== "abort_complete" || complete.sequence !== 2) {
      fail("orchestrator_control_order_invalid");
    }
    machine.transition("abort_complete");
    await operations.readDesktopEof();
    await operations.waitForDesktopExit();
    machine.transition("desktop_exited");
  } catch (error) {
    primaryFailure = error instanceof S10BO1OrchestratorError
      ? error
      : new S10BO1OrchestratorError("orchestrator_internal_failure");
    try {
      machine.abort();
    } catch {
      // The original failure remains authoritative.
    }
    try {
      await operations.initiateDesktopAbort?.();
    } catch {
      // Cleanup and no-log remain mandatory even when graceful abort cannot be initiated.
    }
  }

  let cleanup;
  let noLog;
  let cleanupFailure;
  let businessBoundary;
  let businessFailure;
  let secondaryFailure;
  const retainFirstSecondary = (error) => {
    if (!secondaryFailure) secondaryFailure = error;
  };
  try {
    if (typeof operations.verifyBusinessBoundary !== "function") {
      fail("orchestrator_business_boundary_unknown");
    }
    businessBoundary = await operations.verifyBusinessBoundary();
    validateBusinessBoundaryEvidence(businessBoundary, authority.runId);
    if (!primaryFailure && businessBoundary.scope !== "api_and_fake") {
      fail("orchestrator_business_boundary_unknown");
    }
  } catch (error) {
    businessFailure = error instanceof S10BO1OrchestratorError
      ? error
      : new S10BO1OrchestratorError("orchestrator_business_boundary_unknown");
    retainFirstSecondary(businessFailure);
  }
  try {
    cleanup = await operations.cleanup();
    validateCleanupClosure(cleanup);
    cleanupPassed = true;
  } catch (error) {
    cleanupFailure = error instanceof S10BO1OrchestratorError
      ? error
      : new S10BO1OrchestratorError("orchestrator_cleanup_unknown");
    retainFirstSecondary(cleanupFailure);
  }
  let parentFailure;
  try {
    operations.assertParentAlive?.();
  } catch (error) {
    parentFailure = error instanceof S10BO1OrchestratorError
      ? error
      : new S10BO1OrchestratorError("orchestrator_parent_death");
    retainFirstSecondary(parentFailure);
  }

  let evidenceFailure = primaryFailure?.closure?.evidence_failure_class
    ? new S10BO1OrchestratorError(primaryFailure.closure.evidence_failure_class)
    : undefined;
  if (evidenceFailure) retainFirstSecondary(evidenceFailure);
  let failureRecorded = false;
  const preNoLogFailure = primaryFailure ?? businessFailure ?? cleanupFailure ?? parentFailure;
  if (preNoLogFailure && typeof operations.recordFailure === "function") {
    try {
      await operations.recordFailure({
        failureClass: preNoLogFailure.code,
        businessFailureClass: businessFailure?.code ?? null,
        cleanupFailureClass: cleanupFailure?.code ?? null,
        parentFailureClass: parentFailure?.code ?? null,
      });
      failureRecorded = true;
    } catch (error) {
      evidenceFailure = error instanceof S10BO1OrchestratorError
        ? error
        : new S10BO1OrchestratorError("orchestrator_evidence_write_failed");
      retainFirstSecondary(evidenceFailure);
    }
  }

  let noLogFailure;
  try {
    noLog = await operations.scanNoLog();
    validateNoLogResult(noLog);
  } catch (error) {
    noLogFailure = error instanceof S10BO1OrchestratorError
      ? error
      : new S10BO1OrchestratorError("orchestrator_no_log_invalid");
    retainFirstSecondary(noLogFailure);
  }

  if (!failureRecorded && noLogFailure && typeof operations.recordFailure === "function") {
    try {
      await operations.recordFailure({
        failureClass: primaryFailure?.code ?? secondaryFailure.code,
        businessFailureClass: businessFailure?.code ?? null,
        cleanupFailureClass: cleanupFailure?.code ?? null,
        parentFailureClass: parentFailure?.code ?? null,
      });
      failureRecorded = true;
    } catch (error) {
      if (!evidenceFailure) {
        evidenceFailure = error instanceof S10BO1OrchestratorError
          ? error
          : new S10BO1OrchestratorError("orchestrator_evidence_write_failed");
      }
      retainFirstSecondary(evidenceFailure);
    }
  }

  let failure = primaryFailure ?? secondaryFailure;
  if (failure && typeof operations.recordClosure === "function") {
    try {
      await operations.recordClosure({
        status: "failed",
        failureClass: failure.code,
        businessFailureClass: businessFailure?.code ?? null,
        businessStatus: businessBoundary
          ? businessBoundary.scope === "not_started" ? "not_applicable" : "passed"
          : businessFailure ? "failed" : "unknown",
        cleanupFailureClass: cleanupFailure?.code ?? null,
        cleanupScope: cleanup?.scope ?? null,
        evidenceFailureClass: evidenceFailure?.code ?? null,
        noLogFailureClass: noLogFailure?.code ?? null,
        noLogScope: noLog?.scope ?? null,
        parentFailureClass: parentFailure?.code ?? null,
      });
    } catch (error) {
      if (!evidenceFailure) {
        evidenceFailure = error instanceof S10BO1OrchestratorError
          ? error
          : new S10BO1OrchestratorError("orchestrator_evidence_write_failed");
        retainFirstSecondary(evidenceFailure);
        failure = primaryFailure ?? secondaryFailure;
      }
    }
  }

  if (failure) {
    try {
      machine.closeFailure(cleanupPassed);
    } catch {
      // Failure closure state is secondary to the original failure class.
    }
    throw new S10BO1OrchestratorError(failure.code, {
      business_failure_class: businessFailure?.code ?? null,
      cleanup_failure_class: cleanupFailure?.code ?? null,
      evidence_failure_class: evidenceFailure?.code ?? null,
      no_log_failure_class: noLogFailure?.code ?? null,
      parent_failure_class: parentFailure?.code ?? null,
    });
  }
  machine.transition("cleanup_passed");
  machine.transition("closed_pass");
  try {
    await operations.recordClosure({
      status: "passed",
      failureClass: null,
      businessFailureClass: null,
      businessStatus: "passed",
      cleanupFailureClass: null,
      cleanupScope: cleanup.scope,
      evidenceFailureClass: null,
      noLogFailureClass: null,
      noLogScope: noLog.scope,
      parentFailureClass: null,
    });
  } catch {
    throw new S10BO1OrchestratorError("orchestrator_evidence_write_failed", {
      business_failure_class: null,
      cleanup_failure_class: null,
      evidence_failure_class: "orchestrator_evidence_write_failed",
      no_log_failure_class: null,
      parent_failure_class: null,
    });
  }
  return Object.freeze({
    schema_version: 1,
    status: "passed",
    scope: "S10BO2-startup-abort",
    run_id: authority.runId,
    state: machine.state,
    cleanup,
    no_log: noLog,
    s10b_r8_executed: false,
  });
}

async function requireOwnerDirectory(path) {
  let metadata;
  try {
    metadata = await lstat(path);
    if (
      !metadata.isDirectory() || metadata.isSymbolicLink() || !ownedByCurrentUser(metadata) ||
      (metadata.mode & 0o777) !== 0o700 || (await realpath(path)) !== path
    ) {
      fail("orchestrator_artifact_invalid");
    }
  } catch (error) {
    if (error instanceof S10BO1OrchestratorError) throw error;
    fail("orchestrator_artifact_invalid");
  }
}

async function readSecureFile(path, maximumBytes, modes = [0o600], minimumBytes = 1) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = await handle.stat();
    if (
      !metadata.isFile() || metadata.isSymbolicLink() || !ownedByCurrentUser(metadata) ||
      metadata.nlink !== 1 || !modes.includes(metadata.mode & 0o777) ||
      metadata.size < minimumBytes || metadata.size > maximumBytes || (await realpath(path)) !== path
    ) {
      fail("orchestrator_artifact_invalid");
    }
    return await handle.readFile();
  } catch (error) {
    if (error instanceof S10BO1OrchestratorError) throw error;
    fail("orchestrator_artifact_invalid");
  } finally {
    await handle?.close();
  }
}

async function writeSecureJson(path, value) {
  let handle;
  try {
    handle = await open(
      path,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    await handle.writeFile(`${JSON.stringify(value)}\n`, "utf8");
    await handle.chmod(0o600);
    await handle.sync();
  } catch {
    fail("orchestrator_evidence_write_failed");
  } finally {
    await handle?.close();
  }
}

async function ensureOwnerOnlyDirectory(path, failureCode = "orchestrator_attempt_evidence_invalid") {
  try {
    await mkdir(path, { mode: 0o700 });
    await chmod(path, 0o700);
  } catch (error) {
    if (error?.code !== "EEXIST") fail(failureCode);
  }
  try {
    await requireOwnerDirectory(path);
  } catch {
    fail(failureCode);
  }
}

function validateAttemptRepositories(repositories, expected) {
  return Boolean(
    repositories && !Array.isArray(repositories) && typeof repositories === "object" &&
    exactKeys(repositories, REPOSITORY_KEYS) &&
    REPOSITORY_KEYS.every((role) => (
      FULL_SHA_PATTERN.test(repositories[role] ?? "") && repositories[role] === expected[role]
    )),
  );
}

export function validateAttemptPreclaim(value, authority) {
  if (
    value === null || Array.isArray(value) || typeof value !== "object" ||
    !exactKeys(value, ATTEMPT_PRECLAIM_KEYS) || value.schema_version !== 1 ||
    value.kind !== "feat126-s10b-preclaim" || value.status !== "reserved" ||
    value.run_id !== authority?.runId || value.s10b_r8_executed !== false ||
    !validateAttemptRepositories(value.repositories, authority?.repositories ?? {}) ||
    !Number.isSafeInteger(value.pid) || value.pid <= 1 ||
    !Number.isSafeInteger(value.ppid) || value.ppid <= 0
  ) {
    fail("orchestrator_attempt_evidence_invalid");
  }
  return Object.freeze({ ...value, repositories: Object.freeze({ ...value.repositories }) });
}

export function validateAttemptPreclaimFailure(value, authority) {
  if (
    value === null || Array.isArray(value) || typeof value !== "object" ||
    !exactKeys(value, ATTEMPT_PRECLAIM_FAILURE_KEYS) || value.schema_version !== 1 ||
    value.status !== "failed" || value.run_id !== authority?.runId ||
    value.s10b_r8_executed !== false || !DIGEST_PATTERN.test(value.preclaim_sha256 ?? "") ||
    !/^[a-z][a-z0-9_]{0,127}$/.test(value.failure_class ?? "")
  ) {
    fail("orchestrator_attempt_evidence_invalid");
  }
  return Object.freeze({ ...value });
}

const ATTEMPT_PHASE_PROCESS_RULES = Object.freeze({
  created: Object.freeze({ required: [], allowed: [] }),
  preflight_not_started: Object.freeze({ required: [], allowed: [] }),
  preflight_running: Object.freeze({ required: [], allowed: [] }),
  preflight_failed: Object.freeze({ required: [], allowed: [] }),
  preflight_context_invalid: Object.freeze({ required: [], allowed: [] }),
  preflight_passed: Object.freeze({ required: [], allowed: [] }),
  desktop_building: Object.freeze({ required: [], allowed: [] }),
  desktop_built: Object.freeze({ required: [], allowed: [] }),
  dependencies_starting: Object.freeze({ required: [], allowed: [] }),
  dependencies_ready: Object.freeze({ required: [], allowed: [] }),
  api_starting: Object.freeze({ required: [], allowed: ["api"] }),
  api_ready: Object.freeze({ required: ["api"], allowed: ["api"] }),
  fake_starting: Object.freeze({ required: ["api"], allowed: ["api", "fake"] }),
  fake_ready: Object.freeze({ required: ["api", "fake"], allowed: ["api", "fake"] }),
  desktop_starting: Object.freeze({
    required: ["api", "fake"],
    allowed: ["api", "desktop", "fake"],
  }),
  desktop_spawned: Object.freeze({
    required: ["api", "desktop", "fake"],
    allowed: EXISTING_PROCESS_ROLES,
  }),
  component_ready: Object.freeze({ required: EXISTING_PROCESS_ROLES, allowed: EXISTING_PROCESS_ROLES }),
  abort_sent: Object.freeze({ required: EXISTING_PROCESS_ROLES, allowed: EXISTING_PROCESS_ROLES }),
  abort_complete: Object.freeze({ required: EXISTING_PROCESS_ROLES, allowed: EXISTING_PROCESS_ROLES }),
  desktop_exited: Object.freeze({ required: EXISTING_PROCESS_ROLES, allowed: EXISTING_PROCESS_ROLES }),
  cleanup_passed: Object.freeze({ required: EXISTING_PROCESS_ROLES, allowed: EXISTING_PROCESS_ROLES }),
  closed_pass: Object.freeze({ required: EXISTING_PROCESS_ROLES, allowed: EXISTING_PROCESS_ROLES }),
});

function validateFailureClassOrNull(value) {
  return value === null || /^[a-z][a-z0-9_]{0,127}$/.test(value ?? "");
}

function validateAttemptPhaseState(value) {
  const rule = ATTEMPT_PHASE_PROCESS_RULES[value.phase];
  const roles = value.process_roles;
  const retainedVolumeKeys = value.retained_volume_keys;
  if (
    !rule || !Array.isArray(roles) || new Set(roles).size !== roles.length ||
    JSON.stringify(roles) !== JSON.stringify(EXISTING_PROCESS_ROLES.filter((role) => roles.includes(role))) ||
    roles.some((role) => !rule.allowed.includes(role)) ||
    rule.required.some((role) => !roles.includes(role)) ||
    !Array.isArray(retainedVolumeKeys) || new Set(retainedVolumeKeys).size !== retainedVolumeKeys.length ||
    JSON.stringify(retainedVolumeKeys) !== JSON.stringify(
      S10_NAMED_VOLUME_KEYS.filter((key) => retainedVolumeKeys.includes(key)),
    ) || (value.compose_cleanup_required && !value.compose_attempted)
  ) return false;
  if (!value.run_root_present) {
    return value.phase === "preflight_failed" && value.compose_attempted === false &&
      value.compose_cleanup_required === false && roles.length === 0 && retainedVolumeKeys.length === 0;
  }
  if (value.phase === "preflight_failed" && !value.compose_attempted && retainedVolumeKeys.length !== 0) {
    return false;
  }
  if (value.phase === "preflight_context_invalid" && !value.compose_attempted) return false;
  if (![
    "created",
    "preflight_not_started",
    "preflight_running",
    "preflight_failed",
    "preflight_context_invalid",
  ].includes(value.phase)) {
    if (!value.compose_attempted || retainedVolumeKeys.length !== S10_NAMED_VOLUME_KEYS.length) return false;
  }
  if (
    ((value.phase === "desktop_starting" && roles.includes("desktop")) || [
      "desktop_spawned",
      "component_ready",
      "abort_sent",
      "abort_complete",
      "desktop_exited",
    ].includes(value.phase)) &&
    roles.length !== EXISTING_PROCESS_ROLES.length && value.cleanup_failure_class === null
  ) return false;
  return true;
}

export function validateAttemptMarker(value, authority) {
  if (
    value === null || Array.isArray(value) || typeof value !== "object" ||
    !exactKeys(value, ATTEMPT_MARKER_KEYS) || value.schema_version !== 1 ||
    value.kind !== "feat126-s10bo2-attempt" || value.status !== "claimed" ||
    value.run_id !== authority?.runId || value.s10b_r8_executed !== false ||
    !validateAttemptRepositories(value.repositories, authority?.repositories ?? {}) ||
    !Number.isSafeInteger(value.pid) || value.pid <= 1 ||
    !Number.isSafeInteger(value.ppid) || value.ppid <= 0 ||
    !DIGEST_PATTERN.test(value.start_identity ?? "") ||
    !DIGEST_PATTERN.test(value.binary_sha256 ?? "") ||
    !DIGEST_PATTERN.test(value.script_sha256 ?? "")
  ) {
    fail("orchestrator_attempt_evidence_invalid");
  }
  return Object.freeze({ ...value, repositories: Object.freeze({ ...value.repositories }) });
}

export function validateAttemptFailure(value, authority) {
  if (
    value === null || Array.isArray(value) || typeof value !== "object" ||
    !exactKeys(value, ATTEMPT_FAILURE_KEYS) || value.schema_version !== 1 ||
    value.status !== "failed" || value.run_id !== authority?.runId ||
    value.s10b_r8_executed !== false || !ATTEMPT_PHASES.has(value.phase) ||
    !DIGEST_PATTERN.test(value.attempt_marker_sha256 ?? "") ||
    typeof value.compose_attempted !== "boolean" ||
    typeof value.compose_cleanup_required !== "boolean" ||
    typeof value.run_root_present !== "boolean" || value.no_log_required !== true ||
    !/^[a-z][a-z0-9_]{0,127}$/.test(value.failure_class ?? "") ||
    !validateFailureClassOrNull(value.business_failure_class) ||
    !validateFailureClassOrNull(value.cleanup_failure_class) ||
    !validateFailureClassOrNull(value.parent_failure_class) ||
    !validateAttemptPhaseState(value)
  ) {
    fail("orchestrator_attempt_evidence_invalid");
  }
  return Object.freeze({
    ...value,
    process_roles: Object.freeze([...value.process_roles]),
    retained_volume_keys: Object.freeze([...value.retained_volume_keys]),
  });
}

export function validateAttemptClosure(value, authority) {
  const passed = value?.status === "passed";
  const failed = value?.status === "failed";
  if (
    value === null || Array.isArray(value) || typeof value !== "object" ||
    !exactKeys(value, ATTEMPT_CLOSURE_KEYS) || value.schema_version !== 1 ||
    (!passed && !failed) || value.run_id !== authority?.runId ||
    value.s10b_r8_executed !== false || !DIGEST_PATTERN.test(value.attempt_marker_sha256 ?? "") ||
    value.closure_kind !== (passed ? "success" : "failure") ||
    (passed ? value.failure_class !== null :
      !/^[a-z][a-z0-9_]{0,127}$/.test(value.failure_class ?? "")) ||
    !["passed", "not_applicable", "unknown", "failed"].includes(value.business_status) ||
    ![null, "pre_run_absence", "preflight_artifacts", "run_artifacts"].includes(
      value.cleanup_scope,
    ) ||
    ![null, "attempt_only", "preflight_artifacts", "run_artifacts"].includes(value.no_log_scope) ||
    !validateFailureClassOrNull(value.business_failure_class) ||
    !validateFailureClassOrNull(value.cleanup_failure_class) ||
    !validateFailureClassOrNull(value.evidence_failure_class) ||
    !validateFailureClassOrNull(value.no_log_failure_class) ||
    !validateFailureClassOrNull(value.parent_failure_class) ||
    (failed && (
      (value.cleanup_failure_class === null) !== (value.cleanup_scope !== null) ||
      (value.no_log_failure_class === null) !== (value.no_log_scope !== null) ||
      (value.business_failure_class === null &&
        !["passed", "not_applicable"].includes(value.business_status)) ||
      (value.business_failure_class !== null &&
        !["failed", "unknown"].includes(value.business_status))
    )) ||
    (passed && (
      value.business_status !== "passed" || value.cleanup_scope === null ||
      value.no_log_scope === null || value.business_failure_class !== null ||
      value.cleanup_failure_class !== null || value.evidence_failure_class !== null ||
      value.no_log_failure_class !== null || value.parent_failure_class !== null
    ))
  ) fail("orchestrator_attempt_evidence_invalid");
  return Object.freeze({ ...value });
}

export function validateAttemptReconcile(value, authority) {
  if (
    value === null || Array.isArray(value) || typeof value !== "object" ||
    !exactKeys(value, ATTEMPT_RECONCILE_KEYS) || value.schema_version !== 1 ||
    value.status !== "reconciled" || value.run_id !== authority?.runId ||
    value.s10b_r8_executed !== false || !DIGEST_PATTERN.test(value.attempt_marker_sha256 ?? "") ||
    !/^[a-z][a-z0-9_]{0,127}$/.test(value.failure_class ?? "") ||
    !["passed", "not_applicable", "unknown", "failed"].includes(value.business_status) ||
    ![null, "pre_run_absence", "preflight_artifacts", "run_artifacts"].includes(
      value.cleanup_scope,
    ) ||
    ![null, "attempt_only", "preflight_artifacts", "run_artifacts"].includes(value.no_log_scope) ||
    !validateFailureClassOrNull(value.cleanup_failure_class) ||
    !validateFailureClassOrNull(value.no_log_failure_class) ||
    (value.cleanup_failure_class === null) !== (value.cleanup_scope !== null) ||
    (value.no_log_failure_class === null) !== (value.no_log_scope !== null)
  ) fail("orchestrator_attempt_evidence_invalid");
  return Object.freeze({ ...value });
}

export function buildAttemptReconcileEvidence(attempt, authority, failure, outcome) {
  return validateAttemptReconcile({
    schema_version: 1,
    status: "reconciled",
    run_id: authority?.runId,
    attempt_marker_sha256: attempt?.markerSha256,
    failure_class: failure?.failure_class ?? "orchestrator_unclean_exit",
    business_status: outcome?.businessStatus,
    cleanup_scope: outcome?.cleanup?.scope ?? null,
    cleanup_failure_class: outcome?.cleanupFailure?.code ?? null,
    no_log_scope: outcome?.noLog?.scope ?? null,
    no_log_failure_class: outcome?.noLogFailure?.code ?? null,
    s10b_r8_executed: false,
  }, authority);
}

function canonicalJsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
}

async function readAttemptJson(path, maximumBytes, validator, authority, includeDigest = false) {
  let value;
  let bytes;
  try {
    bytes = await readSecureFile(path, maximumBytes);
    value = JSON.parse(bytes.toString("utf8"));
    if (!bytes.equals(canonicalJsonBytes(value))) fail("orchestrator_attempt_evidence_invalid");
  } catch {
    fail("orchestrator_attempt_evidence_invalid");
  }
  try {
    const validated = validator(value, authority);
    return includeDigest
      ? Object.freeze({ value: validated, digest: sha256(bytes) })
      : validated;
  } catch {
    fail("orchestrator_attempt_evidence_invalid");
  }
}

function attemptPaths(attemptRoot, runId) {
  return Object.freeze({
    markerPath: resolve(attemptRoot, `${runId}.attempt.v1.json`),
    failurePath: resolve(attemptRoot, `${runId}.failure.v1.json`),
    closurePath: resolve(attemptRoot, `${runId}.closure.v1.json`),
    reconcilePath: resolve(attemptRoot, `${runId}.reconcile.v1.json`),
  });
}

function preclaimPaths(attemptRoot, runId) {
  return Object.freeze({
    preclaimPath: resolve(attemptRoot, `${runId}.preclaim.v1.json`),
    preclaimFailurePath: resolve(attemptRoot, `${runId}.preclaim-failure.v1.json`),
  });
}

async function requireAttemptBinding(attempt, authority) {
  const expected = attemptPaths(attempt?.attemptRoot ?? "", authority?.runId ?? "");
  if (
    !attempt || attempt.markerPath !== expected.markerPath || attempt.failurePath !== expected.failurePath ||
    attempt.closurePath !== expected.closurePath || attempt.reconcilePath !== expected.reconcilePath ||
    !DIGEST_PATTERN.test(attempt.markerSha256 ?? "")
  ) fail("orchestrator_attempt_evidence_invalid");
  await ensureOwnerOnlyDirectory(attempt.attemptRoot);
  const observed = await readAttemptJson(
    attempt.markerPath,
    4096,
    validateAttemptMarker,
    authority,
    true,
  );
  if (observed.digest !== attempt.markerSha256) fail("orchestrator_attempt_evidence_invalid");
  const hasPreclaim = [
    attempt.preclaimPath,
    attempt.preclaimFailurePath,
    attempt.preclaimSha256,
    attempt.preclaim,
  ].some((value) => value !== undefined);
  if (hasPreclaim) {
    const preclaimExpected = preclaimPaths(attempt.attemptRoot, authority.runId);
    if (
      attempt.preclaimPath !== preclaimExpected.preclaimPath ||
      attempt.preclaimFailurePath !== preclaimExpected.preclaimFailurePath ||
      !DIGEST_PATTERN.test(attempt.preclaimSha256 ?? "")
    ) fail("orchestrator_attempt_evidence_invalid");
    const preclaimObserved = await readAttemptJson(
      attempt.preclaimPath,
      4096,
      validateAttemptPreclaim,
      authority,
      true,
    );
    if (
      preclaimObserved.digest !== attempt.preclaimSha256 ||
      preclaimObserved.value.pid !== observed.value.pid ||
      preclaimObserved.value.ppid !== observed.value.ppid
    ) fail("orchestrator_attempt_evidence_invalid");
    await requireAbsentAttemptArtifact(attempt.preclaimFailurePath);
  }
  return observed.value;
}

async function requireAbsentAttemptArtifact(path) {
  try {
    await lstat(path);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    fail("orchestrator_attempt_evidence_invalid");
  }
  fail("orchestrator_attempt_evidence_invalid");
}

async function pathExists(path) {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    fail("orchestrator_attempt_evidence_invalid");
  }
}

async function createAttemptPreclaim(path, value) {
  let handle;
  try {
    handle = await open(
      path,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    await handle.writeFile(canonicalJsonBytes(value));
    await handle.chmod(0o600);
    await handle.sync();
    return true;
  } catch (error) {
    if (error?.code === "EEXIST") return false;
    fail("orchestrator_attempt_evidence_invalid");
  } finally {
    await handle?.close();
  }
}

async function readAttemptPreclaim(path, authority, includeDigest = false) {
  return await readAttemptJson(path, 4096, validateAttemptPreclaim, authority, includeDigest);
}

export async function readAttemptPreclaimFailure(path, authority) {
  return await readAttemptJson(path, 4096, validateAttemptPreclaimFailure, authority);
}

async function persistAttemptPreclaimFailure(preclaim, authority, error) {
  const primary = error instanceof S10BO1OrchestratorError
    ? error
    : new S10BO1OrchestratorError("orchestrator_internal_failure");
  const failure = validateAttemptPreclaimFailure({
    schema_version: 1,
    status: "failed",
    run_id: authority.runId,
    preclaim_sha256: preclaim.preclaimSha256,
    failure_class: primary.code,
    s10b_r8_executed: false,
  }, authority);
  try {
    await writeSecureJson(preclaim.preclaimFailurePath, failure);
  } catch {
    throw new S10BO1OrchestratorError(primary.code, {
      business_failure_class: null,
      cleanup_failure_class: null,
      evidence_failure_class: "orchestrator_evidence_write_failed",
      no_log_failure_class: null,
      parent_failure_class: null,
    });
  }
  throw primary;
}

async function loadExistingAttempt(authority, attemptRoot, identity, scriptSha256) {
  const { markerPath, failurePath, closurePath, reconcilePath } = attemptPaths(
    attemptRoot,
    authority.runId,
  );
  let existing;
  for (let readAttempt = 0; readAttempt < 50; readAttempt += 1) {
    try {
      existing = await readAttemptJson(markerPath, 4096, validateAttemptMarker, authority, true);
      break;
    } catch (error) {
      if (readAttempt === 49) throw error;
      await new Promise((resolveWait) => setTimeout(resolveWait, 10));
    }
  }
  if (
    existing.value.script_sha256 !== scriptSha256 ||
    existing.value.binary_sha256 !== identity.binary_sha256
  ) fail("orchestrator_attempt_evidence_invalid");
  const preclaim = preclaimPaths(attemptRoot, authority.runId);
  let preclaimBinding = {};
  if (await pathExists(preclaim.preclaimPath)) {
    const observed = await readAttemptPreclaim(preclaim.preclaimPath, authority, true);
    if (
      observed.value.pid !== existing.value.pid || observed.value.ppid !== existing.value.ppid ||
      await pathExists(preclaim.preclaimFailurePath)
    ) fail("orchestrator_attempt_evidence_invalid");
    preclaimBinding = {
      ...preclaim,
      preclaimSha256: observed.digest,
      preclaim: observed.value,
    };
  }
  return Object.freeze({
    fresh: false,
    attemptRoot,
    markerPath,
    failurePath,
    closurePath,
    reconcilePath,
    markerSha256: existing.digest,
    marker: existing.value,
    ...preclaimBinding,
  });
}

export async function claimAttemptLedger(authority, options = {}) {
  buildPreflightMakeInvocation(authority);
  const attemptRoot = options.attemptRoot ?? ATTEMPT_ROOT;
  await ensureOwnerOnlyDirectory(attemptRoot);
  const { markerPath, failurePath, closurePath, reconcilePath } = attemptPaths(
    attemptRoot,
    authority.runId,
  );
  const preclaim = preclaimPaths(attemptRoot, authority.runId);
  const inspectIdentity = options.inspectIdentity ?? inspectProcessIdentity;
  const resolveIdentity = async () => {
    const identity = options.identity ?? await inspectIdentity(process.pid);
    if (!identity || identity.pid !== process.pid) fail("orchestrator_process_identity_unknown");
    return identity;
  };
  const resolveScriptSha256 = async () => {
    const scriptSha256 = options.scriptSha256 ?? await hashFile(fileURLToPath(import.meta.url));
    if (!DIGEST_PATTERN.test(scriptSha256 ?? "")) fail("orchestrator_attempt_evidence_invalid");
    return scriptSha256;
  };

  if (await pathExists(markerPath)) {
    return await loadExistingAttempt(
      authority,
      attemptRoot,
      await resolveIdentity(),
      await resolveScriptSha256(),
    );
  }

  const preclaimValue = validateAttemptPreclaim({
    schema_version: 1,
    kind: "feat126-s10b-preclaim",
    status: "reserved",
    run_id: authority.runId,
    repositories: authority.repositories,
    pid: process.pid,
    ppid: Math.max(process.ppid, 1),
    s10b_r8_executed: false,
  }, authority);
  const preclaimFresh = await createAttemptPreclaim(preclaim.preclaimPath, preclaimValue);
  if (!preclaimFresh) {
    let existingPreclaim;
    for (let readPreclaim = 0; readPreclaim < 50; readPreclaim += 1) {
      try {
        existingPreclaim = await readAttemptPreclaim(
          preclaim.preclaimPath,
          authority,
          true,
        );
        break;
      } catch (error) {
        if (readPreclaim === 49) throw error;
        await new Promise((resolveWait) => setTimeout(resolveWait, 10));
      }
    }
    for (let wait = 0; wait < 120; wait += 1) {
      if (await pathExists(markerPath)) {
        return await loadExistingAttempt(
          authority,
          attemptRoot,
          await resolveIdentity(),
          await resolveScriptSha256(),
        );
      }
      if (await pathExists(preclaim.preclaimFailurePath)) {
        const failure = await readAttemptPreclaimFailure(preclaim.preclaimFailurePath, authority);
        if (failure.preclaim_sha256 !== existingPreclaim.digest) {
          fail("orchestrator_attempt_evidence_invalid");
        }
        fail("orchestrator_existing_preclaim_failed");
      }
      await new Promise((resolveWait) => setTimeout(resolveWait, 50));
    }
    fail("orchestrator_preclaim_incomplete");
  }
  const preclaimBinding = Object.freeze({
    ...preclaim,
    preclaimSha256: sha256(canonicalJsonBytes(preclaimValue)),
    preclaim: preclaimValue,
  });

  let identity;
  let scriptSha256;
  let marker;
  try {
    identity = await resolveIdentity();
    if (identity.ppid !== preclaimValue.ppid) fail("orchestrator_process_identity_unknown");
    scriptSha256 = await resolveScriptSha256();
    await requireAbsentAttemptArtifact(preclaim.preclaimFailurePath);
    marker = validateAttemptMarker({
      schema_version: 1,
      kind: "feat126-s10bo2-attempt",
      status: "claimed",
      run_id: authority.runId,
      repositories: authority.repositories,
      pid: identity.pid,
      ppid: identity.ppid,
      start_identity: identity.start_identity,
      binary_sha256: identity.binary_sha256,
      script_sha256: scriptSha256,
      s10b_r8_executed: false,
    }, authority);
  } catch (error) {
    await persistAttemptPreclaimFailure(preclaimBinding, authority, error);
  }
  const markerBytes = canonicalJsonBytes(marker);
  const markerSha256 = sha256(markerBytes);
  let handle;
  try {
    handle = await open(
      markerPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    await handle.writeFile(markerBytes);
    await handle.chmod(0o600);
    await handle.sync();
    await requireAbsentAttemptArtifact(failurePath);
    await requireAbsentAttemptArtifact(closurePath);
    await requireAbsentAttemptArtifact(reconcilePath);
    return Object.freeze({
      fresh: true,
      attemptRoot,
      markerPath,
      failurePath,
      closurePath,
      reconcilePath,
      markerSha256,
      marker,
      ...preclaimBinding,
    });
  } catch (error) {
    if (error?.code !== "EEXIST") {
      await persistAttemptPreclaimFailure(
        preclaimBinding,
        authority,
        new S10BO1OrchestratorError("orchestrator_attempt_evidence_invalid"),
      );
    }
  } finally {
    await handle?.close();
  }
  return await loadExistingAttempt(authority, attemptRoot, identity, scriptSha256);
}

export async function writeAttemptFailure(attempt, authority, value) {
  await requireAttemptBinding(attempt, authority);
  const validated = validateAttemptFailure(value, authority);
  if (validated.attempt_marker_sha256 !== attempt.markerSha256) {
    fail("orchestrator_attempt_evidence_invalid");
  }
  await writeSecureJson(attempt.failurePath, validated);
  return validated;
}

export async function readAttemptFailure(attempt, authority) {
  await requireAttemptBinding(attempt, authority);
  return await readAttemptJson(attempt.failurePath, 4096, validateAttemptFailure, authority);
}

export async function writeAttemptClosure(attempt, authority, value) {
  await requireAttemptBinding(attempt, authority);
  const validated = validateAttemptClosure(value, authority);
  if (validated.attempt_marker_sha256 !== attempt.markerSha256) {
    fail("orchestrator_attempt_evidence_invalid");
  }
  await writeSecureJson(attempt.closurePath, validated);
  return validated;
}

export async function readAttemptClosure(attempt, authority) {
  await requireAttemptBinding(attempt, authority);
  return await readAttemptJson(attempt.closurePath, 4096, validateAttemptClosure, authority);
}

export async function writeAttemptReconcile(attempt, authority, value) {
  await requireAttemptBinding(attempt, authority);
  const validated = validateAttemptReconcile(value, authority);
  if (validated.attempt_marker_sha256 !== attempt.markerSha256) {
    fail("orchestrator_attempt_evidence_invalid");
  }
  await writeSecureJson(attempt.reconcilePath, validated);
  return validated;
}

export async function readAttemptReconcile(attempt, authority) {
  await requireAttemptBinding(attempt, authority);
  return await readAttemptJson(
    attempt.reconcilePath,
    4096,
    validateAttemptReconcile,
    authority,
  );
}

async function hashFile(path) {
  return await new Promise((resolveHash, rejectHash) => {
    const hash = createHash("sha256");
    const input = createReadStream(path);
    input.on("error", rejectHash);
    input.on("data", (chunk) => hash.update(chunk));
    input.on("end", () => resolveHash(hash.digest("hex")));
  });
}

function readProcessSnapshot(pid) {
  const result = spawnSync("/bin/ps", ["-p", String(pid), "-o", "ppid=", "-o", "lstart=", "-o", "comm="], {
    encoding: "utf8",
    env: { ...process.env, LANG: "C", LC_ALL: "C" },
    shell: false,
    windowsHide: true,
    maxBuffer: 16 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 2_000,
  });
  if (result.error) fail("orchestrator_process_identity_unknown");
  if (result.status === 1 && (result.stdout ?? "").trim() === "") return null;
  if (result.status !== 0 || result.signal !== null) fail("orchestrator_process_identity_unknown");
  const normalized = (result.stdout ?? "").trim().replace(/\s+/g, " ");
  const match = /^(\d+) ((?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{2}:\d{2}:\d{2} \d{4}) (.+)$/.exec(normalized);
  if (!match) fail("orchestrator_process_identity_unknown");
  const ppid = Number(match[1]);
  const executable = match[3];
  if (!Number.isSafeInteger(ppid) || ppid <= 0 || !isAbsolute(executable)) {
    fail("orchestrator_process_identity_unknown");
  }
  return Object.freeze({ ppid, started: match[2], executable, normalized });
}

export function parseDarwinProcessLaunchIdentity(output, pid) {
  if (typeof output !== "string" || !Number.isSafeInteger(pid) || pid <= 1) {
    fail("orchestrator_process_identity_unknown");
  }
  const processLines = output.match(/^Process:\s+.+ \[(\d+)\]$/gm) ?? [];
  const launchLines = output.match(
    /^Launch Time:\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3,6} [+-]\d{4})$/gm,
  ) ?? [];
  if (processLines.length !== 1 || launchLines.length !== 1) {
    fail("orchestrator_process_identity_unknown");
  }
  const processMatch = /^Process:\s+.+ \[(\d+)\]$/.exec(processLines[0]);
  const launchMatch =
    /^Launch Time:\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3,6} [+-]\d{4})$/
      .exec(launchLines[0]);
  if (Number(processMatch?.[1]) !== pid || !launchMatch?.[1]) {
    fail("orchestrator_process_identity_unknown");
  }
  return launchMatch[1];
}

function readKernelProcessIdentity(pid) {
  const result = spawnSync(
    "/usr/bin/vmmap",
    ["-summary", String(pid)],
    {
      encoding: "utf8",
      env: { ...process.env, LANG: "C", LC_ALL: "C" },
      shell: false,
      windowsHide: true,
      maxBuffer: 64 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 5_000,
    },
  );
  if (result.error || result.status !== 0 || result.signal !== null) {
    fail("orchestrator_process_identity_unknown");
  }
  return parseDarwinProcessLaunchIdentity(result.stdout ?? "", pid);
}

export async function inspectProcessIdentity(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 1) fail("orchestrator_process_identity_unknown");
  const first = readProcessSnapshot(pid);
  if (first === null) return null;
  const kernelStartIdentity = readKernelProcessIdentity(pid);
  const second = readProcessSnapshot(pid);
  if (second === null || second.normalized !== first.normalized) {
    fail("orchestrator_process_identity_unknown");
  }
  let executablePath;
  let binarySha256;
  try {
    executablePath = await realpath(first.executable);
    binarySha256 = await hashFile(executablePath);
  } catch {
    fail("orchestrator_process_identity_unknown");
  }
  if (!DIGEST_PATTERN.test(binarySha256)) fail("orchestrator_process_identity_unknown");
  return Object.freeze({
    pid,
    ppid: first.ppid,
    start_identity: sha256(
      `${pid}\n${first.ppid}\n${first.started}\n${kernelStartIdentity}\n${executablePath}`,
    ),
    binary_sha256: binarySha256,
  });
}

async function captureProcessIdentity(child, expectedBinarySha256, inspect = inspectProcessIdentity) {
  if (!Number.isSafeInteger(child.pid) || child.pid <= 1) fail("orchestrator_process_spawn_failed");
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (child.exitCode !== null || child.signalCode !== null) fail("orchestrator_process_exited_early");
    const identity = await inspect(child.pid);
    if (child.exitCode !== null || child.signalCode !== null) fail("orchestrator_process_exited_early");
    if (identity) {
      if (identity.binary_sha256 !== expectedBinarySha256) {
        fail("orchestrator_process_binary_invalid");
      }
      return identity;
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 20));
  }
  fail("orchestrator_process_identity_unknown");
}

async function openExclusiveLog(path) {
  try {
    const handle = await open(
      path,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    await handle.chmod(0o600);
    return handle;
  } catch {
    fail("orchestrator_log_invalid");
  }
}

export async function spawnOwnedProcess({
  role,
  binary,
  arguments_ = [],
  cwd,
  environment,
  logPath,
  extraStdio = [],
  inspect = inspectProcessIdentity,
}, context) {
  let binarySha256;
  try {
    binarySha256 = await hashFile(binary);
  } catch {
    fail("orchestrator_process_binary_invalid");
  }
  const logHandle = await openExclusiveLog(logPath);
  let child;
  try {
    child = spawn(binary, arguments_, {
      cwd,
      env: environment,
      shell: false,
      windowsHide: true,
      stdio: ["ignore", logHandle.fd, logHandle.fd, ...extraStdio],
    });
  } catch {
    await logHandle.close().catch(() => {});
    fail("orchestrator_process_spawn_failed");
  }
  const provisional = {
    child,
    record: null,
    logPath,
    role,
    provisional: true,
  };
  context.processes[role] = provisional;
  child.on("error", () => {
    context.cleanupUnknown = true;
    provisional.processError = true;
  });
  try {
    await logHandle.close();
  } catch {
    context.cleanupUnknown = true;
    fail("orchestrator_log_invalid");
  }
  let identity;
  try {
    identity = await captureProcessIdentity(child, binarySha256, inspect);
    if (identity.ppid !== process.pid) fail("orchestrator_process_parent_invalid");
  } catch (error) {
    context.cleanupUnknown = true;
    throw error;
  }
  const record = validateProcessRecord({
    schema_version: 1,
    run_id: context.runId,
    role,
    pid: identity.pid,
    ppid: identity.ppid,
    binary_sha256: identity.binary_sha256,
    start_identity: identity.start_identity,
  }, context.runId, role);
  provisional.record = record;
  provisional.provisional = false;
  await writeSecureJson(resolve(context.evidenceRoot, `${role}-process.v1.json`), record);
  return provisional;
}

function childExit(child, role) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return Promise.reject(new S10BO1OrchestratorError(`orchestrator_${role}_exited_early`));
  }
  return new Promise((_, reject) => {
    child.once("exit", () => reject(new S10BO1OrchestratorError(`orchestrator_${role}_exited_early`)));
    child.once("error", () => reject(new S10BO1OrchestratorError(`orchestrator_${role}_process_failed`)));
  });
}

async function waitForHttpReadiness(child, role, path, expectedStatus) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    if (child.exitCode !== null || child.signalCode !== null) fail(`orchestrator_${role}_exited_early`);
    try {
      await new Promise((resolveReady, rejectReady) => {
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
                const value = JSON.parse(body);
                if (response.statusCode !== 200 || value.status !== expectedStatus) throw new Error("not ready");
                resolveReady();
              } catch (error) {
                rejectReady(error);
              }
            });
          },
        );
        request.on("timeout", () => request.destroy(new Error("timeout")));
        request.on("error", rejectReady);
      });
      return;
    } catch {
      await new Promise((resolveWait) => setTimeout(resolveWait, 200));
    }
  }
  fail(`orchestrator_${role}_not_ready`);
}

function guardControlWriter(stream) {
  if (!stream || GUARDED_CONTROL_WRITERS.has(stream)) return;
  GUARDED_CONTROL_WRITERS.add(stream);
  stream.on("error", () => {});
}

async function boundedWritableOperation(stream, operation, timeoutMs) {
  if (
    !stream || stream.destroyed || !stream.writable ||
    !Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > CONTROL_TIMEOUT_MS
  ) fail("orchestrator_control_stream_failed");
  guardControlWriter(stream);
  await new Promise((resolveOperation, rejectOperation) => {
    let settled = false;
    let timeout;
    const settle = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      stream.off("error", onError);
      stream.off("close", onClose);
      if (error) rejectOperation(error);
      else resolveOperation();
    };
    const onError = (error) => settle(error);
    const onClose = () => settle(new Error("control stream closed"));
    stream.once("error", onError);
    stream.once("close", onClose);
    timeout = setTimeout(
      () => settle(new S10BO1OrchestratorError("orchestrator_control_stream_failed")),
      timeoutMs,
    );
    try {
      operation((error) => settle(error));
    } catch (error) {
      settle(error);
    }
  }).catch(() => {
    stream.destroy();
    fail("orchestrator_control_stream_failed");
  });
}

export async function writeFrame(stream, bytes, timeoutMs = CONTROL_TIMEOUT_MS) {
  await boundedWritableOperation(
    stream,
    (complete) => stream.write(bytes, complete),
    timeoutMs,
  );
}

export async function closeControlWriter(stream, timeoutMs = CONTROL_TIMEOUT_MS) {
  if (!stream || stream.writableEnded) return;
  await boundedWritableOperation(stream, (complete) => stream.end(complete), timeoutMs);
}

async function stopOwnedProcess(process_) {
  if (!process_?.child || process_.child.exitCode !== null || process_.child.signalCode !== null) return "absent";
  if (process_.provisional || !process_.record) return "unknown";
  const current = await inspectProcessIdentity(process_.record.pid);
  if (current === null) return "absent";
  if (!sameProcessIdentity(process_.record, current)) return "foreign_identity_preserved";
  process_.child.kill("SIGTERM");
  const stopped = await Promise.race([
    new Promise((resolveExit) => process_.child.once("exit", () => resolveExit(true))),
    new Promise((resolveTimeout) => setTimeout(() => resolveTimeout(false), PROCESS_STOP_TIMEOUT_MS)),
  ]);
  if (stopped) return "stopped";
  const afterTerm = await inspectProcessIdentity(process_.record.pid);
  if (afterTerm === null || !sameProcessIdentity(process_.record, afterTerm)) return "stopped";
  process_.child.kill("SIGKILL");
  const killed = await Promise.race([
    new Promise((resolveExit) => process_.child.once("exit", () => resolveExit(true))),
    new Promise((resolveTimeout) => setTimeout(() => resolveTimeout(false), PROCESS_STOP_TIMEOUT_MS)),
  ]);
  return killed ? "stopped" : "unknown";
}

function inspectListener(port) {
  return new Promise((resolveInspection) => {
    const server = net.createServer();
    server.unref();
    server.once("error", (error) => resolveInspection({
      port,
      listening: error?.code === "EADDRINUSE",
      unknown: error?.code !== "EADDRINUSE",
    }));
    server.listen({ host: "127.0.0.1", port, exclusive: true }, () => {
      server.close(() => resolveInspection({ port, listening: false, unknown: false }));
    });
  });
}

async function loadRunContext(authority, attempt) {
  const runRoot = resolve(GENERATED_ROOT, authority.runId);
  const evidenceRoot = resolve(runRoot, "orchestrator-evidence");
  const preflightEvidenceRoot = resolve(runRoot, "preflight-evidence");
  const binRoot = resolve(runRoot, "bin");
  const logRoot = resolve(runRoot, "logs");
  const buildRoot = resolve(runRoot, "desktop-build");
  const frontendDistRoot = resolve(buildRoot, "frontend-dist");
  const cargoTargetRoot = resolve(buildRoot, "cargo-target");
  for (const directory of [runRoot, preflightEvidenceRoot, binRoot, logRoot]) {
    await requireOwnerDirectory(directory);
  }
  for (const directory of [buildRoot, frontendDistRoot, cargoTargetRoot]) {
    try {
      await mkdir(directory, { mode: 0o700 });
      await chmod(directory, 0o700);
      await requireOwnerDirectory(directory);
    } catch {
      fail("orchestrator_build_root_invalid");
    }
  }
  try {
    await mkdir(evidenceRoot, { mode: 0o700 });
    await chmod(evidenceRoot, 0o700);
  } catch {
    fail("orchestrator_evidence_root_invalid");
  }
  const summaryBytes = await readSecureFile(resolve(preflightEvidenceRoot, "summary.json"), 64 * 1024);
  let summary;
  try {
    summary = JSON.parse(summaryBytes.toString("utf8"));
  } catch {
    fail("orchestrator_preflight_authority_invalid");
  }
  validateRepositorySummary(summary, authority.runId, authority.repositories);
  const secretsPath = resolve(runRoot, "infra-secrets.env");
  const secretsBytes = await readSecureFile(secretsPath, 4096);
  let secrets;
  try {
    secrets = parseFeat126S10Secrets(secretsBytes.toString("utf8"));
  } catch {
    fail("orchestrator_secret_store_invalid");
  }
  const caPath = resolve(runRoot, "caddy-root.crt");
  const ca = await readSecureFile(caPath, 64 * 1024, [0o400, 0o600]);
  const caText = ca.toString("utf8");
  if (
    (caText.match(/-----BEGIN CERTIFICATE-----/g) ?? []).length !== 1 ||
    (caText.match(/-----END CERTIFICATE-----/g) ?? []).length !== 1 || /PRIVATE KEY/.test(caText)
  ) {
    fail("orchestrator_ca_invalid");
  }
  const retainedVolumeNames = await projectVolumeNames(authority.runId);
  const retainedVolumes = classifyProjectVolumes(projectName(authority.runId), retainedVolumeNames);
  if (
    retainedVolumes.namedVolumes !== S10_NAMED_VOLUME_KEYS.length ||
    retainedVolumes.temporaryVolumes !== 0
  ) {
    fail("orchestrator_preflight_cleanup_invalid");
  }
  return {
    ...authority,
    attempt,
    nonce: randomUUID(),
    runRoot,
    evidenceRoot,
    preflightEvidenceRoot,
    binRoot,
    logRoot,
    buildRoot,
    frontendDistRoot,
    cargoTargetRoot,
    summary,
    secrets,
    secretsPath,
    caPath,
    caSha256: sha256(ca),
    phase: "preflight_passed",
    runRootPresent: true,
    retainedVolumeNames,
    composeAttempted: true,
    composeCleanupRequired: false,
    composeStarted: false,
    composeLogsRequired: false,
    cleanupUnknown: false,
    processes: {},
  };
}

async function loadPreflightFailureContext(authority, attempt, provisional, primaryFailure) {
  const runRoot = resolve(GENERATED_ROOT, authority.runId);
  let runRootPresent = true;
  try {
    await lstat(runRoot);
  } catch (error) {
    if (error?.code !== "ENOENT") fail("orchestrator_run_root_invalid");
    runRootPresent = false;
  }
  if (!runRootPresent) {
    return Object.freeze({
      context: {
        ...provisional,
        phase: "preflight_failed",
        runRootPresent: false,
        composeAttempted: false,
        composeCleanupRequired: false,
        primaryFailureClass: primaryFailure.code,
      },
      failure: primaryFailure,
    });
  }

  const preflightEvidenceRoot = resolve(runRoot, "preflight-evidence");
  const logRoot = resolve(runRoot, "logs");
  const evidenceRoot = resolve(runRoot, "orchestrator-evidence");
  for (const directory of [runRoot, preflightEvidenceRoot, logRoot]) {
    await requireOwnerDirectory(directory);
  }
  await ensureOwnerOnlyDirectory(evidenceRoot, "orchestrator_evidence_root_invalid");
  let preflightFailure;
  try {
    preflightFailure = validatePreflightFailureEvidence(
      JSON.parse((await readSecureFile(
        resolve(preflightEvidenceRoot, PREFLIGHT_FAILURE_EVIDENCE_FILE),
        4096,
      )).toString("utf8")),
      authority.runId,
    );
  } catch {
    fail("orchestrator_preflight_failure_evidence_invalid");
  }
  validatePreflightFailureBinding(primaryFailure.code, preflightFailure);
  const secretsPath = resolve(runRoot, "infra-secrets.env");
  let secrets = new Map();
  try {
    secrets = parseFeat126S10Secrets((await readSecureFile(secretsPath, 4096)).toString("utf8"));
  } catch {
    if (preflightFailure.phase !== "authority") fail("orchestrator_secret_store_invalid");
  }
  const observedVolumeNames = await projectVolumeNames(authority.runId);
  const observedVolumes = classifyProjectVolumes(projectName(authority.runId), observedVolumeNames);
  const composeNotAttemptedWithResources = !preflightFailure.compose_attempted && observedVolumeNames.length !== 0;
  return Object.freeze({
    context: {
      ...provisional,
      attempt,
      runRoot,
      evidenceRoot,
      preflightEvidenceRoot,
      logRoot,
      secrets,
      secretsPath,
      phase: "preflight_failed",
      runRootPresent: true,
      primaryFailureClass: preflightFailure.failure_class,
      retainedVolumeNames: preflightFailure.compose_attempted
        ? observedVolumeNames
        : provisional.retainedVolumeNames,
      composeAttempted: preflightFailure.compose_attempted,
      composeCleanupRequired: preflightFailure.compose_attempted &&
        preflightFailure.cleanup_state !== "passed",
      cleanupUnknown: (
        preflightFailure.cleanup_state === "unknown" && !preflightFailure.compose_attempted
      ) || composeNotAttemptedWithResources || observedVolumes.temporaryVolumes !== 0,
    },
    failure: new S10BO1OrchestratorError(preflightFailure.failure_class),
  });
}

export async function executePreflight(authority, signal, runner = runCommand) {
  await runner(
    "preflight",
    "make",
    buildPreflightMakeInvocation(authority),
    {
      env: commandEnvironment(),
      failureParser: parsePreflightFailureFrame,
      timeout: 30 * 60_000,
      signal,
    },
  );
}

async function verifyRepositoryAuthority(repositories, signal) {
  for (const [role, repository] of Object.entries(REPOSITORIES)) {
    const head = (await runCommand(
      "repository",
      "git",
      ["-C", repository, "rev-parse", "HEAD"],
      { signal },
    )).trim();
    const status = await runCommand(
      "repository",
      "git",
      ["-C", repository, "status", "--porcelain", "--untracked-files=all"],
      { signal },
    );
    if (head !== repositories[role]) fail(`orchestrator_${role}_sha_mismatch`);
    if (status.length !== 0) fail(`orchestrator_${role}_worktree_dirty`);
  }
}

async function buildDesktop(context) {
  context.apiVerifierBinary = resolve(context.binRoot, "verify-feat126-s10-e2e");
  await runCommand(
    "api_verifier_build",
    "go",
    [
      "build",
      "-trimpath",
      "-o",
      context.apiVerifierBinary,
      "./cmd/verify-feat126-s10-e2e",
    ],
    {
      cwd: REPOSITORIES.api,
      env: commandEnvironment({ GOCACHE: resolve(context.runRoot, "go-build-cache") }),
      timeout: 30 * 60_000,
      signal: context.parentSignal,
    },
  );
  context.apiVerifierBinarySha256 = await hashFile(context.apiVerifierBinary);
  await runCommand("desktop_frontend_typecheck", "pnpm", ["exec", "vue-tsc", "--noEmit"], {
    cwd: DESKTOP_ROOT,
    env: commandEnvironment({ VITE_FEAT126_S10_DRIVER: "true" }),
    signal: context.parentSignal,
  });
  await runCommand("desktop_frontend_build", "pnpm", [
    "exec",
    "vite",
    "build",
    "--outDir",
    context.frontendDistRoot,
    "--emptyOutDir",
  ], {
    cwd: DESKTOP_ROOT,
    env: commandEnvironment({ VITE_FEAT126_S10_DRIVER: "true" }),
    signal: context.parentSignal,
  });
  const tauriConfig = JSON.stringify({ build: { frontendDist: context.frontendDistRoot } });
  await runCommand(
    "desktop_feature_build",
    "cargo",
    [
      "build",
      "--locked",
      "--release",
      "--manifest-path",
      resolve(DESKTOP_ROOT, "src-tauri/Cargo.toml"),
      "--features",
      "feat126-s10-driver",
    ],
    {
      cwd: DESKTOP_ROOT,
      env: commandEnvironment({
        CARGO_TARGET_DIR: context.cargoTargetRoot,
        TAURI_CONFIG: tauriConfig,
      }),
      timeout: 30 * 60_000,
      signal: context.parentSignal,
    },
  );
  await verifyRepositoryAuthority(context.repositories, context.parentSignal);
  return resolve(context.cargoTargetRoot, "release/yijie-desktop");
}

async function startDependencies(context) {
  const arguments_ = buildPrevalidatedDependencyArguments(context.runId, context.secretsPath);
  context.composeAttempted = true;
  context.composeCleanupRequired = true;
  await runCommand("dependencies", "docker", arguments_, {
    env: commandEnvironment({ FEAT126_S10_RUN_ID: context.runId }),
    timeout: 10 * 60_000,
    signal: context.parentSignal,
  });
  context.composeStarted = true;
  context.composeLogsRequired = true;
}

export async function runApiVerifierProjection(context, runner = runCommand) {
  if (
    context?.apiVerifierBinary !== resolve(context?.binRoot ?? "", "verify-feat126-s10-e2e") ||
    context?.apiRuntimeEnvironment === null || Array.isArray(context?.apiRuntimeEnvironment) ||
    typeof context?.apiRuntimeEnvironment !== "object"
  ) fail("orchestrator_api_projection_invalid");
  let metadata;
  let digest;
  try {
    metadata = await lstat(context.apiVerifierBinary);
    digest = await hashFile(context.apiVerifierBinary);
  } catch {
    fail("orchestrator_api_projection_invalid");
  }
  if (
    !metadata.isFile() || metadata.isSymbolicLink() || !ownedByCurrentUser(metadata) ||
    metadata.nlink !== 1 || digest !== context.apiVerifierBinarySha256 ||
    (await realpath(context.apiVerifierBinary)) !== context.apiVerifierBinary
  ) fail("orchestrator_api_projection_invalid");
  const output = await runner(
    "api_verifier",
    context.apiVerifierBinary,
    ["--profile", "feat-126-s10-local-lab", "--run-id", context.runId],
    {
      cwd: REPOSITORIES.api,
      env: context.apiRuntimeEnvironment,
      maxBuffer: 64 * 1024,
      timeout: 30_000,
      signal: context.parentSignal,
    },
  );
  if (
    typeof output !== "string" || output.length === 0 || output.length > 64 * 1024 ||
    output.includes("\0") || output.includes("\r") || !output.endsWith("\n") ||
    output.slice(0, -1).includes("\n")
  ) fail("orchestrator_api_projection_invalid");
  let value;
  try {
    value = JSON.parse(output);
  } catch {
    fail("orchestrator_api_projection_invalid");
  }
  validateApiVerifierProjection(value, context.runId);
  return Object.freeze(value);
}

async function startApi(context) {
  const binary = resolve(context.binRoot, "yijie-api");
  let snapshot;
  let apiEnvironment;
  try {
    snapshot = await inspectApiBinary(binary);
    if (snapshot.sha256 !== context.summary.api_binary_sha256) fail("orchestrator_api_binary_invalid");
    apiEnvironment = buildApiRuntimeEnvironment({
      authority: readApiRuntimeAuthorityFromPreflightSummary(context.summary, context.runId),
      databasePassword: context.secrets.get("FEAT126_S10_API_DB_PASSWORD"),
      localCaPemPath: context.caPath,
      localCaSha256: context.caSha256,
    });
  } catch (error) {
    if (error instanceof S10BO1OrchestratorError) throw error;
    fail("orchestrator_api_authority_invalid");
  }
  context.processes.api = await spawnOwnedProcess({
    role: "api",
    binary,
    cwd: INFRA_ROOT,
    environment: apiEnvironment,
    logPath: resolve(context.logRoot, "api-orchestrator.log"),
  }, context);
  await waitForHttpReadiness(context.processes.api.child, "api", "/healthz", "ok");
  await waitForHttpReadiness(context.processes.api.child, "api", "/readyz", "ready");
  context.apiRuntimeEnvironment = apiEnvironment;
  context.apiVerifierBefore = await runApiVerifierProjection(context);
  await writeSecureJson(
    resolve(context.evidenceRoot, "api-verifier-before.v1.json"),
    context.apiVerifierBefore,
  );
}

async function startFake(context) {
  const binary = resolve(context.binRoot, "feat126-fake-responses");
  context.processes.fake = await spawnOwnedProcess({
    role: "fake",
    binary,
    cwd: INFRA_ROOT,
    environment: commandEnvironment({
      YIJIE_FEAT126_S10_TEST_PROFILE_ENABLED: "true",
      YIJIE_FEAT126_S10_RUN_ID: context.runId,
      YIJIE_FEAT126_FAKE_RESPONSES_MODE: "complete",
      YIJIE_FEAT126_S10_FAKE_GENERATION: "1",
      YIJIE_FEAT126_FAKE_RESPONSES_MAX_CALLS: "1",
    }),
    logPath: resolve(context.logRoot, "fake-orchestrator.log"),
  }, context);
  for (let attempt = 0; attempt < 40; attempt += 1) {
    if (context.processes.fake.child.exitCode !== null) fail("orchestrator_fake_exited_early");
    const result = spawnSync(resolve(context.binRoot, "feat126-fake-readiness"), [], {
      cwd: INFRA_ROOT,
      env: commandEnvironment({
        YIJIE_FEAT126_S10_TEST_PROFILE_ENABLED: "true",
        YIJIE_FEAT126_S10_RUN_ID: context.runId,
      }),
      encoding: "utf8",
      shell: false,
      windowsHide: true,
      maxBuffer: 4096,
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 2_000,
    });
    if (!result.error && result.status === 0) {
      let value;
      try {
        value = JSON.parse(result.stdout);
        validateProbeResult(value, context.runId);
      } catch {
        fail("orchestrator_fake_authority_invalid");
      }
      context.fakeAuthorityBefore = await probeClosedFakeAuthority(context);
      await writeSecureJson(
        resolve(context.evidenceRoot, "fake-authority-before.v1.json"),
        context.fakeAuthorityBefore,
      );
      return;
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  fail("orchestrator_fake_not_ready");
}

async function probeClosedFakeAuthority(context, requireZero = true) {
  const value = await new Promise((resolveProbe, rejectProbe) => {
    const request = http.get(
      {
        hostname: "127.0.0.1",
        port: 18082,
        path: "/healthz/v2",
        timeout: 1000,
        agent: false,
        headers: {
          Accept: "application/json",
          "X-Yijie-Feat126-Run-Id": context.runId,
          "X-Yijie-Feat126-Fixture-Id": context.summary.fake_readiness.fixture_case_id,
        },
      },
      (response) => {
        let body = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => {
          body += chunk;
          if (body.length > 4096) request.destroy(new Error("capacity"));
        });
        response.on("end", () => {
          try {
            if (response.statusCode !== 200) throw new Error("not ready");
            resolveProbe(JSON.parse(body));
          } catch (error) {
            rejectProbe(error);
          }
        });
      },
    );
    request.on("timeout", () => request.destroy(new Error("timeout")));
    request.on("error", rejectProbe);
  }).catch(() => fail("orchestrator_fake_authority_invalid"));
  return validateClosedFakeAuthorityProjection(value, context, requireZero);
}

export function buildBusinessBoundaryEvidence(before, after, fake, runId) {
  if (before === null && after === null && fake === null) {
    return validateBusinessBoundaryEvidence({
      schema_version: 1,
      status: "passed",
      scope: "not_started",
      run_id: runId,
      api_before_sha256: null,
      api_after_sha256: null,
      fake_accepted_calls: null,
      fake_rejected_calls: null,
      s10b_r8_executed: false,
    }, runId);
  }
  validateApiVerifierProjection(before, runId);
  validateApiVerifierProjection(after, runId);
  const value = {
    schema_version: 1,
    status: "passed",
    scope: fake === null ? "api_only" : "api_and_fake",
    run_id: runId,
    api_before_sha256: before.canonical_hash,
    api_after_sha256: after.canonical_hash,
    fake_accepted_calls: fake?.accepted_calls ?? null,
    fake_rejected_calls: fake?.rejected_calls ?? null,
    s10b_r8_executed: false,
  };
  return validateBusinessBoundaryEvidence(value, runId);
}

async function verifyBusinessBoundary(context) {
  const apiStarted = Boolean(context.processes?.api);
  const fakeStarted = Boolean(context.processes?.fake);
  if (!apiStarted && !fakeStarted) {
    context.businessBoundary = buildBusinessBoundaryEvidence(null, null, null, context.runId);
    return context.businessBoundary;
  }
  if (!apiStarted || !context.apiVerifierBefore) fail("orchestrator_business_boundary_unknown");
  const after = await runApiVerifierProjection(context);
  await writeSecureJson(resolve(context.evidenceRoot, "api-verifier-after.v1.json"), after);
  let fake = null;
  if (fakeStarted) {
    if (!context.fakeAuthorityBefore) fail("orchestrator_business_boundary_unknown");
    fake = await probeClosedFakeAuthority(context, false);
    await writeSecureJson(resolve(context.evidenceRoot, "fake-authority-after.v1.json"), fake);
  }
  context.businessBoundary = buildBusinessBoundaryEvidence(
    context.apiVerifierBefore,
    after,
    fake,
    context.runId,
  );
  await writeSecureJson(
    resolve(context.evidenceRoot, "business-boundary.v1.json"),
    context.businessBoundary,
  );
  return context.businessBoundary;
}

function desktopEnvironment(context) {
  const issuer = "https://localhost:8443/realms/yijie-local";
  const oidc = `${issuer}/protocol/openid-connect`;
  return commandEnvironment({
    YIJIE_ENV: "local",
    YIJIE_FEAT126_S10_TEST_PROFILE_ENABLED: "true",
    YIJIE_FEAT126_S10_DRIVER_ENABLED: "true",
    YIJIE_FEAT126_S10_DRIVER_NONCE: context.nonce,
    YIJIE_FEAT126_S10_RUN_ID: context.runId,
    YIJIE_FEAT126_S10_RUN_ROOT: context.runRoot,
    YIJIE_FEAT126_S10P3_REAL_MAIN_CHAIN: "true",
    YIJIE_FEAT126_S10_SECURE_STORAGE_ENABLED: "true",
    YIJIE_FEAT126_S10_EPHEMERAL_SECRET_BACKEND_ENABLED: "true",
    YIJIE_FEAT126_S10_INFRA_SECRETS_PATH: context.secretsPath,
    YIJIE_FEAT126_FAKE_RESPONSES_BASE_URL: "http://127.0.0.1:18082/v1",
    YIJIE_CHAT_LOCAL_ENABLED: "true",
    YIJIE_CHAT_LOCAL_HOST_ENABLED: "true",
    YIJIE_CHAT_LOCAL_OWNER_USER_ID: "12500000-0000-4000-8000-000000000001",
    YIJIE_CHAT_LOCAL_TENANT_ID: "12500000-0000-4000-8000-100000000001",
    YIJIE_AGENT_HOST_BINARY: resolve(context.binRoot, "yijie-agent-host"),
    YIJIE_AGENT_HOST_HOME: resolve(context.runRoot, "host-home"),
    YIJIE_AGENT_HOST_PORT: "18081",
    YIJIE_CODEX_BINARY: resolve(RUNTIME_ROOT, ".yijie/build/macos/aarch64-apple-darwin/codex"),
    YIJIE_CODEX_MANIFEST: resolve(RUNTIME_ROOT, ".yijie/build/macos/aarch64-apple-darwin/runtime-manifest.json"),
    YIJIE_CODEX_HOME: resolve(context.runRoot, "codex-home"),
    YIJIE_DESKTOP_NATIVE_AUTH_ENABLED: "true",
    YIJIE_DESKTOP_AUTH_ENVIRONMENT: "local-integration",
    YIJIE_DESKTOP_OIDC_ISSUER: issuer,
    YIJIE_DESKTOP_OIDC_AUTHORIZATION_ENDPOINT: `${oidc}/auth`,
    YIJIE_DESKTOP_OIDC_TOKEN_ENDPOINT: `${oidc}/token`,
    YIJIE_DESKTOP_OIDC_JWKS_URI: `${oidc}/certs`,
    YIJIE_DESKTOP_OIDC_REVOCATION_ENDPOINT: `${oidc}/revoke`,
    YIJIE_DESKTOP_OIDC_CLIENT_ID: "yijie-desktop-feat-125-local",
    YIJIE_DESKTOP_API_ORIGIN: "https://localhost:9443/",
    YIJIE_DESKTOP_LOCAL_CA_PEM_PATH: context.caPath,
    YIJIE_DESKTOP_LOCAL_CA_SHA256: context.caSha256,
  });
}

async function startDesktop(context) {
  context.processes.desktop = await spawnOwnedProcess({
    role: "desktop",
    binary: context.desktopBinary,
    cwd: DESKTOP_ROOT,
    environment: desktopEnvironment(context),
    logPath: resolve(context.logRoot, "desktop-orchestrator.log"),
    extraStdio: ["pipe", "pipe"],
  }, context);
  context.controlWriter = context.processes.desktop.child.stdio[3];
  guardControlWriter(context.controlWriter);
  context.controlWriter.on("error", () => { context.cleanupUnknown = true; });
  context.controlReader = createControlFrameReader(context.processes.desktop.child.stdio[4], context);
}

async function readDesktopFrame(context, expectedKind) {
  const readers = [
    context.controlReader.next(expectedKind),
    childExit(context.processes.api.child, "api"),
    childExit(context.processes.fake.child, "fake"),
    childExit(context.processes.desktop.child, "desktop"),
  ];
  return await Promise.race(readers);
}

export async function sendAbort(context) {
  const bytes = encodeControlFrame({
    schema_version: 1,
    run_id: context.runId,
    nonce: context.nonce,
    sequence: 1,
    kind: "abort",
  }, {
    runId: context.runId,
    nonce: context.nonce,
    previousSequence: 0,
    allowedKinds: INFRA_CONTROL_KINDS,
  });
  await writeFrame(context.controlWriter, bytes);
  await closeControlWriter(context.controlWriter);
}

async function readHostProcessEvidence(context, expectedState, previousEvidence) {
  const hostRoot = resolve(context.runRoot, "host");
  await requireOwnerDirectory(hostRoot);
  let entries;
  try {
    entries = await readdir(hostRoot, { withFileTypes: true });
  } catch {
    fail("orchestrator_host_evidence_invalid");
  }
  if (entries.length !== 1 || !entries[0].isDirectory() || entries[0].isSymbolicLink()) {
    fail("orchestrator_host_evidence_invalid");
  }
  const evidenceDirectory = resolve(hostRoot, entries[0].name);
  await requireOwnerDirectory(evidenceDirectory);
  const bytes = await readSecureFile(resolve(evidenceDirectory, "process.json"), 16 * 1024);
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail("orchestrator_host_evidence_invalid");
  }
  let binarySha256;
  try {
    binarySha256 = await hashFile(resolve(context.binRoot, "yijie-agent-host"));
  } catch {
    fail("orchestrator_host_evidence_invalid");
  }
  const evidence = validateHostProcessEvidence(value, {
    runId: context.runId,
    desktopPid: context.processes.desktop.record.pid,
    binarySha256,
    expectedState,
    expectedPid: previousEvidence?.pid,
    expectedNonce: previousEvidence?.instanceNonce,
    expectedStartedAtUnixMs: previousEvidence?.startedAtUnixMs,
  });
  if (entries[0].name !== evidence.instanceNonce) fail("orchestrator_host_evidence_invalid");
  return evidence;
}

async function requestRuntimeEvidence(context, hostEvidence) {
  const value = await new Promise((resolveEvidence, rejectEvidence) => {
    const request = http.get(
      {
        hostname: "127.0.0.1",
        port: 18081,
        path: "/v1/feat126/runtime-evidence",
        timeout: 1000,
        agent: false,
        headers: {
          Accept: "application/json",
          "X-Yijie-Feat126-Run-Id": context.runId,
          "X-Yijie-Feat126-Nonce": hostEvidence.instanceNonce,
        },
      },
      (response) => {
        let body = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => {
          body += chunk;
          if (body.length > 16 * 1024) request.destroy(new Error("capacity"));
        });
        response.on("end", () => {
          try {
            if (response.statusCode !== 200) throw new Error("evidence unavailable");
            resolveEvidence(JSON.parse(body));
          } catch (error) {
            rejectEvidence(error);
          }
        });
      },
    );
    request.on("timeout", () => request.destroy(new Error("timeout")));
    request.on("error", rejectEvidence);
  }).catch(() => fail("orchestrator_runtime_evidence_invalid"));
  let binarySha256;
  let manifestSha256;
  try {
    binarySha256 = await hashFile(resolve(RUNTIME_ROOT, ".yijie/build/macos/aarch64-apple-darwin/codex"));
    manifestSha256 = await hashFile(resolve(RUNTIME_ROOT, ".yijie/build/macos/aarch64-apple-darwin/runtime-manifest.json"));
  } catch {
    fail("orchestrator_runtime_evidence_invalid");
  }
  return validateRuntimeProcessEvidence(value, {
    runId: context.runId,
    hostPid: hostEvidence.pid,
    binarySha256,
    manifestSha256,
    nonce: hostEvidence.instanceNonce,
    profile: "feat-126-s10-local-lab",
  });
}

async function readOwnershipEvidence(context) {
  const hostEvidence = await readHostProcessEvidence(context, "ready");
  const runtimeEvidence = await requestRuntimeEvidence(context, hostEvidence);
  const hostIdentity = await inspectProcessIdentity(hostEvidence.pid);
  const runtimeIdentity = await inspectProcessIdentity(runtimeEvidence.pid);
  if (
    hostIdentity === null || hostIdentity.ppid !== context.processes.desktop.record.pid ||
    hostIdentity.binary_sha256 !== hostEvidence.binarySha256 ||
    runtimeIdentity === null || runtimeIdentity.ppid !== hostEvidence.pid ||
    runtimeIdentity.binary_sha256 !== runtimeEvidence.binary_sha256
  ) {
    fail("orchestrator_ownership_invalid");
  }
  const hostRecord = validateProcessRecord({
    schema_version: 1,
    run_id: context.runId,
    role: "host",
    pid: hostEvidence.pid,
    ppid: hostEvidence.ppid,
    binary_sha256: hostEvidence.binarySha256,
    start_identity: hostIdentity.start_identity,
  }, context.runId, "host");
  const runtimeRecord = validateProcessRecord({
    schema_version: 1,
    run_id: context.runId,
    role: "runtime",
    pid: runtimeEvidence.pid,
    ppid: runtimeEvidence.ppid,
    binary_sha256: runtimeEvidence.binary_sha256,
    start_identity: runtimeIdentity.start_identity,
  }, context.runId, "runtime");
  await writeSecureJson(resolve(context.evidenceRoot, "host-evidence.v1.json"), hostEvidence);
  await writeSecureJson(resolve(context.evidenceRoot, "runtime-evidence.v1.json"), runtimeEvidence);
  await writeSecureJson(resolve(context.evidenceRoot, "host-process.v1.json"), hostRecord);
  await writeSecureJson(resolve(context.evidenceRoot, "runtime-process.v1.json"), runtimeRecord);
  context.hostEvidence = hostEvidence;
  context.runtimeEvidence = runtimeEvidence;
  context.descendantProcesses = { host: hostRecord, runtime: runtimeRecord };
  const infraChildren = ["api", "fake", "desktop"].filter((role) => context.processes[role]);
  return {
    infra: { children: infraChildren },
    desktop: { children: hostRecord.role === "host" ? ["host"] : [] },
    host: { children: runtimeRecord.role === "runtime" ? ["runtime"] : [] },
  };
}

async function waitForDesktopExit(context) {
  const child = context.processes.desktop.child;
  if (child.exitCode !== null || child.signalCode !== null) {
    if (child.exitCode !== 0) fail("orchestrator_desktop_exit_invalid");
    return;
  }
  const result = await withTimeout(
    new Promise((resolveExit, rejectExit) => {
      child.once("error", () => rejectExit(new S10BO1OrchestratorError("orchestrator_desktop_process_failed")));
      child.once("exit", (code, signal) => resolveExit({ code, signal }));
    }),
    PROCESS_STOP_TIMEOUT_MS,
    "orchestrator_desktop_exit_timeout",
  );
  if (result.code !== 0 || result.signal !== null) fail("orchestrator_desktop_exit_invalid");
}

async function listInspectableFiles(root, required, excludedDirectories = new Set()) {
  const found = [];
  async function visit(directory) {
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      fail("orchestrator_no_log_invalid");
    }
    for (const entry of entries) {
      const path = resolve(directory, entry.name);
      if (entry.isSymbolicLink()) fail("orchestrator_no_log_invalid");
      if (entry.isDirectory()) {
        if (!excludedDirectories.has(entry.name)) await visit(path);
      } else if (entry.isFile()) found.push(path);
    }
  }
  let exists = true;
  try {
    await lstat(root);
  } catch (error) {
    if (error?.code === "ENOENT") exists = false;
    else fail("orchestrator_no_log_invalid");
  }
  if (!exists) {
    if (required) fail("orchestrator_no_log_invalid");
    return found;
  }
  try {
    await requireOwnerDirectory(root);
  } catch {
    fail("orchestrator_no_log_invalid");
  }
  await visit(root);
  return found.sort();
}

function noLogPatternSet(context) {
  const literalPatterns = [
    ...[...context.secrets.entries()].map(([name, value]) => ({
      name: `secret:${name}`,
      value,
    })),
    { name: "synthetic_owner", value: SYNTHETIC_OWNER_ID },
    { name: "synthetic_tenant", value: SYNTHETIC_TENANT_ID },
    { name: "run_root", value: context.runRoot },
    { name: "workspace_root", value: WORKSPACE_ROOT },
  ].filter(({ value }) => typeof value === "string" && value.length > 0);
  const forbiddenPatterns = Object.freeze([
    ["bearer", /\bbearer\b/i],
    ["credential", /\bcredentials?\b/i],
    ["dsn", /\b(?:postgres(?:ql)?|redis):\/\//i],
    ["private_key", /private[\s_-]*key/i],
    ["sensitive_field", /["']?(?:argv|bearer|dsn|env|path|payload|secret)["']?\s*:/i],
  ]);
  return Object.freeze({ literalPatterns, forbiddenPatterns });
}

function scanNoLogBuffer(content, literalPatterns, forbiddenPatterns) {
  const value = Buffer.from(content).toString("utf8");
  let hitCount = 0;
  const folded = value.toLocaleLowerCase("en-US");
  for (const { value: pattern } of literalPatterns) {
    if (folded.includes(pattern.toLocaleLowerCase("en-US"))) hitCount += 1;
  }
  for (const [, pattern] of forbiddenPatterns) {
    if (pattern.test(value)) hitCount += 1;
  }
  return Object.freeze({
    rowCount: value.split("\n").filter(Boolean).length,
    hitCount,
  });
}

async function scanNoLogFiles(files, literalPatterns, forbiddenPatterns) {
  let rowCount = 0;
  let hitCount = 0;
  for (const path of files) {
    let content;
    try {
      content = await readSecureFile(path, CHILD_OUTPUT_MAX_BYTES, [0o600], 0);
    } catch {
      fail("orchestrator_no_log_invalid");
    }
    const scan = scanNoLogBuffer(content, literalPatterns, forbiddenPatterns);
    rowCount += scan.rowCount;
    hitCount += scan.hitCount;
  }
  return Object.freeze({ rowCount, hitCount });
}

export async function captureRuntimeLogScan(context, operations = {}) {
  if (
    !context?.composeLogsRequired || !RUN_ID_PATTERN.test(context.runId ?? "") ||
    !(context.secrets instanceof Map)
  ) fail("orchestrator_no_log_invalid");
  const project = projectName(context.runId);
  const list = operations.list ?? (async () => await dockerList([
    "ps",
    "-aq",
    "--filter",
    `label=com.docker.compose.project=${project}`,
  ]));
  const readLogs = operations.readLogs ?? (async (containerId) => await runCommand(
    "container_logs",
    "docker",
    ["logs", containerId],
    { captureAllOutput: true, maxBuffer: CHILD_OUTPUT_MAX_BYTES, timeout: 30_000 },
  ));
  let containerIds;
  try {
    containerIds = [...new Set(await list())].sort();
  } catch {
    fail("orchestrator_no_log_invalid");
  }
  if (
    containerIds.length === 0 ||
    containerIds.some((value) => !/^[0-9a-f]{12,64}$/.test(value ?? ""))
  ) fail("orchestrator_no_log_invalid");
  const { literalPatterns, forbiddenPatterns } = noLogPatternSet(context);
  let rowCount = 0;
  let hitCount = 0;
  for (const containerId of containerIds) {
    let content;
    try {
      content = await readLogs(containerId);
    } catch {
      fail("orchestrator_no_log_invalid");
    }
    if (!Buffer.isBuffer(content) || content.length > CHILD_OUTPUT_MAX_BYTES) {
      fail("orchestrator_no_log_invalid");
    }
    const scan = scanNoLogBuffer(content, literalPatterns, forbiddenPatterns);
    rowCount += scan.rowCount;
    hitCount += scan.hitCount;
  }
  return validateRuntimeLogScan({
    schema_version: 1,
    status: hitCount === 0 ? "passed" : "failed",
    run_id: context.runId,
    source_count: containerIds.length,
    row_count: rowCount,
    hit_count: hitCount,
    source_set_sha256: sha256(containerIds.join("\n")),
  }, context.runId);
}

export async function scanNoLog(context) {
  if (!context?.runRoot || !(context.secrets instanceof Map) || !context.attempt?.markerPath) {
    fail("orchestrator_no_log_invalid");
  }
  const { literalPatterns, forbiddenPatterns } = noLogPatternSet(context);
  if (context.runRootPresent === false) {
    if (
      context.phase !== "preflight_failed" || context.composeAttempted !== false ||
      context.composeCleanupRequired !== false ||
      Object.keys(context.processes ?? {}).length !== 0 ||
      Object.keys(context.descendantProcesses ?? {}).length !== 0 ||
      !sameStringSet(context.retainedVolumeNames, [])
    ) {
      fail("orchestrator_no_log_invalid");
    }
    try {
      await lstat(context.runRoot);
      fail("orchestrator_no_log_invalid");
    } catch (error) {
      if (error instanceof S10BO1OrchestratorError || error?.code !== "ENOENT") {
        fail("orchestrator_no_log_invalid");
      }
    }
    const hasPreclaim = typeof context.attempt.preclaimPath === "string";
    const files = [
      ...(hasPreclaim ? [context.attempt.preclaimPath] : []),
      context.attempt.markerPath,
      ...(context.attemptFailure ? [context.attempt.failurePath] : []),
      ...(context.attemptClosure ? [context.attempt.closurePath] : []),
    ].sort();
    const scan = await scanNoLogFiles(files, literalPatterns, forbiddenPatterns);
    let coverage;
    if (context.attemptClosure) {
      coverage = hasPreclaim ? "preclaim_attempt_ledger" : "attempt_ledger";
    } else if (context.attemptFailure) {
      coverage = hasPreclaim ? "preclaim_marker_and_failure" : "attempt_marker_and_failure";
    } else {
      coverage = hasPreclaim ? "preclaim_and_marker" : "attempt_marker_only";
    }
    return Object.freeze({
      schema_version: 1,
      scope: "attempt_only",
      coverage,
      file_count: files.length,
      row_count: scan.rowCount,
      hit_count: scan.hitCount,
      external_source_count: 0,
      external_row_count: 0,
      external_source_set_sha256: sha256(""),
      pattern_set_sha256: sha256([
        ...literalPatterns.map(({ name }) => name),
        ...forbiddenPatterns.map(([name]) => name),
      ].sort().join("\n")),
    });
  }
  if (
    context.logRoot !== resolve(context.runRoot, "logs") ||
    context.evidenceRoot !== resolve(context.runRoot, "orchestrator-evidence") ||
    context.preflightEvidenceRoot !== resolve(context.runRoot, "preflight-evidence")
  ) {
    fail("orchestrator_no_log_invalid");
  }
  const scanRoots = [
    [context.logRoot, true],
    [context.evidenceRoot, true],
    [context.preflightEvidenceRoot, true],
    [resolve(context.runRoot, "bootstrap-evidence"), false],
    [resolve(context.runRoot, "host"), false],
    [resolve(context.runRoot, "host-home"), false],
    [resolve(context.runRoot, "codex-home"), false],
    [resolve(context.runRoot, "secure-storage"), false, new Set(["ephemeral-secrets"])],
  ];
  let files;
  try {
    await requireOwnerDirectory(context.runRoot);
    files = [...new Set([
      ...(await Promise.all(
        scanRoots.map(([root, required, excluded]) => listInspectableFiles(root, required, excluded)),
      )).flat(),
      ...(typeof context.attempt.preclaimPath === "string" ? [context.attempt.preclaimPath] : []),
      context.attempt.markerPath,
      ...(context.attemptFailure ? [context.attempt.failurePath] : []),
      ...(context.attemptClosure ? [context.attempt.closurePath] : []),
      ...(context.phase === "preflight_failed" ? [resolve(context.runRoot, "REJECTED")] : []),
    ])].sort();
  } catch {
    fail("orchestrator_no_log_invalid");
  }
  const requiredFiles = new Set([
    ...(typeof context.attempt.preclaimPath === "string" ? [context.attempt.preclaimPath] : []),
    context.attempt.markerPath,
  ]);
  if (context.phase === "preflight_failed") {
    requiredFiles.add(resolve(context.preflightEvidenceRoot, PREFLIGHT_FAILURE_EVIDENCE_FILE));
    requiredFiles.add(context.attempt.failurePath);
    requiredFiles.add(resolve(context.runRoot, "REJECTED"));
  } else {
    requiredFiles.add(resolve(context.preflightEvidenceRoot, "summary.json"));
  }
  for (const [role, process_] of Object.entries(context.processes ?? {})) {
    if (process_.logPath) requiredFiles.add(process_.logPath);
    if (process_.record) requiredFiles.add(resolve(context.evidenceRoot, `${role}-process.v1.json`));
  }
  for (const role of Object.keys(context.descendantProcesses ?? {})) {
    requiredFiles.add(resolve(context.evidenceRoot, `${role}-process.v1.json`));
  }
  if (context.hostEvidence) {
    for (const name of [
      "host-evidence.v1.json",
      "host-stopped-evidence.v1.json",
      "runtime-evidence.v1.json",
    ]) requiredFiles.add(resolve(context.evidenceRoot, name));
    const hostInstance = resolve(context.runRoot, "host", context.hostEvidence.instanceNonce);
    for (const name of ["process.json", "stderr.log", "stdout.log"]) {
      requiredFiles.add(resolve(hostInstance, name));
    }
  }
  const preflightOnly = ["preflight_failed", "preflight_context_invalid"].includes(context.phase);
  let runtimeLogScan = context.runtimeLogScan;
  if (!preflightOnly && !runtimeLogScan) {
    try {
      runtimeLogScan = validateRuntimeLogScan(
        JSON.parse((await readSecureFile(
          resolve(context.evidenceRoot, "runtime-log-scan.v1.json"),
          4096,
        )).toString("utf8")),
        context.runId,
      );
    } catch {
      fail("orchestrator_no_log_invalid");
    }
  }
  if (!preflightOnly) requiredFiles.add(resolve(context.evidenceRoot, "runtime-log-scan.v1.json"));
  if (context.apiVerifierBefore) {
    for (const name of [
      "api-verifier-before.v1.json",
      "api-verifier-after.v1.json",
      "business-boundary.v1.json",
    ]) requiredFiles.add(resolve(context.evidenceRoot, name));
    if (context.fakeAuthorityBefore) {
      requiredFiles.add(resolve(context.evidenceRoot, "fake-authority-before.v1.json"));
      requiredFiles.add(resolve(context.evidenceRoot, "fake-authority-after.v1.json"));
    }
  }
  if ([...requiredFiles].some((path) => !files.includes(path))) {
    fail("orchestrator_no_log_invalid");
  }
  const scan = await scanNoLogFiles(files, literalPatterns, forbiddenPatterns);
  return Object.freeze({
    schema_version: 1,
    scope: preflightOnly ? "preflight_artifacts" : "run_artifacts",
    coverage: preflightOnly
      ? "all_preflight_log_and_evidence_sources"
      : "all_run_log_and_evidence_sources",
    file_count: files.length,
    row_count: scan.rowCount + (runtimeLogScan?.row_count ?? 0),
    hit_count: scan.hitCount + (runtimeLogScan?.hit_count ?? 0),
    external_source_count: runtimeLogScan?.source_count ?? 0,
    external_row_count: runtimeLogScan?.row_count ?? 0,
    external_source_set_sha256: runtimeLogScan?.source_set_sha256 ?? sha256(""),
    pattern_set_sha256: sha256([
      ...literalPatterns.map(({ name }) => name),
      ...forbiddenPatterns.map(([name]) => name),
    ].sort().join("\n")),
  });
}

async function dockerList(arguments_) {
  const output = await runCommand(
    "cleanup_inventory",
    "docker",
    arguments_,
    { maxBuffer: 1024 * 1024 },
  );
  return output.split("\n").map((value) => value.trim()).filter(Boolean);
}

async function dockerCount(arguments_) {
  return (await dockerList(arguments_)).length;
}

async function cleanupLiveContext(context) {
  let cleanupUnknown = context.cleanupUnknown;
  if (context.composeLogsRequired) {
    try {
      context.runtimeLogScan = await captureRuntimeLogScan(context);
      await writeSecureJson(
        resolve(context.evidenceRoot, "runtime-log-scan.v1.json"),
        context.runtimeLogScan,
      );
    } catch {
      context.runtimeLogScanUnknown = true;
    }
  }
  try {
    await closeControlWriter(context.controlWriter);
  } catch {
    cleanupUnknown = true;
  }
  context.controlReader?.destroy();
  const outcomes = [];
  for (const role of ["desktop", "fake", "api"]) {
    if (!context.processes[role]) continue;
    try {
      outcomes.push(await stopOwnedProcess(context.processes[role]));
    } catch {
      outcomes.push("unknown");
    }
  }
  cleanupUnknown ||= outcomes.includes("unknown") || outcomes.includes("foreign_identity_preserved");

  if (context.processes.desktop && !context.descendantProcesses) cleanupUnknown = true;
  if (context.hostEvidence) {
    try {
      const stoppedHostEvidence = await readHostProcessEvidence(
        context,
        "stopped",
        context.hostEvidence,
      );
      await writeSecureJson(
        resolve(context.evidenceRoot, "host-stopped-evidence.v1.json"),
        stoppedHostEvidence,
      );
      context.hostStoppedEvidence = stoppedHostEvidence;
    } catch {
      cleanupUnknown = true;
    }
  }

  if (shouldRunComposeCleanup(context)) {
    try {
      await runCommand(
        "cleanup",
        "make",
        ["--silent", "--no-print-directory", "feat-126-s10-stop", `RUN_ID=${context.runId}`],
        { timeout: 10 * 60_000 },
      );
      context.composeStarted = false;
      context.composeCleanupRequired = false;
    } catch {
      cleanupUnknown = true;
    }
  }

  const processRecords = [
    ...Object.values(context.processes).map((process_) => process_.record).filter(Boolean),
    ...Object.values(context.descendantProcesses ?? {}),
  ];
  if (processRecords.length !== Object.keys(context.processes).length +
    Object.keys(context.descendantProcesses ?? {}).length) cleanupUnknown = true;
  const processAssessment = await assessProcessCleanup(processRecords, inspectProcessIdentity);
  cleanupUnknown ||= processAssessment.identityUnknown;

  let listenerInspections = [];
  for (let attempt = 0; attempt < 50; attempt += 1) {
    listenerInspections = await Promise.all(FIXED_PORTS.map(inspectListener));
    if (listenerInspections.every((entry) => !entry.listening && !entry.unknown)) break;
    if (attempt === 49) break;
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  const listeners = listenerInspections.filter((entry) => entry.listening).length;
  cleanupUnknown ||= listenerInspections.some((entry) => entry.unknown);

  const project = projectName(context.runId);
  const containers = await dockerCount(["ps", "-aq", "--filter", `label=com.docker.compose.project=${project}`]);
  const networks = await dockerCount(["network", "ls", "-q", "--filter", `label=com.docker.compose.project=${project}`]);
  const volumeNames = await projectVolumeNames(context.runId);
  const volumes = classifyProjectVolumes(project, volumeNames);
  const namedVolumesPreserved = sameStringSet(volumeNames, context.retainedVolumeNames);
  if (cleanupUnknown) fail("orchestrator_cleanup_unknown");
  const cleanupScope = context.runRootPresent === false
    ? "pre_run_absence"
    : ["preflight_failed", "preflight_context_invalid"].includes(context.phase)
      ? "preflight_artifacts"
      : "run_artifacts";
  return Object.freeze({
    schema_version: 1,
    scope: cleanupScope,
    status: containers === 0 && networks === 0 && processAssessment.processes === 0 &&
      listeners === 0 && namedVolumesPreserved && volumes.temporaryVolumes === 0
      ? "passed"
      : "failed",
    containers,
    networks,
    processes: processAssessment.processes,
    listeners,
    temporary_volumes: volumes.temporaryVolumes,
    named_volume_baseline_count: context.retainedVolumeNames.length,
    named_volume_after_count: volumeNames.length,
    named_volumes_preserved: namedVolumesPreserved,
    prune_executed: false,
    volume_delete_executed: false,
  });
}

export function validateFreshResourceInventory(value) {
  if (
    value === null || Array.isArray(value) || typeof value !== "object" ||
    !exactKeys(value, ["containers", "listeners", "networks", "volume_names"]) ||
    !Number.isSafeInteger(value.containers) || value.containers < 0 ||
    !Number.isSafeInteger(value.networks) || value.networks < 0 ||
    !Array.isArray(value.volume_names) || value.volume_names.some((name) => typeof name !== "string") ||
    !Array.isArray(value.listeners) || value.listeners.length !== FIXED_PORTS.length ||
    value.listeners.some((entry, index) => (
      entry === null || Array.isArray(entry) || typeof entry !== "object" ||
      !exactKeys(entry, ["listening", "port", "unknown"]) || entry.port !== FIXED_PORTS[index] ||
      typeof entry.listening !== "boolean" || typeof entry.unknown !== "boolean"
    )) || value.containers !== 0 || value.networks !== 0 || value.volume_names.length !== 0 ||
    value.listeners.some((entry) => entry.listening || entry.unknown)
  ) fail("orchestrator_run_resources_not_fresh");
  return true;
}

async function verifyFreshRunResources(context) {
  try {
    await lstat(context.runRoot);
    context.runRootPresent = true;
    context.cleanupUnknown = true;
    fail("orchestrator_run_not_fresh");
  } catch (error) {
    if (error instanceof S10BO1OrchestratorError) throw error;
    if (error?.code !== "ENOENT") {
      context.cleanupUnknown = true;
      fail("orchestrator_run_root_invalid");
    }
  }
  const project = projectName(context.runId);
  const containers = await dockerCount([
    "ps",
    "-aq",
    "--filter",
    `label=com.docker.compose.project=${project}`,
  ]);
  const networks = await dockerCount([
    "network",
    "ls",
    "-q",
    "--filter",
    `label=com.docker.compose.project=${project}`,
  ]);
  const volumes = await projectVolumeNames(context.runId);
  const listeners = await Promise.all(FIXED_PORTS.map(inspectListener));
  validateFreshResourceInventory({ containers, networks, volume_names: volumes, listeners });
}

function createLiveOperations(authority, attempt, parentGuard = createParentIdentityGuard()) {
  const parentController = new AbortController();
  const runRoot = resolve(GENERATED_ROOT, authority.runId);
  let context = {
    ...authority,
    attempt,
    runRoot,
    evidenceRoot: resolve(runRoot, "orchestrator-evidence"),
    preflightEvidenceRoot: resolve(runRoot, "preflight-evidence"),
    logRoot: resolve(runRoot, "logs"),
    secrets: new Map(),
    phase: "preflight_not_started",
    runRootPresent: false,
    retainedVolumeNames: Object.freeze([]),
    composeAttempted: false,
    composeCleanupRequired: false,
    composeLogsRequired: false,
    cleanupUnknown: false,
    processes: {},
    parentSignal: parentController.signal,
  };
  let parentDead = false;
  let rejectParentDeath;
  const parentDeath = new Promise((_, reject) => {
    rejectParentDeath = reject;
  });
  parentDeath.catch(() => {});
  function markParentDead() {
    if (parentDead) return;
    parentDead = true;
    context.cleanupUnknown = true;
    parentController.abort();
    void closeControlWriter(context.controlWriter).catch(() => {
      context.cleanupUnknown = true;
    });
    rejectParentDeath(new S10BO1OrchestratorError("orchestrator_parent_death"));
  }
  function requireParentAlive() {
    if (!parentDead && !parentGuard.isAlive()) markParentDead();
    if (parentDead) fail("orchestrator_parent_death");
  }
  return {
    async runPreflight() {
      requireParentAlive();
      context.phase = "preflight_running";
      try {
        await Promise.race([verifyFreshRunResources(context), parentDeath]);
        requireParentAlive();
        await Promise.race([
          executePreflight(authority, parentController.signal),
          parentDeath,
        ]);
      } catch (error) {
        const primary = error instanceof S10BO1OrchestratorError
          ? error
          : new S10BO1OrchestratorError("orchestrator_preflight_failed");
        let failureContext;
        try {
          failureContext = await loadPreflightFailureContext(
            authority,
            attempt,
            context,
            primary,
          );
        } catch (contextError) {
          try {
            await lstat(context.runRoot);
            context.runRootPresent = true;
          } catch (rootError) {
            if (rootError?.code !== "ENOENT") context.cleanupUnknown = true;
          }
          context.phase = "preflight_failed";
          context.cleanupUnknown = true;
          const evidenceFailure = contextError instanceof S10BO1OrchestratorError
            ? contextError.code
            : "orchestrator_preflight_failure_evidence_invalid";
          throw new S10BO1OrchestratorError(primary.code, {
            evidence_failure_class: evidenceFailure,
          });
        }
        context = failureContext.context;
        throw failureContext.failure;
      }
      requireParentAlive();
      try {
        context = await loadRunContext(authority, attempt);
      } catch (error) {
        let observedVolumeNames = [];
        try {
          observedVolumeNames = await projectVolumeNames(authority.runId);
        } catch {
          // The original context-load failure remains primary; cleanup stays unknown.
        }
        context = {
          ...context,
          runRoot: resolve(GENERATED_ROOT, authority.runId),
          evidenceRoot: resolve(GENERATED_ROOT, authority.runId, "orchestrator-evidence"),
          preflightEvidenceRoot: resolve(GENERATED_ROOT, authority.runId, "preflight-evidence"),
          logRoot: resolve(GENERATED_ROOT, authority.runId, "logs"),
          phase: "preflight_context_invalid",
          runRootPresent: true,
          retainedVolumeNames: observedVolumeNames,
          composeAttempted: true,
          composeCleanupRequired: false,
          cleanupUnknown: true,
        };
        throw error;
      }
      context.parentSignal = parentController.signal;
      return context.summary;
    },
    async buildDesktop() {
      requireParentAlive();
      context.phase = "desktop_building";
      context.desktopBinary = await Promise.race([buildDesktop(context), parentDeath]);
      context.phase = "desktop_built";
      requireParentAlive();
    },
    async startDependencies() {
      requireParentAlive();
      context.phase = "dependencies_starting";
      await Promise.race([startDependencies(context), parentDeath]);
      context.phase = "dependencies_ready";
      requireParentAlive();
    },
    async startApi() {
      requireParentAlive();
      context.phase = "api_starting";
      await Promise.race([startApi(context), parentDeath]);
      context.phase = "api_ready";
      requireParentAlive();
    },
    async startFake() {
      requireParentAlive();
      context.phase = "fake_starting";
      await Promise.race([startFake(context), parentDeath]);
      context.phase = "fake_ready";
      requireParentAlive();
    },
    async startDesktop() {
      requireParentAlive();
      context.phase = "desktop_starting";
      await Promise.race([startDesktop(context), parentDeath]);
      context.phase = "desktop_spawned";
      requireParentAlive();
    },
    async readDesktopFrame(expectedKind) {
      const frame = await Promise.race([readDesktopFrame(context, expectedKind), parentDeath]);
      if (expectedKind === "abort_complete") context.phase = "abort_complete";
      return frame;
    },
    async readDesktopEof() {
      return await Promise.race([
        context.controlReader.expectEof(),
        childExit(context.processes.api.child, "api"),
        childExit(context.processes.fake.child, "fake"),
        parentDeath,
      ]);
    },
    async readOwnership() {
      requireParentAlive();
      const ownership = await readOwnershipEvidence(context);
      context.phase = "component_ready";
      requireParentAlive();
      return ownership;
    },
    async sendAbort() {
      requireParentAlive();
      await Promise.race([sendAbort(context), parentDeath]);
      context.phase = "abort_sent";
      requireParentAlive();
    },
    async waitForDesktopExit() {
      requireParentAlive();
      await Promise.race([waitForDesktopExit(context), parentDeath]);
      context.phase = "desktop_exited";
      requireParentAlive();
    },
    async initiateDesktopAbort() {
      try {
        await Promise.race([closeControlWriter(context?.controlWriter), parentDeath]);
      } catch {
        if (context) context.cleanupUnknown = true;
      }
      if (context?.processes.desktop) {
        if (
          context.processes.desktop.child.exitCode !== null ||
          context.processes.desktop.child.signalCode !== null
        ) return;
        await Promise.race([
          new Promise((resolveExit) => context.processes.desktop.child.once("exit", resolveExit)),
          new Promise((resolveTimeout) => setTimeout(resolveTimeout, PROCESS_STOP_TIMEOUT_MS)),
        ]);
      }
    },
    async verifyBusinessBoundary() {
      return await verifyBusinessBoundary(context);
    },
    async cleanup() {
      if (!context) fail("orchestrator_cleanup_unknown");
      const result = await cleanupLiveContext(context);
      requireParentAlive();
      return result;
    },
    async recordFailure({
      failureClass,
      businessFailureClass,
      cleanupFailureClass,
      parentFailureClass,
    }) {
      const processRoles = EXISTING_PROCESS_ROLES.filter((role) => (
        Boolean(context.processes?.[role]) || Boolean(context.descendantProcesses?.[role])
      ));
      const value = await writeAttemptFailure(attempt, authority, {
        schema_version: 1,
        status: "failed",
        run_id: authority.runId,
        attempt_marker_sha256: attempt.markerSha256,
        failure_class: failureClass,
        business_failure_class: businessFailureClass,
        cleanup_failure_class: cleanupFailureClass,
        parent_failure_class: parentFailureClass,
        phase: context.phase,
        compose_attempted: context.composeAttempted,
        compose_cleanup_required: context.composeCleanupRequired,
        run_root_present: context.runRootPresent,
        process_roles: processRoles,
        retained_volume_keys: retainedVolumeKeys(authority.runId, context.retainedVolumeNames),
        no_log_required: true,
        s10b_r8_executed: false,
      });
      context.attemptFailure = value;
      return value;
    },
    async recordClosure({
      status,
      failureClass,
      businessFailureClass,
      businessStatus,
      cleanupFailureClass,
      cleanupScope,
      evidenceFailureClass,
      noLogFailureClass,
      noLogScope,
      parentFailureClass,
    }) {
      const value = await writeAttemptClosure(attempt, authority, {
        schema_version: 1,
        status,
        closure_kind: status === "passed" ? "success" : "failure",
        run_id: authority.runId,
        attempt_marker_sha256: attempt.markerSha256,
        failure_class: failureClass,
        business_failure_class: businessFailureClass,
        business_status: businessStatus,
        cleanup_failure_class: cleanupFailureClass,
        cleanup_scope: cleanupScope,
        evidence_failure_class: evidenceFailureClass,
        no_log_failure_class: noLogFailureClass,
        no_log_scope: noLogScope,
        parent_failure_class: parentFailureClass,
        s10b_r8_executed: false,
      });
      context.attemptClosure = value;
      return value;
    },
    async scanNoLog() {
      if (!context) fail("orchestrator_no_log_invalid");
      const result = await scanNoLog(context);
      requireParentAlive();
      return result;
    },
    assertParentAlive() { requireParentAlive(); },
    pollParentAlive() {
      if (!parentDead && !parentGuard.isAlive()) markParentDead();
      return !parentDead;
    },
    parentDied() { markParentDead(); },
  };
}

export async function loadExistingProcessRecords(
  runRoot,
  runId,
  expectedRoles = EXISTING_PROCESS_ROLES,
) {
  const evidenceRoot = resolve(runRoot, "orchestrator-evidence");
  try {
    await lstat(evidenceRoot);
  } catch (error) {
    if (error?.code === "ENOENT") fail("orchestrator_existing_evidence_incomplete");
    throw error;
  }
  await requireOwnerDirectory(evidenceRoot);
  let entries;
  try {
    entries = await readdir(evidenceRoot, { withFileTypes: true });
  } catch {
    fail("orchestrator_existing_evidence_incomplete");
  }
  const expectedNames = expectedRoles.map((role) => `${role}-process.v1.json`).sort();
  const observedNames = entries
    .filter((entry) => entry.name.endsWith("-process.v1.json"))
    .map((entry) => entry.name)
    .sort();
  if (JSON.stringify(observedNames) !== JSON.stringify(expectedNames)) {
    fail("orchestrator_existing_evidence_incomplete");
  }
  const records = [];
  for (const role of expectedRoles) {
    const path = resolve(evidenceRoot, `${role}-process.v1.json`);
    try {
      const bytes = await readSecureFile(path, 4096);
      const value = JSON.parse(bytes.toString("utf8"));
      if (value?.role !== role) fail("orchestrator_existing_evidence_incomplete");
      records.push(validateProcessRecord(value, runId, role));
    } catch (error) {
      if (error instanceof SyntaxError) fail("orchestrator_process_record_invalid");
      if (error instanceof S10BO1OrchestratorError) throw error;
      fail("orchestrator_process_record_invalid");
    }
  }
  validateExistingProcessRecordSet(records, expectedRoles);
  return Object.freeze(records);
}

async function validateExistingBinaryAuthority(records, runRoot) {
  const paths = Object.freeze({
    api: resolve(runRoot, "bin/yijie-api"),
    desktop: resolve(runRoot, "desktop-build/cargo-target/release/yijie-desktop"),
    fake: resolve(runRoot, "bin/feat126-fake-responses"),
    host: resolve(runRoot, "bin/yijie-agent-host"),
    runtime: resolve(RUNTIME_ROOT, ".yijie/build/macos/aarch64-apple-darwin/codex"),
  });
  for (const record of records) {
    let digest;
    try {
      digest = await hashFile(paths[record.role]);
    } catch {
      fail("orchestrator_existing_evidence_incomplete");
    }
    if (record.binary_sha256 !== digest) fail("orchestrator_existing_evidence_incomplete");
  }
}

async function reconcileExistingRun(authority, runRoot, options = {}) {
  await requireOwnerDirectory(runRoot);
  let unknown = false;
  const expectedRoles = options.expectedRoles ?? EXISTING_PROCESS_ROLES;
  const retainedVolumeNames = options.retainedVolumeNames ?? await projectVolumeNames(authority.runId);
  const records = await loadExistingProcessRecords(runRoot, authority.runId, expectedRoles);
  await validateExistingBinaryAuthority(records, runRoot);
  const byRole = new Map(records.map((record) => [record.role, record]));
  const currentByRole = new Map();
  for (const record of records) {
    let current;
    try {
      current = await inspectProcessIdentity(record.pid);
    } catch {
      unknown = true;
      continue;
    }
    currentByRole.set(record.role, current);
    if (current !== null && !sameProcessIdentity(record, current)) unknown = true;
  }
  if (
    (currentByRole.has("host") && currentByRole.get("host") !== null &&
      (!currentByRole.has("desktop") || currentByRole.get("desktop") === null)) ||
    (currentByRole.has("runtime") && currentByRole.get("runtime") !== null &&
      (!currentByRole.has("host") || currentByRole.get("host") === null))
  ) unknown = true;
  if (!unknown) {
    for (const role of ["desktop", "fake", "api"]) {
      const record = byRole.get(role);
      if (!record) continue;
      const outcome = await reconcileProcess(record, {
        inspect: inspectProcessIdentity,
        async stop(value) {
          process.kill(value.pid, "SIGTERM");
          for (let attempt = 0; attempt < 80; attempt += 1) {
            const current = await inspectProcessIdentity(value.pid);
            if (current === null || !sameProcessIdentity(value, current)) return;
            await new Promise((resolveWait) => setTimeout(resolveWait, 100));
          }
          throw new Error("stop timeout");
        },
      });
      if (!["absent", "stopped"].includes(outcome)) unknown = true;
    }
  }
  if (options.composeCleanupRequired !== false) {
    try {
      await runCommand(
        "cleanup",
        "make",
        ["--silent", "--no-print-directory", "feat-126-s10-stop", `RUN_ID=${authority.runId}`],
        { timeout: 10 * 60_000 },
      );
    } catch {
      unknown = true;
    }
  }
  let processAssessment = { processes: records.length, identityUnknown: false };
  for (let attempt = 0; attempt < 80; attempt += 1) {
    processAssessment = await assessProcessCleanup(records, inspectProcessIdentity);
    if (processAssessment.processes === 0 || processAssessment.identityUnknown) break;
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  unknown ||= processAssessment.processes !== 0 || processAssessment.identityUnknown;

  let listenerInspections = [];
  for (let attempt = 0; attempt < 50; attempt += 1) {
    listenerInspections = await Promise.all(FIXED_PORTS.map(inspectListener));
    if (listenerInspections.every((entry) => !entry.listening && !entry.unknown)) break;
    if (attempt === 49) break;
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  unknown ||= listenerInspections.some((entry) => entry.listening || entry.unknown);

  const project = projectName(authority.runId);
  const containers = await dockerCount(["ps", "-aq", "--filter", `label=com.docker.compose.project=${project}`]);
  const networks = await dockerCount(["network", "ls", "-q", "--filter", `label=com.docker.compose.project=${project}`]);
  const volumeNames = await projectVolumeNames(authority.runId);
  const volumes = classifyProjectVolumes(project, volumeNames);
  unknown ||= containers !== 0 || networks !== 0 ||
    !sameStringSet(volumeNames, retainedVolumeNames) || volumes.temporaryVolumes !== 0;
  if (unknown) fail("orchestrator_cleanup_unknown");
  const cleanup = Object.freeze({
    schema_version: 1,
    scope: options.scope ?? "run_artifacts",
    status: "passed",
    containers,
    networks,
    processes: processAssessment.processes,
    listeners: listenerInspections.filter((entry) => entry.listening).length,
    temporary_volumes: volumes.temporaryVolumes,
    named_volume_baseline_count: retainedVolumeNames.length,
    named_volume_after_count: volumeNames.length,
    named_volumes_preserved: true,
    prune_executed: false,
    volume_delete_executed: false,
  });
  validateCleanupClosure(cleanup);
  return Object.freeze({ cleanup, records });
}

async function readOptionalAttemptFailure(attempt, authority) {
  try {
    await lstat(attempt.failurePath);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    fail("orchestrator_attempt_evidence_invalid");
  }
  return await readAttemptFailure(attempt, authority);
}

async function readOptionalAttemptClosure(attempt, authority) {
  try {
    await lstat(attempt.closurePath);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    fail("orchestrator_attempt_evidence_invalid");
  }
  return await readAttemptClosure(attempt, authority);
}

async function readOptionalAttemptReconcile(attempt, authority) {
  try {
    await lstat(attempt.reconcilePath);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    fail("orchestrator_attempt_evidence_invalid");
  }
  return await readAttemptReconcile(attempt, authority);
}

async function readSecureJson(path, maximumBytes = 16 * 1024) {
  try {
    return JSON.parse((await readSecureFile(path, maximumBytes)).toString("utf8"));
  } catch (error) {
    if (error instanceof S10BO1OrchestratorError) throw error;
    fail("orchestrator_artifact_invalid");
  }
}

export function persistedOwnershipEvidenceRequiredFiles(records) {
  if (!Array.isArray(records)) fail("orchestrator_existing_evidence_incomplete");
  const roles = new Set(records.map((record) => record?.role));
  if (!roles.has("host") && !roles.has("runtime")) return Object.freeze([]);
  if (!["desktop", "host", "runtime"].every((role) => roles.has(role))) {
    fail("orchestrator_existing_evidence_incomplete");
  }
  return Object.freeze([
    "host-evidence.v1.json",
    "host-stopped-evidence.v1.json",
    "runtime-evidence.v1.json",
  ]);
}

async function loadPersistedOwnershipEvidence(context, byRole) {
  const hostRecord = byRole.get("host");
  const runtimeRecord = byRole.get("runtime");
  const requiredFiles = persistedOwnershipEvidenceRequiredFiles([...byRole.values()]);
  if (requiredFiles.length === 0) return;
  const desktopRecord = byRole.get("desktop");
  let hostBinarySha256;
  let runtimeBinarySha256;
  let manifestSha256;
  try {
    hostBinarySha256 = await hashFile(resolve(context.binRoot, "yijie-agent-host"));
    runtimeBinarySha256 = await hashFile(
      resolve(RUNTIME_ROOT, ".yijie/build/macos/aarch64-apple-darwin/codex"),
    );
    manifestSha256 = await hashFile(
      resolve(RUNTIME_ROOT, ".yijie/build/macos/aarch64-apple-darwin/runtime-manifest.json"),
    );
  } catch {
    fail("orchestrator_existing_evidence_incomplete");
  }
  const hostEvidence = validateHostProcessEvidence(
    await readSecureJson(resolve(context.evidenceRoot, requiredFiles[0])),
    {
      runId: context.runId,
      desktopPid: desktopRecord.pid,
      binarySha256: hostBinarySha256,
      expectedState: "ready",
      expectedPid: hostRecord.pid,
    },
  );
  const runtimeEvidence = validateRuntimeProcessEvidence(
    await readSecureJson(resolve(context.evidenceRoot, requiredFiles[2])),
    {
      runId: context.runId,
      hostPid: hostRecord.pid,
      binarySha256: runtimeBinarySha256,
      manifestSha256,
      nonce: hostEvidence.instanceNonce,
      profile: "feat-126-s10-local-lab",
    },
  );
  if (
    runtimeEvidence.pid !== runtimeRecord.pid || hostEvidence.pid !== hostRecord.pid ||
    runtimeEvidence.binary_sha256 !== runtimeRecord.binary_sha256 ||
    hostEvidence.binarySha256 !== hostRecord.binary_sha256
  ) fail("orchestrator_existing_evidence_incomplete");
  const hostStoppedEvidence = validateHostProcessEvidence(
    await readSecureJson(resolve(context.evidenceRoot, requiredFiles[1])),
    {
      runId: context.runId,
      desktopPid: desktopRecord.pid,
      binarySha256: hostBinarySha256,
      expectedState: "stopped",
      expectedPid: hostEvidence.pid,
      expectedNonce: hostEvidence.instanceNonce,
      expectedStartedAtUnixMs: hostEvidence.startedAtUnixMs,
    },
  );
  context.hostEvidence = hostEvidence;
  context.runtimeEvidence = runtimeEvidence;
  context.hostStoppedEvidence = hostStoppedEvidence;
}

async function loadReconcileNoLogContext(authority, attempt, failure, closure, records) {
  const runRoot = resolve(GENERATED_ROOT, authority.runId);
  const logRoot = resolve(runRoot, "logs");
  const evidenceRoot = resolve(runRoot, "orchestrator-evidence");
  const preflightEvidenceRoot = resolve(runRoot, "preflight-evidence");
  let secrets = new Map();
  let summary;
  try {
    secrets = parseFeat126S10Secrets((await readSecureFile(
      resolve(runRoot, "infra-secrets.env"),
      4096,
    )).toString("utf8"));
  } catch {
    if (failure?.phase !== "preflight_failed") fail("orchestrator_secret_store_invalid");
  }
  if (records.length !== 0) {
    try {
      summary = await readSecureJson(resolve(preflightEvidenceRoot, "summary.json"), 64 * 1024);
      validateRepositorySummary(summary, authority.runId, authority.repositories);
    } catch {
      fail("orchestrator_existing_evidence_incomplete");
    }
  }
  const byRole = new Map(records.map((record) => [record.role, record]));
  const processes = {};
  for (const [role, logName] of [
    ["api", "api-orchestrator.log"],
    ["fake", "fake-orchestrator.log"],
    ["desktop", "desktop-orchestrator.log"],
  ]) {
    const record = byRole.get(role);
    if (record) processes[role] = { record, logPath: resolve(logRoot, logName) };
  }
  const descendantProcesses = Object.fromEntries(
    ["host", "runtime"].filter((role) => byRole.has(role)).map((role) => [role, byRole.get(role)]),
  );
  const context = {
    ...authority,
    attempt,
    attemptFailure: failure,
    attemptClosure: closure,
    runRoot,
    binRoot: resolve(runRoot, "bin"),
    runRootPresent: true,
    logRoot,
    evidenceRoot,
    preflightEvidenceRoot,
    secrets,
    summary,
    phase: failure?.phase ?? "desktop_exited",
    processes,
    descendantProcesses,
  };
  await loadPersistedOwnershipEvidence(context, byRole);
  try {
    const apiVerifierBefore = await readSecureJson(
      resolve(evidenceRoot, "api-verifier-before.v1.json"),
    );
    validateApiVerifierProjection(apiVerifierBefore, authority.runId);
    context.apiVerifierBefore = apiVerifierBefore;
  } catch {
    if (byRole.has("api") && !["api_starting", "dependencies_ready"].includes(context.phase)) {
      fail("orchestrator_existing_evidence_incomplete");
    }
  }
  if (byRole.has("fake")) {
    try {
      context.fakeAuthorityBefore = validateClosedFakeAuthorityProjection(await readSecureJson(
        resolve(evidenceRoot, "fake-authority-before.v1.json"),
      ), context);
    } catch {
      if (context.phase !== "fake_starting") fail("orchestrator_existing_evidence_incomplete");
    }
  }
  return context;
}

async function reconcileClaimedAttempt(authority, attempt) {
  let ownerIdentity;
  try {
    ownerIdentity = await inspectProcessIdentity(attempt.marker.pid);
  } catch {
    fail("orchestrator_cleanup_unknown");
  }
  if (ownerIdentity && sameProcessIdentity(attempt.marker, ownerIdentity)) {
    fail("orchestrator_existing_run_active");
  }

  const failure = await readOptionalAttemptFailure(attempt, authority);
  const closure = await readOptionalAttemptClosure(attempt, authority);
  const priorReconcile = await readOptionalAttemptReconcile(attempt, authority);
  if (priorReconcile) fail("orchestrator_existing_run_reconciled");
  if (
    closure && (
      (closure.status === "passed" && failure !== null) ||
      (closure.status === "failed" && (
        !failure || closure.failure_class !== failure.failure_class ||
        closure.business_failure_class !== failure.business_failure_class ||
        closure.cleanup_failure_class !== failure.cleanup_failure_class ||
        closure.parent_failure_class !== failure.parent_failure_class
      ))
    )
  ) fail("orchestrator_attempt_evidence_invalid");
  const persistReconcile = async ({
    businessStatus,
    cleanup,
    cleanupFailure,
    noLog,
    noLogFailure,
  }) => await writeAttemptReconcile(
    attempt,
    authority,
    buildAttemptReconcileEvidence(attempt, authority, failure, {
      businessStatus,
      cleanup,
      cleanupFailure,
      noLog,
      noLogFailure,
    }),
  );
  const runRoot = resolve(GENERATED_ROOT, authority.runId);
  let runRootPresent = true;
  try {
    await lstat(runRoot);
  } catch (error) {
    if (error?.code !== "ENOENT") fail("orchestrator_run_root_invalid");
    runRootPresent = false;
  }

  if (!runRootPresent) {
    if (
      closure || (failure && (
        failure.run_root_present !== false || failure.phase !== "preflight_failed" ||
        failure.compose_attempted !== false || failure.compose_cleanup_required !== false ||
        failure.process_roles.length !== 0 || failure.retained_volume_keys.length !== 0
      ))
    ) {
      fail("orchestrator_cleanup_unknown");
    }
    const retainedVolumeNames = await projectVolumeNames(authority.runId);
    if (retainedVolumeNames.length !== 0) fail("orchestrator_cleanup_unknown");
    const context = {
      ...authority,
      attempt,
      attemptFailure: failure,
      attemptClosure: closure,
      runRoot,
      runRootPresent: false,
      phase: "preflight_failed",
      composeAttempted: false,
      composeCleanupRequired: false,
      cleanupUnknown: false,
      retainedVolumeNames,
      processes: {},
      secrets: new Map(),
    };
    let cleanup;
    let cleanupFailure;
    let noLog;
    let noLogFailure;
    try {
      cleanup = await cleanupLiveContext(context);
      validateCleanupClosure(cleanup);
    } catch (error) {
      cleanupFailure = error instanceof S10BO1OrchestratorError
        ? error
        : new S10BO1OrchestratorError("orchestrator_cleanup_unknown");
    }
    try {
      noLog = await scanNoLog(context);
      validateNoLogResult(noLog);
    } catch (error) {
      noLogFailure = error instanceof S10BO1OrchestratorError
        ? error
        : new S10BO1OrchestratorError("orchestrator_no_log_invalid");
    }
    await persistReconcile({
      businessStatus: "not_applicable",
      cleanup,
      cleanupFailure,
      noLog,
      noLogFailure,
    });
    if (cleanupFailure) throw cleanupFailure;
    if (noLogFailure) throw noLogFailure;
    fail("orchestrator_existing_run_reconciled");
  }

  if (failure && failure.run_root_present !== true) fail("orchestrator_cleanup_unknown");
  if (
    failure && ((failure.phase === "desktop_starting" && failure.process_roles.includes("desktop")) || [
      "desktop_spawned",
      "component_ready",
      "abort_sent",
      "abort_complete",
      "desktop_exited",
    ].includes(failure.phase)) &&
    failure.process_roles.length !== EXISTING_PROCESS_ROLES.length
  ) fail("orchestrator_cleanup_unknown");
  const expectedRoles = failure?.process_roles ?? EXISTING_PROCESS_ROLES;
  const baselineVolumeNames = failure
    ? volumeNamesFromKeys(authority.runId, failure.retained_volume_keys)
    : volumeNamesFromKeys(authority.runId, S10_NAMED_VOLUME_KEYS);
  let reconciled;
  let cleanupFailure;
  try {
    reconciled = await reconcileExistingRun(authority, runRoot, {
      expectedRoles,
      composeCleanupRequired: failure?.compose_cleanup_required ?? true,
      retainedVolumeNames: baselineVolumeNames,
      scope: failure && ["preflight_failed", "preflight_context_invalid"].includes(failure.phase)
        ? "preflight_artifacts"
        : "run_artifacts",
    });
  } catch (error) {
    cleanupFailure = error instanceof S10BO1OrchestratorError
      ? error
      : new S10BO1OrchestratorError("orchestrator_cleanup_unknown");
  }
  let noLog;
  let noLogFailure;
  let businessStatus = closure?.business_status ?? (
    failure && [
      "preflight_not_started",
      "preflight_running",
      "preflight_failed",
      "preflight_context_invalid",
      "desktop_building",
      "desktop_built",
      "dependencies_starting",
      "dependencies_ready",
      "api_starting",
    ].includes(failure.phase) ? "not_applicable" : "unknown"
  );
  if (reconciled) {
    try {
      const noLogContext = await loadReconcileNoLogContext(
        authority,
        attempt,
        failure,
        closure,
        reconciled.records,
      );
      noLog = await scanNoLog(noLogContext);
      validateNoLogResult(noLog);
      try {
        const boundary = validateBusinessBoundaryEvidence(
          await readSecureJson(resolve(noLogContext.evidenceRoot, "business-boundary.v1.json")),
          authority.runId,
        );
        businessStatus = boundary.scope === "not_started" ? "not_applicable" : "passed";
      } catch {
        // A missing post-run boundary remains unknown unless the recorded phase predates API readiness.
      }
    } catch (error) {
      noLogFailure = error instanceof S10BO1OrchestratorError
        ? error
        : new S10BO1OrchestratorError("orchestrator_no_log_invalid");
    }
  } else {
    noLogFailure = new S10BO1OrchestratorError("orchestrator_no_log_invalid");
  }
  await persistReconcile({
    businessStatus,
    cleanup: reconciled?.cleanup,
    cleanupFailure,
    noLog,
    noLogFailure,
  });
  if (cleanupFailure) throw cleanupFailure;
  if (noLogFailure) throw noLogFailure;
  if (businessStatus === "unknown" || businessStatus === "failed") {
    fail("orchestrator_business_boundary_unknown");
  }
  fail("orchestrator_existing_run_reconciled");
}

async function executeOrchestrator(authority) {
  const attempt = await claimAttemptLedger(authority);
  if (!attempt.fresh) await reconcileClaimedAttempt(authority, attempt);
  const operations = createLiveOperations(authority, attempt);
  const handlers = new Map();
  for (const signal of ["SIGHUP", "SIGINT", "SIGTERM"]) {
    const handler = () => operations.parentDied();
    handlers.set(signal, handler);
    process.on(signal, handler);
  }
  const parentWatchdog = setInterval(() => operations.pollParentAlive(), 100);
  parentWatchdog.unref();
  try {
    operations.pollParentAlive();
    return await runStartupAbortFlow(authority, operations);
  } finally {
    clearInterval(parentWatchdog);
    for (const [signal, handler] of handlers) process.off(signal, handler);
  }
}

async function main() {
  if (process.argv.length !== 3) fail("orchestrator_arguments_invalid");
  const authority = validateOrchestratorInput(process.argv[2], process.env, []);
  const result = await executeOrchestrator(authority);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${JSON.stringify(buildOrchestratorFailureEnvelope(error))}\n`);
    process.exitCode = 1;
  });
}
