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
  readExpectedSHAs,
  validateProbeResult,
} from "./feat-126-s10b-preflight.mjs";

const INFRA_ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const WORKSPACE_ROOT = resolve(INFRA_ROOT, "..");
const GENERATED_ROOT = resolve(INFRA_ROOT, "environments/local/generated/feat-126-s10");
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
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const CONTROL_KEYS = Object.freeze(["kind", "nonce", "run_id", "schema_version", "sequence"]);
const CONTROL_MAX_BYTES = 1024;
const CONTROL_TIMEOUT_MS = 60_000;
const GUARDED_CONTROL_WRITERS = new WeakSet();
const PROCESS_STOP_TIMEOUT_MS = 8_000;
const CHILD_OUTPUT_MAX_BYTES = 1024 * 1024;
const FIXED_PORTS = Object.freeze([5432, 8443, 9443, 18080, 18081, 18082]);
const REPOSITORY_KEYS = Object.freeze(["api", "contracts", "desktop", "governance", "host", "infra", "runtime"]);
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

const S10BO1_STATE_INDEX = new Map(S10BO1_STATES.map((state, index) => [state, index]));
const S10BO2_STATE_INDEX = new Map(S10BO2_STATES.map((state, index) => [state, index]));

export class S10BO1OrchestratorError extends Error {
  constructor(code) {
    super(code);
    this.name = "S10BO1OrchestratorError";
    this.code = code;
  }
}

function fail(code) {
  throw new S10BO1OrchestratorError(code);
}

function exactKeys(value, expected) {
  return JSON.stringify(Object.keys(value).sort()) === JSON.stringify(expected);
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

function repositoryEnvironment(repositories) {
  return Object.fromEntries(
    Object.entries(repositories).map(([role, digest]) => [
      `FEAT126_S10B_${role.toUpperCase()}_SHA`,
      digest,
    ]),
  );
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
        if (outputBytes > maximumBytes) {
          stop(new Error("command output capacity exceeded"));
          return;
        }
        output.push(chunk);
      });
      child.stderr.on("data", (chunk) => {
        errorBytes += chunk.length;
        if (errorBytes > maximumBytes) stop(new Error("command error capacity exceeded"));
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
          settle(new Error("command failed"));
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

export function validateApiVerifierProjection(value, runId) {
  const validCounts = (entry) => entry && Number.isSafeInteger(entry.count) && entry.count >= 0 &&
    Array.isArray(entry.enums) && entry.enums.every((item) => typeof item === "string") &&
    DIGEST_PATTERN.test(entry.canonical_hash ?? "");
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    value.schema_version !== 1 || value.status !== "passed" || value.run_id !== runId ||
    value.profile !== "feat-126-s10-local-lab" || value.denylist_hit_count !== 0 ||
    !validCounts(value.tasks) || !validCounts(value.audit) || !validCounts(value.idempotency) ||
    !DIGEST_PATTERN.test(value.canonical_hash ?? "")
  ) {
    fail("orchestrator_api_projection_invalid");
  }
  return true;
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
    value.schema_version !== 1 || value.status !== "passed" ||
    value.containers !== 0 || value.networks !== 0 || value.processes !== 0 || value.listeners !== 0 ||
    value.temporary_volumes !== 0 || value.named_volumes_preserved !== true ||
    value.prune_executed !== false || value.volume_delete_executed !== false
  ) {
    fail("orchestrator_cleanup_incomplete");
  }
  return true;
}

export function validateNoLogResult(value) {
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    value.schema_version !== 1 || !Number.isSafeInteger(value.file_count) || value.file_count <= 0 ||
    !Number.isSafeInteger(value.row_count) || value.row_count < 0 || value.hit_count !== 0 ||
    !DIGEST_PATTERN.test(value.pattern_set_sha256 ?? "")
  ) {
    fail("orchestrator_no_log_invalid");
  }
  return true;
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

export function validateExistingProcessRecordSet(records) {
  if (!Array.isArray(records) || records.length !== EXISTING_PROCESS_ROLES.length) {
    fail("orchestrator_existing_evidence_incomplete");
  }
  const roles = records.map((record) => record?.role).sort();
  if (JSON.stringify(roles) !== JSON.stringify(EXISTING_PROCESS_ROLES)) {
    fail("orchestrator_existing_evidence_incomplete");
  }
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
  const infraPid = byRole.get("desktop").ppid;
  if (
    byRole.get("api").ppid !== infraPid || byRole.get("fake").ppid !== infraPid ||
    pids.includes(infraPid) ||
    byRole.get("host").ppid !== byRole.get("desktop").pid ||
    byRole.get("runtime").ppid !== byRole.get("host").pid
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
  try {
    cleanup = await operations.cleanup();
    validateCleanupClosure(cleanup);
    cleanupPassed = true;
  } catch (error) {
    cleanupFailure = error instanceof S10BO1OrchestratorError
      ? error
      : new S10BO1OrchestratorError("orchestrator_cleanup_unknown");
  }
  let noLogFailure;
  try {
    noLog = await operations.scanNoLog();
    validateNoLogResult(noLog);
  } catch (error) {
    noLogFailure = error instanceof S10BO1OrchestratorError
      ? error
      : new S10BO1OrchestratorError("orchestrator_no_log_invalid");
  }
  let parentFailure;
  try {
    operations.assertParentAlive?.();
  } catch (error) {
    parentFailure = error instanceof S10BO1OrchestratorError
      ? error
      : new S10BO1OrchestratorError("orchestrator_parent_death");
  }

  if (cleanupFailure) primaryFailure = cleanupFailure;
  else if (noLogFailure) primaryFailure = noLogFailure;
  else if (parentFailure) primaryFailure = parentFailure;

  if (primaryFailure) {
    try {
      machine.closeFailure(cleanupPassed);
    } catch {
      // Failure closure state is secondary to the original failure class.
    }
    throw primaryFailure;
  }
  machine.transition("cleanup_passed");
  machine.transition("closed_pass");
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

async function loadRunContext(authority) {
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
  return {
    ...authority,
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
    composeAttempted: false,
    composeStarted: false,
    cleanupUnknown: false,
    processes: {},
  };
}

async function executePreflight(authority, signal) {
  await runCommand(
    "preflight",
    "make",
    [
      "--silent",
      "--no-print-directory",
      "feat-126-s10b-preflight",
      `RUN_ID=${authority.runId}`,
    ],
    {
      env: commandEnvironment(repositoryEnvironment(authority.repositories)),
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
  await runCommand("dependencies", "docker", arguments_, {
    env: commandEnvironment({ FEAT126_S10_RUN_ID: context.runId }),
    timeout: 10 * 60_000,
    signal: context.parentSignal,
  });
  context.composeStarted = true;
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
      await probeClosedFakeAuthority(context);
      return;
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  fail("orchestrator_fake_not_ready");
}

async function probeClosedFakeAuthority(context) {
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
    !exactKeys(value, expectedKeys) || value.accepted_calls !== 0 || value.rejected_calls !== 0 ||
    value.dataset_id !== context.summary.fake_readiness.dataset_id ||
    value.fixture_case_id !== context.summary.fake_readiness.fixture_case_id ||
    value.dataset_sha256 !== context.summary.fake_readiness.dataset_sha256
  ) {
    fail("orchestrator_fake_authority_invalid");
  }
  validateFakeAuthority(value, {
    runId: context.runId,
    mode: "complete",
    generation: 1,
    callCap: 1,
  });
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

export async function scanNoLog(context) {
  if (
    !context?.runRoot || context.logRoot !== resolve(context.runRoot, "logs") ||
    context.evidenceRoot !== resolve(context.runRoot, "orchestrator-evidence") ||
    context.preflightEvidenceRoot !== resolve(context.runRoot, "preflight-evidence") ||
    !(context.secrets instanceof Map)
  ) {
    fail("orchestrator_no_log_invalid");
  }
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
  const scanRoots = [
    [context.logRoot, true],
    [context.evidenceRoot, true],
    [context.preflightEvidenceRoot, true],
    [resolve(context.runRoot, "bootstrap-evidence"), false],
    [resolve(context.runRoot, "host"), false],
    [resolve(context.runRoot, "secure-storage"), false, new Set(["ephemeral-secrets"])],
  ];
  let files;
  try {
    await requireOwnerDirectory(context.runRoot);
    files = [...new Set((await Promise.all(
      scanRoots.map(([root, required, excluded]) => listInspectableFiles(root, required, excluded)),
    )).flat())].sort();
  } catch {
    fail("orchestrator_no_log_invalid");
  }
  const requiredFiles = new Set([resolve(context.preflightEvidenceRoot, "summary.json")]);
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
  if ([...requiredFiles].some((path) => !files.includes(path))) {
    fail("orchestrator_no_log_invalid");
  }
  let rowCount = 0;
  let hitCount = 0;
  for (const path of files) {
    let content;
    try {
      content = await readSecureFile(path, CHILD_OUTPUT_MAX_BYTES, [0o600], 0);
    } catch {
      fail("orchestrator_no_log_invalid");
    }
    let value;
    try {
      value = new TextDecoder("utf-8", { fatal: true }).decode(content);
    } catch {
      fail("orchestrator_no_log_invalid");
    }
    rowCount += value.split("\n").filter(Boolean).length;
    const folded = value.toLocaleLowerCase("en-US");
    for (const { value: pattern } of literalPatterns) {
      if (folded.includes(pattern.toLocaleLowerCase("en-US"))) hitCount += 1;
    }
    for (const [, pattern] of forbiddenPatterns) {
      if (pattern.test(value)) hitCount += 1;
    }
  }
  return Object.freeze({
    schema_version: 1,
    file_count: files.length,
    row_count: rowCount,
    hit_count: hitCount,
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

  if (context.composeAttempted) {
    try {
      await runCommand(
        "cleanup",
        "make",
        ["--silent", "--no-print-directory", "feat-126-s10-stop", `RUN_ID=${context.runId}`],
        { timeout: 10 * 60_000 },
      );
      context.composeStarted = false;
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

  const project = `yijie-feat126-s10-${context.runId.replaceAll("-", "")}`;
  const containers = await dockerCount(["ps", "-aq", "--filter", `label=com.docker.compose.project=${project}`]);
  const networks = await dockerCount(["network", "ls", "-q", "--filter", `label=com.docker.compose.project=${project}`]);
  const volumes = classifyProjectVolumes(
    project,
    await dockerList(["volume", "ls", "-q", "--filter", `label=com.docker.compose.project=${project}`]),
  );
  if (cleanupUnknown) fail("orchestrator_cleanup_unknown");
  return Object.freeze({
    schema_version: 1,
    status: containers === 0 && networks === 0 && processAssessment.processes === 0 &&
      listeners === 0 && volumes.namedVolumes === S10_NAMED_VOLUME_KEYS.length &&
      volumes.temporaryVolumes === 0 ? "passed" : "failed",
    containers,
    networks,
    processes: processAssessment.processes,
    listeners,
    temporary_volumes: volumes.temporaryVolumes,
    named_volumes_preserved: volumes.namedVolumes === S10_NAMED_VOLUME_KEYS.length,
    prune_executed: false,
    volume_delete_executed: false,
  });
}

async function createLiveOperations(authority, parentGuard = createParentIdentityGuard()) {
  const parentController = new AbortController();
  const runRoot = resolve(GENERATED_ROOT, authority.runId);
  let context = {
    ...authority,
    runRoot,
    evidenceRoot: resolve(runRoot, "orchestrator-evidence"),
    preflightEvidenceRoot: resolve(runRoot, "preflight-evidence"),
    logRoot: resolve(runRoot, "logs"),
    secrets: new Map(),
    composeAttempted: true,
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
      await Promise.race([
        executePreflight(authority, parentController.signal),
        parentDeath,
      ]);
      requireParentAlive();
      context = await loadRunContext(authority);
      context.parentSignal = parentController.signal;
      return context.summary;
    },
    async buildDesktop() {
      requireParentAlive();
      context.desktopBinary = await Promise.race([buildDesktop(context), parentDeath]);
      requireParentAlive();
    },
    async startDependencies() {
      requireParentAlive();
      await Promise.race([startDependencies(context), parentDeath]);
      requireParentAlive();
    },
    async startApi() {
      requireParentAlive();
      await Promise.race([startApi(context), parentDeath]);
      requireParentAlive();
    },
    async startFake() {
      requireParentAlive();
      await Promise.race([startFake(context), parentDeath]);
      requireParentAlive();
    },
    async startDesktop() {
      requireParentAlive();
      await Promise.race([startDesktop(context), parentDeath]);
      requireParentAlive();
    },
    async readDesktopFrame(expectedKind) {
      return await Promise.race([readDesktopFrame(context, expectedKind), parentDeath]);
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
      requireParentAlive();
      return ownership;
    },
    async sendAbort() {
      requireParentAlive();
      await Promise.race([sendAbort(context), parentDeath]);
      requireParentAlive();
    },
    async waitForDesktopExit() {
      requireParentAlive();
      await Promise.race([waitForDesktopExit(context), parentDeath]);
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
    async cleanup() {
      if (!context) fail("orchestrator_cleanup_unknown");
      const result = await cleanupLiveContext(context);
      requireParentAlive();
      return result;
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

export async function loadExistingProcessRecords(runRoot, runId) {
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
  const expectedNames = EXISTING_PROCESS_ROLES.map((role) => `${role}-process.v1.json`).sort();
  const observedNames = entries
    .filter((entry) => entry.name.endsWith("-process.v1.json"))
    .map((entry) => entry.name)
    .sort();
  if (JSON.stringify(observedNames) !== JSON.stringify(expectedNames)) {
    fail("orchestrator_existing_evidence_incomplete");
  }
  const records = [];
  for (const role of EXISTING_PROCESS_ROLES) {
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
  validateExistingProcessRecordSet(records);
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

async function reconcileExistingRun(authority, runRoot) {
  await requireOwnerDirectory(runRoot);
  let unknown = false;
  const records = await loadExistingProcessRecords(runRoot, authority.runId);
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
    (currentByRole.get("host") !== null && currentByRole.get("desktop") === null) ||
    (currentByRole.get("runtime") !== null && currentByRole.get("host") === null)
  ) unknown = true;
  if (!unknown) {
    for (const role of ["desktop", "fake", "api"]) {
      const record = byRole.get(role);
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

  const project = `yijie-feat126-s10-${authority.runId.replaceAll("-", "")}`;
  const containers = await dockerCount(["ps", "-aq", "--filter", `label=com.docker.compose.project=${project}`]);
  const networks = await dockerCount(["network", "ls", "-q", "--filter", `label=com.docker.compose.project=${project}`]);
  const volumes = classifyProjectVolumes(
    project,
    await dockerList(["volume", "ls", "-q", "--filter", `label=com.docker.compose.project=${project}`]),
  );
  unknown ||= containers !== 0 || networks !== 0 ||
    volumes.namedVolumes !== S10_NAMED_VOLUME_KEYS.length || volumes.temporaryVolumes !== 0;
  if (unknown) fail("orchestrator_cleanup_unknown");
  fail("orchestrator_existing_run_reconciled");
}

async function executeOrchestrator(authority) {
  const operations = await createLiveOperations(authority);
  const handlers = new Map();
  for (const signal of ["SIGHUP", "SIGINT", "SIGTERM"]) {
    const handler = () => operations.parentDied();
    handlers.set(signal, handler);
    process.on(signal, handler);
  }
  const parentWatchdog = setInterval(() => operations.pollParentAlive(), 100);
  parentWatchdog.unref();
  const runRoot = resolve(GENERATED_ROOT, authority.runId);
  try {
    operations.pollParentAlive();
    try {
      await lstat(runRoot);
      await reconcileExistingRun(authority, runRoot);
    } catch (error) {
      if (error instanceof S10BO1OrchestratorError) throw error;
      if (error?.code !== "ENOENT") fail("orchestrator_run_root_invalid");
    }
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
    const code = error instanceof S10BO1OrchestratorError ? error.code : "orchestrator_internal_failure";
    process.stderr.write(`${JSON.stringify({ schema_version: 1, status: "failed", failure_class: code })}\n`);
    process.exitCode = 1;
  });
}
