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
import { DatabaseSync } from "node:sqlite";
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
const R8_CASE_RESULT_KEYS = Object.freeze([
  ...CONTROL_KEYS, "assertion_count", "assertion_set_sha256", "case_id", "status",
]);
const STARTUP_FAILURE_CONTROL_KEYS = Object.freeze([...CONTROL_KEYS, "failure_class"]);
const POST_READY_FAILURE_CONTROL_KEYS = Object.freeze([...CONTROL_KEYS, "failure_class"]);
const CONTROL_MAX_BYTES = 1024;
const CONTROL_TIMEOUT_MS = 60_000;
const R8_CASE_TIMEOUT_MS = 120_000;
const DESKTOP_EXIT_DRAIN_TIMEOUT_MS = 100;
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
const RUNTIME_LOG_SCAN_V1_KEYS = Object.freeze([
  "hit_count",
  "row_count",
  "run_id",
  "schema_version",
  "source_count",
  "source_set_sha256",
  "status",
]);
const RUNTIME_LOG_SCAN_V2_KEYS = Object.freeze([
  ...RUNTIME_LOG_SCAN_V1_KEYS,
  "hit_origin_set_sha256",
  "hit_rule_set_sha256",
]);
const RUNTIME_LOG_SCAN_V3_LEGACY_KEYS = Object.freeze([
  ...RUNTIME_LOG_SCAN_V2_KEYS,
  "hit_origin_rule_set_sha256",
]);
const RUNTIME_LOG_SCAN_V3_KEYS = Object.freeze([
  ...RUNTIME_LOG_SCAN_V3_LEGACY_KEYS,
  "hit_field_class_set_sha256",
  "hit_origin_rule_field_class_set_sha256",
]);
const RUNTIME_LOG_SCAN_V4_KEYS = Object.freeze([
  ...RUNTIME_LOG_SCAN_V3_KEYS,
  "hit_origin_rule_field_class_reason_class_set_sha256",
  "hit_reason_class_set_sha256",
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
const R8_CASE_EVIDENCE_KEYS = Object.freeze([
  "assertion_count",
  "assertion_set_sha256",
  "case_id",
  "frame_sequence",
  "ordinal",
  "run_id",
  "schema_version",
  "status",
]);
const R8_ASSERTIONS = Object.freeze({
  s10b_002: Object.freeze(["opaque_project", "single_session", "single_turn", "completed_terminal"]),
  s10b_003: Object.freeze(["assistant_plaintext", "reasoning_complete", "reasoning_ordered", "terminal_exact"]),
  s10b_004: Object.freeze(["interrupt_terminal", "incomplete_answer", "incomplete_reasoning", "terminal_once"]),
  s10b_005_planned_restart: Object.freeze(["history_page_20", "history_page_50", "restart_closed", "resync_same_session", "cursor_monotonic"]),
  s10b_006: Object.freeze(["fallback_title", "user_rename_wins", "session_pin", "project_pin", "stable_sort"]),
  s10b_007: Object.freeze(["gap_recovery", "reconnect", "race_closed", "no_late_commit", "cursor_resync"]),
  s10b_008: Object.freeze(["desktop_delete", "host_delete", "runtime_delete", "receipt_closed", "restart_unreadable"]),
  s10b_009: Object.freeze(["public_task_content_free", "audit_content_free", "counts_bound", "path_absent", "title_absent"]),
  s10b_010: Object.freeze(["log_content_free", "bbolt_content_free", "audit_content_free", "telemetry_content_free", "process_output_content_free"]),
  s10b_011: Object.freeze(["metadata_p95_200ms", "history_p95_300ms", "reducer_10000", "db_1m_messages", "idempotency_10000"]),
});
const FROZEN_R8_CANARY_PATTERNS = Object.freeze([
  { name: "canary:prompt", value: "请为合成任务000整理订单风险并给出只读检查清单。" },
  { name: "canary:assistant_title", value: "订单风险检查 000" },
  { name: "canary:raw", value: "Synthetic reasoning 000: constraints checked before conclusion." },
  { name: "canary:project", value: "<run_root>/project" },
]);
const R8_BUSINESS_EVIDENCE_KEYS = Object.freeze([
  "api_after_sha256",
  "api_before_sha256",
  "audit_count_delta",
  "business_cases",
  "case_count",
  "case_order_sha256",
  "fake_accepted_calls",
  "fake_authority_set_sha256",
  "fake_generation_count",
  "fake_rejected_calls",
  "idempotency_count_delta",
  "run_id",
  "s10b_r8_executed",
  "schema_version",
  "status",
  "tasks_count_delta",
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
const DESKTOP_CONTROL_KINDS = Object.freeze([
  "abort_complete", "component_failed", "component_ready", "startup_failed",
]);
const DESKTOP_STARTUP_FAILURE_CLASSES = Object.freeze([
  "driver_app_data_invalid",
  "driver_authority_invalid",
  "driver_bind_failed",
  "driver_bind_context_denied",
  "driver_bind_context_invalid",
  "driver_bind_context_unauthenticated",
  "driver_bind_context_unavailable",
  "driver_bind_event_failed",
  "driver_bind_project_snapshot_failed",
  "driver_bind_readiness_snapshot_failed",
  "driver_bind_session_snapshot_failed",
  "driver_control_channel_invalid",
  "driver_control_monitor_invalid",
  "driver_control_projection_invalid",
  "driver_frontend_bootstrap_timeout",
  "driver_frontend_ipc_timeout",
  "driver_frontend_startup_invalid",
  "driver_login_authorization_page_failed",
  "driver_login_authorization_request_invalid",
  "driver_login_authorization_start_failed",
  "driver_login_callback_rejected",
  "driver_login_concurrent",
  "driver_login_credential_submit_failed",
  "driver_login_credentials_rejected",
  "driver_login_failed",
  "driver_login_form_invalid",
  "driver_login_projection_invalid",
  "driver_login_runtime_invalid",
  "driver_login_secret_invalid",
  "driver_login_session_failed",
  "driver_login_storage_failed",
  "driver_login_token_exchange_failed",
  "driver_nonce_invalid",
  "driver_profile_invalid",
  "driver_project_invalid",
  "driver_project_projection_invalid",
  "driver_project_revalidation_failed",
  "driver_readiness_failed",
  "driver_ready_emit_failed",
  "driver_run_id_invalid",
  "driver_secret_authority_invalid",
  "driver_setup_panic",
  "driver_setup_timeout",
  "driver_page_load_timeout",
  "driver_startup_timeout",
  "driver_tauri_startup_invalid",
]);
const DESKTOP_POST_READY_FAILURE_CLASSES = Object.freeze([
  "driver_case_create_failed",
  "driver_case_failed",
  "driver_case_result_failed",
  "driver_control_projection_invalid",
  "driver_frontend_startup_invalid",
]);
const RUNTIME_LOG_SOURCE_KEYS = Object.freeze([
  "container_id",
  "data_classification",
  "feature",
  "project",
  "run_id",
  "service_role",
  "slice",
]);
const RUNTIME_LOG_SERVICE_ROLES = Object.freeze([
  "feat126-s10-api-db",
  "feat126-s10-caddy",
  "feat126-s10-keycloak",
  "feat126-s10-keycloak-db",
]);
const STRUCTURED_NO_LOG_RULES = Object.freeze([
  "absolute_local_path",
  "sensitive_value_field",
  "unclassified_sensitive_field",
]);
const APPROVED_CONTEXT_MESSAGES = Object.freeze([
  "failed to map Codex notification",
  "starting yijie-agent-host",
  "starting yijie-api",
]);
const STRUCTURED_NO_LOG_FIELD_CLASSES = Object.freeze([
  "literal_value",
  "local_path",
  "structured_sensitive",
  "structured_unclassified",
  "unstructured_pattern",
]);
const STRUCTURED_NO_LOG_REASON_CLASSES = Object.freeze([
  "literal_authority_match",
  "local_machine_path_value",
  "sensitive_nonempty_value",
  "unclassified_context_value",
  "unclassified_caddy_system_value",
  "unstructured_pattern_match",
]);
const DESKTOP_PRODUCTION_FEATURES = Object.freeze([
  "feat126-s10-driver",
  "tauri/custom-protocol",
]);
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

export const S10B_R8_STATES = Object.freeze([
  "created",
  "preflight_running",
  "preflight_passed",
  "desktop_built",
  "dependencies_ready",
  "api_ready",
  "fake_ready",
  "desktop_ready",
  "host_ready",
  "runtime_ready",
  ...S10BO1_CASES.slice(0, -1),
  "cleanup_passed",
  "closed_pass",
]);

export const S10B_R8_FAKE_GENERATIONS = Object.freeze([
  Object.freeze({ generation: 1, mode: "complete", callCap: 2, firstCase: "s10b_002" }),
  Object.freeze({ generation: 2, mode: "incomplete", callCap: 1, firstCase: "s10b_004" }),
  Object.freeze({ generation: 3, mode: "disconnect", callCap: 1, firstCase: "s10b_006" }),
  Object.freeze({ generation: 4, mode: "oversize", callCap: 1, firstCase: "s10b_011" }),
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
  ...S10B_R8_STATES,
]);

const S10BO1_STATE_INDEX = new Map(S10BO1_STATES.map((state, index) => [state, index]));
const S10BO2_STATE_INDEX = new Map(S10BO2_STATES.map((state, index) => [state, index]));
const S10B_R8_STATE_INDEX = new Map(S10B_R8_STATES.map((state, index) => [state, index]));

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

function asciiCompare(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
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

export function validateR8OrchestratorInput(runId, environment = process.env, arguments_ = []) {
  const authority = validateOrchestratorInput(runId, environment, arguments_);
  return Object.freeze({ ...authority, r8: true });
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

export function createR8StateMachine() {
  return createOrderedStateMachine(S10B_R8_STATES, S10B_R8_STATE_INDEX);
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

export function validateStartupFailureControlFrame(frame, authority) {
  if (
    authority === null || typeof authority !== "object" || Array.isArray(authority) ||
    !exactKeys(authority, ["allowedKinds", "nonce", "previousSequence", "runId"]) ||
    !RUN_ID_PATTERN.test(authority.runId ?? "") ||
    !RUN_ID_PATTERN.test(authority.nonce ?? "") ||
    authority.previousSequence !== 0 ||
    !Array.isArray(authority.allowedKinds) ||
    new Set(authority.allowedKinds).size !== authority.allowedKinds.length ||
    authority.allowedKinds.some((kind) => !DESKTOP_CONTROL_KINDS.includes(kind)) ||
    JSON.stringify([...authority.allowedKinds].sort(asciiCompare)) !== JSON.stringify(
      [...DESKTOP_CONTROL_KINDS].filter((kind) => kind !== "component_failed").sort(asciiCompare),
    ) ||
    frame === null || typeof frame !== "object" || Array.isArray(frame) ||
    !exactKeys(frame, STARTUP_FAILURE_CONTROL_KEYS) || frame.schema_version !== 1 ||
    frame.run_id !== authority.runId || frame.nonce !== authority.nonce ||
    frame.sequence !== 1 || frame.kind !== "startup_failed" ||
    !DESKTOP_STARTUP_FAILURE_CLASSES.includes(frame.failure_class)
  ) {
    fail("orchestrator_control_frame_invalid");
  }
  return Object.freeze({
    schema_version: 1,
    run_id: authority.runId,
    nonce: authority.nonce,
    sequence: 1,
    kind: "startup_failed",
    failure_class: frame.failure_class,
  });
}

export function validatePostReadyFailureControlFrame(frame, authority) {
  if (
    authority === null || typeof authority !== "object" || Array.isArray(authority) ||
    !exactKeys(authority, ["allowedKinds", "nonce", "previousSequence", "runId"]) ||
    !RUN_ID_PATTERN.test(authority.runId ?? "") || !RUN_ID_PATTERN.test(authority.nonce ?? "") ||
    !Array.isArray(authority.allowedKinds) ||
    JSON.stringify([...authority.allowedKinds].sort(asciiCompare)) !==
      JSON.stringify([...DESKTOP_CONTROL_KINDS].sort(asciiCompare)) ||
    authority.previousSequence < 1 ||
    frame === null || typeof frame !== "object" || Array.isArray(frame) ||
    !exactKeys(frame, POST_READY_FAILURE_CONTROL_KEYS) || frame.schema_version !== 1 ||
    frame.run_id !== authority.runId || frame.nonce !== authority.nonce ||
    !Number.isSafeInteger(frame.sequence) || frame.sequence !== authority.previousSequence + 1 ||
    frame.kind !== "component_failed" || !DESKTOP_POST_READY_FAILURE_CLASSES.includes(frame.failure_class)
  ) fail("orchestrator_control_frame_invalid");
  return Object.freeze({ ...frame });
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
  if (frame?.kind === "startup_failed") {
    return validateStartupFailureControlFrame(frame, authority);
  }
  if (frame?.kind === "component_failed") {
    return validatePostReadyFailureControlFrame(frame, authority);
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

export function encodeR8ControlFrame(frame, authority) {
  const caseFrame = frame?.kind === "mode_transition";
  if (
    frame === null || Array.isArray(frame) || typeof frame !== "object" ||
    !exactKeys(frame, caseFrame ? [...CONTROL_KEYS, "case_id"] : CONTROL_KEYS) ||
    frame.schema_version !== 1 || frame.run_id !== authority?.runId ||
    frame.nonce !== authority?.nonce || frame.sequence !== authority?.previousSequence + 1 ||
    (caseFrame
      ? !S10BO1_CASES.slice(0, -1).includes(frame.case_id)
      : !["planned_restart", "abort"].includes(frame.kind))
  ) fail("orchestrator_control_frame_invalid");
  const encoded = Buffer.from(`${JSON.stringify(frame)}\n`, "utf8");
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
      if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) timeoutMs = CONTROL_TIMEOUT_MS;
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
        allowedKinds: previousSequence === 0
          ? DESKTOP_CONTROL_KINDS.filter((kind) => kind !== "component_failed")
          : DESKTOP_CONTROL_KINDS,
      });
      if (frame.kind === "component_failed") {
        throw new S10BO1OrchestratorError(frame.failure_class);
      }
      if (frame.kind === "startup_failed") {
        if (expectedKind !== "component_ready" || previousSequence !== 0) {
          fail("orchestrator_control_order_invalid");
        }
        throw new S10BO1OrchestratorError(frame.failure_class);
      }
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

export function createR8ControlFrameReader(stream, authority) {
  const iterator = stream[Symbol.asyncIterator]();
  let buffered = Buffer.alloc(0);
  let previousSequence = 0;
  let closed = false;
  return Object.freeze({
    get sequence() { return previousSequence; },
    async next(
      expectedKind,
      expectedCaseId = null,
      timeoutMs = expectedKind === "case_result" ? R8_CASE_TIMEOUT_MS : CONTROL_TIMEOUT_MS,
    ) {
      if (closed) fail("orchestrator_control_eof");
      while (buffered.indexOf(0x0a) === -1) {
        const result = await withTimeout(iterator.next(), timeoutMs, "orchestrator_control_timeout");
        if (result.done) { closed = true; fail("orchestrator_control_eof"); }
        buffered = Buffer.concat([buffered, Buffer.from(result.value)]);
        if (buffered.indexOf(0x0a) === -1 && buffered.length > CONTROL_MAX_BYTES) {
          fail("orchestrator_control_frame_oversize");
        }
      }
      const newline = buffered.indexOf(0x0a);
      if (newline + 1 > CONTROL_MAX_BYTES) fail("orchestrator_control_frame_oversize");
      const bytes = buffered.subarray(0, newline + 1);
      buffered = buffered.subarray(newline + 1);
      let frame;
      try {
        frame = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes).trimEnd());
      } catch { fail("orchestrator_control_frame_invalid"); }
      const startupFailure = frame?.kind === "startup_failed";
      if (startupFailure) {
        const validated = validateStartupFailureControlFrame(frame, {
          allowedKinds: DESKTOP_CONTROL_KINDS.filter((kind) => kind !== "component_failed"),
          nonce: authority.nonce,
          previousSequence,
          runId: authority.runId,
        });
        if (expectedKind !== "component_ready") fail("orchestrator_control_order_invalid");
        previousSequence = validated.sequence;
        throw new S10BO1OrchestratorError(validated.failure_class);
      }
      previousSequence += 1;
      const caseResult = expectedKind === "case_result";
      const postReadyFailure = frame?.kind === "component_failed";
      if (
        frame === null || Array.isArray(frame) || typeof frame !== "object" ||
        !exactKeys(frame, postReadyFailure
          ? POST_READY_FAILURE_CONTROL_KEYS
          : caseResult ? R8_CASE_RESULT_KEYS : CONTROL_KEYS) ||
        frame.schema_version !== 1 || frame.run_id !== authority.runId ||
        frame.nonce !== authority.nonce || frame.sequence !== previousSequence ||
        (postReadyFailure
          ? (previousSequence < 2 || !DESKTOP_POST_READY_FAILURE_CLASSES.includes(frame.failure_class))
          : frame.kind !== expectedKind) ||
        (!postReadyFailure && caseResult && (frame.case_id !== expectedCaseId || frame.status !== "passed" ||
          !Number.isSafeInteger(frame.assertion_count) || frame.assertion_count <= 0 ||
          !DIGEST_PATTERN.test(frame.assertion_set_sha256 ?? "")))
      ) fail("orchestrator_control_frame_invalid");
      if (postReadyFailure) throw new S10BO1OrchestratorError(frame.failure_class);
      return Object.freeze({ ...frame });
    },
    async expectEof(timeoutMs = CONTROL_TIMEOUT_MS) {
      if (buffered.length !== 0) fail("orchestrator_control_trailing_frame");
      const result = await withTimeout(iterator.next(), timeoutMs, "orchestrator_control_timeout");
      if (!result.done || Buffer.from(result.value ?? "").length !== 0) {
        fail("orchestrator_control_trailing_frame");
      }
      closed = true;
      return true;
    },
    destroy() { closed = true; stream.destroy(); },
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
    mode: context.fakeSpec?.mode ?? "complete",
    generation: context.fakeSpec?.generation ?? 1,
    callCap: context.fakeSpec?.callCap ?? 1,
  });
  return Object.freeze({ ...value });
}

export async function persistR8FakeFinalAuthority(context, specification, value) {
  const finalAuthority = validateClosedFakeAuthorityProjection(value, {
    ...context,
    fakeSpec: specification,
  }, false);
  await writeSecureJson(
    resolve(context.evidenceRoot, `r8-fake-${specification.generation}-final.v1.json`),
    finalAuthority,
  );
  if (
    finalAuthority.accepted_calls !== specification.callCap ||
    finalAuthority.rejected_calls !== 0
  ) fail("orchestrator_fake_authority_invalid");
  context.r8FakeAuthorities.push(finalAuthority);
  return finalAuthority;
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
  const versionOne = value?.schema_version === 1;
  const versionTwo = value?.schema_version === 2;
  const versionThree = value?.schema_version === 3;
  const versionFour = value?.schema_version === 4;
  const versionThreeLegacy = versionThree && exactKeys(value, RUNTIME_LOG_SCAN_V3_LEGACY_KEYS);
  const versionThreeExplainable = versionThree && exactKeys(value, RUNTIME_LOG_SCAN_V3_KEYS);
  const versionAtLeastThree = versionThree || versionFour;
  const versionExplainable = versionThreeExplainable || versionFour;
  const emptySetSha256 = sha256("");
  const canonicalSourceSetSha256 = sha256(
    RUNTIME_LOG_SERVICE_ROLES
      .map((role) => `compose:${role}`)
      .sort(asciiCompare)
      .join("\n"),
  );
  if (
    value === null || Array.isArray(value) || typeof value !== "object" ||
    (!versionOne && !versionTwo && !versionThree && !versionFour) ||
    (versionFour
      ? !exactKeys(value, RUNTIME_LOG_SCAN_V4_KEYS)
      : versionThree
      ? !versionThreeLegacy && !versionThreeExplainable
      : !exactKeys(value, versionTwo ? RUNTIME_LOG_SCAN_V2_KEYS : RUNTIME_LOG_SCAN_V1_KEYS)) ||
    value.status !== (value.hit_count === 0 ? "passed" : "failed") ||
    value.run_id !== runId || !Number.isSafeInteger(value.source_count) ||
    value.source_count <= 0 || !Number.isSafeInteger(value.row_count) || value.row_count < 0 ||
    !Number.isSafeInteger(value.hit_count) || value.hit_count < 0 ||
    !DIGEST_PATTERN.test(value.source_set_sha256 ?? "") ||
    ((versionTwo || versionAtLeastThree) && (
      !DIGEST_PATTERN.test(value.hit_origin_set_sha256 ?? "") ||
      !DIGEST_PATTERN.test(value.hit_rule_set_sha256 ?? "") ||
      (value.hit_count === 0 && (
        value.hit_origin_set_sha256 !== emptySetSha256 ||
        value.hit_rule_set_sha256 !== emptySetSha256
      )) ||
      (value.hit_count > 0 && (
        value.hit_origin_set_sha256 === emptySetSha256 ||
        value.hit_rule_set_sha256 === emptySetSha256
      ))
    )) ||
    (versionAtLeastThree && (
      value.source_count !== RUNTIME_LOG_SERVICE_ROLES.length ||
      value.source_set_sha256 !== canonicalSourceSetSha256 ||
      !DIGEST_PATTERN.test(value.hit_origin_rule_set_sha256 ?? "") ||
      (value.hit_count === 0 && value.hit_origin_rule_set_sha256 !== emptySetSha256) ||
      (value.hit_count > 0 && value.hit_origin_rule_set_sha256 === emptySetSha256)
    )) ||
    (versionExplainable && (
      !DIGEST_PATTERN.test(value.hit_field_class_set_sha256 ?? "") ||
      !DIGEST_PATTERN.test(value.hit_origin_rule_field_class_set_sha256 ?? "") ||
      (value.hit_count === 0 && (
        value.hit_field_class_set_sha256 !== emptySetSha256 ||
        value.hit_origin_rule_field_class_set_sha256 !== emptySetSha256
      )) ||
      (value.hit_count > 0 && (
        value.hit_field_class_set_sha256 === emptySetSha256 ||
        value.hit_origin_rule_field_class_set_sha256 === emptySetSha256
      ))
    )) ||
    (versionFour && (
      !DIGEST_PATTERN.test(value.hit_reason_class_set_sha256 ?? "") ||
      !DIGEST_PATTERN.test(value.hit_origin_rule_field_class_reason_class_set_sha256 ?? "") ||
      (value.hit_count === 0 && (
        value.hit_reason_class_set_sha256 !== emptySetSha256 ||
        value.hit_origin_rule_field_class_reason_class_set_sha256 !== emptySetSha256
      )) ||
      (value.hit_count > 0 && (
        value.hit_reason_class_set_sha256 === emptySetSha256 ||
        value.hit_origin_rule_field_class_reason_class_set_sha256 === emptySetSha256
      ))
    ))
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
    s10b_r8_executed: expectedR8(authority),
    execution: "separately-authorized-isolated-live-only",
  });
}

export function buildR8OrchestratorPlan(input) {
  const authority = validateR8OrchestratorInput(
    input?.runId,
    input?.environment ?? {},
    input?.arguments_ ?? [],
  );
  return Object.freeze({
    schema_version: 1,
    kind: "feat126-s10b-r8-plan",
    run_id: authority.runId,
    repositories: authority.repositories,
    ownership: Object.freeze({ infra: ["api", "fake", "desktop"], desktop: ["host"], host: ["runtime"] }),
    states: S10B_R8_STATES,
    cases: S10BO1_CASES,
    fake_generations: S10B_R8_FAKE_GENERATIONS,
    business_cases: "frozen_s10b_002_011",
    s10b_r8_executed: true,
    execution: "single-authorized-fresh-r8-only",
  });
}

export function validateR8CaseEvidence(value, authority) {
  const expectedCase = S10BO1_CASES[value?.ordinal - 1];
  const expectedAssertions = R8_ASSERTIONS[expectedCase];
  const expectedAssertionDigest = sha256(`${expectedAssertions.join("\n")}\n`);
  if (
    value === null || Array.isArray(value) || typeof value !== "object" ||
    !exactKeys(value, R8_CASE_EVIDENCE_KEYS) || value.schema_version !== 1 ||
    value.status !== "passed" || value.run_id !== authority?.runId ||
    !Number.isSafeInteger(value.ordinal) || value.ordinal < 1 || value.ordinal > 10 ||
    value.case_id !== expectedCase || !Number.isSafeInteger(value.frame_sequence) ||
    value.frame_sequence < 2 || value.frame_sequence > 8 ||
    value.assertion_count !== expectedAssertions.length ||
    value.assertion_set_sha256 !== expectedAssertionDigest
  ) fail("orchestrator_case_evidence_invalid");
  return Object.freeze({ ...value });
}

function countDelta(before, after) {
  return after.count - before.count;
}

export function buildR8BusinessEvidence(before, after, fakeAuthorities, caseEvidence, runId) {
  validateApiVerifierProjection(before, runId);
  validateApiVerifierProjection(after, runId);
  if (
    before.tasks.count !== 0 || before.idempotency.count !== 0 ||
    before.tasks.enums.length !== 0 || before.idempotency.enums.length !== 0 ||
    countDelta(before.tasks, after.tasks) !== 2 ||
    countDelta(before.idempotency, after.idempotency) !== 2 ||
    countDelta(before.audit, after.audit) !== 2 ||
    JSON.stringify(after.tasks.enums) !== JSON.stringify(["draft"]) ||
    JSON.stringify(after.idempotency.enums) !== JSON.stringify(["bound"]) ||
    JSON.stringify(after.audit.enums) !== JSON.stringify(["success"]) ||
    !Array.isArray(fakeAuthorities) || fakeAuthorities.length !== S10B_R8_FAKE_GENERATIONS.length ||
    !Array.isArray(caseEvidence) || caseEvidence.length !== 10
  ) fail("orchestrator_business_boundary_invalid");
  const validatedCases = caseEvidence.map((value) => validateR8CaseEvidence(value, { runId }));
  const fakeTuples = fakeAuthorities.map((value, index) => {
    const specification = S10B_R8_FAKE_GENERATIONS[index];
    validateFakeAuthority(value, { runId, ...specification });
    const expectedCalls = specification.callCap;
    if (value.accepted_calls !== expectedCalls || value.rejected_calls !== 0) {
      fail("orchestrator_business_boundary_invalid");
    }
    return JSON.stringify([
      value.generation,
      value.mode,
      value.call_cap,
      value.accepted_calls,
      value.rejected_calls,
    ]);
  });
  const caseOrder = validatedCases.map(({ case_id: caseId }) => caseId);
  if (JSON.stringify(caseOrder) !== JSON.stringify(S10BO1_CASES.slice(0, -1))) {
    fail("orchestrator_business_boundary_invalid");
  }
  return validateR8BusinessEvidence({
    schema_version: 1,
    status: "passed",
    run_id: runId,
    business_cases: "frozen_s10b_002_011",
    api_before_sha256: before.canonical_hash,
    api_after_sha256: after.canonical_hash,
    tasks_count_delta: 2,
    audit_count_delta: 2,
    idempotency_count_delta: 2,
    fake_generation_count: fakeAuthorities.length,
    fake_accepted_calls: fakeAuthorities.reduce((sum, value) => sum + value.accepted_calls, 0),
    fake_rejected_calls: fakeAuthorities.reduce((sum, value) => sum + value.rejected_calls, 0),
    fake_authority_set_sha256: sha256(fakeTuples.sort(asciiCompare).join("\n")),
    case_count: validatedCases.length,
    case_order_sha256: sha256(caseOrder.join("\n")),
    s10b_r8_executed: true,
  }, runId);
}

export function validateR8BusinessEvidence(value, runId) {
  if (
    value === null || Array.isArray(value) || typeof value !== "object" ||
    !exactKeys(value, R8_BUSINESS_EVIDENCE_KEYS) || value.schema_version !== 1 ||
    value.status !== "passed" || value.run_id !== runId ||
    value.business_cases !== "frozen_s10b_002_011" || value.s10b_r8_executed !== true ||
    !DIGEST_PATTERN.test(value.api_before_sha256 ?? "") ||
    !DIGEST_PATTERN.test(value.api_after_sha256 ?? "") ||
    value.api_after_sha256 === value.api_before_sha256 ||
    value.tasks_count_delta !== 2 || value.audit_count_delta !== 2 ||
    value.idempotency_count_delta !== 2 || value.fake_generation_count !== 4 ||
    value.fake_accepted_calls !== 5 || value.fake_rejected_calls !== 0 ||
    !DIGEST_PATTERN.test(value.fake_authority_set_sha256 ?? "") || value.case_count !== 10 ||
    value.case_order_sha256 !== sha256(S10BO1_CASES.slice(0, -1).join("\n"))
  ) fail("orchestrator_business_boundary_invalid");
  return Object.freeze({ ...value });
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

function r8ProcessEvidenceNames() {
  return Object.freeze([
    "api-process.v1.json",
    ...S10B_R8_FAKE_GENERATIONS.map(({ generation }) =>
      `r8-fake-${generation}-process.v1.json`,
    ),
    "r8-desktop-1-process.v1.json",
    "r8-desktop-2-process.v1.json",
    ...[1, 2].flatMap((lifecycle) => [
      `r8-lifecycle-${lifecycle}-host-process.v1.json`,
      `r8-lifecycle-${lifecycle}-runtime-process.v1.json`,
    ]),
  ].sort(asciiCompare));
}

export function r8ProcessEvidenceNamesForPhase(phase) {
  const names = [];
  const apiStarted = ["api_starting", "api_ready", "fake_starting", "fake_ready", "desktop_starting",
    "desktop_spawned", "desktop_ready", "host_ready", "runtime_ready", ...S10BO1_CASES.slice(0, -1)]
    .includes(phase);
  if (!apiStarted) return Object.freeze(names);
  names.push("api-process.v1.json");
  const fakeStarted = ["fake_starting", "fake_ready", "desktop_starting", "desktop_spawned", "desktop_ready",
    "host_ready", "runtime_ready", ...S10BO1_CASES.slice(0, -1)].includes(phase);
  if (!fakeStarted) return Object.freeze(names);
  const lifecycleCount = ["s10b_005_planned_restart", "s10b_006", "s10b_007", "s10b_008", "s10b_009", "s10b_010", "s10b_011"].includes(phase) ? 2 : 1;
  const fakeCount = phase === "s10b_003" || phase === "s10b_004" ? 2
    : ["s10b_005_planned_restart", "s10b_006", "s10b_007", "s10b_008", "s10b_009"].includes(phase) ? 3
      : ["s10b_010", "s10b_011"].includes(phase) ? 4 : 1;
  names.push(...Array.from({ length: fakeCount }, (_, index) => `r8-fake-${index + 1}-process.v1.json`));
  const desktopStarted = ["desktop_starting", "desktop_spawned", "desktop_ready", "host_ready", "runtime_ready",
    "s10b_002", "s10b_003", "s10b_004", "s10b_005_planned_restart", "s10b_006", "s10b_007",
    "s10b_008", "s10b_009", "s10b_010", "s10b_011"].includes(phase);
  if (!desktopStarted) return Object.freeze(names.sort(asciiCompare));
  names.push(...Array.from({ length: lifecycleCount }, (_, index) => `r8-desktop-${index + 1}-process.v1.json`));
  const ownershipStarted = ["host_ready", "runtime_ready", "s10b_002", "s10b_003", "s10b_004",
    "s10b_005_planned_restart", "s10b_006", "s10b_007", "s10b_008", "s10b_009", "s10b_010", "s10b_011"].includes(phase);
  if (!ownershipStarted) return Object.freeze(names.sort(asciiCompare));
  const ownershipCount = lifecycleCount;
  names.push(...Array.from({ length: ownershipCount }, (_, index) => [
    `r8-lifecycle-${index + 1}-host-process.v1.json`,
    `r8-lifecycle-${index + 1}-runtime-process.v1.json`,
  ]).flat());
  return Object.freeze(names.sort(asciiCompare));
}

export function validateR8ProcessRecordSet(
  records,
  evidenceNames,
  { phase = "s10b_011", complete = false } = {},
) {
  if (!Array.isArray(records) || !Array.isArray(evidenceNames) ||
    records.length !== evidenceNames.length || new Set(evidenceNames).size !== evidenceNames.length ||
    new Set(records.map((record) => record.pid)).size !== records.length) {
    fail("orchestrator_existing_evidence_incomplete");
  }
  const allowedNames = r8ProcessEvidenceNamesForPhase(phase);
  if (evidenceNames.some((name) => !allowedNames.includes(name))) {
    fail("orchestrator_existing_evidence_incomplete");
  }
  const roleForName = (name) => name === "api-process.v1.json" ? "api"
    : /^r8-fake-\d+-process\.v1\.json$/.test(name) ? "fake"
      : /^r8-desktop-\d+-process\.v1\.json$/.test(name) ? "desktop"
        : /^r8-lifecycle-\d+-host-process\.v1\.json$/.test(name) ? "host"
          : /^r8-lifecycle-\d+-runtime-process\.v1\.json$/.test(name) ? "runtime"
            : null;
  if (evidenceNames.some((name, index) => roleForName(name) !== records[index]?.role)) {
    fail("orchestrator_existing_evidence_incomplete");
  }
  const roleCounts = new Map();
  for (const record of records) {
    const count = roleCounts.get(record.role) ?? 0;
    roleCounts.set(record.role, count + 1);
  }
  if ((roleCounts.get("api") ?? 0) > 1 || (roleCounts.get("fake") ?? 0) > 4 ||
    (roleCounts.get("desktop") ?? 0) > 2 || (roleCounts.get("host") ?? 0) > 2 ||
    (roleCounts.get("runtime") ?? 0) > 2 || (complete && (
      roleCounts.get("api") !== 1 || roleCounts.get("fake") !== 4 ||
      roleCounts.get("desktop") !== 2 || roleCounts.get("host") !== 2 || roleCounts.get("runtime") !== 2
    ))) {
    fail("orchestrator_existing_evidence_incomplete");
  }
  const byName = new Map(evidenceNames.map((name, index) => [name, records[index]]));
  const numberedNames = (pattern) => evidenceNames.flatMap((name) => {
    const match = pattern.exec(name);
    return match ? [Number(match[1])] : [];
  });
  const requireContiguous = (numbers) => {
    const ordered = [...numbers].sort((left, right) => left - right);
    if (ordered.some((number, index) => number !== index + 1)) {
      fail("orchestrator_existing_evidence_incomplete");
    }
  };
  const fakeGenerations = numberedNames(/^r8-fake-(\d+)-process\.v1\.json$/);
  const desktopLifecycles = numberedNames(/^r8-desktop-(\d+)-process\.v1\.json$/);
  const hostLifecycles = numberedNames(/^r8-lifecycle-(\d+)-host-process\.v1\.json$/);
  const runtimeLifecycles = numberedNames(/^r8-lifecycle-(\d+)-runtime-process\.v1\.json$/);
  for (const numbers of [fakeGenerations, desktopLifecycles, hostLifecycles, runtimeLifecycles]) {
    requireContiguous(numbers);
  }
  if (
    hostLifecycles.length !== runtimeLifecycles.length ||
    hostLifecycles.some((lifecycle, index) => runtimeLifecycles[index] !== lifecycle)
  ) fail("orchestrator_existing_evidence_incomplete");
  const api = byName.get("api-process.v1.json");
  if ((!api && records.length !== 0) || (api && ![...byName.entries()]
    .filter(([name]) => /^r8-(?:fake|desktop)-/.test(name))
    .every(([, record]) => record.ppid === api.ppid))) {
    fail("orchestrator_existing_evidence_incomplete");
  }
  for (const lifecycle of hostLifecycles) {
    const desktop = byName.get(`r8-desktop-${lifecycle}-process.v1.json`);
    const host = byName.get(`r8-lifecycle-${lifecycle}-host-process.v1.json`);
    const runtime = byName.get(`r8-lifecycle-${lifecycle}-runtime-process.v1.json`);
    if (!desktop || !host || !runtime || host.ppid !== desktop.pid || runtime.ppid !== host.pid) {
      fail("orchestrator_existing_evidence_incomplete");
    }
  }
  if (complete && JSON.stringify([...evidenceNames].sort(asciiCompare)) !==
    JSON.stringify(r8ProcessEvidenceNames())) {
    fail("orchestrator_existing_evidence_incomplete");
  }
  return true;
}

function r8CompletedCaseCountForPhase(phase) {
  const index = S10BO1_CASES.slice(0, -1).indexOf(phase);
  return index < 0 ? 0 : index + 1;
}

export function r8NoLogRequiredEvidenceNames(context) {
  if (!context?.r8) return Object.freeze([]);
  const names = new Set();
  const reachedPhase = context.phase ?? context.r8CaseEvidence?.at(-1)?.case_id ?? "created";
  const completedCases = Math.max(
    r8CompletedCaseCountForPhase(reachedPhase),
    context.phase ? 0 : (context.r8CaseEvidence?.length ?? 0),
  );
  const reachedApiVerifier = context.apiVerifierBefore && [
    "api_ready", "fake_starting", "fake_ready", "desktop_starting", "desktop_spawned",
    "desktop_ready", "host_ready", "runtime_ready", ...S10BO1_CASES.slice(0, -1),
  ].includes(reachedPhase);
  if (reachedApiVerifier) names.add("api-verifier-before.v1.json");
  const currentGeneration = context.fakeSpec?.generation ?? Number.MAX_SAFE_INTEGER;
  const finalCount = context.r8Business && completedCases === 10
    ? context.r8FakeAuthorities?.length ?? 0
    : Math.min(
      context.r8FakeAuthorities?.length ?? 0,
      Math.max(0, currentGeneration - 1),
    );
  for (let generation = 1; generation <= finalCount; generation += 1) {
    names.add(`r8-fake-${generation}-before.v1.json`);
    names.add(`r8-fake-${generation}-final.v1.json`);
  }
  if (
    context.fakeSpec && context.fakeAuthorityBefore &&
    context.fakeAuthorityBefore.generation === context.fakeSpec.generation
  ) names.add(`r8-fake-${context.fakeSpec.generation}-before.v1.json`);
  const caseCount = Math.min(context.r8CaseEvidence?.length ?? 0, completedCases);
  for (let ordinal = 1; ordinal <= caseCount; ordinal += 1) {
    names.add(`r8-case-${String(ordinal).padStart(2, "0")}.v1.json`);
  }
  if (context.r8Business && reachedPhase === "s10b_011" && caseCount === 10) {
    names.add("r8-api-verifier-after.v1.json");
    names.add("r8-business-boundary.v1.json");
  }
  return Object.freeze([...names].sort(asciiCompare));
}

export function r8OwnershipStoppedEvidenceRequired(context, lifecycle) {
  if (!context.r8) return true;
  return Boolean((context.ownershipHistory ?? []).find((ownership) =>
    ownership.hostEvidenceName === `r8-lifecycle-${lifecycle}-host-evidence.v1.json`,
  )?.hostStoppedEvidence);
}

export function r8PersistedStoppedEvidenceRequired(context, lifecycle) {
  if (!context?.r8) return true;
  return Boolean(context.requireCompleteR8Evidence || (lifecycle === 1 && [
    "s10b_005_planned_restart", "s10b_006", "s10b_007", "s10b_008", "s10b_009",
    "s10b_010", "s10b_011",
  ].includes(context.phase)));
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
  let primaryFailurePersistenceAttempted = false;
  let primaryEvidenceFailure;
  let cleanupPassed = false;
  let noLogAuthorityCaptureAttempted = false;
  const captureNoLogAuthority = async () => {
    if (noLogAuthorityCaptureAttempted) return;
    noLogAuthorityCaptureAttempted = true;
    if (typeof operations.captureNoLogAuthority !== "function") {
      fail("orchestrator_no_log_invalid");
    }
    await operations.captureNoLogAuthority();
  };
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
    await captureNoLogAuthority();
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
      await captureNoLogAuthority();
    } catch {
      // The original startup failure remains primary; the final no-log scan fails closed.
    }
    if (typeof operations.recordFailure === "function") {
      primaryFailurePersistenceAttempted = true;
      try {
        await operations.recordFailure({
          failureClass: primaryFailure.code,
          businessFailureClass: null,
          cleanupFailureClass: null,
          parentFailureClass: null,
        });
      } catch (persistenceError) {
        primaryEvidenceFailure = persistenceError instanceof S10BO1OrchestratorError
          ? persistenceError
          : new S10BO1OrchestratorError("orchestrator_evidence_write_failed");
      }
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

  let evidenceFailure = primaryEvidenceFailure ?? (primaryFailure?.closure?.evidence_failure_class
    ? new S10BO1OrchestratorError(primaryFailure.closure.evidence_failure_class)
    : undefined);
  if (evidenceFailure) retainFirstSecondary(evidenceFailure);
  let failureRecorded = primaryFailurePersistenceAttempted;
  const preNoLogFailure = primaryFailure ?? businessFailure ?? cleanupFailure ?? parentFailure;
  if (!failureRecorded && preNoLogFailure && typeof operations.recordFailure === "function") {
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
  if (primaryFailure && businessFailure) {
    businessFailure = null;
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
    s10b_r8_executed: expectedR8(authority),
  });
}

export async function runR8Flow(authority, operations) {
  if (!expectedR8(authority)) fail("orchestrator_r8_authority_invalid");
  const machine = createR8StateMachine();
  let primaryFailure;
  let evidenceFailure;
  let cleanup;
  let cleanupFailure;
  let noLog;
  let noLogFailure;
  let business;
  let businessFailure;
  let parentFailure;
  let failureRecorded = false;
  const failAs = (error, fallback) => error instanceof S10BO1OrchestratorError
    ? error
    : new S10BO1OrchestratorError(fallback);
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
    await operations.startFakeGeneration(S10B_R8_FAKE_GENERATIONS[0]);
    machine.transition("fake_ready");
    await operations.startDesktopLifecycle(1, "before_restart");
    machine.transition("desktop_ready");
    await operations.readLifecycleOwnership(1);
    machine.transition("host_ready");
    machine.transition("runtime_ready");
    for (const caseId of ["s10b_002", "s10b_003"]) {
      await operations.executeCase(caseId);
      machine.transition(caseId);
    }
    await operations.startFakeGeneration(S10B_R8_FAKE_GENERATIONS[1]);
    for (const caseId of ["s10b_004"]) {
      await operations.executeCase(caseId);
      machine.transition(caseId);
    }
    await operations.completePlannedRestart();
    await operations.startFakeGeneration(S10B_R8_FAKE_GENERATIONS[2]);
    await operations.startDesktopLifecycle(2, "after_restart");
    await operations.readLifecycleOwnership(2);
    for (const caseId of [
      "s10b_005_planned_restart", "s10b_006", "s10b_007", "s10b_008", "s10b_009", "s10b_010",
    ]) {
      await operations.executeCase(caseId);
      machine.transition(caseId);
    }
    await operations.startFakeGeneration(S10B_R8_FAKE_GENERATIONS[3]);
    await operations.executeCase("s10b_011");
    machine.transition("s10b_011");
    await operations.completeAbort();
  } catch (error) {
    primaryFailure = failAs(error, "orchestrator_internal_failure");
    try { machine.abort(); } catch { /* Preserve the first leaf. */ }
    try { await operations.captureNoLogAuthority(); } catch { /* Final scan fails closed. */ }
    try {
      await operations.recordFailure({
        failureClass: primaryFailure.code,
        businessFailureClass: null,
        cleanupFailureClass: null,
        parentFailureClass: null,
      });
      failureRecorded = true;
    } catch (error_) {
      evidenceFailure = failAs(error_, "orchestrator_evidence_write_failed");
    }
    try { await operations.initiateDesktopAbort?.(); } catch { /* Cleanup remains mandatory. */ }
  }
  if (!primaryFailure) {
    try {
      business = await operations.verifyR8Business();
      validateR8BusinessEvidence(business, authority.runId);
    } catch (error) {
      businessFailure = failAs(error, "orchestrator_business_boundary_unknown");
    }
  }
  try {
    cleanup = await operations.cleanup();
    validateCleanupClosure(cleanup);
  } catch (error) {
    cleanupFailure = failAs(error, "orchestrator_cleanup_unknown");
  }
  try {
    operations.assertParentAlive?.();
  } catch (error) {
    parentFailure = failAs(error, "orchestrator_parent_death");
  }
  const preScanFailure = primaryFailure ?? businessFailure ?? cleanupFailure ?? parentFailure ?? evidenceFailure;
  if (!failureRecorded && preScanFailure) {
    try {
      await operations.recordFailure({
        failureClass: preScanFailure.code,
        businessFailureClass: businessFailure?.code ?? null,
        cleanupFailureClass: cleanupFailure?.code ?? null,
        parentFailureClass: parentFailure?.code ?? null,
      });
      failureRecorded = true;
    } catch (error) {
      evidenceFailure ??= failAs(error, "orchestrator_evidence_write_failed");
    }
  }
  try {
    noLog = await operations.scanNoLog();
    validateNoLogResult(noLog);
  } catch (error) {
    noLogFailure = failAs(error, "orchestrator_no_log_invalid");
  }
  let failure = primaryFailure ?? businessFailure ?? cleanupFailure ?? parentFailure ??
    evidenceFailure ?? noLogFailure;
  if (!failureRecorded && failure) {
    try {
      await operations.recordFailure({
        failureClass: failure.code,
        businessFailureClass: businessFailure?.code ?? null,
        cleanupFailureClass: cleanupFailure?.code ?? null,
        parentFailureClass: parentFailure?.code ?? null,
      });
      failureRecorded = true;
    } catch (error) {
      evidenceFailure ??= failAs(error, "orchestrator_evidence_write_failed");
      failure = failure ?? evidenceFailure;
    }
  }
  const businessStatus = business ? "passed" : businessFailure ? "failed"
    : primaryFailure ? "not_applicable" : "unknown";
  try {
    await operations.recordClosure({
      status: failure ? "failed" : "passed",
      failureClass: failure?.code ?? null,
      businessFailureClass: businessFailure?.code ?? null,
      businessStatus,
      cleanupFailureClass: cleanupFailure?.code ?? null,
      cleanupScope: cleanup?.scope ?? null,
      evidenceFailureClass: evidenceFailure?.code ?? null,
      noLogFailureClass: noLogFailure?.code ?? null,
      noLogScope: noLog?.scope ?? null,
      parentFailureClass: parentFailure?.code ?? null,
    });
  } catch (error) {
    evidenceFailure ??= failAs(error, "orchestrator_evidence_write_failed");
    failure ??= evidenceFailure;
  }
  if (failure) {
    try { machine.closeFailure(Boolean(cleanup && !cleanupFailure)); } catch { /* First leaf wins. */ }
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
  return Object.freeze({
    schema_version: 1,
    status: "passed",
    scope: "LIA-126-048-fresh-r8",
    run_id: authority.runId,
    state: machine.state,
    business,
    cleanup,
    no_log: noLog,
    s10b_r8_executed: true,
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

function expectedR8(authority) {
  return authority?.r8 === true;
}

export function validateAttemptPreclaim(value, authority) {
  if (
    value === null || Array.isArray(value) || typeof value !== "object" ||
    !exactKeys(value, ATTEMPT_PRECLAIM_KEYS) || value.schema_version !== 1 ||
    value.kind !== (expectedR8(authority) ? "feat126-s10b-r8-preclaim" : "feat126-s10b-preclaim") ||
    value.status !== "reserved" || value.run_id !== authority?.runId ||
    value.s10b_r8_executed !== expectedR8(authority) ||
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
    value.s10b_r8_executed !== expectedR8(authority) || !DIGEST_PATTERN.test(value.preclaim_sha256 ?? "") ||
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
  desktop_ready: Object.freeze({ required: EXISTING_PROCESS_ROLES, allowed: EXISTING_PROCESS_ROLES }),
  host_ready: Object.freeze({ required: EXISTING_PROCESS_ROLES, allowed: EXISTING_PROCESS_ROLES }),
  runtime_ready: Object.freeze({ required: EXISTING_PROCESS_ROLES, allowed: EXISTING_PROCESS_ROLES }),
  ...Object.fromEntries(S10BO1_CASES.slice(0, -1).map((phase) => [
    phase,
    Object.freeze({ required: EXISTING_PROCESS_ROLES, allowed: EXISTING_PROCESS_ROLES }),
  ])),
});

const PRE_OWNERSHIP_DESKTOP_FAILURE_CLASSES = Object.freeze([
  ...DESKTOP_STARTUP_FAILURE_CLASSES,
  "orchestrator_control_eof",
  "orchestrator_control_frame_invalid",
  "orchestrator_control_frame_oversize",
  "orchestrator_control_order_invalid",
  "orchestrator_control_timeout",
  "orchestrator_api_exited_early",
  "orchestrator_desktop_exited_early",
  "orchestrator_fake_exited_early",
]);

function validateFailureClassOrNull(value) {
  return value === null || /^[a-z][a-z0-9_]{0,127}$/.test(value ?? "");
}

function isKnownPreOwnershipDesktopFailure(value) {
  return ["desktop_starting", "desktop_spawned"].includes(value?.phase) &&
    PRE_OWNERSHIP_DESKTOP_FAILURE_CLASSES.includes(value.failure_class) &&
    JSON.stringify(value.process_roles) === JSON.stringify(["api", "desktop", "fake"]);
}

function isKnownR8OwnershipFailure(value) {
  return value?.s10b_r8_executed === true && value.phase === "desktop_ready" &&
    [
      "orchestrator_artifact_invalid",
      "orchestrator_host_evidence_invalid",
      "orchestrator_ownership_invalid",
      "orchestrator_process_identity_unknown",
      "orchestrator_runtime_evidence_invalid",
    ].includes(value.failure_class) &&
    JSON.stringify(value.process_roles) === JSON.stringify(["api", "desktop", "fake"]);
}

function requiresCompleteDescendantProcessRoles(value) {
  return (value.phase === "desktop_starting" && value.process_roles.includes("desktop")) || [
    "desktop_spawned",
    "component_ready",
    "abort_sent",
    "abort_complete",
    "desktop_exited",
    "desktop_ready",
    "host_ready",
    "runtime_ready",
    ...S10BO1_CASES.slice(0, -1),
  ].includes(value.phase);
}

export function validateReconcileFailureProcessState(failure) {
  if (
    failure && requiresCompleteDescendantProcessRoles(failure) &&
    failure.process_roles.length !== EXISTING_PROCESS_ROLES.length &&
    !isKnownPreOwnershipDesktopFailure(failure) && !isKnownR8OwnershipFailure(failure)
  ) fail("orchestrator_cleanup_unknown");
  return true;
}

function validateAttemptPhaseState(value) {
  const rule = ATTEMPT_PHASE_PROCESS_RULES[value.phase];
  const roles = value.process_roles;
  const retainedVolumeKeys = value.retained_volume_keys;
  if (
    !rule || !Array.isArray(roles) || new Set(roles).size !== roles.length ||
    JSON.stringify(roles) !== JSON.stringify(EXISTING_PROCESS_ROLES.filter((role) => roles.includes(role))) ||
    roles.some((role) => !rule.allowed.includes(role)) ||
    (rule.required.some((role) => !roles.includes(role)) &&
      !isKnownR8OwnershipFailure(value)) ||
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
    requiresCompleteDescendantProcessRoles(value) &&
    roles.length !== EXISTING_PROCESS_ROLES.length && value.cleanup_failure_class === null &&
    !isKnownPreOwnershipDesktopFailure(value) && !isKnownR8OwnershipFailure(value)
  ) return false;
  return true;
}

export function validateAttemptMarker(value, authority) {
  if (
    value === null || Array.isArray(value) || typeof value !== "object" ||
    !exactKeys(value, ATTEMPT_MARKER_KEYS) || value.schema_version !== 1 ||
    value.kind !== (expectedR8(authority) ? "feat126-s10b-r8-attempt" : "feat126-s10bo2-attempt") ||
    value.status !== "claimed" || value.run_id !== authority?.runId ||
    value.s10b_r8_executed !== expectedR8(authority) ||
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
    value.s10b_r8_executed !== expectedR8(authority) || !ATTEMPT_PHASES.has(value.phase) ||
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
    value.s10b_r8_executed !== expectedR8(authority) || !DIGEST_PATTERN.test(value.attempt_marker_sha256 ?? "") ||
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
      (value.cleanup_failure_class === null && value.cleanup_scope === null) ||
      (value.no_log_failure_class === null && value.no_log_scope === null) ||
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
    value.s10b_r8_executed !== expectedR8(authority) || !DIGEST_PATTERN.test(value.attempt_marker_sha256 ?? "") ||
    !/^[a-z][a-z0-9_]{0,127}$/.test(value.failure_class ?? "") ||
    !["passed", "not_applicable", "unknown", "failed"].includes(value.business_status) ||
    ![null, "pre_run_absence", "preflight_artifacts", "run_artifacts"].includes(
      value.cleanup_scope,
    ) ||
    ![null, "attempt_only", "preflight_artifacts", "run_artifacts"].includes(value.no_log_scope) ||
    !validateFailureClassOrNull(value.cleanup_failure_class) ||
    !validateFailureClassOrNull(value.no_log_failure_class) ||
    (value.cleanup_failure_class === null && value.cleanup_scope === null) ||
    (value.no_log_failure_class === null && value.no_log_scope === null)
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
    s10b_r8_executed: expectedR8(authority),
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
    s10b_r8_executed: expectedR8(authority),
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
  const inspectIdentity = options.inspectIdentity ?? inspectProcessIdentityWithRetry;
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
    kind: expectedR8(authority) ? "feat126-s10b-r8-preclaim" : "feat126-s10b-preclaim",
    status: "reserved",
    run_id: authority.runId,
    repositories: authority.repositories,
    pid: process.pid,
    ppid: Math.max(process.ppid, 1),
    s10b_r8_executed: expectedR8(authority),
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
      kind: expectedR8(authority) ? "feat126-s10b-r8-attempt" : "feat126-s10bo2-attempt",
      status: "claimed",
      run_id: authority.runId,
      repositories: authority.repositories,
      pid: identity.pid,
      ppid: identity.ppid,
      start_identity: identity.start_identity,
      binary_sha256: identity.binary_sha256,
      script_sha256: scriptSha256,
      s10b_r8_executed: expectedR8(authority),
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

export async function inspectProcessIdentityWithRetry(pid, options = {}) {
  const inspect = options.inspect ?? inspectProcessIdentity;
  const wait = options.wait ?? ((duration) => new Promise((resolveWait) => setTimeout(resolveWait, duration)));
  const attempts = options.attempts ?? 3;
  if (!Number.isSafeInteger(attempts) || attempts < 1 || attempts > 3) {
    fail("orchestrator_process_identity_unknown");
  }
  let lastError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await inspect(pid);
    } catch (error) {
      if (!(error instanceof S10BO1OrchestratorError) || error.code !== "orchestrator_process_identity_unknown") {
        throw error;
      }
      lastError = error;
      if (attempt + 1 < attempts) await wait(20);
    }
  }
  throw lastError;
}

export async function inspectExpectedProcessIdentityWithRetry(pid, expected, options = {}) {
  const inspect = options.inspect ?? inspectProcessIdentityWithRetry;
  const wait = options.wait ?? ((duration) => new Promise((resolveWait) => setTimeout(resolveWait, duration)));
  const attempts = options.attempts ?? 3;
  if (
    !Number.isSafeInteger(expected?.ppid) || expected.ppid <= 0 ||
    !DIGEST_PATTERN.test(expected?.binarySha256 ?? "") ||
    !Number.isSafeInteger(attempts) || attempts < 1 || attempts > 3
  ) fail("orchestrator_process_identity_unknown");
  let identity = null;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    identity = await inspect(pid);
    if (
      identity !== null && identity.ppid === expected.ppid &&
      identity.binary_sha256 === expected.binarySha256
    ) return identity;
    if (attempt + 1 < attempts) await wait(20);
  }
  return identity;
}

async function captureProcessIdentity(child, expectedBinarySha256, inspect = inspectProcessIdentityWithRetry) {
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
  inspect = inspectProcessIdentityWithRetry,
  onSpawn,
  deferIdentityOnExit = false,
  evidenceBasename = role,
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
    evidenceBasename,
    record: null,
    logPath,
    role,
    provisional: true,
  };
  context.processes[role] = provisional;
  context.processHistory ??= [];
  context.processHistory.push(provisional);
  child.on("error", () => {
    context.cleanupUnknown = true;
    provisional.processError = true;
  });
  if (onSpawn) {
    try {
      await onSpawn(provisional);
    } catch (error) {
      context.cleanupUnknown = true;
      await logHandle.close().catch(() => {});
      throw error instanceof S10BO1OrchestratorError
        ? error
        : new S10BO1OrchestratorError("orchestrator_control_channel_invalid");
    }
  }
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
    if (
      deferIdentityOnExit &&
      error instanceof S10BO1OrchestratorError &&
      ["orchestrator_process_exited_early", "orchestrator_process_identity_unknown"].includes(
        error.code,
      ) &&
      (child.exitCode !== null || child.signalCode !== null)
    ) {
      provisional.earlyExit = true;
      return provisional;
    }
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
  await writeSecureJson(resolve(context.evidenceRoot, `${evidenceBasename}-process.v1.json`), record);
  return provisional;
}

function childExit(child, role, signal = null) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return Promise.reject(new S10BO1OrchestratorError(`orchestrator_${role}_exited_early`));
  }
  return new Promise((_, reject) => {
    const cleanup = () => {
      child.removeListener("exit", onExit);
      child.removeListener("error", onError);
    };
    const onExit = () => {
      cleanup();
      reject(new S10BO1OrchestratorError(`orchestrator_${role}_exited_early`));
    };
    const onError = () => {
      cleanup();
      reject(new S10BO1OrchestratorError(`orchestrator_${role}_process_failed`));
    };
    child.once("exit", onExit);
    child.once("error", onError);
    signal?.addEventListener("abort", cleanup, { once: true });
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
  const current = await inspectProcessIdentityWithRetry(process_.record.pid);
  if (current === null) return "absent";
  if (!sameProcessIdentity(process_.record, current)) return "foreign_identity_preserved";
  process_.child.kill("SIGTERM");
  const stopped = await Promise.race([
    new Promise((resolveExit) => process_.child.once("exit", () => resolveExit(true))),
    new Promise((resolveTimeout) => setTimeout(() => resolveTimeout(false), PROCESS_STOP_TIMEOUT_MS)),
  ]);
  if (stopped) return "stopped";
  const afterTerm = await inspectProcessIdentityWithRetry(process_.record.pid);
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
    processHistory: [],
    descendantProcessHistory: [],
    ownershipHistory: [],
    r8CaseEvidence: [],
    r8FakeAuthorities: [],
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

export function desktopProductionBuildFeatures(features = DESKTOP_PRODUCTION_FEATURES) {
  if (
    !Array.isArray(features) ||
    JSON.stringify(features) !== JSON.stringify(DESKTOP_PRODUCTION_FEATURES)
  ) fail("orchestrator_desktop_build_invalid");
  return features.join(",");
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
  const frontendEnvironment = {
    VITE_FEAT126_S10_DRIVER: "true",
    ...(expectedR8(context) ? { VITE_FEAT126_S10_R8: "true" } : {}),
  };
  await runCommand("desktop_frontend_typecheck", "pnpm", ["exec", "vue-tsc", "--noEmit"], {
    cwd: DESKTOP_ROOT,
    env: commandEnvironment(frontendEnvironment),
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
    env: commandEnvironment(frontendEnvironment),
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
      desktopProductionBuildFeatures(),
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

async function startFake(context, specification = {}) {
  const mode = specification.mode ?? "complete";
  const generation = specification.generation ?? 1;
  const callCap = specification.callCap ?? 1;
  const binary = resolve(context.binRoot, "feat126-fake-responses");
  context.processes.fake = await spawnOwnedProcess({
    role: "fake",
    binary,
    cwd: INFRA_ROOT,
    environment: commandEnvironment({
      YIJIE_FEAT126_S10_TEST_PROFILE_ENABLED: "true",
      YIJIE_FEAT126_S10_RUN_ID: context.runId,
      YIJIE_FEAT126_FAKE_RESPONSES_MODE: mode,
      YIJIE_FEAT126_S10_FAKE_GENERATION: String(generation),
      YIJIE_FEAT126_FAKE_RESPONSES_MAX_CALLS: String(callCap),
    }),
    logPath: resolve(context.logRoot, specification.logName ?? "fake-orchestrator.log"),
    evidenceBasename: specification.evidenceBasename ?? "fake",
  }, context);
  context.fakeSpec = Object.freeze({ mode, generation, callCap });
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
        resolve(context.evidenceRoot, specification.authorityBeforeName ?? "fake-authority-before.v1.json"),
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

export function desktopEnvironment(context) {
  const issuer = "https://localhost:8443/realms/yijie-local";
  const oidc = `${issuer}/protocol/openid-connect`;
  const r8 = context.r8Phase ? {
    YIJIE_FEAT126_S10_R8_ENABLED: "true",
    YIJIE_FEAT126_S10_R8_PHASE: context.r8Phase,
  } : {};
  return commandEnvironment({
    YIJIE_ENV: "local",
    YIJIE_FEAT126_S10_TEST_PROFILE_ENABLED: "true",
    YIJIE_FEAT126_S10_DRIVER_ENABLED: "true",
    YIJIE_FEAT126_S10_DRIVER_NONCE: context.nonce,
    YIJIE_FEAT126_S10_RUN_ID: context.runId,
    YIJIE_FEAT126_S10_RUN_ROOT: context.runRoot,
    YIJIE_FEAT126_S10P3_REAL_MAIN_CHAIN: "true",
    YIJIE_FEAT126_S10_SECURE_STORAGE_ENABLED: "false",
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
    ...r8,
  });
}

async function startDesktop(context, specification = {}) {
  context.nonce = specification.nonce ?? context.nonce;
  context.r8Phase = specification.r8Phase;
  context.processes.desktop = await spawnOwnedProcess({
    role: "desktop",
    binary: context.desktopBinary,
    cwd: DESKTOP_ROOT,
    environment: desktopEnvironment(context),
    logPath: resolve(context.logRoot, specification.logName ?? "desktop-orchestrator.log"),
    evidenceBasename: specification.evidenceBasename ?? "desktop",
    extraStdio: ["pipe", "pipe"],
    deferIdentityOnExit: true,
    onSpawn(provisional) {
      context.controlWriter = provisional.child.stdio[3];
      guardControlWriter(context.controlWriter);
      context.controlWriter.on("error", () => { context.cleanupUnknown = true; });
      context.controlReader = specification.r8Phase
        ? createR8ControlFrameReader(provisional.child.stdio[4], context)
        : createControlFrameReader(provisional.child.stdio[4], context);
      context.pendingDesktopFrame = context.controlReader.next("component_ready");
      context.pendingDesktopFrame.catch(() => {});
    },
  }, context);
}

export async function readDesktopFrame(context, expectedKind, expectedCaseId = null) {
  const controlFrame = expectedKind === "component_ready" && context.pendingDesktopFrame
    ? context.pendingDesktopFrame
    : context.r8
      ? context.controlReader.next(expectedKind, expectedCaseId)
      : context.controlReader.next(expectedKind);
  if (expectedKind === "component_ready") context.pendingDesktopFrame = null;
  const settle = (kind, promise) => promise.then(
    (value) => Object.freeze({ kind, value }),
    (error) => Object.freeze({ error, kind }),
  );
  const observation = new AbortController();
  const controlOutcome = settle("control", controlFrame);
  const readers = [
    controlOutcome,
    settle("api_exit", childExit(context.processes.api.child, "api", observation.signal)),
    settle("fake_exit", childExit(context.processes.fake.child, "fake", observation.signal)),
    settle("desktop_exit", childExit(context.processes.desktop.child, "desktop", observation.signal)),
  ];
  const isDesktopFailureLeaf = (outcome) => outcome?.error instanceof S10BO1OrchestratorError && [
    ...DESKTOP_STARTUP_FAILURE_CLASSES,
    ...DESKTOP_POST_READY_FAILURE_CLASSES,
  ].includes(outcome.error.code);
  try {
    let outcome = await Promise.race(readers);
    if (outcome.kind.endsWith("_exit")) {
      const queuedControl = await Promise.race([
        controlOutcome,
        new Promise((resolveQueued) => setTimeout(
          () => resolveQueued(null),
          DESKTOP_EXIT_DRAIN_TIMEOUT_MS,
        )),
      ]);
      if (isDesktopFailureLeaf(queuedControl)) outcome = queuedControl;
    }
    if (outcome.error) throw outcome.error;
    if (outcome.kind !== "control") fail("orchestrator_internal_failure");
    const frame = outcome.value;
    if (expectedKind === "component_ready" && context.processes.desktop.earlyExit) {
      fail("orchestrator_desktop_exited_early");
    }
    return frame;
  } catch (error) {
    if (
      expectedKind === "component_ready" && error instanceof S10BO1OrchestratorError &&
      DESKTOP_STARTUP_FAILURE_CLASSES.includes(error.code)
    ) context.phase = "desktop_starting";
    throw error;
  } finally {
    observation.abort();
  }
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

export async function sendR8ControlFrame(context, kind, caseId = null) {
  const previousSequence = context.r8ControlSequence ?? 0;
  const frame = {
    schema_version: 1,
    run_id: context.runId,
    nonce: context.nonce,
    sequence: previousSequence + 1,
    kind,
    ...(caseId === null ? {} : { case_id: caseId }),
  };
  await writeFrame(context.controlWriter, encodeR8ControlFrame(frame, {
    runId: context.runId,
    nonce: context.nonce,
    previousSequence,
  }));
  context.r8ControlSequence = frame.sequence;
  if (["planned_restart", "abort"].includes(kind)) {
    await closeControlWriter(context.controlWriter);
  }
  return Object.freeze(frame);
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
  if (entries.length < 1 || entries.some((entry) => !entry.isDirectory() || entry.isSymbolicLink())) {
    fail("orchestrator_host_evidence_invalid");
  }
  const knownNonces = new Set((context.ownershipHistory ?? []).map(
    (entry) => entry.hostEvidence?.instanceNonce,
  ).filter(Boolean));
  const unknownEntries = entries.filter((entry) => !knownNonces.has(entry.name));
  if (previousEvidence) {
    if (unknownEntries.length !== 0 || entries.filter(
      (entry) => entry.name === previousEvidence.instanceNonce,
    ).length !== 1) fail("orchestrator_host_evidence_invalid");
  } else if (knownNonces.size === 0) {
    if (entries.length !== 1) fail("orchestrator_host_evidence_invalid");
  } else if (unknownEntries.length !== 1) {
    fail("orchestrator_host_evidence_invalid");
  }
  const candidates = previousEvidence
    ? entries.filter((entry) => entry.name === previousEvidence.instanceNonce)
    : knownNonces.size === 0 ? entries : unknownEntries;
  if (candidates.length < 1) fail("orchestrator_host_evidence_invalid");
  let accepted;
  let duplicate = false;
  for (const entry of candidates) {
    const evidenceDirectory = resolve(hostRoot, entry.name);
    try {
      await requireOwnerDirectory(evidenceDirectory);
      const bytes = await readSecureFile(resolve(evidenceDirectory, "process.json"), 16 * 1024);
      const value = JSON.parse(bytes.toString("utf8"));
      let binarySha256;
      try {
        binarySha256 = await hashFile(resolve(context.binRoot, "yijie-agent-host"));
      } catch {
        fail("orchestrator_host_evidence_invalid");
      }
      const evidence = validateHostProcessEvidence(value, {
        runId: context.runId,
        desktopPid: previousEvidence?.ppid ?? context.processes.desktop.record.pid,
        binarySha256,
        expectedState,
        expectedPid: previousEvidence?.pid,
        expectedNonce: previousEvidence?.instanceNonce,
        expectedStartedAtUnixMs: previousEvidence?.startedAtUnixMs,
      });
      if (entry.name !== evidence.instanceNonce) fail("orchestrator_host_evidence_invalid");
      if (accepted) duplicate = true;
      else accepted = evidence;
    } catch (error) {
      if (previousEvidence) throw error;
    }
  }
  if (!accepted || duplicate) fail("orchestrator_host_evidence_invalid");
  return accepted;
}

async function requestRuntimeEvidence(context, hostEvidence) {
  const value = await observeRuntimeEvidenceWithRetry(() => new Promise((resolveEvidence, rejectEvidence) => {
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
  }));
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

export async function observeRuntimeEvidenceWithRetry(observe, options = {}) {
  const wait = options.wait ?? ((duration) => new Promise((resolveWait) => setTimeout(resolveWait, duration)));
  const attempts = options.attempts ?? 3;
  if (typeof observe !== "function" || !Number.isSafeInteger(attempts) || attempts < 1 || attempts > 3) {
    fail("orchestrator_runtime_evidence_invalid");
  }
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await observe();
    } catch {
      if (attempt + 1 < attempts) await wait(50);
    }
  }
  fail("orchestrator_runtime_evidence_invalid");
}

async function readOwnershipEvidence(context, specification = {}) {
  const hostEvidence = await readHostProcessEvidence(context, "ready");
  const runtimeEvidence = await requestRuntimeEvidence(context, hostEvidence);
  const hostEvidenceName = specification.hostEvidenceName ?? "host-evidence.v1.json";
  const runtimeEvidenceName = specification.runtimeEvidenceName ?? "runtime-evidence.v1.json";
  const hostProcessName = specification.hostProcessName ?? "host-process.v1.json";
  const runtimeProcessName = specification.runtimeProcessName ?? "runtime-process.v1.json";
  const hostStoppedEvidenceName = specification.hostStoppedEvidenceName ?? "host-stopped-evidence.v1.json";
  await writeSecureJson(resolve(context.evidenceRoot, hostEvidenceName), hostEvidence);
  await writeSecureJson(resolve(context.evidenceRoot, runtimeEvidenceName), runtimeEvidence);
  const hostIdentity = await inspectExpectedProcessIdentityWithRetry(hostEvidence.pid, {
    ppid: context.processes.desktop.record.pid,
    binarySha256: hostEvidence.binarySha256,
  });
  const runtimeIdentity = await inspectExpectedProcessIdentityWithRetry(runtimeEvidence.pid, {
    ppid: hostEvidence.pid,
    binarySha256: runtimeEvidence.binary_sha256,
  });
  if (hostIdentity === null) fail("orchestrator_host_evidence_invalid");
  if (runtimeIdentity === null) fail("orchestrator_runtime_evidence_invalid");
  const hostRecord = validateProcessRecord({
    schema_version: 1,
    run_id: context.runId,
    role: "host",
    pid: hostEvidence.pid,
    ppid: hostIdentity.ppid,
    binary_sha256: hostIdentity.binary_sha256,
    start_identity: hostIdentity.start_identity,
  }, context.runId, "host");
  const runtimeRecord = validateProcessRecord({
    schema_version: 1,
    run_id: context.runId,
    role: "runtime",
    pid: runtimeEvidence.pid,
    ppid: runtimeIdentity.ppid,
    binary_sha256: runtimeIdentity.binary_sha256,
    start_identity: runtimeIdentity.start_identity,
  }, context.runId, "runtime");
  await writeSecureJson(resolve(context.evidenceRoot, hostProcessName), hostRecord);
  await writeSecureJson(resolve(context.evidenceRoot, runtimeProcessName), runtimeRecord);
  context.hostEvidence = hostEvidence;
  context.runtimeEvidence = runtimeEvidence;
  context.descendantProcesses = { host: hostRecord, runtime: runtimeRecord };
  context.descendantProcessHistory ??= [];
  context.descendantProcessHistory.push(hostRecord, runtimeRecord);
  context.ownershipHistory ??= [];
  context.ownershipHistory.push({
    hostEvidence,
    runtimeEvidence,
    hostEvidenceName,
    runtimeEvidenceName,
    hostProcessName,
    runtimeProcessName,
    hostStoppedEvidenceName,
  });
  if (
    hostIdentity.ppid !== context.processes.desktop.record.pid ||
    hostIdentity.binary_sha256 !== hostEvidence.binarySha256 ||
    runtimeIdentity.ppid !== hostEvidence.pid ||
    runtimeIdentity.binary_sha256 !== runtimeEvidence.binary_sha256
  ) fail("orchestrator_ownership_invalid");
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

async function validateStateRootMetadata(root) {
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
      let metadata;
      try {
        metadata = await lstat(path);
      } catch {
        fail("orchestrator_no_log_invalid");
      }
      if (
        metadata.isSymbolicLink() || !ownedByCurrentUser(metadata) ||
        (metadata.mode & 0o022) !== 0 || (await realpath(path)) !== path
      ) fail("orchestrator_no_log_invalid");
      if (metadata.isDirectory()) await visit(path);
      else if (!metadata.isFile() || metadata.nlink !== 1) {
        fail("orchestrator_no_log_invalid");
      }
    }
  }
  try {
    await lstat(root);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    fail("orchestrator_no_log_invalid");
  }
  try {
    await requireOwnerDirectory(root);
  } catch {
    fail("orchestrator_no_log_invalid");
  }
  await visit(root);
}

function encodedSecretPatterns(name, bytes) {
  const patterns = [
    { name: `${name}:hex`, value: bytes.toString("hex") },
    { name: `${name}:base64`, value: bytes.toString("base64") },
    { name: `${name}:base64url`, value: bytes.toString("base64url") },
  ];
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes).trim();
    if (text.length >= 16 && !/[\r\n\0]/.test(text)) {
      patterns.push({ name: `${name}:text`, value: text });
    }
  } catch {
    // Binary synthetic secrets remain covered by their closed encodings.
  }
  return patterns;
}

async function optionalSecureSecret(path, maximumBytes, minimumBytes = 1) {
  try {
    await lstat(path);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    fail("orchestrator_no_log_invalid");
  }
  try {
    return await readSecureFile(path, maximumBytes, [0o600], minimumBytes);
  } catch {
    fail("orchestrator_no_log_invalid");
  }
}

async function runScopedSecretPatterns(context) {
  if (!context.runRoot || context.runRootPresent === false) return [];
  const requireComplete = context.requireCompleteNoLogAuthority === true || [
    "component_ready", "abort_sent", "abort_complete", "desktop_exited",
  ].includes(context.phase);
  const patterns = [];
  const hostHome = resolve(context.runRoot, "host-home");
  const apiToken = await optionalSecureSecret(resolve(hostHome, "api-token"), 1024);
  if (requireComplete && apiToken === null) fail("orchestrator_no_log_invalid");
  if (apiToken !== null) {
    let token;
    try {
      token = new TextDecoder("utf-8", { fatal: true }).decode(apiToken).trim();
    } catch {
      fail("orchestrator_no_log_invalid");
    }
    if (!/^[A-Za-z0-9_-]{43}$/.test(token)) fail("orchestrator_no_log_invalid");
    patterns.push({ name: "state_secret:host_api_token", value: token });
  }
  const receiptKey = await optionalSecureSecret(
    resolve(hostHome, "cleanup-receipt.key"),
    32,
    32,
  );
  if (requireComplete && receiptKey === null) fail("orchestrator_no_log_invalid");
  if (receiptKey !== null) {
    patterns.push(...encodedSecretPatterns("state_secret:host_receipt_key", receiptKey));
  }

  const secretRoot = resolve(context.runRoot, "secure-storage", "ephemeral-secrets");
  const roles = [
    ["chat_sqlcipher", "chat-sqlcipher-v1.secret", 1, 32],
    ["receipt_hmac", "receipt-hmac-v1.secret", 2, 32],
    ["native_auth", "native-auth-v1.secret", 3, 16 * 1024],
  ];
  let secretRootPresent = true;
  try {
    await lstat(secretRoot);
  } catch (error) {
    if (error?.code === "ENOENT") secretRootPresent = false;
    else fail("orchestrator_no_log_invalid");
  }
  if (!secretRootPresent) {
    if (requireComplete) fail("orchestrator_no_log_invalid");
    return patterns;
  }
  try {
    await requireOwnerDirectory(secretRoot);
    const entries = await readdir(secretRoot, { withFileTypes: true });
    if (
      entries.some((entry) => !entry.isFile() || !roles.some(([, basename]) => basename === entry.name))
    ) fail("orchestrator_no_log_invalid");
  } catch {
    fail("orchestrator_no_log_invalid");
  }
  for (const [role, basename, tag, maximumPayloadBytes] of roles) {
    const encoded = await optionalSecureSecret(
      resolve(secretRoot, basename),
      14 + maximumPayloadBytes,
      15,
    );
    if (requireComplete && encoded === null) fail("orchestrator_no_log_invalid");
    if (encoded === null) continue;
    const payloadLength = encoded.length >= 14 ? encoded.readUInt32BE(10) : -1;
    if (
      encoded.length !== 14 + payloadLength ||
      !encoded.subarray(0, 8).equals(Buffer.from([0x59, 0x4a, 0x31, 0x32, 0x36, 0x53, 0x31, 0x00])) ||
      encoded[8] !== tag || encoded[9] !== 0 || payloadLength < 1 ||
      payloadLength > maximumPayloadBytes || (tag !== 3 && payloadLength !== 32)
    ) fail("orchestrator_no_log_invalid");
    patterns.push(...encodedSecretPatterns(
      `state_secret:ephemeral_${role}`,
      encoded.subarray(14),
    ));
  }
  return patterns;
}

export async function captureRunScopedNoLogAuthority(context) {
  try {
    const patterns = await runScopedSecretPatterns(context);
    const merged = new Map((context.runScopedSecretPatterns ?? []).map((pattern) => [
      JSON.stringify([pattern.name, pattern.value]),
      pattern,
    ]));
    for (const pattern of patterns) {
      merged.set(JSON.stringify([pattern.name, pattern.value]), Object.freeze({
        name: pattern.name,
        value: pattern.value,
      }));
    }
    context.runScopedSecretPatterns = Object.freeze([...merged.values()]);
    context.noLogAuthorityCaptureFailed = false;
  } catch (error) {
    context.noLogAuthorityCaptureFailed = true;
    throw error;
  }
}

async function noLogPatternSet(context) {
  if (context.noLogAuthorityCaptureFailed === true) fail("orchestrator_no_log_invalid");
  let scopedPatterns;
  if (context.runScopedSecretPatterns !== undefined) {
    if (
      !Array.isArray(context.runScopedSecretPatterns) ||
      context.runScopedSecretPatterns.some(({ name, value } = {}) => (
        typeof name !== "string" || typeof value !== "string" || value.length === 0
      ))
    ) fail("orchestrator_no_log_invalid");
    scopedPatterns = context.runScopedSecretPatterns;
  } else if (context.noLogAuthorityCaptureRequired === true) {
    fail("orchestrator_no_log_invalid");
  } else {
    scopedPatterns = await runScopedSecretPatterns(context);
  }
  const literalPatterns = [
    ...[...context.secrets.entries()].map(([name, value]) => ({
      name: `secret:${name}`,
      value,
    })),
    ...scopedPatterns,
    { name: "synthetic_owner", value: SYNTHETIC_OWNER_ID },
    { name: "synthetic_tenant", value: SYNTHETIC_TENANT_ID },
    { name: "run_root", value: context.runRoot },
    ...FROZEN_R8_CANARY_PATTERNS.filter(({ name }) => name !== "canary:project"),
    { name: "canary:project", value: resolve(context.runRoot, "project") },
    { name: "workspace_root", value: WORKSPACE_ROOT },
  ].filter(({ value }) => typeof value === "string" && value.length > 0);
  const forbiddenPatterns = Object.freeze([
    [
      "absolute_local_path",
      /(?:^|[\s"'=:])(?:\/(?:Users|home|private|tmp)(?:\/|$)|\/var\/folders(?:\/|$)|[A-Za-z]:[\\/](?:Users|Documents and Settings)[\\/])/m,
    ],
    ["bearer", /\bbearer\b/i],
    ["credential", /\bcredentials?\b/i],
    ["dsn", /\b(?:postgres(?:ql)?|redis):\/\//i],
    ["private_key", /private[\s_-]*key/i],
  ]);
  return Object.freeze({
    literalPatterns,
    forbiddenPatterns,
    classificationRules: STRUCTURED_NO_LOG_RULES,
  });
}

function emptyStructuredValue(value) {
  return value === null || value === "" ||
    (Array.isArray(value) && value.length === 0) ||
    (typeof value === "object" && value !== null && !Array.isArray(value) &&
      Object.keys(value).length === 0);
}

function sensitiveStructuredField(key) {
  return /(?:^|_)(?:authorization|bearer|cookies?|credentials?|dsn|keys?|passwords?|private_keys?|secrets?|tokens?)(?:_|$)/
    .test(key);
}

function unclassifiedStructuredField(key) {
  return [
    "argv",
    "binary",
    "body",
    "command",
    "content",
    "cwd",
    "env",
    "executable",
    "headers",
    "message",
    "msg",
    "path",
    "payload",
    "prompt",
    "query",
    "request",
    "response",
    "uri",
    "url",
  ].includes(key) ||
    /_(?:argv|binary|body|command|content|cwd|env|executable|headers|message|msg|path|payload|prompt|query|request|response|uri|url)$/.test(key);
}

function publicRequestTarget(value) {
  return value === "/healthz" || value === "/healthz/v2";
}

function approvedContextFieldValue(key, value) {
  if (emptyStructuredValue(value)) return true;
  if (key === "path" || key === "uri" || /_(?:path|uri)$/.test(key)) {
    return publicRequestTarget(value);
  }
  if (key === "env") return value === "local";
  if (key === "argv") return Array.isArray(value) && value.length === 0;
  if (key === "status") return value === "ready";
  if (key === "request" || key === "headers" || key.endsWith("_headers")) {
    return value !== null && typeof value === "object";
  }
  if (key === "msg") {
    return APPROVED_CONTEXT_MESSAGES.includes(value);
  }
  if (key === "jwks_url") {
    return value === "https://localhost:8443/realms/yijie-local/protocol/openid-connect/certs";
  }
  if (key === "retained_volume_keys") {
    return Array.isArray(value) &&
      JSON.stringify(value) === JSON.stringify(S10_NAMED_VOLUME_KEYS);
  }
  if (key === "final_authorization_revision") {
    return value === 3;
  }
  if (key === "secret_descriptor_sha256") {
    return DIGEST_PATTERN.test(value ?? "");
  }
  if (key === "secret_roles") {
    return Array.isArray(value) &&
      JSON.stringify(value) === JSON.stringify(["chat_sqlcipher", "receipt_hmac", "native_auth"]);
  }
  return key === "payload" &&
    value !== null && typeof value === "object" && !Array.isArray(value) &&
    exactKeys(value, ["status"]) && value.status === "ready";
}

function approvedCaddySystemFieldValue(key, value) {
  if (key === "message" || key === "msg") {
    if (/^maxprocs: Leaving GOMAXPROCS=[1-9][0-9]?: CPU quota undefined$/.test(value)) {
      return true;
    }
    if (
      /^failed to sufficiently increase receive buffer size \(was: [1-9][0-9]* kiB, wanted: [1-9][0-9]* kiB, got: [1-9][0-9]* kiB\)\. See https:\/\/github\.com\/quic-go\/quic-go\/wiki\/UDP-Buffer-Sizes for details\.$/.test(value)
    ) {
      return true;
    }
    return [
      "adapted config to JSON",
      "admin endpoint started",
      "acquiring lock",
      "autosaved config",
      "autosaved config (load with --resume flag)",
      "Caddyfile input is not formatted; run 'caddy fmt --overwrite' to fix inconsistencies",
      "certificate cache maintenance started",
      "cleaning storage unit",
      "automatic HTTP->HTTPS redirects are disabled",
      "enabling automatic HTTP->HTTPS redirects",
      "enabling automatic TLS certificate management",
      "finished cleaning storage units",
      "GOMEMLIMIT is updated",
      "handled request",
      "received request",
      "enabling HTTP/3 listener",
      "done waiting on internal rate limiter",
      "issuing certificate",
      "lock acquired",
      "obtaining certificate",
      "certificate obtained successfully",
      "releasing lock",
      "root certificate trust store installation disabled; unconfigured clients may show warnings",
      "server is listening only on the HTTPS port but has no TLS connection policies; adding one to enable TLS",
      "server running",
      "shutting down apps, then terminating",
      "shutdown complete",
      "stopped background certificate maintenance",
      "initial configuration loaded",
      "selected upstream",
      "serving initial configuration",
      "started background certificate maintenance",
      "storage cleaning happened too recently; skipping for now",
      "upstream roundtrip",
      "using config from file",
      "waiting on internal rate limiter",
    ].includes(value);
  }
  if (unclassifiedStructuredField(key) && approvedContextFieldValue(key, value)) return true;
  if (key === "level") return value === "info" || value === "debug" || value === "warn";
  if (key === "ts" || key === "duration") return typeof value === "number" && value >= 0;
  if (key === "file") {
    return value === "/etc/caddy/Caddyfile" || value === "/config/caddy/autosave.json";
  }
  if (key === "config_file") return value === "/etc/caddy/Caddyfile";
  if (key === "autosave_file") return value === "/config/caddy/autosave.json";
  if (key === "path" || key === "storage_path") {
    return value === "/config/caddy/autosave.json" || value === "/data/caddy" ||
      value === "storage:pki/authorities/local/root.crt";
  }
  if (key === "adapter") return value === "caddyfile";
  if (key === "line") return Number.isSafeInteger(value) && value > 0 && value <= 4096;
  if (key === "package") {
    return value === "github.com/KimMachineGun/automemlimit/memlimit";
  }
  if (key === "gomemlimit") {
    return Number.isSafeInteger(value) && value >= 16 * 1024 * 1024 && value <= 16 * 1024 ** 3;
  }
  if (key === "previous") {
    return value === 9223372036854776000 ||
      (Number.isSafeInteger(value) && value >= 16 * 1024 * 1024 && value <= 16 * 1024 ** 3);
  }
  if (key === "logger") {
    return [
      "admin",
      "admin.api",
      "http",
      "http.auto_https",
      "http.handlers.reverse_proxy",
      "http.log",
      "http.log.access",
      "pki.ca.local",
      "tls",
      "tls.cache.maintenance",
      "tls.issuance.internal",
      "tls.obtain",
    ].includes(value);
  }
  if (key === "storage") return value === "FileStorage:/data/caddy";
  if (key === "address") return value === "localhost:2019" || value === "127.0.0.1:2019";
  if (key === "enforce_origin" || key === "resumed") return value === false;
  if (key === "env") return value === "local";
  if (key === "argv") return Array.isArray(value) && value.length === 0;
  if (key === "domains") {
    return Array.isArray(value) && value.length === 1 && value[0] === "localhost";
  }
  if (key === "server_name") return value === "srv0" || value === "srv1" || value === "localhost";
  if (key === "cache") return value === "synthetic-cache" || /^0x[0-9a-f]{6,16}$/.test(value);
  if (key === "addr") return value === ":8443" || value === ":9443";
  if (key === "https_port") return value === 8443 || value === 9443;
  if (key === "protocols") {
    return Array.isArray(value) && JSON.stringify(value) === JSON.stringify(["h1", "h2", "h3"]);
  }
  if (key === "identifier") return value === "localhost";
  if (key === "identifiers") {
    return Array.isArray(value) && value.length === 1 && value[0] === "localhost";
  }
  if (key === "ca") return value === "local";
  if (key === "account") return value === "";
  if (key === "issuer") return value === "local";
  if (key === "attempt") return value === 1;
  if (key === "instance") return RUN_ID_PATTERN.test(value);
  if (key === "try_again") return typeof value === "number" && Number.isFinite(value) && value > 0;
  if (key === "try_again_in") {
    return typeof value === "number" && Number.isFinite(value) && value > 0 && value <= 86_400;
  }
  if (key === "origins") {
    return Array.isArray(value) && JSON.stringify([...value].sort()) === JSON.stringify([
      "//127.0.0.1:2019",
      "//[::1]:2019",
      "//localhost:2019",
    ]);
  }
  if (key === "upstream") return value === "host.docker.internal:18080";
  if (key === "name") return value === "srv0" || value === "srv1";
  if (key === "request" || key === "headers" || key === "resp_headers" ||
      key === "tls" || key === "context") {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }
  if (key === "remote_ip" || key === "client_ip") return value === "127.0.0.1";
  if (key === "remote_port") return typeof value === "string" && /^\d{1,5}$/.test(value);
  if (key === "proto") return value === "HTTP/1.1" || value === "";
  if (key === "method") return value === "GET";
  if (key === "host") return value === "localhost:8443" || value === "127.0.0.1:2019";
  if (key === "uri") return publicRequestTarget(value) || value === "/config/";
  if (key === "user_agent") {
    return Array.isArray(value) && value.length === 1 &&
      (value[0] === "curl/8.7.1" || value[0] === "Wget");
  }
  if (key === "accept") return Array.isArray(value) && value.length === 1 && value[0] === "*/*";
  if (key === "accept_encoding") {
    return Array.isArray(value) && value.length === 1 && value[0] === "identity";
  }
  if (key === "connection") {
    return Array.isArray(value) && value.length === 1 && value[0] === "close";
  }
  if (key === "version") return value === 772;
  if (key === "cipher_suite") return value === 4865;
  if (key === "bytes_read") return value === 0;
  if (key === "user_id") return value === "";
  if (key === "size") return value === 6;
  if (key === "status") return value === 200 || value === "ready";
  if (key === "payload") {
    return value !== null && typeof value === "object" && !Array.isArray(value) &&
      exactKeys(value, ["status"]) && value.status === "ready";
  }
  if (key === "server") return Array.isArray(value) && value.length === 1 && value[0] === "Caddy";
  if (key === "content_type") {
    return Array.isArray(value) && value.length === 1 && value[0] === "text/plain; charset=utf-8";
  }
  return false;
}

function approvedCaddyAccessEvent(value) {
  return exactKeys(value, [
    "level", "ts", "logger", "msg", "request", "bytes_read", "user_id", "duration",
    "size", "status", "resp_headers",
  ]) &&
    value.request !== null && typeof value.request === "object" && !Array.isArray(value.request) &&
    value.request.headers !== null && typeof value.request.headers === "object" &&
    !Array.isArray(value.request.headers) &&
    value.request.tls !== null && typeof value.request.tls === "object" &&
    !Array.isArray(value.request.tls) &&
    value.resp_headers !== null && typeof value.resp_headers === "object" &&
    !Array.isArray(value.resp_headers) &&
    exactKeys(value.request, [
      "remote_ip", "remote_port", "client_ip", "proto", "method", "host", "uri", "headers",
      "tls",
    ]) &&
    exactKeys(value.request.headers, ["User-Agent", "Accept"]) &&
    exactKeys(value.request.tls, [
      "resumed", "version", "cipher_suite", "proto", "server_name",
    ]) &&
    exactKeys(value.resp_headers, ["Server", "Content-Type"]);
}

function approvedCaddyAdminHealthcheckEvent(value) {
  if (
    !exactKeys(value, [
      "level", "ts", "logger", "msg", "method", "host", "uri", "remote_ip",
      "remote_port", "headers",
    ]) || value.level !== "info" || value.logger !== "admin.api" ||
    value.msg !== "received request" || value.method !== "GET" ||
    value.host !== "127.0.0.1:2019" || value.uri !== "/config/" ||
    value.remote_ip !== "127.0.0.1" || !/^\d{1,5}$/.test(value.remote_port ?? "") ||
    value.headers === null || typeof value.headers !== "object" || Array.isArray(value.headers)
  ) return false;
  return exactKeys(value.headers, ["Accept", "Connection", "User-Agent"]) &&
    Object.entries(value.headers).every(([key, entry]) => (
      approvedCaddySystemFieldValue(normalizedStructuredField(key), entry)
    ));
}

function approvedCaddySystemEvent(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const message = typeof value.msg === "string" ? value.msg : value.message;
  if (typeof message !== "string") return false;
  const schema = (...keys) => exactKeys(value, keys);
  if (!Object.entries(value).every(([key, entry]) => (
    approvedCaddySystemFieldValue(normalizedStructuredField(key), entry)
  ))) return false;
  if (message === "handled request") {
    return value.logger === "http.log.access" && approvedCaddyAccessEvent(value);
  }
  if (message === "received request") return approvedCaddyAdminHealthcheckEvent(value);
  if (/^maxprocs: Leaving GOMAXPROCS=[1-9][0-9]?: CPU quota undefined$/.test(message)) {
    return schema("level", "ts", "msg");
  }
  if (message.startsWith("failed to sufficiently increase receive buffer size ")) {
    return schema("level", "ts", "msg");
  }
  switch (message) {
    case "GOMEMLIMIT is updated":
      return schema("level", "ts", "msg", "GOMEMLIMIT", "previous");
    case "using config from file":
      return schema("level", "ts", "msg", "file");
    case "adapted config to JSON":
      return schema("level", "ts", "msg", "adapter");
    case "Caddyfile input is not formatted; run 'caddy fmt --overwrite' to fix inconsistencies":
      return schema("level", "ts", "msg", "adapter", "file", "line");
    case "admin endpoint started":
      return value.logger === "admin" &&
        schema("level", "ts", "logger", "msg", "address", "enforce_origin", "origins");
    case "server is listening only on the HTTPS port but has no TLS connection policies; adding one to enable TLS":
      return value.logger === "http.auto_https" &&
        schema("level", "ts", "logger", "msg", "server_name", "https_port");
    case "enabling automatic TLS certificate management":
      return value.logger === "http" &&
        schema("level", "ts", "logger", "msg", "domains");
    case "automatic HTTP->HTTPS redirects are disabled":
      return value.logger === "http.auto_https" &&
        schema("level", "ts", "logger", "msg", "server_name");
    case "enabling automatic HTTP->HTTPS redirects":
      return value.logger === "http.auto_https" &&
        schema("level", "ts", "logger", "msg", "server_name");
    case "started background certificate maintenance":
    case "stopped background certificate maintenance":
      return value.logger === "tls.cache.maintenance" &&
        schema("level", "ts", "logger", "msg", "cache");
    case "enabling HTTP/3 listener":
      return value.logger === "http" && schema("level", "ts", "logger", "msg", "addr");
    case "server running":
      return value.logger === "http.log" &&
        schema("level", "ts", "logger", "msg", "name", "protocols");
    case "waiting on internal rate limiter":
    case "done waiting on internal rate limiter":
      return value.logger === "tls.issuance.internal" &&
        schema("level", "ts", "logger", "msg", "identifiers", "ca", "account");
    case "acquiring lock":
    case "lock acquired":
    case "obtaining certificate":
    case "issuing certificate":
    case "releasing lock":
      return value.logger === "tls.obtain" &&
        schema("level", "ts", "logger", "msg", "identifier");
    case "certificate obtained successfully":
      return value.logger === "tls.obtain" &&
        schema("level", "ts", "logger", "msg", "identifier", "issuer");
    case "root certificate trust store installation disabled; unconfigured clients may show warnings":
      return value.logger === "pki.ca.local" &&
        schema("level", "ts", "logger", "msg", "path");
    case "cleaning storage unit":
      return value.logger === "tls" &&
        schema("level", "ts", "logger", "msg", "storage");
    case "storage cleaning happened too recently; skipping for now":
      return value.logger === "tls" && value.try_again > value.ts &&
        Math.abs((value.try_again - value.ts) - value.try_again_in) <= 1 &&
        schema(
          "level", "ts", "logger", "msg", "storage", "instance", "try_again",
          "try_again_in",
        );
    case "selected upstream":
      return value.logger === "http.handlers.reverse_proxy" &&
        schema("level", "ts", "logger", "msg", "upstream");
    case "upstream roundtrip":
      return value.logger === "http.handlers.reverse_proxy" &&
        schema("level", "ts", "logger", "msg", "upstream", "duration");
    case "autosaved config (load with --resume flag)":
      return schema("level", "ts", "msg", "file");
    case "finished cleaning storage units":
      return value.logger === "tls" && schema("level", "ts", "logger", "msg");
    case "serving initial configuration":
    case "shutting down apps, then terminating":
    case "shutdown complete":
      return schema("level", "ts", "msg");
    default:
      return false;
  }
}

function localAbsolutePath(value) {
  if (typeof value !== "string") return false;
  if (/^[A-Za-z]:[\\/](?:Users|Documents and Settings)[\\/]/.test(value)) return true;
  if (
    /^file:\/\/\/(?:Applications|Library|System|Users|Volumes|home|private|tmp)(?:\/|$)/.test(value) ||
    /^file:\/\/\/(?:opt\/homebrew|usr\/local)(?:\/|$)/.test(value) ||
    /^file:\/\/\/var\/folders(?:\/|$)/.test(value) ||
    /^file:\/\/\/[A-Za-z]:[\\/](?:Users|Documents and Settings)[\\/]/.test(value)
  ) return true;
  if (!isAbsolute(value)) return false;
  return /^\/(?:Applications|Library|System|Users|Volumes|home|private|tmp)(?:\/|$)/.test(value) ||
    /^\/(?:opt\/homebrew|usr\/local)(?:\/|$)/.test(value) ||
    /^\/var\/folders(?:\/|$)/.test(value);
}

function normalizedStructuredField(rawKey) {
  return rawKey
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase()
    .replaceAll("-", "_");
}

function structuredNoLogHits(value, origin = null) {
  const hits = new Map();
  const addHit = (rule, fieldClass, reasonClass) => {
    const key = JSON.stringify([rule, fieldClass, reasonClass]);
    hits.set(key, Object.freeze({ rule, fieldClass, reasonClass }));
  };
  function visit(current, sensitiveContext = false, depth = 0) {
    const caddyOrigin = origin === "compose:feat126-s10-caddy";
    if (
      caddyOrigin && depth === 0 &&
      (current === null || typeof current !== "object" || Array.isArray(current))
    ) {
      addHit(
        "unclassified_sensitive_field",
        "structured_unclassified",
        "unclassified_caddy_system_value",
      );
    }
    if (typeof current === "string") {
      if (localAbsolutePath(current)) {
        addHit("absolute_local_path", "local_path", "local_machine_path_value");
      }
      if (!sensitiveContext && /\bbearer\b/i.test(current)) {
        addHit("bearer", "unstructured_pattern", "unstructured_pattern_match");
      }
      if (!sensitiveContext && /\bcredentials?\b/i.test(current)) {
        addHit("credential", "unstructured_pattern", "unstructured_pattern_match");
      }
      if (!sensitiveContext && /\b(?:postgres(?:ql)?|redis):\/\//i.test(current)) {
        addHit("dsn", "unstructured_pattern", "unstructured_pattern_match");
      }
      if (!sensitiveContext && /private[\s_-]*key/i.test(current)) {
        addHit("private_key", "unstructured_pattern", "unstructured_pattern_match");
      }
      return;
    }
    if (Array.isArray(current)) {
      for (const entry of current) visit(entry, sensitiveContext, depth + 1);
      return;
    }
    if (current === null || typeof current !== "object") return;
    if (caddyOrigin && depth === 0 && !approvedCaddySystemEvent(current)) {
      addHit(
        "unclassified_sensitive_field",
        "structured_unclassified",
        "unclassified_caddy_system_value",
      );
    }
    for (const [rawKey, entry] of Object.entries(current)) {
      const key = normalizedStructuredField(rawKey);
      const sensitiveField = sensitiveStructuredField(key);
      const approvedContext = approvedContextFieldValue(key, entry);
      if (sensitiveField && !emptyStructuredValue(entry) && !approvedContext) {
        addHit("sensitive_value_field", "structured_sensitive", "sensitive_nonempty_value");
      }
      if (
        !sensitiveField &&
        (caddyOrigin
          ? !approvedCaddySystemFieldValue(key, entry)
          : unclassifiedStructuredField(key) && !approvedContext)
      ) {
        addHit(
          "unclassified_sensitive_field",
          "structured_unclassified",
          caddyOrigin
            ? "unclassified_caddy_system_value"
            : "unclassified_context_value",
        );
      }
      visit(entry, sensitiveContext || sensitiveField, depth + 1);
    }
  }
  visit(value);
  return [...hits.values()].sort((left, right) => (
    asciiCompare(left.rule, right.rule) || asciiCompare(left.fieldClass, right.fieldClass) ||
    asciiCompare(left.reasonClass, right.reasonClass)
  ));
}

export function scanNoLogBuffer(content, literalPatterns, forbiddenPatterns, origin = null) {
  let value;
  try {
    value = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(content));
  } catch {
    fail("orchestrator_no_log_invalid");
  }
  const hits = new Map();
  const addHit = (rule, fieldClass, reasonClass) => {
    const key = JSON.stringify([rule, fieldClass, reasonClass]);
    hits.set(key, Object.freeze({ rule, fieldClass, reasonClass }));
  };
  const folded = value.toLowerCase();
  for (const { name, value: pattern } of literalPatterns) {
    if (folded.includes(pattern.toLowerCase())) {
      addHit(name, "literal_value", "literal_authority_match");
    }
  }
  function parseUniqueJson(input) {
    try {
      const structured = JSON.parse(input);
      YAML.parse(input, { version: "1.2", uniqueKeys: true });
      return Object.freeze({ parsed: true, structured });
    } catch {
      return Object.freeze({ parsed: false });
    }
  }
  function classifyUnstructuredLine(line) {
    for (const match of line.matchAll(/["']?([A-Za-z][A-Za-z0-9_-]{0,127})["']?\s*:/g)) {
      const key = normalizedStructuredField(match[1]);
      const bearerAuthorization = key === "authorization" &&
        /\bbearer\b/i.test(line.slice((match.index ?? 0) + match[0].length));
      if (sensitiveStructuredField(key) && !bearerAuthorization) {
        addHit("sensitive_value_field", "structured_sensitive", "sensitive_nonempty_value");
      }
      if (unclassifiedStructuredField(key)) {
        addHit(
          "unclassified_sensitive_field",
          "structured_unclassified",
          origin === "compose:feat126-s10-caddy"
            ? "unclassified_caddy_system_value"
            : "unclassified_context_value",
        );
      }
    }
  }

  const nonemptyLines = value.split("\n").filter(Boolean);
  const unstructuredLines = [];
  const complete = parseUniqueJson(value.trim());
  if (complete.parsed) {
    for (const hit of structuredNoLogHits(complete.structured, origin)) {
      addHit(hit.rule, hit.fieldClass, hit.reasonClass);
    }
  } else {
    for (const line of nonemptyLines) {
      const parsedLine = parseUniqueJson(line);
      if (parsedLine.parsed) {
        for (const hit of structuredNoLogHits(parsedLine.structured, origin)) {
          addHit(hit.rule, hit.fieldClass, hit.reasonClass);
        }
        continue;
      }
      unstructuredLines.push(line);
      classifyUnstructuredLine(line);
      if (origin === "compose:feat126-s10-caddy" && line !== "ready") {
        addHit(
          "unclassified_sensitive_field",
          "structured_unclassified",
          "unclassified_caddy_system_value",
        );
      }
    }
  }
  const unstructured = unstructuredLines.join("\n");
  for (const [name, pattern] of forbiddenPatterns) {
    if (pattern.test(unstructured)) {
      addHit(
        name,
        name === "absolute_local_path" ? "local_path" : "unstructured_pattern",
        name === "absolute_local_path"
          ? "local_machine_path_value"
          : "unstructured_pattern_match",
      );
    }
  }
  const sortedHits = [...hits.values()].sort((left, right) => (
    asciiCompare(left.rule, right.rule) || asciiCompare(left.fieldClass, right.fieldClass) ||
    asciiCompare(left.reasonClass, right.reasonClass)
  ));
  return Object.freeze({
    rowCount: nonemptyLines.length,
    hitCount: sortedHits.length,
    hits: Object.freeze(sortedHits),
  });
}

function noLogPatternDigest(literalPatterns, forbiddenPatterns, classificationRules) {
  return sha256([...new Set([
    ...literalPatterns.map(({ name }) => name),
    ...forbiddenPatterns.map(([name]) => name),
    ...classificationRules,
    ...APPROVED_CONTEXT_MESSAGES.map((value) => `approved_context_msg:${value}`),
    ...STRUCTURED_NO_LOG_FIELD_CLASSES,
    ...STRUCTURED_NO_LOG_REASON_CLASSES,
  ])].sort(asciiCompare).join("\n"));
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

async function scanRuntimeLogDatabase(path, literalPatterns, forbiddenPatterns, required) {
  let metadata;
  try {
    metadata = await lstat(path);
  } catch (error) {
    if (!required && error?.code === "ENOENT") {
      return Object.freeze({ present: false, rowCount: 0, hitCount: 0 });
    }
    fail("orchestrator_no_log_invalid");
  }
  if (
    !metadata.isFile() || metadata.isSymbolicLink() || !ownedByCurrentUser(metadata) ||
    metadata.nlink !== 1 || (metadata.mode & 0o022) !== 0 || metadata.size > 16 * 1024 * 1024 ||
    (await realpath(path)) !== path
  ) fail("orchestrator_no_log_invalid");
  let database;
  let result;
  let operationError;
  try {
    database = new DatabaseSync(path, { readOnly: true });
    const tables = database.prepare(
      "SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name ASC",
    ).all().map(({ name }) => name);
    if (JSON.stringify(tables) !== JSON.stringify([
      "_sqlx_migrations", "logs", "sqlite_sequence",
    ])) fail("orchestrator_no_log_invalid");
    const columns = database.prepare("PRAGMA table_info(logs)").all().map((column) => ({
      cid: column.cid,
      name: column.name,
      type: column.type,
      notnull: column.notnull,
      dflt_value: column.dflt_value,
      pk: column.pk,
    }));
    if (JSON.stringify(columns) !== JSON.stringify([
      { cid: 0, name: "id", type: "INTEGER", notnull: 0, dflt_value: null, pk: 1 },
      { cid: 1, name: "ts", type: "INTEGER", notnull: 1, dflt_value: null, pk: 0 },
      { cid: 2, name: "ts_nanos", type: "INTEGER", notnull: 1, dflt_value: null, pk: 0 },
      { cid: 3, name: "level", type: "TEXT", notnull: 1, dflt_value: null, pk: 0 },
      { cid: 4, name: "target", type: "TEXT", notnull: 1, dflt_value: null, pk: 0 },
      { cid: 5, name: "feedback_log_body", type: "TEXT", notnull: 0, dflt_value: null, pk: 0 },
      { cid: 6, name: "module_path", type: "TEXT", notnull: 0, dflt_value: null, pk: 0 },
      { cid: 7, name: "file", type: "TEXT", notnull: 0, dflt_value: null, pk: 0 },
      { cid: 8, name: "line", type: "INTEGER", notnull: 0, dflt_value: null, pk: 0 },
      { cid: 9, name: "thread_id", type: "TEXT", notnull: 0, dflt_value: null, pk: 0 },
      { cid: 10, name: "process_uuid", type: "TEXT", notnull: 0, dflt_value: null, pk: 0 },
      { cid: 11, name: "estimated_bytes", type: "INTEGER", notnull: 1, dflt_value: "0", pk: 0 },
    ])) fail("orchestrator_no_log_invalid");
    const rows = database.prepare(
      "SELECT level, target, feedback_log_body, module_path, file " +
      "FROM logs ORDER BY id ASC LIMIT 4097",
    ).all();
    if (rows.length > 4096) fail("orchestrator_no_log_invalid");
    let rowCount = 0;
    let hitCount = 0;
    let totalBytes = 0;
    for (const row of rows) {
      if (
        typeof row.level !== "string" || typeof row.target !== "string" ||
        ![row.feedback_log_body, row.module_path, row.file].every(
          (value) => value === null || typeof value === "string",
        )
      ) fail("orchestrator_no_log_invalid");
      const rowHits = new Set();
      for (const value of [
        row.level, row.target, row.feedback_log_body, row.module_path, row.file,
      ]) {
        if (value === null) continue;
        const content = Buffer.from(`${value}\n`, "utf8");
        totalBytes += content.length;
        if (totalBytes > CHILD_OUTPUT_MAX_BYTES) fail("orchestrator_no_log_invalid");
        const scan = scanNoLogBuffer(content, literalPatterns, forbiddenPatterns);
        for (const hit of scan.hits) {
          rowHits.add(JSON.stringify([hit.rule, hit.fieldClass, hit.reasonClass]));
        }
      }
      rowCount += 1;
      hitCount += rowHits.size;
    }
    result = Object.freeze({ present: true, rowCount, hitCount });
  } catch (error) {
    operationError = error instanceof S10BO1OrchestratorError
      ? error
      : new S10BO1OrchestratorError("orchestrator_no_log_invalid");
  }
  let closeFailed = false;
  if (database) {
    try {
      database.close();
    } catch {
      closeFailed = true;
    }
  }
  if (operationError) throw operationError;
  if (closeFailed || !result) fail("orchestrator_no_log_invalid");
  return result;
}

export async function captureRuntimeLogScan(context, operations = {}) {
  if (
    !context?.composeLogsRequired || !RUN_ID_PATTERN.test(context.runId ?? "") ||
    !(context.secrets instanceof Map)
  ) fail("orchestrator_no_log_invalid");
  const project = projectName(context.runId);
  const list = operations.list ?? (async () => (await dockerList([
    "ps",
    "-a",
    "--filter",
    `label=com.docker.compose.project=${project}`,
    "--format",
    [
      "{{.ID}}",
      '{{.Label "com.docker.compose.project"}}',
      '{{.Label "ai.yijie.feature"}}',
      '{{.Label "ai.yijie.slice"}}',
      '{{.Label "ai.yijie.run-id"}}',
      '{{.Label "ai.yijie.data-classification"}}',
      '{{.Label "com.docker.compose.service"}}',
    ].join("\t"),
  ])).map((row) => {
    const parts = row.split("\t");
    if (parts.length !== RUNTIME_LOG_SOURCE_KEYS.length) fail("orchestrator_no_log_invalid");
    return {
      container_id: parts[0],
      project: parts[1],
      feature: parts[2],
      slice: parts[3],
      run_id: parts[4],
      data_classification: parts[5],
      service_role: parts[6],
    };
  }));
  const readLogs = operations.readLogs ?? (async (containerId) => await runCommand(
    "container_logs",
    "docker",
    ["logs", containerId],
    { captureAllOutput: true, maxBuffer: CHILD_OUTPUT_MAX_BYTES, timeout: 30_000 },
  ));
  let sources;
  try {
    sources = (await list()).map((source) => {
      if (
        source === null || typeof source !== "object" || Array.isArray(source) ||
        !exactKeys(source, RUNTIME_LOG_SOURCE_KEYS) ||
        !/^[0-9a-f]{12,64}$/.test(source.container_id ?? "") ||
        source.project !== project || source.feature !== "FEAT-126" ||
        source.slice !== "S10E" || source.run_id !== context.runId ||
        source.data_classification !== "synthetic-only" ||
        !RUNTIME_LOG_SERVICE_ROLES.includes(source.service_role)
      ) fail("orchestrator_no_log_invalid");
      return Object.freeze({
        containerId: source.container_id,
        origin: `compose:${source.service_role}`,
      });
    }).sort((left, right) => asciiCompare(left.origin, right.origin));
  } catch {
    fail("orchestrator_no_log_invalid");
  }
  if (
    sources.length !== RUNTIME_LOG_SERVICE_ROLES.length ||
    new Set(sources.map(({ containerId }) => containerId)).size !== sources.length ||
    new Set(sources.map(({ origin }) => origin)).size !== sources.length ||
    JSON.stringify(sources.map(({ origin }) => origin)) !== JSON.stringify(
      RUNTIME_LOG_SERVICE_ROLES.map((role) => `compose:${role}`).sort(asciiCompare),
    )
  ) fail("orchestrator_no_log_invalid");
  const { literalPatterns, forbiddenPatterns } = await noLogPatternSet(context);
  let rowCount = 0;
  let hitCount = 0;
  const hitOrigins = [];
  const hitRules = [];
  const hitOriginRules = [];
  const hitFieldClasses = [];
  const hitOriginRuleFieldClasses = [];
  const hitReasonClasses = [];
  const hitOriginRuleFieldClassReasonClasses = [];
  for (const source of sources) {
    let content;
    try {
      content = await readLogs(source.containerId);
    } catch {
      fail("orchestrator_no_log_invalid");
    }
    if (!Buffer.isBuffer(content) || content.length > CHILD_OUTPUT_MAX_BYTES) {
      fail("orchestrator_no_log_invalid");
    }
    const scan = scanNoLogBuffer(content, literalPatterns, forbiddenPatterns, source.origin);
    rowCount += scan.rowCount;
    hitCount += scan.hitCount;
    for (const { rule, fieldClass, reasonClass } of scan.hits) {
      hitOrigins.push(source.origin);
      hitRules.push(rule);
      hitOriginRules.push(JSON.stringify([source.origin, rule]));
      hitFieldClasses.push(fieldClass);
      hitOriginRuleFieldClasses.push(JSON.stringify([source.origin, rule, fieldClass]));
      hitReasonClasses.push(reasonClass);
      hitOriginRuleFieldClassReasonClasses.push(
        JSON.stringify([source.origin, rule, fieldClass, reasonClass]),
      );
    }
  }
  return validateRuntimeLogScan({
    schema_version: 4,
    status: hitCount === 0 ? "passed" : "failed",
    run_id: context.runId,
    source_count: sources.length,
    row_count: rowCount,
    hit_count: hitCount,
    source_set_sha256: sha256(sources.map(({ origin }) => origin).join("\n")),
    hit_origin_set_sha256: sha256([...new Set(hitOrigins)].sort(asciiCompare).join("\n")),
    hit_rule_set_sha256: sha256([...new Set(hitRules)].sort(asciiCompare).join("\n")),
    hit_origin_rule_set_sha256: sha256(
      [...new Set(hitOriginRules)].sort(asciiCompare).join("\n"),
    ),
    hit_field_class_set_sha256: sha256(
      [...new Set(hitFieldClasses)].sort(asciiCompare).join("\n"),
    ),
    hit_origin_rule_field_class_set_sha256: sha256(
      [...new Set(hitOriginRuleFieldClasses)].sort(asciiCompare).join("\n"),
    ),
    hit_reason_class_set_sha256: sha256(
      [...new Set(hitReasonClasses)].sort(asciiCompare).join("\n"),
    ),
    hit_origin_rule_field_class_reason_class_set_sha256: sha256(
      [...new Set(hitOriginRuleFieldClassReasonClasses)].sort(asciiCompare).join("\n"),
    ),
  }, context.runId);
}

export async function scanNoLog(context) {
  if (!context?.runRoot || !(context.secrets instanceof Map) || !context.attempt?.markerPath) {
    fail("orchestrator_no_log_invalid");
  }
  const { literalPatterns, forbiddenPatterns, classificationRules } = await noLogPatternSet(context);
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
      pattern_set_sha256: noLogPatternDigest(
        literalPatterns,
        forbiddenPatterns,
        classificationRules,
      ),
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
    [resolve(context.runRoot, "secure-storage"), false, new Set(["ephemeral-secrets"])],
  ];
  let files;
  try {
    await requireOwnerDirectory(context.runRoot);
    await Promise.all([
      validateStateRootMetadata(resolve(context.runRoot, "host-home")),
      validateStateRootMetadata(resolve(context.runRoot, "codex-home")),
    ]);
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
    if (process_.record && (!context.r8 || role === "api")) {
      requiredFiles.add(resolve(context.evidenceRoot, `${role}-process.v1.json`));
    }
  }
  for (const process_ of context.processHistory ?? []) {
    if (process_.logPath) requiredFiles.add(process_.logPath);
    if (process_.record) {
      requiredFiles.add(resolve(
        context.evidenceRoot,
        `${process_.evidenceBasename ?? process_.role}-process.v1.json`,
      ));
    }
  }
  for (const role of Object.keys(context.descendantProcesses ?? {})) {
    if (!context.r8) requiredFiles.add(resolve(context.evidenceRoot, `${role}-process.v1.json`));
  }
  if (context.hostEvidence && !context.r8) {
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
  for (const ownership of context.ownershipHistory ?? []) {
    for (const name of [
      ownership.hostEvidenceName,
      ownership.runtimeEvidenceName,
      ownership.hostProcessName,
      ownership.runtimeProcessName,
    ]) requiredFiles.add(resolve(context.evidenceRoot, name));
    const lifecycleMatch = /r8-lifecycle-(\d+)-/.exec(ownership.hostEvidenceName ?? "");
    const lifecycle = lifecycleMatch ? Number(lifecycleMatch[1]) : 1;
    if (r8OwnershipStoppedEvidenceRequired(context, lifecycle)) {
      requiredFiles.add(resolve(context.evidenceRoot, ownership.hostStoppedEvidenceName));
    }
    const hostInstance = resolve(context.runRoot, "host", ownership.hostEvidence.instanceNonce);
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
    const names = context.r8 ? r8NoLogRequiredEvidenceNames(context) : [
      "api-verifier-before.v1.json",
      "api-verifier-after.v1.json",
      "business-boundary.v1.json",
      ...(context.fakeAuthorityBefore
        ? ["fake-authority-before.v1.json", "fake-authority-after.v1.json"]
        : []),
    ];
    for (const name of names) requiredFiles.add(resolve(context.evidenceRoot, name));
  }
  if ([...requiredFiles].some((path) => !files.includes(path))) {
    fail("orchestrator_no_log_invalid");
  }
  const runtimeDatabaseScan = await scanRuntimeLogDatabase(
    resolve(context.runRoot, "codex-home", "logs_2.sqlite"),
    literalPatterns,
    forbiddenPatterns,
    Boolean(context.runtimeEvidence || context.descendantProcesses?.runtime),
  );
  const scan = await scanNoLogFiles(files, literalPatterns, forbiddenPatterns);
  return Object.freeze({
    schema_version: 1,
    scope: preflightOnly ? "preflight_artifacts" : "run_artifacts",
    coverage: preflightOnly
      ? "all_preflight_log_and_evidence_sources"
      : "all_run_log_and_evidence_sources",
    file_count: files.length + (runtimeDatabaseScan.present ? 1 : 0),
    row_count: scan.rowCount + runtimeDatabaseScan.rowCount + (runtimeLogScan?.row_count ?? 0),
    hit_count: scan.hitCount + runtimeDatabaseScan.hitCount + (runtimeLogScan?.hit_count ?? 0),
    external_source_count: runtimeLogScan?.source_count ?? 0,
    external_row_count: runtimeLogScan?.row_count ?? 0,
    external_source_set_sha256: runtimeLogScan?.source_set_sha256 ?? sha256(""),
    pattern_set_sha256: noLogPatternDigest(
      literalPatterns,
      forbiddenPatterns,
      classificationRules,
    ),
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

function preOwnershipDescendantAbsenceRequired(roles) {
  return roles.includes("desktop") && !["host", "runtime"].every((role) => roles.includes(role));
}

export async function requirePreOwnershipDescendantsAbsent(runRoot) {
  if (typeof runRoot !== "string" || !isAbsolute(runRoot)) fail("orchestrator_cleanup_unknown");
  try {
    await requireOwnerDirectory(runRoot);
  } catch {
    fail("orchestrator_cleanup_unknown");
  }
  try {
    await lstat(resolve(runRoot, "host"));
  } catch (error) {
    if (error?.code === "ENOENT") return true;
  }
  fail("orchestrator_cleanup_unknown");
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
  const ownedProcesses = context.processHistory?.length > 0
    ? [...context.processHistory].reverse()
    : ["desktop", "fake", "api"].map((role) => context.processes[role]).filter(Boolean);
  for (const process_ of ownedProcesses) {
    try {
      outcomes.push(await stopOwnedProcess(process_));
    } catch {
      outcomes.push("unknown");
    }
  }
  cleanupUnknown ||= outcomes.includes("unknown") || outcomes.includes("foreign_identity_preserved");

  const observedRoles = [
    ...Object.keys(context.processes ?? {}),
    ...Object.keys(context.descendantProcesses ?? {}),
  ];
  if (preOwnershipDescendantAbsenceRequired(observedRoles)) {
    try {
      await requirePreOwnershipDescendantsAbsent(context.runRoot);
    } catch {
      cleanupUnknown = true;
    }
  }
  if (context.hostEvidence && !(context.ownershipHistory ?? []).some(
    (entry) => entry.hostEvidence.instanceNonce === context.hostEvidence.instanceNonce &&
      entry.hostStoppedEvidence,
  )) {
    try {
      const ownership = (context.ownershipHistory ?? []).find(
        (entry) => entry.hostEvidence.instanceNonce === context.hostEvidence.instanceNonce,
      );
      const stoppedHostEvidence = await readHostProcessEvidence(
        context,
        "stopped",
        context.hostEvidence,
      );
      await writeSecureJson(
        resolve(context.evidenceRoot, ownership?.hostStoppedEvidenceName ?? "host-stopped-evidence.v1.json"),
        stoppedHostEvidence,
      );
      context.hostStoppedEvidence = stoppedHostEvidence;
      if (ownership) ownership.hostStoppedEvidence = stoppedHostEvidence;
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

  const ownedProcessEntries = context.processHistory?.length > 0
    ? context.processHistory
    : Object.values(context.processes);
  const processRecords = [
    ...ownedProcessEntries.map((process_) => process_.record).filter(Boolean),
    ...(context.descendantProcessHistory?.length > 0
      ? context.descendantProcessHistory
      : Object.values(context.descendantProcesses ?? {})),
  ];
  const unrecordedLiveChildren = ownedProcessEntries.filter((process_) => (
    !process_.record && process_.child &&
    process_.child.exitCode === null && process_.child.signalCode === null
  ));
  if (unrecordedLiveChildren.length !== 0) cleanupUnknown = true;
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
    noLogAuthorityCaptureRequired: true,
    noLogAuthorityCaptureFailed: false,
    processes: {},
    processHistory: [],
    descendantProcessHistory: [],
    ownershipHistory: [],
    r8CaseEvidence: [],
    r8FakeAuthorities: [],
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
      context.noLogAuthorityCaptureRequired = true;
      context.noLogAuthorityCaptureFailed = false;
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
    async startFakeGeneration(specification) {
      requireParentAlive();
      if (!expectedR8(authority) || !S10B_R8_FAKE_GENERATIONS.includes(specification)) {
        fail("orchestrator_fake_authority_invalid");
      }
      if (context.processes.fake) {
        const finalAuthority = await probeClosedFakeAuthority(context, false);
        const previous = context.fakeSpec;
        await persistR8FakeFinalAuthority(context, previous, finalAuthority);
        const outcome = await stopOwnedProcess(context.processes.fake);
        if (!["absent", "stopped"].includes(outcome)) fail("orchestrator_cleanup_unknown");
        for (let attempt_ = 0; attempt_ < 50; attempt_ += 1) {
          const listener = await inspectListener(18082);
          if (!listener.listening && !listener.unknown) break;
          if (attempt_ === 49) fail("orchestrator_fake_authority_invalid");
          await new Promise((resolveWait) => setTimeout(resolveWait, 100));
        }
      }
      const priorPhase = context.phase;
      if (specification.generation === 1) context.phase = "fake_starting";
      await Promise.race([startFake(context, {
        ...specification,
        evidenceBasename: `r8-fake-${specification.generation}`,
        logName: `r8-fake-${specification.generation}.log`,
        authorityBeforeName: `r8-fake-${specification.generation}-before.v1.json`,
      }), parentDeath]);
      context.phase = specification.generation === 1 ? "fake_ready" : priorPhase;
      requireParentAlive();
    },
    async startDesktop() {
      requireParentAlive();
      context.phase = "desktop_starting";
      await Promise.race([startDesktop(context), parentDeath]);
      context.phase = "desktop_spawned";
      requireParentAlive();
    },
    async startDesktopLifecycle(lifecycle, r8Phase) {
      requireParentAlive();
      if (!expectedR8(authority) || ![1, 2].includes(lifecycle) ||
        (lifecycle === 1 ? r8Phase !== "before_restart" : r8Phase !== "after_restart")) {
        fail("orchestrator_r8_authority_invalid");
      }
      const priorPhase = context.phase;
      context.nonce = randomUUID();
      context.r8ControlSequence = 0;
      if (lifecycle === 1) context.phase = "desktop_starting";
      await Promise.race([startDesktop(context, {
        r8Phase,
        nonce: context.nonce,
        evidenceBasename: `r8-desktop-${lifecycle}`,
        logName: `r8-desktop-${lifecycle}.log`,
      }), parentDeath]);
      const ready = await Promise.race([
        readDesktopFrame(context, "component_ready"),
        childExit(context.processes.api.child, "api"),
        childExit(context.processes.fake.child, "fake"),
        parentDeath,
      ]);
      if (ready.kind !== "component_ready" || ready.sequence !== 1) {
        fail("orchestrator_control_order_invalid");
      }
      context.phase = lifecycle === 1 ? "desktop_ready" : priorPhase;
      requireParentAlive();
    },
    async readLifecycleOwnership(lifecycle) {
      requireParentAlive();
      const priorPhase = context.phase;
      const suffix = `r8-lifecycle-${lifecycle}`;
      const ownership = await readOwnershipEvidence(context, {
        hostEvidenceName: `${suffix}-host-evidence.v1.json`,
        runtimeEvidenceName: `${suffix}-runtime-evidence.v1.json`,
        hostProcessName: `${suffix}-host-process.v1.json`,
        runtimeProcessName: `${suffix}-runtime-process.v1.json`,
        hostStoppedEvidenceName: `${suffix}-host-stopped-evidence.v1.json`,
      });
      validateOwnership(ownership);
      context.phase = lifecycle === 1 ? "runtime_ready" : priorPhase;
      requireParentAlive();
      return ownership;
    },
    async executeCase(caseId) {
      requireParentAlive();
      const ordinal = S10BO1_CASES.slice(0, -1).indexOf(caseId) + 1;
      if (ordinal !== context.r8CaseEvidence.length + 1) fail("orchestrator_control_order_invalid");
      await sendR8ControlFrame(context, "mode_transition", caseId);
      const result = await Promise.race([
        readDesktopFrame(context, "case_result", caseId),
        parentDeath,
      ]);
      const evidence = validateR8CaseEvidence({
        schema_version: 1,
        status: "passed",
        run_id: context.runId,
        ordinal,
        case_id: caseId,
        frame_sequence: result.sequence,
        assertion_count: result.assertion_count,
        assertion_set_sha256: result.assertion_set_sha256,
      }, context);
      await writeSecureJson(
        resolve(context.evidenceRoot, `r8-case-${String(ordinal).padStart(2, "0")}.v1.json`),
        evidence,
      );
      context.r8CaseEvidence.push(evidence);
      context.phase = caseId;
      requireParentAlive();
    },
    async completePlannedRestart() {
      requireParentAlive();
      await captureRunScopedNoLogAuthority(context);
      await sendR8ControlFrame(context, "planned_restart");
      const terminal = await Promise.race([
        context.controlReader.next("planned_restart"),
        childExit(context.processes.api.child, "api"),
        childExit(context.processes.fake.child, "fake"),
        parentDeath,
      ]);
      if (terminal.sequence !== 5) fail("orchestrator_control_order_invalid");
      await context.controlReader.expectEof();
      await waitForDesktopExit(context);
      const ownership = context.ownershipHistory.at(-1);
      const stopped = await readHostProcessEvidence(context, "stopped", ownership.hostEvidence);
      await writeSecureJson(resolve(context.evidenceRoot, ownership.hostStoppedEvidenceName), stopped);
      ownership.hostStoppedEvidence = stopped;
      context.phase = "s10b_005_planned_restart";
      requireParentAlive();
    },
    async completeAbort() {
      requireParentAlive();
      await captureRunScopedNoLogAuthority(context);
      await sendR8ControlFrame(context, "abort");
      const complete = await Promise.race([
        context.controlReader.next("abort_complete"),
        childExit(context.processes.api.child, "api"),
        childExit(context.processes.fake.child, "fake"),
        parentDeath,
      ]);
      if (complete.sequence !== 9) fail("orchestrator_control_order_invalid");
      await context.controlReader.expectEof();
      await waitForDesktopExit(context);
      const ownership = context.ownershipHistory.at(-1);
      const stopped = await readHostProcessEvidence(context, "stopped", ownership.hostEvidence);
      await writeSecureJson(resolve(context.evidenceRoot, ownership.hostStoppedEvidenceName), stopped);
      ownership.hostStoppedEvidence = stopped;
      context.phase = "s10b_011";
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
    async captureNoLogAuthority() {
      requireParentAlive();
      await captureRunScopedNoLogAuthority(context);
      requireParentAlive();
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
    async verifyR8Business() {
      if (!expectedR8(authority) || !context.apiVerifierBefore) {
        fail("orchestrator_business_boundary_unknown");
      }
      if (context.processes.fake && context.r8FakeAuthorities.length < 4) {
        const finalAuthority = await probeClosedFakeAuthority(context, false);
        const specification = context.fakeSpec;
        await persistR8FakeFinalAuthority(context, specification, finalAuthority);
      }
      const after = await runApiVerifierProjection(context);
      await writeSecureJson(resolve(context.evidenceRoot, "r8-api-verifier-after.v1.json"), after);
      context.r8Business = buildR8BusinessEvidence(
        context.apiVerifierBefore,
        after,
        context.r8FakeAuthorities,
        context.r8CaseEvidence,
        context.runId,
      );
      await writeSecureJson(
        resolve(context.evidenceRoot, "r8-business-boundary.v1.json"),
        context.r8Business,
      );
      return context.r8Business;
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
      const observedRoles = new Set([
        ...Object.values(context.processes ?? {}).filter((process_) => process_?.record)
          .map((process_) => process_.role),
        ...Object.values(context.descendantProcesses ?? {}).filter(Boolean)
          .map((process_) => process_.role),
        ...(context.processHistory ?? []).filter((process_) => process_?.record)
          .map((process_) => process_.role),
        ...(context.descendantProcessHistory ?? []).map((process_) => process_.role),
      ]);
      const processRoles = EXISTING_PROCESS_ROLES.filter((role) => observedRoles.has(role));
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
        s10b_r8_executed: expectedR8(authority),
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
        s10b_r8_executed: expectedR8(authority),
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
  options = {},
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
  const r8 = options.r8 === true;
  const expectedNames = r8
    ? r8ProcessEvidenceNamesForPhase(options.phase ?? "s10b_011")
    : expectedRoles.map((role) => `${role}-process.v1.json`).sort();
  const observedNames = entries
    .filter((entry) => entry.name.endsWith("-process.v1.json"))
    .map((entry) => entry.name)
    .sort();
  if (r8
    ? observedNames.some((name) => !expectedNames.includes(name))
    : JSON.stringify(observedNames) !== JSON.stringify(expectedNames)) {
    fail("orchestrator_existing_evidence_incomplete");
  }
  const records = [];
  for (const name of observedNames) {
    const role = r8
      ? name === "api-process.v1.json" ? "api"
        : name.includes("-desktop-") ? "desktop"
          : name.includes("-fake-") ? "fake"
            : name.includes("-host-process.") ? "host"
              : name.includes("-runtime-process.") ? "runtime"
                : null
      : name.slice(0, -"-process.v1.json".length);
    if (!role) fail("orchestrator_existing_evidence_incomplete");
    const path = resolve(evidenceRoot, name);
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
  if (r8) {
    const roles = EXISTING_PROCESS_ROLES.filter((role) => records.some((record) => record.role === role));
    if (JSON.stringify(roles) !== JSON.stringify(expectedRoles)) {
      fail("orchestrator_existing_evidence_incomplete");
    }
    validateR8ProcessRecordSet(records, observedNames, options.requireComplete === true);
  } else {
    validateExistingProcessRecordSet(records, expectedRoles);
  }
  Object.defineProperty(records, "evidenceNames", {
    enumerable: false,
    value: Object.freeze([...observedNames]),
  });
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
  const records = await loadExistingProcessRecords(runRoot, authority.runId, expectedRoles, {
    r8: expectedR8(authority),
    phase: options.phase,
    requireComplete: options.requireComplete === true,
  });
  await validateExistingBinaryAuthority(records, runRoot);
  const byRole = new Map(EXISTING_PROCESS_ROLES.map((role) => [
    role,
    records.filter((record) => record.role === role),
  ]));
  const currentByPid = new Map();
  for (const record of records) {
    let current;
    try {
      current = await inspectProcessIdentityWithRetry(record.pid);
    } catch {
      unknown = true;
      continue;
    }
    currentByPid.set(record.pid, current);
    if (current !== null && !sameProcessIdentity(record, current)) unknown = true;
  }
  for (const record of records) {
    const current = currentByPid.get(record.pid);
    if (current === null || !["host", "runtime"].includes(record.role)) continue;
    const parent = records.find((candidate) => candidate.pid === record.ppid);
    if (!parent || currentByPid.get(parent.pid) === null) unknown = true;
  }
  if (!unknown) {
    const infraOwnedRecords = records.filter((record) =>
      ["api", "desktop", "fake"].includes(record.role),
    ).reverse();
    for (const record of infraOwnedRecords) {
      const outcome = await reconcileProcess(record, {
        inspect: inspectProcessIdentityWithRetry,
        async stop(value) {
          process.kill(value.pid, "SIGTERM");
          for (let attempt = 0; attempt < 80; attempt += 1) {
            const current = await inspectProcessIdentityWithRetry(value.pid);
            if (current === null || !sameProcessIdentity(value, current)) return;
            await new Promise((resolveWait) => setTimeout(resolveWait, 100));
          }
          throw new Error("stop timeout");
        },
      });
      if (!["absent", "stopped"].includes(outcome)) unknown = true;
    }
  }
  if (preOwnershipDescendantAbsenceRequired(expectedRoles)) {
    try {
      await requirePreOwnershipDescendantsAbsent(runRoot);
    } catch {
      unknown = true;
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

async function loadR8PersistedOwnershipEvidence(context, records) {
  const byName = new Map(records.evidenceNames.map((name, index) => [name, records[index]]));
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
  context.ownershipHistory = [];
  context.descendantProcessHistory = [];
  const lifecycles = [1, 2].filter((lifecycle) => records.evidenceNames.includes(
    `r8-lifecycle-${lifecycle}-host-process.v1.json`,
  ));
  for (const lifecycle of lifecycles) {
    const desktopRecord = byName.get(`r8-desktop-${lifecycle}-process.v1.json`);
    const hostRecord = byName.get(`r8-lifecycle-${lifecycle}-host-process.v1.json`);
    const runtimeRecord = byName.get(`r8-lifecycle-${lifecycle}-runtime-process.v1.json`);
    if (!desktopRecord || !hostRecord || !runtimeRecord) fail("orchestrator_existing_evidence_incomplete");
    const prefix = `r8-lifecycle-${lifecycle}`;
    const hostEvidence = validateHostProcessEvidence(
      await readSecureJson(resolve(context.evidenceRoot, `${prefix}-host-evidence.v1.json`)),
      {
        runId: context.runId,
        desktopPid: desktopRecord.pid,
        binarySha256: hostBinarySha256,
        expectedState: "ready",
        expectedPid: hostRecord.pid,
      },
    );
    const runtimeEvidence = validateRuntimeProcessEvidence(
      await readSecureJson(resolve(context.evidenceRoot, `${prefix}-runtime-evidence.v1.json`)),
      {
        runId: context.runId,
        hostPid: hostRecord.pid,
        binarySha256: runtimeBinarySha256,
        manifestSha256,
        nonce: hostEvidence.instanceNonce,
        profile: "feat-126-s10-local-lab",
      },
    );
    let hostStoppedEvidence = null;
    try {
      hostStoppedEvidence = validateHostProcessEvidence(
        await readSecureJson(resolve(context.evidenceRoot, `${prefix}-host-stopped-evidence.v1.json`)),
        {
          runId: context.runId,
          desktopPid: desktopRecord.pid,
          binarySha256: hostBinarySha256,
          expectedState: "stopped",
          expectedPid: hostRecord.pid,
          expectedNonce: hostEvidence.instanceNonce,
          expectedStartedAtUnixMs: hostEvidence.startedAtUnixMs,
        },
      );
    } catch (error) {
      if (r8PersistedStoppedEvidenceRequired(context, lifecycle)) throw error;
    }
    context.ownershipHistory.push({
      hostEvidence,
      runtimeEvidence,
      hostStoppedEvidence,
      hostEvidenceName: `${prefix}-host-evidence.v1.json`,
      runtimeEvidenceName: `${prefix}-runtime-evidence.v1.json`,
      hostStoppedEvidenceName: `${prefix}-host-stopped-evidence.v1.json`,
      hostProcessName: `${prefix}-host-process.v1.json`,
      runtimeProcessName: `${prefix}-runtime-process.v1.json`,
    });
    context.descendantProcessHistory.push(hostRecord, runtimeRecord);
  }
  const final = context.ownershipHistory.at(-1);
  if (!final) return;
  context.hostEvidence = final.hostEvidence;
  context.runtimeEvidence = final.runtimeEvidence;
  context.hostStoppedEvidence = final.hostStoppedEvidence;
  const finalLifecycle = context.ownershipHistory.length;
  context.descendantProcesses = {
    host: byName.get(`r8-lifecycle-${finalLifecycle}-host-process.v1.json`),
    runtime: byName.get(`r8-lifecycle-${finalLifecycle}-runtime-process.v1.json`),
  };
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
  const r8 = expectedR8(authority);
  const byRole = new Map(records.map((record) => [record.role, record]));
  const processes = {};
  const processHistory = [];
  if (r8) {
    const apiRecord = records[records.evidenceNames.indexOf("api-process.v1.json")];
    if (apiRecord) {
      processes.api = { record: apiRecord, logPath: resolve(logRoot, "api-orchestrator.log") };
      processHistory.push({ role: "api", record: apiRecord, evidenceBasename: "api" });
    }
  }
  for (const [role, logName] of [
    ["api", "api-orchestrator.log"],
    ["fake", "fake-orchestrator.log"],
    ["desktop", "desktop-orchestrator.log"],
  ]) {
    const record = byRole.get(role);
    if (record && !r8) processes[role] = { record, logPath: resolve(logRoot, logName) };
  }
  if (r8) {
    for (const name of records.evidenceNames) {
      if (!/^r8-(?:fake|desktop)-[0-9]+-process\.v1\.json$/.test(name)) continue;
      const record = records[records.evidenceNames.indexOf(name)];
      const match = name.match(/^r8-(fake|desktop)-([0-9]+)-process\.v1\.json$/);
      processHistory.push({
        role: match[1],
        record,
        evidenceBasename: name.slice(0, -"-process.v1.json".length),
        logPath: resolve(logRoot, `r8-${match[1]}-${match[2]}.log`),
      });
    }
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
    processHistory,
    fakeSpec: r8 ? S10B_R8_FAKE_GENERATIONS[
      Math.max(0, Math.max(...records.evidenceNames
        .map((name) => /^r8-fake-(\d+)-process\.v1\.json$/.exec(name)?.[1] ?? "0")
        .map(Number), 1) - 1)
    ] : undefined,
  };
  const hasR8Ownership = r8 && records.evidenceNames.some((name) =>
    /^r8-lifecycle-[12]-host-process\.v1\.json$/.test(name));
  context.requireCompleteR8Evidence = Boolean(
    r8 && closure?.status === "passed",
  );
  if (hasR8Ownership) await loadR8PersistedOwnershipEvidence(context, records);
  else if (!r8) await loadPersistedOwnershipEvidence(context, byRole);
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
  if (byRole.has("fake") && !r8) {
    try {
      context.fakeAuthorityBefore = validateClosedFakeAuthorityProjection(await readSecureJson(
        resolve(evidenceRoot, "fake-authority-before.v1.json"),
      ), context);
    } catch {
      if (context.phase !== "fake_starting") fail("orchestrator_existing_evidence_incomplete");
    }
  }
  if (r8) {
    let evidenceNames;
    try {
      evidenceNames = new Set((await readdir(evidenceRoot, { withFileTypes: true }))
        .filter((entry) => entry.isFile() && !entry.isSymbolicLink())
        .map((entry) => entry.name));
    } catch {
      fail("orchestrator_existing_evidence_incomplete");
    }
    const completedCaseCount = context.requireCompleteR8Evidence
      ? S10BO1_CASES.length - 1
      : r8CompletedCaseCountForPhase(context.phase);
    const expectedCaseNames = Array.from({ length: completedCaseCount }, (_, index) =>
      `r8-case-${String(index + 1).padStart(2, "0")}.v1.json`);
    const observedCaseNames = [...evidenceNames].filter((name) => /^r8-case-\d{2}\.v1\.json$/.test(name))
      .sort(asciiCompare);
    if (JSON.stringify(observedCaseNames) !== JSON.stringify(expectedCaseNames)) {
      fail("orchestrator_existing_evidence_incomplete");
    }
    context.r8CaseEvidence = [];
    for (const [index, caseId] of S10BO1_CASES.slice(0, completedCaseCount).entries()) {
      const evidence = validateR8CaseEvidence(
        await readSecureJson(resolve(evidenceRoot, expectedCaseNames[index])),
        authority,
      );
      if (evidence.case_id !== caseId) fail("orchestrator_existing_evidence_incomplete");
      context.r8CaseEvidence.push(evidence);
    }
    const fakeProcessCount = records.evidenceNames.filter((name) =>
      /^r8-fake-\d+-process\.v1\.json$/.test(name)).length;
    context.r8FakeAuthorities = [];
    for (const specification of S10B_R8_FAKE_GENERATIONS.slice(0, fakeProcessCount)) {
      context.fakeSpec = specification;
      const beforeName = `r8-fake-${specification.generation}-before.v1.json`;
      const finalName = `r8-fake-${specification.generation}-final.v1.json`;
      const firstCaseOrdinal = S10BO1_CASES.indexOf(specification.firstCase) + 1;
      const beforeRequired = context.requireCompleteR8Evidence ||
        specification.generation < fakeProcessCount || completedCaseCount >= firstCaseOrdinal;
      const finalRequired = context.requireCompleteR8Evidence || specification.generation < fakeProcessCount;
      if (beforeRequired && !evidenceNames.has(beforeName)) fail("orchestrator_existing_evidence_incomplete");
      if (finalRequired && !evidenceNames.has(finalName)) fail("orchestrator_existing_evidence_incomplete");
      if (evidenceNames.has(beforeName)) {
        const before = validateClosedFakeAuthorityProjection(
          await readSecureJson(resolve(evidenceRoot, beforeName)),
          context,
        );
        context.fakeAuthorityBefore = before;
      }
      if (evidenceNames.has(finalName)) {
        const final = validateClosedFakeAuthorityProjection(
          await readSecureJson(resolve(evidenceRoot, finalName)),
          context,
          false,
        );
        if (final.accepted_calls !== specification.callCap || final.rejected_calls !== 0) {
          fail("orchestrator_existing_evidence_incomplete");
        }
        context.r8FakeAuthorities.push(final);
      }
    }
    const hasAfter = evidenceNames.has("r8-api-verifier-after.v1.json");
    const hasBusiness = evidenceNames.has("r8-business-boundary.v1.json");
    if (hasBusiness && !hasAfter) fail("orchestrator_existing_evidence_incomplete");
    if (hasAfter) {
      context.r8ApiVerifierAfter = validateApiVerifierProjection(
        await readSecureJson(resolve(evidenceRoot, "r8-api-verifier-after.v1.json")),
        authority.runId,
      );
    }
    if (hasBusiness) {
      context.r8Business = validateR8BusinessEvidence(
        await readSecureJson(resolve(evidenceRoot, "r8-business-boundary.v1.json")),
        authority.runId,
      );
    }
    if (context.requireCompleteR8Evidence && (!hasAfter || !hasBusiness ||
      context.r8FakeAuthorities.length !== S10B_R8_FAKE_GENERATIONS.length)) {
      fail("orchestrator_existing_evidence_incomplete");
    }
    if (context.requireCompleteR8Evidence) {
      const reconstructed = buildR8BusinessEvidence(
        context.apiVerifierBefore,
        context.r8ApiVerifierAfter,
        context.r8FakeAuthorities,
        context.r8CaseEvidence,
        authority.runId,
      );
      if (JSON.stringify(reconstructed) !== JSON.stringify(context.r8Business)) {
        fail("orchestrator_existing_evidence_incomplete");
      }
    }
  }
  context.r8CompleteEvidence = Boolean(context.r8Business && context.requireCompleteR8Evidence);
  return context;
}

async function reconcileClaimedAttempt(authority, attempt) {
  let ownerIdentity;
  try {
    ownerIdentity = await inspectProcessIdentityWithRetry(attempt.marker.pid);
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
        (failure.business_failure_class !== null &&
          closure.business_failure_class !== failure.business_failure_class) ||
        (failure.cleanup_failure_class !== null &&
          closure.cleanup_failure_class !== failure.cleanup_failure_class) ||
        (failure.parent_failure_class !== null &&
          closure.parent_failure_class !== failure.parent_failure_class)
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
  validateReconcileFailureProcessState(failure);
  const expectedRoles = failure?.process_roles ?? EXISTING_PROCESS_ROLES;
  const baselineVolumeNames = failure
    ? volumeNamesFromKeys(authority.runId, failure.retained_volume_keys)
    : volumeNamesFromKeys(authority.runId, S10_NAMED_VOLUME_KEYS);
  const reconcileNoLogAuthority = {
    runRoot,
    runRootPresent: true,
    phase: failure?.phase ?? "desktop_exited",
    requireCompleteNoLogAuthority: expectedRoles.includes("desktop"),
  };
  try {
    await captureRunScopedNoLogAuthority(reconcileNoLogAuthority);
  } catch {
    // Cleanup remains mandatory; the later no-log result fails closed.
  }
  let reconciled;
  let cleanupFailure;
  try {
    reconciled = await reconcileExistingRun(authority, runRoot, {
      expectedRoles,
      phase: failure?.phase,
      requireComplete: Boolean(failure?.phase === "s10b_011" || closure?.status === "passed"),
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
      noLogContext.noLogAuthorityCaptureRequired = true;
      noLogContext.noLogAuthorityCaptureFailed =
        reconcileNoLogAuthority.noLogAuthorityCaptureFailed;
      noLogContext.runScopedSecretPatterns =
        reconcileNoLogAuthority.runScopedSecretPatterns;
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
    return await (expectedR8(authority)
      ? runR8Flow(authority, operations)
      : runStartupAbortFlow(authority, operations));
  } finally {
    clearInterval(parentWatchdog);
    for (const [signal, handler] of handlers) process.off(signal, handler);
  }
}

async function main() {
  const r8 = process.argv[2] === "--r8";
  const runId = process.argv[r8 ? 3 : 2];
  if (process.argv.length !== (r8 ? 4 : 3)) fail("orchestrator_arguments_invalid");
  const authority = r8
    ? validateR8OrchestratorInput(runId, process.env, [])
    : validateOrchestratorInput(runId, process.env, []);
  const result = await executeOrchestrator(authority);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${JSON.stringify(buildOrchestratorFailureEnvelope(error))}\n`);
    process.exitCode = 1;
  });
}
