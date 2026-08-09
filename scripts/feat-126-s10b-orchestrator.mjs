#!/usr/bin/env node

import { lstat } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { readExpectedSHAs } from "./feat-126-s10b-preflight.mjs";

const INFRA_ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const RUN_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
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

export const S10BO1_TARGETED_MATRIX = Object.freeze([
  "S10BO1-001", "S10BO1-002", "S10BO1-003", "S10BO1-004",
  "S10BO1-005", "S10BO1-006", "S10BO1-007", "S10BO1-008",
  "S10BO1-009", "S10BO1-010", "S10BO1-011", "S10BO1-012",
  "S10BO1-013", "S10BO1-014",
]);

export const S10BO1_CONTROL_KINDS = Object.freeze([
  "component_ready", "mode_transition", "planned_restart", "case_result", "abort",
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

const STATE_INDEX = new Map(S10BO1_STATES.map((state, index) => [state, index]));
const REPOSITORY_KEYS = Object.freeze(["api", "contracts", "desktop", "governance", "host", "infra", "runtime"]);

export class S10BO1OrchestratorError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function fail(code) {
  throw new S10BO1OrchestratorError(code);
}

export function validateOrchestratorInput(runId, environment = process.env, arguments_ = []) {
  if (!RUN_ID_PATTERN.test(runId ?? "")) fail("orchestrator_run_id_invalid");
  if (arguments_.length !== 0) fail("orchestrator_arguments_invalid");
  if (FORBIDDEN_ENV.some((key) => Object.hasOwn(environment, key))) {
    fail("orchestrator_override_forbidden");
  }
  const repositories = readExpectedSHAs(environment);
  return Object.freeze({ runId, repositories });
}

export function validateRepositorySummary(summary, runId, repositories) {
  if (
    summary === null || Array.isArray(summary) || typeof summary !== "object" ||
    summary.schema_version !== 1 || summary.status !== "passed" ||
    summary.scope !== "S10B-001-combined-preflight" || summary.run_id !== runId ||
    summary.cleanup !== "passed" || summary.s10b_r5_executed !== false ||
    summary.repositories === null || Array.isArray(summary.repositories) ||
    JSON.stringify(Object.keys(summary.repositories).sort()) !== JSON.stringify(REPOSITORY_KEYS) ||
    REPOSITORY_KEYS.some((key) => summary.repositories[key] !== repositories[key])
  ) {
    fail("orchestrator_preflight_authority_invalid");
  }
  return Object.freeze({ runId, repositories, apiBinarySha256: summary.api_binary_sha256 });
}

export function createStateMachine() {
  let current = "created";
  let aborted = false;
  return Object.freeze({
    get state() { return current; },
    transition(next) {
      if (aborted || !STATE_INDEX.has(next) || STATE_INDEX.get(next) !== STATE_INDEX.get(current) + 1) {
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
    closeFailure() {
      if (!aborted || current !== "aborting") fail("orchestrator_abort_invalid");
      current = "cleanup_passed";
      current = "closed_fail";
      return current;
    },
  });
}

export function validateControlFrame(frame, runId, nonce, previousSequence = 0) {
  if (
    frame === null || typeof frame !== "object" || Array.isArray(frame) ||
    frame.schema_version !== 1 || frame.run_id !== runId || frame.nonce !== nonce ||
    !Number.isSafeInteger(frame.sequence) || frame.sequence !== previousSequence + 1 ||
    !S10BO1_CONTROL_KINDS.includes(frame.kind) || Object.keys(frame).some((key) =>
      ["path", "url", "argv", "env", "payload", "secret", "bearer", "dsn"].includes(key))
  ) {
    fail("orchestrator_control_frame_invalid");
  }
  return Object.freeze({ schema_version: 1, run_id: runId, nonce, sequence: frame.sequence, kind: frame.kind });
}

export function validateContentFreeEvidence(evidence, authority) {
  if (
    evidence === null || typeof evidence !== "object" || Array.isArray(evidence) ||
    evidence.schema_version !== 1 || evidence.run_id !== authority.runId ||
    evidence.role !== authority.role || !Number.isInteger(evidence.pid) || evidence.pid <= 0 ||
    !Number.isInteger(evidence.ppid) || evidence.ppid <= 0 ||
    !/^[0-9a-f]{64}$/.test(evidence.binary_sha256 ?? "") ||
    !/^[0-9a-f]{64}$/.test(evidence.manifest_sha256 ?? "") || evidence.nonce !== authority.nonce ||
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
    /^[0-9a-f]{64}$/.test(entry.canonical_hash ?? "");
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    value.schema_version !== 1 || value.status !== "passed" || value.run_id !== runId ||
    value.profile !== "feat-126-s10-local-lab" || value.denylist_hit_count !== 0 ||
    !validCounts(value.tasks) || !validCounts(value.audit) || !validCounts(value.idempotency) ||
    !/^[0-9a-f]{64}$/.test(value.canonical_hash ?? "")
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
    value.schema_version !== 1 || !Number.isSafeInteger(value.file_count) || value.file_count < 0 ||
    !Number.isSafeInteger(value.row_count) || value.row_count < 0 || value.hit_count !== 0 ||
    !/^[0-9a-f]{64}$/.test(value.pattern_set_sha256 ?? "")
  ) {
    fail("orchestrator_no_log_invalid");
  }
  return true;
}

export function validateOwnership(manifests) {
  const expected = Object.freeze({ infra: ["api", "fake", "desktop"], desktop: ["host"], host: ["runtime"] });
  if (manifests === null || typeof manifests !== "object") fail("orchestrator_manifest_invalid");
  for (const [owner, children] of Object.entries(expected)) {
    if (JSON.stringify(manifests[owner]?.children ?? []) !== JSON.stringify(children)) {
      fail("orchestrator_ownership_invalid");
    }
  }
  if (manifests.infra.children.includes("host") || manifests.infra.children.includes("runtime")) {
    fail("orchestrator_ownership_invalid");
  }
  return true;
}

export function buildOrchestratorPlan(input) {
  const authority = validateOrchestratorInput(input?.runId, input?.environment ?? {}, input?.arguments_ ?? []);
  return Object.freeze({
    schema_version: 1,
    kind: "feat126-s10b-orchestrator-plan",
    run_id: authority.runId,
    repositories: authority.repositories,
    ownership: Object.freeze({ infra: ["api", "fake", "desktop"], desktop: ["host"], host: ["runtime"] }),
    states: S10BO1_STATES,
    cases: S10BO1_CASES,
    execution: "separately-authorized-live-only",
  });
}

async function rejectExistingRun(runId) {
  const runRoot = resolve(INFRA_ROOT, "environments/local/generated/feat-126-s10", runId);
  try {
    await lstat(runRoot);
    fail("orchestrator_existing_run_reconciled");
  } catch (error) {
    if (error instanceof S10BO1OrchestratorError) throw error;
    if (error?.code !== "ENOENT") fail("orchestrator_run_root_invalid");
  }
}

async function main() {
  if (process.argv.length !== 3) fail("orchestrator_arguments_invalid");
  const input = validateOrchestratorInput(process.argv[2], process.env, []);
  await rejectExistingRun(input.runId);
  fail("orchestrator_live_execution_not_authorized");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    const code = error instanceof S10BO1OrchestratorError ? error.code : "orchestrator_internal_failure";
    process.stderr.write(`${JSON.stringify({ schema_version: 1, status: "failed", failure_class: code })}\n`);
    process.exitCode = 1;
  });
}
