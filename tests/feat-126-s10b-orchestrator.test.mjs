import test from "node:test";
import assert from "node:assert/strict";

import {
  S10BO1_CASES,
  S10BO1_STATES,
  S10BO1_TARGETED_MATRIX,
  S10BO1OrchestratorError,
  buildOrchestratorPlan,
  createStateMachine,
  validateOwnership,
  validateRepositorySummary,
  validateOrchestratorInput,
  validateContentFreeEvidence,
  validateControlFrame,
  validateApiVerifierProjection,
  validateCleanupClosure,
  validateDesktopDriverProjection,
  validateFakeAuthority,
  validateNoLogResult,
} from "../scripts/feat-126-s10b-orchestrator.mjs";
import { FEAT_126_S10_API_RUNTIME_AUTHORITY } from "../scripts/feat-126-s10-api-runtime-profile.mjs";

const runId = "019fbd88-cbc3-4bf1-934d-7b05cd693f80";
const repositories = Object.freeze({
  governance: "1".repeat(40), contracts: "2".repeat(40), api: "3".repeat(40),
  host: "4".repeat(40), desktop: "5".repeat(40), runtime: "6".repeat(40), infra: "7".repeat(40),
});
const environment = Object.fromEntries(Object.entries(repositories).map(([role, sha]) => [`FEAT126_S10B_${role.toUpperCase()}_SHA`, sha]));
const completed = Object.freeze([
  "authority", "ports", "host_runtime_artifact", "secret_init", "compose", "images", "dependencies",
  "tls_oidc", "identity", "migration", "bootstrap", "api_binary", "host_binary",
  "fake_binary", "probe_binary", "api_health", "api_readiness",
  "host_owned_fake_authority", "fake_readiness", "content_free_logs",
]);

function errorCode(fn) {
  try { fn(); } catch (error) { return error instanceof S10BO1OrchestratorError ? error.code : error.message; }
  return null;
}

test("S10BO1-001 accepts only canonical run and exact repository authority", () => {
  assert.deepEqual(validateOrchestratorInput(runId, environment, []), { runId, repositories });
  assert.equal(errorCode(() => validateOrchestratorInput("not-a-run", environment, [])), "orchestrator_run_id_invalid");
  assert.equal(errorCode(() => validateOrchestratorInput(runId, { ...environment, FEAT126_S10B_ORCHESTRATOR_MODE: "complete" }, [])), "orchestrator_override_forbidden");
  assert.equal(errorCode(() => validateOrchestratorInput(runId, environment, ["unexpected"])), "orchestrator_arguments_invalid");
});

test("S10BO1-002 rejects stale or non-passed same-run preflight", () => {
  const summary = {
    schema_version: 1,
    status: "passed",
    scope: "S10B-001-combined-preflight",
    run_id: runId,
    repositories,
    api_binary_sha256: "a".repeat(64),
    host_runtime_artifact_gate: {
      schema_version: 1,
      status: "passed",
      verifier: "host-runtime-healthcheck-artifact-only",
      host_repository_sha: repositories.host,
      runtime_repository_sha: repositories.runtime,
      runtime_binary_sha256: "c".repeat(64),
      runtime_manifest_sha256: "d".repeat(64),
    },
    api_runtime_authority: FEAT_126_S10_API_RUNTIME_AUTHORITY,
    fake_readiness: {
      schema_version: 1,
      status: "ready",
      run_id: runId,
      dataset_id: "feat126-title-raw-v1",
      fixture_case_id: "normal-000",
      dataset_sha256: "b".repeat(64),
    },
    completed,
    cleanup: "passed",
    s10b_r5_executed: false,
  };
  assert.deepEqual(validateRepositorySummary(summary, runId, repositories).repositories, repositories);
  assert.equal(errorCode(() => validateRepositorySummary({ ...summary, run_id: "019fbd88-cbc3-4bf1-934d-7b05cd693f81" }, runId, repositories)), "orchestrator_preflight_authority_invalid");
  assert.equal(errorCode(() => validateRepositorySummary({ ...summary, status: "failed" }, runId, repositories)), "orchestrator_preflight_authority_invalid");
});

test("S10BO1-003 enforces one closed state order without retry or skip", () => {
  const machine = createStateMachine();
  for (const state of S10BO1_STATES.slice(1)) assert.equal(machine.transition(state), state);
  assert.equal(machine.state, "closed_pass");
  assert.equal(errorCode(() => machine.transition("created")), "orchestrator_state_transition_invalid");
  assert.equal(S10BO1_CASES[3], "s10b_005_planned_restart");
});

test("S10BO1-004 enforces Infra to Desktop to Host to Runtime ownership", () => {
  assert.equal(validateOwnership({ infra: { children: ["api", "fake", "desktop"] }, desktop: { children: ["host"] }, host: { children: ["runtime"] } }), true);
  assert.equal(errorCode(() => validateOwnership({ infra: { children: ["api", "fake", "desktop", "host"] }, desktop: { children: ["host"] }, host: { children: ["runtime"] } })), "orchestrator_ownership_invalid");
});

test("S10BO1-005 closes the abort path without retry", () => {
  const machine = createStateMachine();
  assert.equal(machine.abort(), "aborting");
  assert.equal(machine.closeFailure(), "closed_fail");
  assert.equal(errorCode(() => machine.closeFailure()), "orchestrator_abort_invalid");
});

test("S10BO1-006 plan is content-free and live execution remains separate", () => {
  const plan = buildOrchestratorPlan({ runId, environment, arguments_: [] });
  assert.equal(plan.execution, "separately-authorized-isolated-live-only");
  assert.equal(plan.business_cases, "disabled");
  assert.equal(plan.s10b_r8_executed, false);
  assert.doesNotMatch(JSON.stringify(plan), /secret|bearer|DSN|payload|path|argv|env/);
});

test("S10BO1-007 targeted matrix is closed and ordered", () => {
  assert.deepEqual(S10BO1_TARGETED_MATRIX, Array.from({ length: 14 }, (_, index) => `S10BO1-${String(index + 1).padStart(3, "0")}`));
});

test("S10BO1-008 control frames are same-run, nonce-bound and monotonic", () => {
  const frame = validateControlFrame({ schema_version: 1, run_id: runId, nonce: runId, sequence: 1, kind: "component_ready" }, runId, runId, 0);
  assert.equal(frame.sequence, 1);
  assert.equal(errorCode(() => validateControlFrame({ ...frame, sequence: 3 }, runId, runId, 1)), "orchestrator_control_frame_invalid");
  assert.equal(errorCode(() => validateControlFrame({ ...frame, path: "/private" }, runId, runId, 0)), "orchestrator_control_frame_invalid");
});

test("S10BO1-009 evidence accepts only content-free identity", () => {
  assert.equal(validateContentFreeEvidence({
    schema_version: 1, run_id: runId, role: "runtime", pid: 12, ppid: 10,
    binary_sha256: "a".repeat(64), manifest_sha256: "b".repeat(64), nonce: runId,
    profile: "feat-126-s10-local-lab", state: "ready",
  }, { runId, role: "runtime", nonce: runId, profile: "feat-126-s10-local-lab" }), true);
});

test("S10BO1-010 fake authority binds mode, generation and call cap", () => {
  const authority = { runId, mode: "disconnect", generation: 3, callCap: 5 };
  assert.equal(validateFakeAuthority({ schema_version: 1, status: "ready", run_id: runId, mode: "disconnect", generation: 3, call_cap: 5 }, authority), true);
  assert.equal(errorCode(() => validateFakeAuthority({ schema_version: 1, status: "ready", run_id: runId, mode: "complete", generation: 3, call_cap: 5 }, authority)), "orchestrator_fake_authority_invalid");
});

test("S10BO1-011 API verifier projection is content-free and denylist-clean", () => {
  const counts = { count: 1, enums: ["draft"], canonical_hash: "a".repeat(64) };
  assert.equal(validateApiVerifierProjection({ schema_version: 1, status: "passed", run_id: runId, profile: "feat-126-s10-local-lab", tasks: counts, audit: counts, idempotency: counts, denylist_hit_count: 0, canonical_hash: "b".repeat(64) }, runId), true);
});

test("S10BO1-012 Desktop driver is test-profile, nonce and PKCE bound", () => {
  assert.equal(validateDesktopDriverProjection({ schema_version: 1, message_kind: "component_ready", run_id: runId, nonce: runId, sequence: 1, profile: "feat-126-s10-local-lab", project: { capability: "local_only" }, authorization: { flow: "authorization_code", method: "S256", code_challenge: "x".repeat(43) } }, { runId, nonce: runId }), true);
});

test("S10BO1-013 cleanup is exact and preserves named volumes", () => {
  const cleanup = { schema_version: 1, scope: "run_artifacts", status: "passed", containers: 0, networks: 0, processes: 0, listeners: 0, temporary_volumes: 0, named_volume_baseline_count: 4, named_volume_after_count: 4, named_volumes_preserved: true, prune_executed: false, volume_delete_executed: false };
  assert.equal(validateCleanupClosure(cleanup), true);
  assert.equal(errorCode(() => validateCleanupClosure({ ...cleanup, named_volumes_preserved: false })), "orchestrator_cleanup_incomplete");
});

test("S10BO1-014 no-log result requires zero hits", () => {
  const noLog = {
    schema_version: 1,
    scope: "run_artifacts",
    coverage: "all_run_log_and_evidence_sources",
    file_count: 8,
    row_count: 12,
    hit_count: 0,
    external_source_count: 4,
    external_row_count: 4,
    external_source_set_sha256: "b".repeat(64),
    pattern_set_sha256: "c".repeat(64),
  };
  assert.equal(validateNoLogResult(noLog), true);
  assert.equal(errorCode(() => validateNoLogResult({ ...noLog, hit_count: 1 })), "orchestrator_no_log_invalid");
});
