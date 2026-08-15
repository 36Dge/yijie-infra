import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import test from "node:test";

import {
  S10BO1_CASES,
  S10BO1OrchestratorError,
  S10B_R8_FROZEN_CASE_IDS,
  S10B_R8_FAKE_GENERATIONS,
  S10B_R8_STATES,
  allocateR8LifecycleNonce,
  buildOrchestratorPlan,
  buildR8DefaultOffEvidence,
  buildR8BusinessEvidence,
  buildR8OrchestratorPlan,
  createR8ControlFrameReader,
  createR8StateMachine,
  encodeR8ControlFrame,
  loadExistingProcessRecords,
  persistR8FakeFinalAuthority,
  r8CaseAuthority,
  r8ControlTimeoutFor,
  r8NoLogRequiredEvidenceNames,
  r8ProcessEvidenceNamesForPhase,
  runR8Flow,
  scanOpaqueNoLogFile,
  validateOrchestratorInput,
  validateR8BusinessEvidence,
  validateR8CaseEvidence,
  validateR8DefaultOffEvidence,
  validateR8OrchestratorInput,
  validateR8ProcessRecordSet,
} from "../scripts/feat-126-s10b-orchestrator.mjs";
import { FEAT_126_S10_API_RUNTIME_AUTHORITY } from "../scripts/feat-126-s10-api-runtime-profile.mjs";

const runId = "019fbd88-cbc3-4bf1-934d-7b05cd693f80";
const nonce = "019fbd88-cbc3-4bf1-934d-7b05cd693f81";
const repositories = Object.freeze({
  governance: "1".repeat(40),
  contracts: "2".repeat(40),
  api: "3".repeat(40),
  host: "4".repeat(40),
  desktop: "5".repeat(40),
  runtime: "6".repeat(40),
  infra: "7".repeat(40),
});
const environment = Object.fromEntries(Object.entries(repositories).map(
  ([role, sha]) => [`FEAT126_S10B_${role.toUpperCase()}_SHA`, sha],
));
const hash = "a".repeat(64);
const completed = Object.freeze([
  "authority", "ports", "host_runtime_artifact", "secret_init", "compose", "images", "dependencies",
  "tls_oidc", "identity", "migration", "bootstrap", "api_binary", "host_binary",
  "fake_binary", "probe_binary", "api_health", "api_readiness",
  "host_owned_fake_authority", "fake_readiness", "content_free_logs",
]);

function summary() {
  return {
    schema_version: 1,
    status: "passed",
    scope: "S10B-001-combined-preflight",
    run_id: runId,
    repositories,
    api_binary_sha256: hash,
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
}

function cleanupResult() {
  return {
    schema_version: 1,
    scope: "run_artifacts",
    status: "passed",
    containers: 0,
    networks: 0,
    processes: 0,
    listeners: 0,
    temporary_volumes: 0,
    named_volume_baseline_count: 4,
    named_volume_after_count: 4,
    named_volumes_preserved: true,
    prune_executed: false,
    volume_delete_executed: false,
  };
}

function noLogResult() {
  return {
    schema_version: 1,
    scope: "run_artifacts",
    coverage: "all_run_log_and_evidence_sources",
    file_count: 1,
    row_count: 0,
    hit_count: 0,
    external_source_count: 4,
    external_row_count: 0,
    external_source_set_sha256: "c".repeat(64),
    pattern_set_sha256: "d".repeat(64),
  };
}

function projection({ tasks = 0, audit = 0, idempotency = 0 } = {}) {
  const entry = (count, enums) => ({ count, enums, canonical_hash: hash });
  return {
    schema_version: 1,
    status: "passed",
    profile: "feat-126-s10-local-lab",
    run_id: runId,
    tasks: entry(tasks, tasks === 0 ? [] : ["draft"]),
    audit: entry(audit, audit === 0 ? [] : ["success"]),
    idempotency: entry(idempotency, idempotency === 0 ? [] : ["bound"]),
    denylist_hit_count: 0,
    canonical_hash: tasks === 0 ? "b".repeat(64) : "c".repeat(64),
  };
}

function fakeAuthority(specification) {
  return {
    schema_version: 1,
    status: "ready",
    run_id: runId,
    mode: specification.mode,
    generation: specification.generation,
    call_cap: specification.callCap,
    accepted_calls: specification.callCap,
    rejected_calls: 0,
  };
}

function closedFakeAuthority(specification, overrides = {}) {
  return {
    ...fakeAuthority(specification),
    dataset_id: "feat126-title-raw-v1",
    fixture_case_id: "normal-000",
    dataset_sha256: "b".repeat(64),
    ...overrides,
  };
}

function caseEvidence() {
  return S10BO1_CASES.slice(0, -1).map((caseId, index) => {
    const authority = r8CaseAuthority(caseId);
    return {
      schema_version: 1,
      status: "passed",
      run_id: runId,
      ordinal: index + 1,
      case_id: caseId,
      frame_sequence: index < 3 ? index + 2 : index - 1,
      assertion_count: authority.assertionCount,
      assertion_set_sha256: authority.assertionSetSha256,
    };
  });
}

function caseFrame(caseId, sequence) {
  const authority = r8CaseAuthority(caseId);
  return JSON.stringify({
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence,
    kind: "case_result",
    case_id: caseId,
    status: "passed",
    assertion_count: authority.assertionCount,
    assertion_set_sha256: authority.assertionSetSha256,
  });
}

test("S10BR8-001 keeps startup and full-case authorities disjoint", () => {
  assert.deepEqual(validateOrchestratorInput(runId, environment), { runId, repositories });
  assert.deepEqual(validateR8OrchestratorInput(runId, environment), {
    runId,
    repositories,
    r8: true,
  });
  assert.equal(buildOrchestratorPlan({ runId, environment }).s10b_r8_executed, false);
  const plan = buildR8OrchestratorPlan({ runId, environment });
  assert.equal(plan.kind, "feat126-s10b-r8-plan");
  assert.equal(plan.business_cases, "frozen_s10b_002_011");
  assert.equal(plan.s10b_r8_executed, true);
  assert.equal(plan.execution, "single-authorized-fresh-r8-only");
  for (const name of [
    "VITE_FEAT126_S10_R8",
    "YIJIE_FEAT126_S10_R8_ENABLED",
    "YIJIE_FEAT126_S10_R8_PHASE",
  ]) {
    assert.throws(
      () => validateR8OrchestratorInput(runId, { ...environment, [name]: "true" }),
      (error) => error?.code === "orchestrator_override_forbidden",
    );
  }
});

test("S10BR8-002 freezes exact states, cases, and four fake generations", () => {
  assert.deepEqual(S10B_R8_FROZEN_CASE_IDS, [
    "s10b_001", "s10b_002", "s10b_003", "s10b_004", "s10b_005", "s10b_006",
    "s10b_007", "s10b_008", "s10b_009", "s10b_010", "s10b_011", "s10b_012",
  ]);
  assert.deepEqual(S10B_R8_STATES.slice(-12), [...S10BO1_CASES.slice(0, -1), "cleanup_passed", "closed_pass"]);
  assert.deepEqual(S10B_R8_FAKE_GENERATIONS, [
    { generation: 1, mode: "complete", callCap: 2, firstCase: "s10b_002" },
    { generation: 2, mode: "incomplete", callCap: 1, firstCase: "s10b_004" },
    { generation: 3, mode: "disconnect", callCap: 1, firstCase: "s10b_006" },
    { generation: 4, mode: "oversize", callCap: 1, firstCase: "s10b_011" },
  ]);
  const machine = createR8StateMachine();
  for (const state of S10B_R8_STATES.slice(1)) assert.equal(machine.transition(state), state);
});

test("S10BR8-002A allocates one fresh nonce for each lifecycle without collision retry", () => {
  const first = "12600000-0000-4000-8000-000000000071";
  const second = "12600000-0000-4000-8000-000000000072";
  assert.equal(allocateR8LifecycleNonce([], () => first), first);
  assert.equal(allocateR8LifecycleNonce([first], () => second), second);
  assert.throws(
    () => allocateR8LifecycleNonce([first], () => first),
    (error) => error?.code === "orchestrator_r8_authority_invalid",
  );
  assert.throws(
    () => allocateR8LifecycleNonce([first], () => "not-a-uuid"),
    (error) => error?.code === "orchestrator_r8_authority_invalid",
  );
});

test("S10BR8-003 encodes only monotonic fixed mode and terminal frames", () => {
  const mode = encodeR8ControlFrame({
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence: 1,
    kind: "mode_transition",
    case_id: "s10b_002",
  }, { runId, nonce, previousSequence: 0 });
  assert.equal(JSON.parse(mode).case_id, "s10b_002");
  const terminal = encodeR8ControlFrame({
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence: 5,
    kind: "planned_restart",
  }, { runId, nonce, previousSequence: 4 });
  assert.equal(JSON.parse(terminal).kind, "planned_restart");
  assert.throws(() => encodeR8ControlFrame({
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence: 1,
    kind: "mode_transition",
    case_id: "operator_case",
  }, { runId, nonce, previousSequence: 0 }));
});

test("S10BR8-004 reads ordered case results before planned restart", async () => {
  const frames = ["s10b_002", "s10b_003", "s10b_004"]
    .map((caseId, index) => caseFrame(caseId, index + 1));
  frames.push(JSON.stringify({
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence: 4,
    kind: "planned_restart",
  }));
  const reader = createR8ControlFrameReader(Readable.from(`${frames.join("\n")}\n`), { runId, nonce });
  for (const caseId of S10BO1_CASES.slice(0, 3)) {
    assert.equal((await reader.next("case_result", caseId)).case_id, caseId);
  }
  assert.equal((await reader.next("planned_restart")).sequence, 4);
  assert.equal(await reader.expectEof(), true);
});

test("S10BR8-004B gives only case results the bounded 120-second probe window", async () => {
  const authority = r8CaseAuthority("s10b_002");
  assert.equal(r8ControlTimeoutFor("case_result"), 120_000);
  assert.equal(r8ControlTimeoutFor("component_ready"), 60_000);
  const control = Readable.from(`${JSON.stringify({
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence: 1,
    kind: "case_result",
    case_id: "s10b_002",
    status: "passed",
    assertion_count: authority.assertionCount,
    assertion_set_sha256: authority.assertionSetSha256,
  })}\n`);
  const reader = createR8ControlFrameReader(control, { runId, nonce });
  assert.equal((await reader.next("case_result", "s10b_002")).case_id, "s10b_002");
  const startup = createR8ControlFrameReader(Readable.from([]), { runId, nonce });
  await assert.rejects(startup.next("component_ready"), (error) => error?.code === "orchestrator_control_eof");
});

test("S10BR8-004A rejects S10B-005 before restart and requires it after restart", async () => {
  const earlyFrames = ["s10b_002", "s10b_003", "s10b_004", "s10b_005_planned_restart"]
    .map((caseId, index) => caseFrame(caseId, index + 1));
  const earlyReader = createR8ControlFrameReader(
    Readable.from(`${earlyFrames.join("\n")}\n`),
    { runId, nonce },
  );
  for (const caseId of S10BO1_CASES.slice(0, 3)) await earlyReader.next("case_result", caseId);
  await assert.rejects(earlyReader.next("planned_restart"));

  const missingFrames = S10BO1_CASES.slice(4, -1)
    .map((caseId, index) => caseFrame(caseId, index + 1));
  const missingReader = createR8ControlFrameReader(
    Readable.from(`${missingFrames.join("\n")}\n`),
    { runId, nonce },
  );
  await assert.rejects(missingReader.next("case_result", "s10b_005_planned_restart"));
});

test("S10BR8-005 validates content-free case and aggregate business evidence", () => {
  const cases = caseEvidence();
  cases.forEach((value) => assert.equal(validateR8CaseEvidence(value, { runId }).status, "passed"));
  const evidence = buildR8BusinessEvidence(
    projection(),
    projection({ tasks: 2, audit: 2, idempotency: 2 }),
    S10B_R8_FAKE_GENERATIONS.map(fakeAuthority),
    cases,
    runId,
  );
  assert.equal(validateR8BusinessEvidence(evidence, runId).fake_accepted_calls, 5);
  assert.equal(evidence.case_count, 10);
  assert.equal(evidence.s10b_r8_executed, true);
  assert.deepEqual(Object.keys(evidence).sort(), [
    "api_after_sha256", "api_before_sha256", "audit_count_delta", "business_cases",
    "case_count", "case_order_sha256", "fake_accepted_calls", "fake_authority_set_sha256",
    "fake_generation_count", "fake_rejected_calls", "idempotency_count_delta", "run_id",
    "s10b_r8_executed", "schema_version", "status", "tasks_count_delta",
  ].sort());
});

test("S10BR8-006 fails closed on case order, fake calls, or API aggregates", () => {
  const cases = caseEvidence();
  assert.throws(() => buildR8BusinessEvidence(
    projection(),
    projection({ tasks: 1, audit: 2, idempotency: 2 }),
    S10B_R8_FAKE_GENERATIONS.map(fakeAuthority),
    cases,
    runId,
  ));
  const fakes = S10B_R8_FAKE_GENERATIONS.map(fakeAuthority);
  fakes[2] = { ...fakes[2], accepted_calls: 0 };
  assert.throws(() => buildR8BusinessEvidence(
    projection(), projection({ tasks: 2, audit: 2, idempotency: 2 }), fakes, cases, runId,
  ));
  const reordered = [...cases];
  [reordered[0], reordered[1]] = [reordered[1], reordered[0]];
  assert.throws(() => buildR8BusinessEvidence(
    projection(),
    projection({ tasks: 2, audit: 2, idempotency: 2 }),
    S10B_R8_FAKE_GENERATIONS.map(fakeAuthority),
    reordered,
    runId,
  ));
});

test("S10BR8-006A persists the closed fake authority before enforcing exact call counts", async (t) => {
  const evidenceRoot = await mkdtemp(join(tmpdir(), "feat126-r8-fake-final-"));
  t.after(() => rm(evidenceRoot, { recursive: true, force: true }));
  const specification = S10B_R8_FAKE_GENERATIONS[1];
  const observed = closedFakeAuthority(specification, { accepted_calls: 0, rejected_calls: 1 });
  const context = {
    runId,
    evidenceRoot,
    fakeSpec: specification,
    r8FakeAuthorities: [],
    summary: summary(),
  };
  await assert.rejects(
    persistR8FakeFinalAuthority(context, specification, observed),
    (error) => error?.code === "orchestrator_fake_authority_invalid",
  );
  const evidencePath = join(evidenceRoot, "r8-fake-2-final.v1.json");
  assert.deepEqual(JSON.parse(await readFile(evidencePath, "utf8")), observed);
  assert.equal((await stat(evidencePath)).mode & 0o777, 0o600);
  assert.deepEqual(context.r8FakeAuthorities, []);
});

test("S10BR8-006B retains an exact fake authority for aggregate verification", async (t) => {
  const evidenceRoot = await mkdtemp(join(tmpdir(), "feat126-r8-fake-valid-"));
  t.after(() => rm(evidenceRoot, { recursive: true, force: true }));
  const specification = S10B_R8_FAKE_GENERATIONS[1];
  const observed = closedFakeAuthority(specification);
  const context = {
    runId,
    evidenceRoot,
    fakeSpec: specification,
    r8FakeAuthorities: [],
    summary: summary(),
  };
  assert.deepEqual(
    await persistR8FakeFinalAuthority(context, specification, observed),
    observed,
  );
  assert.deepEqual(context.r8FakeAuthorities, [observed]);
});

function r8FlowOperations(calls, overrides = {}) {
  const cases = caseEvidence();
  const business = buildR8BusinessEvidence(
    projection(),
    projection({ tasks: 2, audit: 2, idempotency: 2 }),
    S10B_R8_FAKE_GENERATIONS.map(fakeAuthority),
    cases,
    runId,
  );
  return {
    async runPreflight() { calls.push("preflight"); return summary(); },
    async buildDesktop() { calls.push("build_desktop"); },
    async startDependencies() { calls.push("dependencies"); },
    async startApi() { calls.push("api"); },
    async startFakeGeneration(specification) { calls.push(`fake:${specification.generation}`); },
    async startDesktopLifecycle(lifecycle, phase) { calls.push(`desktop:${lifecycle}:${phase}`); },
    async readLifecycleOwnership(lifecycle) { calls.push(`ownership:${lifecycle}`); },
    async executeCase(caseId) { calls.push(`case:${caseId}`); },
    async scanNoLogCheckpoint(caseId) {
      calls.push(`case_no_log:${caseId}`);
      return noLogResult();
    },
    async completePlannedRestart() { calls.push("planned_restart"); },
    async completeAbort() { calls.push("abort"); },
    async captureNoLogAuthority() { calls.push("capture_no_log_authority"); },
    async initiateDesktopAbort() { calls.push("desktop_abort"); },
    async verifyR8Business() { calls.push("business"); return business; },
    async cleanup() { calls.push("cleanup"); return cleanupResult(); },
    async scanNoLog() { calls.push("no_log"); return noLogResult(); },
    async recordFailure(value) { calls.push(`failure:${value.failureClass}`); },
    async recordClosure(value) {
      calls.push(`closure:${value.status}:${value.businessStatus}`);
    },
    ...overrides,
  };
}

test("S10BR8-007 runs one frozen order with two Desktop lifecycles and four fake generations", async () => {
  const calls = [];
  const result = await runR8Flow({ runId, repositories, r8: true }, r8FlowOperations(calls));
  assert.equal(result.status, "passed");
  assert.equal(result.s10b_r8_executed, true);
  assert.equal(calls.filter((call) => call.startsWith("desktop:")).length, 2);
  assert.equal(calls.filter((call) => call.startsWith("fake:")).length, 4);
  assert.deepEqual(calls.filter((call) => call.startsWith("case:")),
    S10BO1_CASES.slice(0, -1).map((caseId) => `case:${caseId}`));
  assert.deepEqual(calls.filter((call) => call.startsWith("case_no_log:")),
    S10BO1_CASES.slice(0, -1).map((caseId) => `case_no_log:${caseId}`));
  assert.equal(calls.filter((call) => call === "planned_restart").length, 1);
  assert.deepEqual(calls.slice(-4), ["business", "cleanup", "no_log", "closure:passed:passed"]);
});

test("S10BR8-008 keeps primary failure immutable, skips business, and closes once", async () => {
  const calls = [];
  const failureValues = [];
  const closureValues = [];
  await assert.rejects(
    runR8Flow({ runId, repositories, r8: true }, r8FlowOperations(calls, {
      async executeCase(caseId) {
        calls.push(`case:${caseId}`);
        if (caseId === "s10b_006") throw new S10BO1OrchestratorError("orchestrator_control_timeout");
      },
      async recordFailure(value) { failureValues.push(value); calls.push(`failure:${value.failureClass}`); },
      async recordClosure(value) { closureValues.push(value); calls.push(`closure:${value.status}:${value.businessStatus}`); },
    })),
    (error) => error?.code === "orchestrator_control_timeout",
  );
  assert.equal(calls.includes("business"), false);
  assert.equal(calls.filter((call) => call === "desktop_abort").length, 1);
  assert.equal(calls.filter((call) => call === "cleanup").length, 1);
  assert.equal(failureValues.length, 1);
  assert.equal(failureValues[0].failureClass, "orchestrator_control_timeout");
  assert.equal(closureValues.length, 1);
  assert.equal(closureValues[0].failureClass, "orchestrator_control_timeout");
  assert.equal(closureValues[0].businessStatus, "not_applicable");
  assert.equal(closureValues[0].cleanupScope, "run_artifacts");
});

test("S10BR8-008 aborts at the first per-case no-log failure without later cases", async () => {
  const calls = [];
  await assert.rejects(
    runR8Flow({ runId, repositories, r8: true }, r8FlowOperations(calls, {
      async scanNoLogCheckpoint(caseId) {
        calls.push(`case_no_log:${caseId}`);
        return caseId === "s10b_003" ? { ...noLogResult(), hit_count: 1 } : noLogResult();
      },
    })),
    (error) => error?.code === "orchestrator_no_log_invalid",
  );
  assert.deepEqual(calls.filter((call) => call.startsWith("case:")), [
    "case:s10b_002",
    "case:s10b_003",
  ]);
  assert.equal(calls.filter((call) => call === "desktop_abort").length, 1);
  assert.equal(calls.includes("business"), false);
});

function r8ProcessRecords(names) {
  const infraPid = 42;
  const records = [];
  const pidByName = new Map();
  for (const [index, name] of names.entries()) pidByName.set(name, 100 + index);
  for (const [index, name] of names.entries()) {
    const role = name === "api-process.v1.json" ? "api"
      : name.includes("-fake-") ? "fake"
        : name.includes("-desktop-") ? "desktop"
          : name.includes("-host-process.") ? "host" : "runtime";
    const lifecycle = /r8-lifecycle-(\d+)-/.exec(name)?.[1];
    const ppid = role === "host"
      ? pidByName.get(`r8-desktop-${lifecycle}-process.v1.json`)
      : role === "runtime"
        ? pidByName.get(`r8-lifecycle-${lifecycle}-host-process.v1.json`)
        : infraPid;
    records.push({
      schema_version: 1,
      run_id: runId,
      role,
      pid: pidByName.get(name),
      ppid,
      binary_sha256: String((index % 9) + 1).repeat(64),
      start_identity: String.fromCharCode(97 + (index % 6)).repeat(64),
    });
  }
  return records;
}

test("S10BR8-009 validates partial and complete process evidence without gaps or extras", () => {
  const partialNames = r8ProcessEvidenceNamesForPhase("s10b_006");
  assert.equal(validateR8ProcessRecordSet(
    r8ProcessRecords(partialNames),
    partialNames,
    { phase: "s10b_006" },
  ), true);
  const completeNames = r8ProcessEvidenceNamesForPhase("s10b_011");
  assert.equal(validateR8ProcessRecordSet(
    r8ProcessRecords(completeNames),
    completeNames,
    { phase: "s10b_011", complete: true },
  ), true);
  const missingGeneration = partialNames.filter((name) => name !== "r8-fake-2-process.v1.json");
  assert.throws(() => validateR8ProcessRecordSet(
    r8ProcessRecords(missingGeneration),
    missingGeneration,
    { phase: "s10b_006" },
  ));
  const extra = [...partialNames, "r8-fake-4-process.v1.json"].sort();
  assert.throws(() => validateR8ProcessRecordSet(
    r8ProcessRecords(extra),
    extra,
    { phase: "s10b_006" },
  ));
  const broken = r8ProcessRecords(partialNames);
  const hostIndex = partialNames.indexOf("r8-lifecycle-2-host-process.v1.json");
  broken[hostIndex] = { ...broken[hostIndex], ppid: 999 };
  assert.throws(() => validateR8ProcessRecordSet(broken, partialNames, { phase: "s10b_006" }));
});

test("S10BR8-009 complete process validation survives the persisted-record loading boundary", async (t) => {
  const runRoot = await realpath(await mkdtemp(join(tmpdir(), "feat126-r8-complete-records-")));
  await chmod(runRoot, 0o700);
  t.after(() => rm(runRoot, { recursive: true, force: true }));
  const evidenceRoot = join(runRoot, "orchestrator-evidence");
  await mkdir(evidenceRoot, { mode: 0o700 });
  await chmod(evidenceRoot, 0o700);
  const partialNames = r8ProcessEvidenceNamesForPhase("s10b_006");
  const partialRecords = r8ProcessRecords(partialNames);
  for (const [index, name] of partialNames.entries()) {
    const evidencePath = join(evidenceRoot, name);
    await writeFile(evidencePath, `${JSON.stringify(partialRecords[index])}\n`, { mode: 0o600 });
    await chmod(evidencePath, 0o600);
  }
  await assert.rejects(
    loadExistingProcessRecords(
      runRoot,
      runId,
      ["api", "desktop", "fake", "host", "runtime"],
      { r8: true, phase: "s10b_011", requireComplete: true },
    ),
    (error) => error?.code === "orchestrator_existing_evidence_incomplete",
  );
});

test("S10BR8-010 derives no-log evidence from the reached prefix and requires full success", () => {
  const partial = r8NoLogRequiredEvidenceNames({
    r8: true,
    apiVerifierBefore: projection(),
    fakeSpec: S10B_R8_FAKE_GENERATIONS[2],
    fakeAuthorityBefore: fakeAuthority(S10B_R8_FAKE_GENERATIONS[2]),
    r8FakeAuthorities: S10B_R8_FAKE_GENERATIONS.slice(0, 2).map(fakeAuthority),
    r8CaseEvidence: caseEvidence().slice(0, 4),
  });
  assert.equal(partial.includes("r8-fake-3-before.v1.json"), true);
  assert.equal(partial.includes("r8-fake-3-final.v1.json"), false);
  assert.equal(partial.includes("r8-case-04.v1.json"), true);
  assert.equal(partial.includes("r8-case-05.v1.json"), false);
  assert.equal(partial.includes("r8-runtime-log-scan-04.v1.json"), true);
  assert.equal(partial.includes("r8-no-log-04.v1.json"), true);

  const complete = r8NoLogRequiredEvidenceNames({
    r8: true,
    apiVerifierBefore: projection(),
    fakeSpec: S10B_R8_FAKE_GENERATIONS[3],
    fakeAuthorityBefore: fakeAuthority(S10B_R8_FAKE_GENERATIONS[3]),
    r8FakeAuthorities: S10B_R8_FAKE_GENERATIONS.map(fakeAuthority),
    r8CaseEvidence: caseEvidence(),
    r8Business: { status: "passed" },
  });
  assert.equal(complete.includes("r8-api-verifier-after.v1.json"), true);
  assert.equal(complete.includes("r8-business-boundary.v1.json"), true);
  assert.equal(complete.filter((name) => /^r8-case-/.test(name)).length, 10);
  assert.equal(complete.filter((name) => /^r8-runtime-log-scan-/.test(name)).length, 10);
  assert.equal(complete.filter((name) => /^r8-no-log-/.test(name)).length, 10);
  assert.equal(complete.filter((name) => /^r8-fake-\d+-final/.test(name)).length, 4);
});

test("S10BR8-010 scans opaque Host bbolt bytes without requiring UTF-8", async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "feat126-r8-bbolt-scan-")));
  t.after(() => rm(root, { recursive: true, force: true }));
  const databasePath = join(root, "sessions.db");
  await writeFile(databasePath, Buffer.from([0xff, 0x00, ...Buffer.from("closed-state")]));
  await chmod(databasePath, 0o600);
  assert.deepEqual(
    await scanOpaqueNoLogFile(databasePath, [{ name: "canary", value: "never-present" }], [], true),
    { present: true, rowCount: 1, hitCount: 0 },
  );
  await writeFile(databasePath, Buffer.from([0xff, 0x00, ...Buffer.from("fixed-canary")]));
  await chmod(databasePath, 0o600);
  assert.equal(
    (await scanOpaqueNoLogFile(
      databasePath,
      [{ name: "canary", value: "fixed-canary" }],
      [],
      true,
    )).hitCount,
    1,
  );
});

test("S10BR8-012 binds final default-off evidence to run and repository authority", () => {
  const authority = { runId, repositories, r8: true };
  const evidence = buildR8DefaultOffEvidence(authority, {
    ambientSetCount: 0,
    trackedConfigCount: 7,
    trackedConfigSetSha256: "e".repeat(64),
    trackedDefaultOnCount: 0,
    untrackedConfigCount: 0,
    liveProcessCount: 0,
  });
  assert.equal(evidence.schema_version, 2);
  assert.deepEqual(validateR8DefaultOffEvidence(evidence, authority), evidence);
  const {
    tracked_config_count: _trackedConfigCount,
    tracked_config_set_sha256: _trackedConfigSetSha256,
    ...legacy
  } = evidence;
  assert.equal(validateR8DefaultOffEvidence({ ...legacy, schema_version: 1 }, authority).schema_version, 1);
  for (const invalid of [
    { ambient_set_count: 1 },
    { tracked_config_count: 0 },
    { tracked_config_set_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
    { tracked_default_on_count: 1 },
    { untracked_config_count: 1 },
    { live_process_count: 1 },
    { repository_authority_sha256: "f".repeat(64) },
  ]) {
    assert.throws(() => validateR8DefaultOffEvidence({ ...evidence, ...invalid }, authority));
  }
});
