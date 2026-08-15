import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { PassThrough, Readable } from "node:stream";
import test from "node:test";

import { FEAT_126_S10_API_RUNTIME_AUTHORITY } from "../scripts/feat-126-s10-api-runtime-profile.mjs";
import {
  attemptPrevalidatedDependencyStart,
  preparePreflightFailureEvidenceRoots,
} from "../scripts/feat-126-s10b-preflight.mjs";
import {
  S10BO1OrchestratorError,
  S10BO3_TARGETED_MATRIX,
  buildBusinessBoundaryEvidence,
  buildAttemptReconcileEvidence,
  buildOrchestratorFailureEnvelope,
  buildPreflightMakeInvocation,
  claimAttemptLedger,
  classifyProjectVolumes,
  captureRuntimeLogScan,
  executePreflight,
  loadExistingProcessRecords,
  parsePreflightFailureFrame,
  persistedOwnershipEvidenceRequiredFiles,
  readAttemptClosure,
  readAttemptFailure,
  readAttemptPreclaimFailure,
  readAttemptReconcile,
  readDesktopFrame,
  requirePreOwnershipDescendantsAbsent,
  r8NoLogRequiredEvidenceNames,
  r8OwnershipStoppedEvidenceRequired,
  r8PersistedStoppedEvidenceRequired,
  runStartupAbortFlow,
  scanNoLog,
  scanNoLogBuffer,
  shouldRunComposeCleanup,
  validateAttemptClosure,
  validateAttemptFailure,
  validateAttemptMarker,
  validateAttemptPreclaim,
  validateAttemptPreclaimFailure,
  validateAttemptReconcile,
  validateBusinessBoundaryEvidence,
  validateCleanupClosure,
  validateExistingProcessRecordSet,
  validateFreshResourceInventory,
  validateNoLogResult,
  createControlFrameReader,
  createR8ControlFrameReader,
  validatePreflightFailureBinding,
  validateReconcileFailureProcessState,
  validateRuntimeLogScan,
  validateStartupFailureControlFrame,
  writeAttemptClosure,
  writeAttemptFailure,
  writeAttemptReconcile,
} from "../scripts/feat-126-s10b-orchestrator.mjs";

const runId = "12600000-0000-4000-8000-000000000070";
const repositories = Object.freeze({
  governance: "1".repeat(40),
  contracts: "2".repeat(40),
  api: "3".repeat(40),
  host: "4".repeat(40),
  desktop: "5".repeat(40),
  runtime: "6".repeat(40),
  infra: "7".repeat(40),
});
const authority = Object.freeze({ runId, repositories });
const identity = Object.freeze({
  pid: process.pid,
  ppid: Math.max(process.ppid, 1),
  start_identity: "a".repeat(64),
  binary_sha256: "b".repeat(64),
});
const scriptSha256 = "c".repeat(64);

test("S10BO3 R8 reader preserves every closed bind startup leaf", async () => {
  const failureClasses = [
    "driver_bind_context_denied",
    "driver_bind_context_invalid",
    "driver_bind_context_unauthenticated",
    "driver_bind_context_unavailable",
    "driver_bind_event_failed",
    "driver_bind_project_snapshot_failed",
    "driver_bind_readiness_snapshot_failed",
    "driver_bind_session_snapshot_failed",
  ];
  for (const failureClass of failureClasses) {
    const nonce = "12600000-0000-4000-8000-000000000080";
    const control = Readable.from(`${JSON.stringify({
      schema_version: 1,
      run_id: runId,
      nonce,
      sequence: 1,
      kind: "startup_failed",
      failure_class: failureClass,
    })}\n`);
    const reader = createR8ControlFrameReader(control, { runId, nonce });
    await assert.rejects(reader.next("component_ready"),
      (error) => error?.code === failureClass);
  }
});

test("S10BO3 R8 reader preserves a valid pre-ready startup failure leaf", async () => {
  const nonce = "12600000-0000-4000-8000-000000000076";
  const control = Readable.from(`${JSON.stringify({
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence: 1,
    kind: "startup_failed",
    failure_class: "driver_bind_failed",
  })}\n`);
  const reader = createR8ControlFrameReader(control, { runId, nonce });
  await assert.rejects(reader.next("component_ready"),
    (error) => error?.code === "driver_bind_failed");
});

test("S10BO3 R8 reader rejects a startup failure with a noninitial sequence", async () => {
  const nonce = "12600000-0000-4000-8000-000000000077";
  const control = Readable.from(`${JSON.stringify({
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence: 2,
    kind: "startup_failed",
    failure_class: "driver_bind_failed",
  })}\n`);
  const reader = createR8ControlFrameReader(control, { runId, nonce });
  await assert.rejects(reader.next("component_ready"),
    (error) => error?.code === "orchestrator_control_frame_invalid");
});

test("S10BO3 R8 reader rejects invalid startup failure shape and class", async (t) => {
  for (const [name, extra] of [
    ["shape", { unexpected: true }],
    ["class", { failure_class: "driver_unknown_failure" }],
  ]) {
    await t.test(name, async () => {
      const nonce = name === "shape"
        ? "12600000-0000-4000-8000-000000000078"
        : "12600000-0000-4000-8000-000000000079";
      const control = Readable.from(`${JSON.stringify({
        schema_version: 1,
        run_id: runId,
        nonce,
        sequence: 1,
        kind: "startup_failed",
        failure_class: "driver_bind_failed",
        ...extra,
      })}\n`);
      const reader = createR8ControlFrameReader(control, { runId, nonce });
      await assert.rejects(reader.next("component_ready"),
        (error) => error?.code === "orchestrator_control_frame_invalid");
    });
  }
});

test("S10BO3 corrective preserves a content-free post-ready failure leaf", async () => {
  const nonce = "12600000-0000-4000-8000-000000000071";
  const control = Readable.from(`${JSON.stringify({
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence: 1,
    kind: "component_ready",
  })}\n${JSON.stringify({
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence: 2,
    kind: "component_failed",
    failure_class: "driver_case_failed",
  })}\n`);
  const reader = createR8ControlFrameReader(control, { runId, nonce });
  assert.equal((await reader.next("component_ready")).kind, "component_ready");
  await assert.rejects(reader.next("case_result", "s10b_002"),
    (error) => error?.code === "driver_case_failed");
});

test("S10BO3 preserves exact content-free metadata failure leaves", async () => {
  for (const failureClass of [
    "driver_case_session_rename_failed",
    "driver_case_session_pin_failed",
    "driver_case_project_pin_failed",
  ]) {
    const nonce = "12600000-0000-4000-8000-000000000076";
    const control = Readable.from(`${JSON.stringify({
      schema_version: 1,
      run_id: runId,
      nonce,
      sequence: 1,
      kind: "component_ready",
    })}\n${JSON.stringify({
      schema_version: 1,
      run_id: runId,
      nonce,
      sequence: 2,
      kind: "component_failed",
      failure_class: failureClass,
    })}\n`);
    const reader = createR8ControlFrameReader(control, { runId, nonce });
    assert.equal((await reader.next("component_ready")).kind, "component_ready");
    await assert.rejects(reader.next("case_result", "s10b_005_planned_restart"),
      (error) => error?.code === failureClass);
  }
});

test("S10BO3 corrective accepts a post-ready leaf in startup-abort mode", async () => {
  const nonce = "12600000-0000-4000-8000-000000000075";
  const control = Readable.from(`${JSON.stringify({
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence: 1,
    kind: "component_ready",
  })}\n${JSON.stringify({
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence: 2,
    kind: "component_failed",
    failure_class: "driver_control_projection_invalid",
  })}\n`);
  const reader = createControlFrameReader(control, { runId, nonce });
  assert.equal((await reader.next("component_ready")).kind, "component_ready");
  await assert.rejects(reader.next("abort_complete"),
    (error) => error?.code === "driver_control_projection_invalid");
});

test("S10BO3 corrective drains a post-ready failure frame before projecting child exit", async () => {
  const nonce = "12600000-0000-4000-8000-000000000072";
  const stream = new PassThrough();
  const controlReader = createR8ControlFrameReader(stream, { runId, nonce });
  stream.write(`${JSON.stringify({
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence: 1,
    kind: "component_ready",
  })}\n`);
  await controlReader.next("component_ready");
  const child = () => Object.assign(new EventEmitter(), { exitCode: null, signalCode: null });
  const context = {
    r8: true,
    controlReader,
    pendingDesktopFrame: null,
    phase: "runtime_ready",
    processes: {
      api: { child: child() },
      fake: { child: child() },
      desktop: { child: child() },
    },
  };
  const result = readDesktopFrame(context, "case_result", "s10b_002");
  context.processes.desktop.child.emit("exit", 1, null);
  setImmediate(() => stream.end(`${JSON.stringify({
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence: 2,
    kind: "component_failed",
    failure_class: "driver_case_failed",
  })}\n`));
  await assert.rejects(result, (error) => error?.code === "driver_case_failed");
  for (const process_ of Object.values(context.processes)) {
    assert.equal(process_.child.listenerCount("exit"), 0);
    assert.equal(process_.child.listenerCount("error"), 0);
  }
});

test("S10BO3 corrective prefers a post-ready failure frame over an API exit", async () => {
  const nonce = "12600000-0000-4000-8000-000000000073";
  const stream = new PassThrough();
  const controlReader = createR8ControlFrameReader(stream, { runId, nonce });
  stream.write(`${JSON.stringify({
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence: 1,
    kind: "component_ready",
  })}\n`);
  await controlReader.next("component_ready");
  const child = () => Object.assign(new EventEmitter(), { exitCode: null, signalCode: null });
  const context = {
    r8: true,
    controlReader,
    pendingDesktopFrame: null,
    phase: "runtime_ready",
    processes: {
      api: { child: child() },
      fake: { child: child() },
      desktop: { child: child() },
    },
  };
  const result = readDesktopFrame(context, "case_result", "s10b_002");
  context.processes.api.child.emit("exit", 1, null);
  setImmediate(() => stream.end(`${JSON.stringify({
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence: 2,
    kind: "component_failed",
    failure_class: "driver_case_failed",
  })}\n`));
  await assert.rejects(result, (error) => error?.code === "driver_case_failed");
});

test("S10BO3 corrective does not let a successful frame hide an API exit", async () => {
  const nonce = "12600000-0000-4000-8000-000000000074";
  const stream = new PassThrough();
  const controlReader = createR8ControlFrameReader(stream, { runId, nonce });
  stream.write(`${JSON.stringify({
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence: 1,
    kind: "component_ready",
  })}\n`);
  await controlReader.next("component_ready");
  const child = () => Object.assign(new EventEmitter(), { exitCode: null, signalCode: null });
  const context = {
    r8: true,
    controlReader,
    pendingDesktopFrame: null,
    phase: "runtime_ready",
    processes: {
      api: { child: child() },
      fake: { child: child() },
      desktop: { child: child() },
    },
  };
  const result = readDesktopFrame(context, "case_result", "s10b_002");
  context.processes.api.child.emit("exit", 1, null);
  setImmediate(() => stream.write(`${JSON.stringify({
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence: 2,
    kind: "case_result",
    assertion_count: 1,
    assertion_set_sha256: "a".repeat(64),
    case_id: "s10b_002",
    status: "passed",
  })}\n`));
  await assert.rejects(result, (error) => error?.code === "orchestrator_api_exited_early");
});

test("S10BO3 corrective derives no-log requirements from the reached R8 phase", () => {
  const projection = { status: "passed" };
  const generation = { generation: 1 };
  const runtimeReady = {
    r8: true,
    phase: "runtime_ready",
    apiVerifierBefore: projection,
    fakeSpec: generation,
    fakeAuthorityBefore: generation,
    r8FakeAuthorities: [],
    r8CaseEvidence: [],
  };
  assert.deepEqual(r8NoLogRequiredEvidenceNames(runtimeReady), [
    "api-verifier-before.v1.json",
    "r8-fake-1-before.v1.json",
  ]);
  const thirdGenerationPreCallFailure = {
    ...runtimeReady,
    phase: "s10b_006",
    fakeSpec: { generation: 3 },
    fakeAuthorityBefore: { generation: 3 },
    r8FakeAuthorities: [{ generation: 1 }, { generation: 2 }],
    r8CaseEvidence: Array.from({ length: 5 }, () => ({ status: "passed" })),
  };
  assert.deepEqual(r8NoLogRequiredEvidenceNames(thirdGenerationPreCallFailure), [
    "api-verifier-before.v1.json",
    "r8-case-01.v1.json",
    "r8-case-02.v1.json",
    "r8-case-03.v1.json",
    "r8-case-04.v1.json",
    "r8-case-05.v1.json",
    "r8-fake-1-before.v1.json",
    "r8-fake-1-final.v1.json",
    "r8-fake-2-before.v1.json",
    "r8-fake-2-final.v1.json",
    "r8-fake-3-before.v1.json",
  ]);
  assert.equal(r8OwnershipStoppedEvidenceRequired(runtimeReady, 1), false);
  const lifecycleOneStopped = {
    ...runtimeReady,
    phase: "s10b_005_planned_restart",
    ownershipHistory: [{
      hostEvidenceName: "r8-lifecycle-1-host-evidence.v1.json",
      hostStoppedEvidence: { state: "stopped" },
    }],
  };
  assert.equal(r8OwnershipStoppedEvidenceRequired(lifecycleOneStopped, 1), true);
  assert.equal(r8OwnershipStoppedEvidenceRequired(lifecycleOneStopped, 2), false);
  assert.equal(r8OwnershipStoppedEvidenceRequired({
    ...lifecycleOneStopped,
    phase: "s10b_011",
    ownershipHistory: [
      ...lifecycleOneStopped.ownershipHistory,
      {
        hostEvidenceName: "r8-lifecycle-2-host-evidence.v1.json",
        hostStoppedEvidence: null,
      },
    ],
  }, 2), false);
  assert.equal(r8OwnershipStoppedEvidenceRequired({
    ...lifecycleOneStopped,
    phase: "s10b_011",
    ownershipHistory: [
      ...lifecycleOneStopped.ownershipHistory,
      {
        hostEvidenceName: "r8-lifecycle-2-host-evidence.v1.json",
        hostStoppedEvidence: { state: "stopped" },
      },
    ],
  }, 2), true);
  assert.equal(r8PersistedStoppedEvidenceRequired({
    r8: true,
    phase: "s10b_011",
    requireCompleteR8Evidence: false,
  }, 1), true);
  assert.equal(r8PersistedStoppedEvidenceRequired({
    r8: true,
    phase: "s10b_011",
    requireCompleteR8Evidence: false,
  }, 2), false);
  assert.equal(r8PersistedStoppedEvidenceRequired({
    r8: true,
    phase: "s10b_011",
    requireCompleteR8Evidence: true,
  }, 2), true);
});

const completed = Object.freeze([
  "authority", "ports", "secret_init", "compose", "images", "dependencies",
  "tls_oidc", "identity", "migration", "bootstrap", "api_binary", "host_binary",
  "fake_binary", "probe_binary", "api_health", "api_readiness",
  "host_owned_fake_authority", "fake_readiness", "content_free_logs",
]);

function errorCode(error) {
  return error instanceof S10BO1OrchestratorError ? error.code : error?.message;
}

function codeIs(code) {
  return (error) => errorCode(error) === code;
}

async function canonicalTemporaryRoot(t, name) {
  const alias = await mkdtemp(resolve(tmpdir(), name));
  const root = await realpath(alias);
  await chmod(root, 0o700);
  t.after(async () => { await rm(root, { recursive: true, force: true }); });
  return root;
}

async function claimTemporaryAttempt(t, name = "feat126-s10bo3-attempt-") {
  const root = await canonicalTemporaryRoot(t, name);
  const attemptRoot = resolve(root, "attempts");
  const attempt = await claimAttemptLedger(authority, { attemptRoot, identity, scriptSha256 });
  return { root, attemptRoot, attempt };
}

async function writeSyntheticAttemptFiles(t, name) {
  const root = await canonicalTemporaryRoot(t, name);
  const attemptRoot = resolve(root, "attempts");
  await mkdir(attemptRoot, { mode: 0o700 });
  await chmod(attemptRoot, 0o700);
  const markerPath = resolve(attemptRoot, `${runId}.attempt.v1.json`);
  const failurePath = resolve(attemptRoot, `${runId}.failure.v1.json`);
  const closurePath = resolve(attemptRoot, `${runId}.closure.v1.json`);
  const reconcilePath = resolve(attemptRoot, `${runId}.reconcile.v1.json`);
  const marker = attemptMarker();
  const markerBytes = canonicalJsonBytes(marker);
  const markerSha256 = sha256(markerBytes);
  const failure = attemptFailure({ attempt_marker_sha256: markerSha256 });
  await writeFile(markerPath, markerBytes, { mode: 0o600 });
  await chmod(markerPath, 0o600);
  return {
    root,
    failure,
    attempt: Object.freeze({
      fresh: true,
      attemptRoot,
      markerPath,
      failurePath,
      closurePath,
      reconcilePath,
      markerSha256,
      marker,
    }),
  };
}

function canonicalJsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function attemptMarker(overrides = {}) {
  return {
    schema_version: 1,
    kind: "feat126-s10bo2-attempt",
    status: "claimed",
    run_id: runId,
    repositories,
    pid: identity.pid,
    ppid: identity.ppid,
    start_identity: identity.start_identity,
    binary_sha256: identity.binary_sha256,
    script_sha256: scriptSha256,
    s10b_r8_executed: false,
    ...overrides,
  };
}

function attemptFailure(overrides = {}) {
  return {
    schema_version: 1,
    status: "failed",
    run_id: runId,
    attempt_marker_sha256: sha256(canonicalJsonBytes(attemptMarker())),
    failure_class: "preflight_authority_invalid",
    business_failure_class: null,
    cleanup_failure_class: null,
    parent_failure_class: null,
    phase: "preflight_failed",
    compose_attempted: false,
    compose_cleanup_required: false,
    run_root_present: false,
    process_roles: [],
    retained_volume_keys: [],
    no_log_required: true,
    s10b_r8_executed: false,
    ...overrides,
  };
}

function attemptClosure(overrides = {}) {
  return {
    schema_version: 1,
    status: "failed",
    closure_kind: "failure",
    run_id: runId,
    attempt_marker_sha256: sha256(canonicalJsonBytes(attemptMarker())),
    failure_class: "preflight_authority_invalid",
    business_failure_class: null,
    business_status: "not_applicable",
    cleanup_failure_class: null,
    cleanup_scope: "pre_run_absence",
    evidence_failure_class: null,
    no_log_failure_class: null,
    no_log_scope: "attempt_only",
    parent_failure_class: null,
    s10b_r8_executed: false,
    ...overrides,
  };
}

function summary() {
  return {
    schema_version: 1,
    status: "passed",
    scope: "S10B-001-combined-preflight",
    run_id: runId,
    repositories,
    api_binary_sha256: "d".repeat(64),
    api_runtime_authority: FEAT_126_S10_API_RUNTIME_AUTHORITY,
    fake_readiness: {
      schema_version: 1,
      status: "ready",
      run_id: runId,
      dataset_id: "feat126-title-raw-v1",
      fixture_case_id: "normal-000",
      dataset_sha256: "e".repeat(64),
    },
    completed,
    cleanup: "passed",
    s10b_r5_executed: false,
  };
}

function cleanupResult(overrides = {}) {
  return {
    schema_version: 1,
    scope: "pre_run_absence",
    status: "passed",
    containers: 0,
    networks: 0,
    processes: 0,
    listeners: 0,
    temporary_volumes: 0,
    named_volume_baseline_count: 0,
    named_volume_after_count: 0,
    named_volumes_preserved: true,
    prune_executed: false,
    volume_delete_executed: false,
    ...overrides,
  };
}

function noLogResult(overrides = {}) {
  return {
    schema_version: 1,
    scope: "attempt_only",
    coverage: "attempt_marker_and_failure",
    file_count: 2,
    row_count: 2,
    hit_count: 0,
    external_source_count: 0,
    external_row_count: 0,
    external_source_set_sha256: sha256(""),
    pattern_set_sha256: "f".repeat(64),
    ...overrides,
  };
}

function processRecord(role, index) {
  const pids = { api: 101, desktop: 102, fake: 103, host: 104, runtime: 105 };
  const ppids = { api: 10, desktop: 10, fake: 10, host: pids.desktop, runtime: pids.host };
  return {
    schema_version: 1,
    run_id: runId,
    role,
    pid: pids[role],
    ppid: ppids[role],
    binary_sha256: String(index + 1).repeat(64),
    start_identity: String.fromCharCode(97 + index).repeat(64),
  };
}

test("S10BO3-001 forwards all seven exact SHA Make assignments from one authority", async () => {
  const expected = [
    "--silent",
    "--no-print-directory",
    "feat-126-s10b-preflight",
    `RUN_ID=${runId}`,
    `GOVERNANCE_SHA=${repositories.governance}`,
    `CONTRACTS_SHA=${repositories.contracts}`,
    `API_SHA=${repositories.api}`,
    `HOST_SHA=${repositories.host}`,
    `DESKTOP_SHA=${repositories.desktop}`,
    `RUNTIME_SHA=${repositories.runtime}`,
    `INFRA_SHA=${repositories.infra}`,
  ];
  assert.deepEqual(buildPreflightMakeInvocation(authority), expected);

  const controller = new AbortController();
  let captured;
  await executePreflight(authority, controller.signal, async (...arguments_) => {
    captured = arguments_;
    return "";
  });
  assert.equal(captured[0], "preflight");
  assert.equal(captured[1], "make");
  assert.deepEqual(captured[2], expected);
  assert.equal(captured[3].signal, controller.signal);
  assert.equal(captured[3].failureParser, parsePreflightFailureFrame);
  for (const key of [
    "GOVERNANCE_SHA", "CONTRACTS_SHA", "API_SHA", "HOST_SHA", "DESKTOP_SHA",
    "RUNTIME_SHA", "INFRA_SHA", "FEAT126_S10B_GOVERNANCE_SHA",
  ]) assert.equal(Object.hasOwn(captured[3].env, key), false);

  assert.throws(
    () => buildPreflightMakeInvocation({ ...authority, repositories: { ...repositories, host: "short" } }),
    codeIs("orchestrator_preflight_authority_invalid"),
  );
  assert.throws(
    () => buildPreflightMakeInvocation({
      ...authority,
      repositories: { ...repositories, unexpected: "8".repeat(40) },
    }),
    codeIs("orchestrator_preflight_authority_invalid"),
  );
});

test("S10BO3-002 accepts one strict content-free preflight failure frame", () => {
  const valid = Buffer.from(
    '{"schema_version":1,"status":"failed","failure_class":"preflight_authority_invalid"}\n',
  );
  assert.equal(parsePreflightFailureFrame(valid), "preflight_authority_invalid");
  assert.equal(
    parsePreflightFailureFrame(Buffer.from(
      `${valid.toString("utf8")}make: *** [feat-126-s10b-preflight] Error 1\n`,
    )),
    "preflight_authority_invalid",
  );

  const invalid = [
    Buffer.alloc(0),
    Buffer.from(valid.subarray(0, -1)),
    Buffer.from(valid.toString("utf8").replace("\n", "\r\n")),
    Buffer.from(` ${valid.toString("utf8")}`),
    Buffer.from(`${valid.toString("utf8")}${valid.toString("utf8")}`),
    Buffer.from('{"schema_version":1,"schema_version":1,"status":"failed","failure_class":"x"}\n'),
    Buffer.from('{"schema_version":1,"status":"failed","failure_class":"x","path":"/tmp"}\n'),
    Buffer.from('{"schema_version":2,"status":"failed","failure_class":"x"}\n'),
    Buffer.from('{"schema_version":1,"status":"ok","failure_class":"x"}\n'),
    Buffer.from('{"schema_version":1,"status":"failed","failure_class":"INVALID"}\n'),
    Buffer.from(`${valid.toString("utf8")}make: *** [other-target] Error 1\n`),
    Buffer.from(
      `${valid.toString("utf8")}make: *** [feat-126-s10b-preflight] Error 1\nextra\n`,
    ),
    Buffer.from([0xff, 0x0a]),
    Buffer.alloc(2049, 0x20),
  ];
  for (const value of invalid) {
    assert.throws(() => parsePreflightFailureFrame(value), codeIs("orchestrator_preflight_failed"));
  }
});

test("S10BO3-003 retains the primary failure and reports all closure failures as secondary", async () => {
  const calls = [];
  let recorded;
  let observed;
  await assert.rejects(
    runStartupAbortFlow(authority, {
      async runPreflight() {
        calls.push("preflight");
        throw new S10BO1OrchestratorError("preflight_authority_invalid");
      },
      async initiateDesktopAbort() { calls.push("abort"); },
      async verifyBusinessBoundary() {
        calls.push("business");
        return buildBusinessBoundaryEvidence(null, null, null, runId);
      },
      async cleanup() {
        calls.push("cleanup");
        throw new S10BO1OrchestratorError("orchestrator_cleanup_unknown");
      },
      assertParentAlive() {
        calls.push("parent");
        throw new S10BO1OrchestratorError("orchestrator_parent_death");
      },
      async recordFailure(value) {
        calls.push("record");
        recorded = value;
      },
      async scanNoLog() {
        calls.push("no_log");
        throw new S10BO1OrchestratorError("orchestrator_no_log_invalid");
      },
    }),
    (error) => {
      observed = error;
      return errorCode(error) === "preflight_authority_invalid";
    },
  );
  assert.deepEqual(
    calls,
    ["preflight", "record", "abort", "business", "cleanup", "parent", "no_log"],
  );
  assert.deepEqual(recorded, {
    failureClass: "preflight_authority_invalid",
    businessFailureClass: null,
    cleanupFailureClass: null,
    parentFailureClass: null,
  });
  assert.deepEqual(observed.closure, {
    business_failure_class: null,
    cleanup_failure_class: "orchestrator_cleanup_unknown",
    evidence_failure_class: null,
    no_log_failure_class: "orchestrator_no_log_invalid",
    parent_failure_class: "orchestrator_parent_death",
  });
  assert.deepEqual(buildOrchestratorFailureEnvelope(observed), {
    schema_version: 1,
    status: "failed",
    failure_class: "preflight_authority_invalid",
    business_failure_class: null,
    cleanup_failure_class: "orchestrator_cleanup_unknown",
    evidence_failure_class: null,
    no_log_failure_class: "orchestrator_no_log_invalid",
    parent_failure_class: "orchestrator_parent_death",
  });
  assert.deepEqual(
    buildOrchestratorFailureEnvelope(new S10BO1OrchestratorError("primary_failure", {
      cleanup_failure_class: "invalid-secondary",
      evidence_failure_class: null,
      no_log_failure_class: null,
      parent_failure_class: null,
    })),
    {
      schema_version: 1,
      status: "failed",
      failure_class: "orchestrator_internal_failure",
      business_failure_class: null,
      cleanup_failure_class: null,
      evidence_failure_class: null,
      no_log_failure_class: null,
      parent_failure_class: null,
    },
  );

  const mainFailure = spawnSync(
    process.execPath,
    ["scripts/feat-126-s10b-orchestrator.mjs"],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(mainFailure.status, 1);
  assert.equal(mainFailure.stdout, "");
  assert.deepEqual(JSON.parse(mainFailure.stderr), {
    schema_version: 1,
    status: "failed",
    failure_class: "orchestrator_arguments_invalid",
    business_failure_class: null,
    cleanup_failure_class: null,
    evidence_failure_class: null,
    no_log_failure_class: null,
    parent_failure_class: null,
  });
});

test("S10BO3 corrective attempts immutable primary failure persistence exactly once", async () => {
  let persistenceAttempts = 0;
  let recordedClosure;
  let observed;
  await assert.rejects(
    runStartupAbortFlow(authority, {
      async runPreflight() {
        throw new S10BO1OrchestratorError("preflight_authority_invalid");
      },
      async recordFailure() {
        persistenceAttempts += 1;
        throw new S10BO1OrchestratorError("orchestrator_evidence_write_failed");
      },
      async initiateDesktopAbort() {},
      async verifyBusinessBoundary() {
        return buildBusinessBoundaryEvidence(null, null, null, runId);
      },
      async cleanup() { return cleanupResult(); },
      async scanNoLog() { return noLogResult(); },
      async recordClosure(value) { recordedClosure = value; },
    }),
    (error) => {
      observed = error;
      return errorCode(error) === "preflight_authority_invalid";
    },
  );
  assert.equal(persistenceAttempts, 1);
  assert.equal(recordedClosure.failureClass, "preflight_authority_invalid");
  assert.equal(recordedClosure.evidenceFailureClass, "orchestrator_evidence_write_failed");
  assert.equal(observed.closure.evidence_failure_class, "orchestrator_evidence_write_failed");
});

test("S10BO3 corrective persists a known no-log scope when the completed scan fails", async () => {
  let recordedClosure;
  let observed;
  await assert.rejects(
    runStartupAbortFlow(authority, {
      async runPreflight() {
        throw new S10BO1OrchestratorError("preflight_authority_invalid");
      },
      async initiateDesktopAbort() {},
      async verifyBusinessBoundary() {
        return buildBusinessBoundaryEvidence(null, null, null, runId);
      },
      async cleanup() { return cleanupResult(); },
      async recordFailure() {},
      async scanNoLog() {
        return noLogResult({
          scope: "preflight_artifacts",
          coverage: "all_preflight_log_and_evidence_sources",
          file_count: 3,
          row_count: 3,
          hit_count: 1,
        });
      },
      async recordClosure(value) {
        const projected = attemptClosure({
          failure_class: value.failureClass,
          business_failure_class: value.businessFailureClass,
          business_status: value.businessStatus,
          cleanup_failure_class: value.cleanupFailureClass,
          cleanup_scope: value.cleanupScope,
          evidence_failure_class: value.evidenceFailureClass,
          no_log_failure_class: value.noLogFailureClass,
          no_log_scope: value.noLogScope,
          parent_failure_class: value.parentFailureClass,
        });
        recordedClosure = validateAttemptClosure(projected, authority);
      },
    }),
    (error) => {
      observed = error;
      return errorCode(error) === "preflight_authority_invalid";
    },
  );
  assert.equal(recordedClosure.no_log_scope, "preflight_artifacts");
  assert.equal(recordedClosure.no_log_failure_class, "orchestrator_no_log_invalid");
  assert.equal(observed.closure.evidence_failure_class, null);
  assert.equal(observed.closure.no_log_failure_class, "orchestrator_no_log_invalid");
});

test("S10BO3 corrective persists every closed Desktop login leaf without continuation", async (t) => {
  const loginFailureClasses = [
    "driver_login_authorization_page_failed",
    "driver_login_authorization_request_invalid",
    "driver_login_authorization_start_failed",
    "driver_login_callback_rejected",
    "driver_login_concurrent",
    "driver_login_credential_submit_failed",
    "driver_login_credentials_rejected",
    "driver_login_failed",
    "driver_login_form_invalid",
    "driver_login_runtime_invalid",
    "driver_login_secret_invalid",
    "driver_login_session_failed",
    "driver_login_storage_failed",
    "driver_login_token_exchange_failed",
  ];
  for (const failureClass of loginFailureClasses) {
    const nonce = "12600000-0000-4000-8000-000000000071";
    const frame = {
      schema_version: 1,
      run_id: runId,
      nonce,
      sequence: 1,
      kind: "startup_failed",
      failure_class: failureClass,
    };
    assert.equal(validateStartupFailureControlFrame(frame, {
      allowedKinds: ["abort_complete", "component_ready", "startup_failed"],
      nonce,
      previousSequence: 0,
      runId,
    }).failure_class, failureClass);
  }
  const { root, attempt } = await writeSyntheticAttemptFiles(t, "feat126-s10bo3-desktop-leaf-");
  const retainedVolumeKeys = [
    "feat126_s10_api_postgres_data",
    "feat126_s10_keycloak_postgres_data",
    "feat126_s10_caddy_data",
    "feat126_s10_caddy_config",
  ];
  const calls = [];
  let desktopStarts = 0;
  let phase = "desktop_spawned";
  let boundary;
  await assert.rejects(
    runStartupAbortFlow(authority, {
      async runPreflight() { calls.push("preflight"); return summary(); },
      async buildDesktop() { calls.push("build_desktop"); },
      async startDependencies() { calls.push("dependencies"); },
      async startApi() { calls.push("api"); },
      async startFake() { calls.push("fake"); },
      async startDesktop() { calls.push("desktop"); desktopStarts += 1; },
      async readDesktopFrame(kind) {
        calls.push(`read:${kind}`);
        phase = "desktop_starting";
        throw new S10BO1OrchestratorError("driver_login_credentials_rejected");
      },
      async readOwnership() { calls.push("ownership"); throw new Error("unreachable"); },
      async sendAbort() { calls.push("normal_abort"); throw new Error("unreachable"); },
      async readDesktopEof() { calls.push("read:eof"); throw new Error("unreachable"); },
      async waitForDesktopExit() { calls.push("desktop_exit"); throw new Error("unreachable"); },
      async initiateDesktopAbort() { calls.push("failure_abort"); },
      async verifyBusinessBoundary() {
        calls.push("business_boundary_check");
        boundary = buildBusinessBoundaryEvidence(null, null, null, runId);
        return boundary;
      },
      async cleanup() {
        calls.push("cleanup");
        assert.equal(await requirePreOwnershipDescendantsAbsent(root), true);
        return cleanupResult({
          scope: "run_artifacts",
          named_volume_baseline_count: 4,
          named_volume_after_count: 4,
        });
      },
      async recordFailure(value) {
        calls.push("record_failure");
        await writeAttemptFailure(attempt, authority, attemptFailure({
          attempt_marker_sha256: attempt.markerSha256,
          failure_class: value.failureClass,
          business_failure_class: value.businessFailureClass,
          cleanup_failure_class: value.cleanupFailureClass,
          parent_failure_class: value.parentFailureClass,
          phase,
          compose_attempted: true,
          compose_cleanup_required: false,
          run_root_present: true,
          process_roles: ["api", "desktop", "fake"],
          retained_volume_keys: retainedVolumeKeys,
        }));
      },
      async scanNoLog() {
        calls.push("no_log");
        return noLogResult({
          scope: "run_artifacts",
          coverage: "all_run_log_and_evidence_sources",
          file_count: 3,
          external_source_count: 4,
          external_row_count: 4,
          external_source_set_sha256: "d".repeat(64),
        });
      },
      async recordClosure(value) {
        calls.push("record_closure");
        await writeAttemptClosure(attempt, authority, attemptClosure({
          attempt_marker_sha256: attempt.markerSha256,
          failure_class: value.failureClass,
          business_failure_class: value.businessFailureClass,
          business_status: value.businessStatus,
          cleanup_failure_class: value.cleanupFailureClass,
          cleanup_scope: value.cleanupScope,
          evidence_failure_class: value.evidenceFailureClass,
          no_log_failure_class: value.noLogFailureClass,
          no_log_scope: value.noLogScope,
          parent_failure_class: value.parentFailureClass,
        }));
      },
    }),
    codeIs("driver_login_credentials_rejected"),
  );
  const failure = await readAttemptFailure(attempt, authority);
  const closure = await readAttemptClosure(attempt, authority);
  assert.equal(failure.failure_class, "driver_login_credentials_rejected");
  assert.equal(failure.phase, "desktop_starting");
  assert.deepEqual(failure.process_roles, ["api", "desktop", "fake"]);
  assert.equal(failure.cleanup_failure_class, null);
  assert.equal(closure.failure_class, "driver_login_credentials_rejected");
  assert.equal(closure.evidence_failure_class, null);
  assert.equal(closure.business_status, "not_applicable");
  assert.equal(boundary.scope, "not_started");
  assert.equal(desktopStarts, 1);
  assert.deepEqual(calls, [
    "preflight", "build_desktop", "dependencies", "api", "fake", "desktop",
    "read:component_ready", "record_failure", "failure_abort", "business_boundary_check",
    "cleanup", "no_log", "record_closure",
  ]);
  assert.equal(calls.includes("ownership"), false);
  assert.equal(calls.includes("normal_abort"), false);
  assert.equal(calls.includes("read:eof"), false);
  assert.equal(calls.includes("desktop_exit"), false);
});

test("S10BO3 corrective fails closed when pre-ownership sidecar artifacts exist", async (t) => {
  const runRoot = await canonicalTemporaryRoot(t, "feat126-s10bo3-descendant-absence-");
  assert.equal(await requirePreOwnershipDescendantsAbsent(runRoot), true);

  const hostRoot = resolve(runRoot, "host");
  const instanceRoot = resolve(hostRoot, "12600000-0000-4000-8000-000000000071");
  await mkdir(hostRoot, { mode: 0o700 });
  await chmod(hostRoot, 0o700);
  await mkdir(instanceRoot, { mode: 0o700 });
  await chmod(instanceRoot, 0o700);
  await writeFile(resolve(instanceRoot, "process.json"), `${JSON.stringify({
    schemaVersion: 1,
    runId,
    role: "agent_host_child",
    pid: 104,
    ppid: 102,
    binarySha256: "4".repeat(64),
    instanceNonce: "12600000-0000-4000-8000-000000000071",
    startedAtUnixMs: 1,
    endedAtUnixMs: 2,
    state: "stopped",
    exitCode: 0,
    stdoutBytes: 0,
    stderrBytes: 0,
    stdoutTruncated: false,
    stderrTruncated: false,
    logLimitBytes: 256 * 1024,
  })}\n`, { mode: 0o600 });
  await chmod(resolve(instanceRoot, "process.json"), 0o600);
  await assert.rejects(
    requirePreOwnershipDescendantsAbsent(runRoot),
    codeIs("orchestrator_cleanup_unknown"),
  );

  const source = await readFile("scripts/feat-126-s10b-orchestrator.mjs", "utf8");
  const cleanupStart = source.indexOf("async function cleanupLiveContext");
  const cleanupEnd = source.indexOf("function createLiveOperations", cleanupStart);
  const reconcileStart = source.indexOf("async function reconcileExistingRun");
  const reconcileEnd = source.indexOf("async function readOptionalAttemptFailure", reconcileStart);
  assert.match(
    source.slice(cleanupStart, cleanupEnd),
    /requirePreOwnershipDescendantsAbsent\(context\.runRoot\)/,
  );
  assert.match(
    source.slice(reconcileStart, reconcileEnd),
    /requirePreOwnershipDescendantsAbsent\(runRoot\)/,
  );
  assert.doesNotMatch(
    source.slice(reconcileStart, reconcileEnd),
    /readOwnershipEvidence|requestRuntimeEvidence/,
  );
});

test("S10BO3-004 attempt ledger consumes a run ID exactly once with O_EXCL", async (t) => {
  const { attemptRoot, attempt } = await claimTemporaryAttempt(t);
  assert.equal(attempt.fresh, true);
  assert.equal((await lstat(attempt.markerPath)).mode & 0o777, 0o600);
  const markerBefore = await readFile(attempt.markerPath, "utf8");

  const reused = await claimAttemptLedger(authority, { attemptRoot, identity, scriptSha256 });
  assert.equal(reused.fresh, false);
  assert.deepEqual(reused.marker, attempt.marker);
  assert.equal(await readFile(attempt.markerPath, "utf8"), markerBefore);
  await assert.rejects(
    claimAttemptLedger(authority, {
      attemptRoot,
      identity,
      scriptSha256: "d".repeat(64),
    }),
    codeIs("orchestrator_attempt_evidence_invalid"),
  );

  const concurrentRoot = resolve(await canonicalTemporaryRoot(t, "feat126-s10bo3-race-"), "attempts");
  const claimed = await Promise.all([
    claimAttemptLedger(authority, { attemptRoot: concurrentRoot, identity, scriptSha256 }),
    claimAttemptLedger(authority, { attemptRoot: concurrentRoot, identity, scriptSha256 }),
  ]);
  assert.equal(claimed.filter((value) => value.fresh).length, 1);
  assert.equal(claimed.filter((value) => !value.fresh).length, 1);
});

test("S10BO3 corrective reserves the run before process identity and persists a terminal failure", async (t) => {
  const root = await canonicalTemporaryRoot(t, "feat126-s10b-preclaim-");
  const attemptRoot = resolve(root, "attempts");
  await assert.rejects(
    claimAttemptLedger(authority, {
      attemptRoot,
      scriptSha256,
      async inspectIdentity() {
        throw new S10BO1OrchestratorError("orchestrator_process_identity_unknown");
      },
    }),
    codeIs("orchestrator_process_identity_unknown"),
  );

  const preclaimPath = resolve(attemptRoot, `${runId}.preclaim.v1.json`);
  const preclaimFailurePath = resolve(attemptRoot, `${runId}.preclaim-failure.v1.json`);
  const markerPath = resolve(attemptRoot, `${runId}.attempt.v1.json`);
  assert.equal((await lstat(attemptRoot)).mode & 0o777, 0o700);
  assert.equal((await lstat(preclaimPath)).mode & 0o777, 0o600);
  assert.equal((await lstat(preclaimFailurePath)).mode & 0o777, 0o600);
  await assert.rejects(lstat(markerPath), (error) => error?.code === "ENOENT");

  const preclaim = validateAttemptPreclaim(JSON.parse(await readFile(preclaimPath, "utf8")), authority);
  const failure = await readAttemptPreclaimFailure(preclaimFailurePath, authority);
  assert.equal(failure.failure_class, "orchestrator_process_identity_unknown");
  assert.equal(failure.preclaim_sha256, sha256(canonicalJsonBytes(preclaim)));
  assert.equal(validateAttemptPreclaimFailure(failure, authority).s10b_r8_executed, false);
  assert.doesNotMatch(
    JSON.stringify({ preclaim, failure }),
    /bearer|credential|dsn|private[\s_-]*key|"(?:argv|env|path|payload|secret)"/i,
  );

  await assert.rejects(
    claimAttemptLedger(authority, { attemptRoot, identity, scriptSha256 }),
    codeIs("orchestrator_existing_preclaim_failed"),
  );
});

test("S10BO3 corrective invokes the canonical orchestrator with an absolute Node path", async () => {
  const makefile = await readFile("Makefile", "utf8");
  assert.match(makefile, /NODE_PATH="\$\$\(command -v node\)"/);
  assert.match(makefile, /case "\$\$NODE_PATH" in \/\*\)/);
  assert.match(makefile, /"\$\$NODE_PATH" scripts\/feat-126-s10b-orchestrator\.mjs/);
  assert.doesNotMatch(makefile, /\n\s*node scripts\/feat-126-s10b-orchestrator\.mjs/);
});

test("S10BO3-005 rejects malformed, symlinked, hard-linked, or authority-drifted attempt evidence", async (t) => {
  assert.throws(
    () => validateAttemptMarker({ ...attemptMarker(), unexpected: true }, authority),
    codeIs("orchestrator_attempt_evidence_invalid"),
  );
  assert.throws(
    () => validateAttemptMarker({
      ...attemptMarker(),
      repositories: { ...repositories, api: "9".repeat(40) },
    }, authority),
    codeIs("orchestrator_attempt_evidence_invalid"),
  );

  await t.test("wrong marker mode", async (subtest) => {
    const { attempt } = await writeSyntheticAttemptFiles(subtest, "feat126-s10bo3-mode-");
    await chmod(attempt.markerPath, 0o644);
    await assert.rejects(
      writeAttemptFailure(attempt, authority, attemptFailure()),
      codeIs("orchestrator_attempt_evidence_invalid"),
    );
  });

  await t.test("non-canonical marker bytes", async (subtest) => {
    const { attempt } = await writeSyntheticAttemptFiles(subtest, "feat126-s10bo3-bytes-");
    await writeFile(attempt.markerPath, `${JSON.stringify(attempt.marker)}\n\n`, { mode: 0o600 });
    await chmod(attempt.markerPath, 0o600);
    await assert.rejects(
      writeAttemptFailure(attempt, authority, attemptFailure()),
      codeIs("orchestrator_attempt_evidence_invalid"),
    );
  });

  for (const kind of ["symlink", "hardlink"]) {
    await t.test(kind, async (subtest) => {
      const root = await canonicalTemporaryRoot(subtest, `feat126-s10bo3-${kind}-`);
      const attemptRoot = resolve(root, "attempts");
      await mkdir(attemptRoot, { mode: 0o700 });
      await chmod(attemptRoot, 0o700);
      const markerPath = resolve(attemptRoot, `${runId}.attempt.v1.json`);
      const target = resolve(root, "marker-target.json");
      await writeFile(target, `${JSON.stringify(attemptMarker())}\n`, { mode: 0o600 });
      await chmod(target, 0o600);
      if (kind === "symlink") await symlink(target, markerPath);
      else await link(target, markerPath);
      await assert.rejects(
        claimAttemptLedger(authority, { attemptRoot, identity, scriptSha256 }),
        codeIs("orchestrator_attempt_evidence_invalid"),
      );
    });
  }
});

test("S10BO3-006 failure evidence is immutable, strict, and bound to the consumed attempt", async (t) => {
  const { attempt } = await writeSyntheticAttemptFiles(t, "feat126-s10bo3-failure-");
  const failure = attemptFailure({ attempt_marker_sha256: attempt.markerSha256 });
  assert.deepEqual(await writeAttemptFailure(attempt, authority, failure), failure);
  assert.deepEqual(await readAttemptFailure(attempt, authority), failure);
  assert.equal((await lstat(attempt.failurePath)).mode & 0o777, 0o600);
  await assert.rejects(
    writeAttemptFailure(attempt, authority, { ...failure, failure_class: "preflight_other" }),
    codeIs("orchestrator_evidence_write_failed"),
  );
  assert.throws(
    () => validateAttemptFailure({ ...failure, payload: "forbidden" }, authority),
    codeIs("orchestrator_attempt_evidence_invalid"),
  );
  assert.throws(
    () => validateAttemptFailure({ ...failure, process_roles: ["fake", "api"] }, authority),
    codeIs("orchestrator_attempt_evidence_invalid"),
  );
  assert.throws(
    () => validateAttemptFailure({ ...failure, run_id: "12600000-0000-4000-8000-000000000071" }, authority),
    codeIs("orchestrator_attempt_evidence_invalid"),
  );
  assert.equal(
    validateAttemptFailure({
      ...failure,
      phase: "preflight_context_invalid",
      compose_attempted: true,
      run_root_present: true,
    }, authority).phase,
    "preflight_context_invalid",
  );
  await assert.rejects(
    writeAttemptFailure(
      attempt,
      authority,
      { ...failure, attempt_marker_sha256: "0".repeat(64) },
    ),
    codeIs("orchestrator_attempt_evidence_invalid"),
  );

  const closure = attemptClosure({ attempt_marker_sha256: attempt.markerSha256 });
  assert.deepEqual(await writeAttemptClosure(attempt, authority, closure), closure);
  assert.deepEqual(await readAttemptClosure(attempt, authority), closure);
  assert.equal((await lstat(attempt.closurePath)).mode & 0o777, 0o600);
  assert.equal(validateAttemptClosure(closure, authority).s10b_r8_executed, false);
  assert.equal(validateAttemptClosure({
    ...closure,
    cleanup_failure_class: "orchestrator_cleanup_unknown",
    cleanup_scope: "run_artifacts",
    no_log_failure_class: "orchestrator_no_log_invalid",
    no_log_scope: "run_artifacts",
  }, authority).no_log_scope, "run_artifacts");
  assert.throws(
    () => validateAttemptClosure({ ...closure, no_log_scope: null }, authority),
    codeIs("orchestrator_attempt_evidence_invalid"),
  );
  await assert.rejects(
    writeAttemptClosure(attempt, authority, { ...closure, failure_class: "other_failure" }),
    codeIs("orchestrator_evidence_write_failed"),
  );
});

test("S10BO3-007 establishes content-free no-log evidence when preflight never created run root", async (t) => {
  const { root, attempt } = await claimTemporaryAttempt(t, "feat126-s10bo3-absent-");
  const failure = attemptFailure({ attempt_marker_sha256: attempt.markerSha256 });
  await writeAttemptFailure(attempt, authority, failure);
  const runRoot = resolve(root, "absent-run-root");
  const context = {
    ...authority,
    attempt,
    attemptFailure: failure,
    runRoot,
    runRootPresent: false,
    phase: "preflight_failed",
    composeAttempted: false,
    composeCleanupRequired: false,
    retainedVolumeNames: [],
    processes: {},
    secrets: new Map(),
  };
  const result = await scanNoLog(context);
  assert.equal(result.file_count, 3);
  assert.equal(result.scope, "attempt_only");
  assert.equal(result.coverage, "preclaim_marker_and_failure");
  assert.equal(result.row_count, 3);
  assert.equal(result.hit_count, 0);
  assert.equal(validateNoLogResult(result), true);

  for (const invalid of [
    { composeAttempted: true },
    { composeCleanupRequired: true },
    { phase: "preflight_running" },
    { retainedVolumeNames: ["unexpected"] },
    { processes: { api: {} } },
  ]) {
    await assert.rejects(
      scanNoLog({ ...context, ...invalid }),
      codeIs("orchestrator_no_log_invalid"),
    );
  }

  const markerOnly = await scanNoLog({ ...context, attemptFailure: undefined });
  assert.equal(markerOnly.scope, "attempt_only");
  assert.equal(markerOnly.coverage, "preclaim_and_marker");
  assert.equal(markerOnly.file_count, 2);
  assert.equal(markerOnly.row_count, 2);
  assert.equal(markerOnly.hit_count, 0);
  assert.equal(validateNoLogResult(markerOnly), true);

  await mkdir(runRoot, { mode: 0o700 });
  await chmod(runRoot, 0o700);
  await assert.rejects(scanNoLog(context), codeIs("orchestrator_no_log_invalid"));
});

test("S10BO3-007 accepts only fixed content-free Host messages", () => {
  const runtimeUnavailable = scanNoLogBuffer(Buffer.from(`${JSON.stringify({
    level: "ERROR",
    msg: "Codex Runtime unavailable",
    failure_code: "artifact_verification_failed",
    time: 1,
  })}\n`), [], []);
  assert.equal(runtimeUnavailable.hitCount, 0);

  const fixedWarning = scanNoLogBuffer(Buffer.from(`${JSON.stringify({
    level: "WARN",
    method: "item/completed",
    msg: "failed to map Codex notification",
    time: 1,
  })}\n`), [], []);
  assert.equal(fixedWarning.hitCount, 0);

  const unknownWarning = scanNoLogBuffer(Buffer.from(`${JSON.stringify({
    level: "WARN",
    method: "item/completed",
    msg: "unreviewed synthetic host warning",
    time: 1,
  })}\n`), [], []);
  assert.deepEqual(unknownWarning.hits, [{
    rule: "unclassified_sensitive_field",
    fieldClass: "structured_unclassified",
    reasonClass: "unclassified_context_value",
  }]);
});

test("S10BO3-008 accepts only phase-declared process record sets and ownership chains", async (t) => {
  const roles = ["api", "desktop", "fake", "host", "runtime"];
  const records = roles.map(processRecord);
  assert.equal(validateExistingProcessRecordSet([], []), true);
  assert.equal(validateExistingProcessRecordSet([records[0]], ["api"]), true);
  assert.equal(
    validateExistingProcessRecordSet([records[1], records[3]], ["desktop", "host"]),
    true,
  );
  assert.equal(
    validateExistingProcessRecordSet(records.slice(0, 3), ["api", "desktop", "fake"]),
    true,
  );
  assert.throws(
    () => validateExistingProcessRecordSet([records[3]], ["host"]),
    codeIs("orchestrator_existing_evidence_incomplete"),
  );
  assert.throws(
    () => validateExistingProcessRecordSet([records[4]], ["runtime"]),
    codeIs("orchestrator_existing_evidence_incomplete"),
  );
  assert.throws(
    () => validateExistingProcessRecordSet([records[2], records[0]], ["fake", "api"]),
    codeIs("orchestrator_existing_evidence_incomplete"),
  );

  const runRoot = await canonicalTemporaryRoot(t, "feat126-s10bo3-records-");
  const evidenceRoot = resolve(runRoot, "orchestrator-evidence");
  await mkdir(evidenceRoot, { mode: 0o700 });
  await chmod(evidenceRoot, 0o700);
  assert.deepEqual(await loadExistingProcessRecords(runRoot, runId, []), []);
  for (const record of records.slice(0, 3)) {
    const path = resolve(evidenceRoot, `${record.role}-process.v1.json`);
    await writeFile(path, `${JSON.stringify(record)}\n`, { mode: 0o600 });
    await chmod(path, 0o600);
  }
  assert.deepEqual(
    await loadExistingProcessRecords(runRoot, runId, ["api", "desktop", "fake"]),
    records.slice(0, 3),
  );
  await assert.rejects(
    loadExistingProcessRecords(runRoot, runId, ["api"]),
    codeIs("orchestrator_existing_evidence_incomplete"),
  );
});

test("S10BO3-009 treats named-volume preservation as exact before/after set equality", async () => {
  const project = `yijie-feat126-s10-${runId.replaceAll("-", "")}`;
  const named = [
    `${project}_feat126_s10_api_postgres_data`,
    `${project}_feat126_s10_keycloak_postgres_data`,
    `${project}_feat126_s10_caddy_data`,
    `${project}_feat126_s10_caddy_config`,
  ];
  assert.deepEqual(classifyProjectVolumes(project, []), { namedVolumes: 0, temporaryVolumes: 0 });
  assert.deepEqual(classifyProjectVolumes(project, named), { namedVolumes: 4, temporaryVolumes: 0 });
  assert.deepEqual(
    classifyProjectVolumes(project, [named[0], `${project}_temporary`]),
    { namedVolumes: 1, temporaryVolumes: 1 },
  );
  assert.equal(validateCleanupClosure(cleanupResult()), true);
  const liveCleanup = cleanupResult({
    scope: "run_artifacts",
    named_volume_baseline_count: named.length,
    named_volume_after_count: named.length,
  });
  assert.equal(validateCleanupClosure(liveCleanup), true);
  const preflightBeforeComposeCleanup = cleanupResult({ scope: "preflight_artifacts" });
  const preflightAfterComposeCleanup = cleanupResult({
    scope: "preflight_artifacts",
    named_volume_baseline_count: named.length,
    named_volume_after_count: named.length,
  });
  assert.equal(validateCleanupClosure(preflightBeforeComposeCleanup), true);
  assert.equal(validateCleanupClosure(preflightAfterComposeCleanup), true);
  assert.throws(
    () => validateCleanupClosure({ ...liveCleanup, scope: "pre_run_absence" }),
    codeIs("orchestrator_cleanup_incomplete"),
  );
  assert.throws(
    () => validateCleanupClosure({ ...cleanupResult(), scope: "run_artifacts" }),
    codeIs("orchestrator_cleanup_incomplete"),
  );
  assert.throws(
    () => validateCleanupClosure({ ...cleanupResult(), scope: "unknown" }),
    codeIs("orchestrator_cleanup_incomplete"),
  );
  assert.equal(
    shouldRunComposeCleanup({
      composeAttempted: false,
      composeCleanupRequired: true,
      runRootPresent: false,
    }),
    true,
  );
  assert.equal(
    shouldRunComposeCleanup({
      composeAttempted: true,
      composeCleanupRequired: false,
      runRootPresent: true,
    }),
    false,
  );

  const source = await readFile("scripts/feat-126-s10b-orchestrator.mjs", "utf8");
  const start = source.indexOf("async function cleanupLiveContext");
  const end = source.indexOf("function createLiveOperations", start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  const cleanupSource = source.slice(start, end);
  assert.match(cleanupSource, /if \(shouldRunComposeCleanup\(context\)\)/);
  assert.doesNotMatch(cleanupSource, /if \(context\.composeAttempted\)/);
  assert.match(cleanupSource, /sameStringSet\(volumeNames, context\.retainedVolumeNames\)/);
  assert.doesNotMatch(cleanupSource, /volumes\.namedVolumes\s*===\s*S10_NAMED_VOLUME_KEYS\.length/);
});

test("S10BO3-010 keeps the pre-run closure content-free and never upgrades it to R8", async () => {
  const planSource = await readFile("scripts/feat-126-s10b-orchestrator.mjs", "utf8");
  assert.match(planSource, /phase:\s*"preflight_not_started"/);
  assert.match(planSource, /runRootPresent:\s*false/);
  assert.match(planSource, /composeAttempted:\s*false/);
  assert.match(planSource, /s10b_r8_executed:\s*false/);
  assert.doesNotMatch(
    JSON.stringify({ marker: attemptMarker(), failure: attemptFailure() }),
    /bearer|credential|dsn|private[\s_-]*key|"(?:argv|env|path|payload|secret)"/i,
  );
  assert.equal(validateCleanupClosure(cleanupResult()), true);
  assert.equal(validateNoLogResult(noLogResult()), true);
  assert.equal(validateNoLogResult(noLogResult({
    scope: "preflight_artifacts",
    coverage: "all_preflight_log_and_evidence_sources",
    file_count: 3,
  })), true);
  assert.equal(validateNoLogResult(noLogResult({
    scope: "run_artifacts",
    coverage: "all_run_log_and_evidence_sources",
    file_count: 3,
    external_source_count: 1,
    external_row_count: 1,
    external_source_set_sha256: "e".repeat(64),
  })), true);
  assert.throws(
    () => validateNoLogResult(noLogResult({ coverage: "all_run_log_and_evidence_sources" })),
    codeIs("orchestrator_no_log_invalid"),
  );
  assert.throws(
    () => validateNoLogResult(noLogResult({
      scope: "preflight_artifacts",
      coverage: "all_run_log_and_evidence_sources",
      file_count: 3,
      external_source_count: 1,
      external_row_count: 1,
      external_source_set_sha256: "e".repeat(64),
    })),
    codeIs("orchestrator_no_log_invalid"),
  );

  const dependencyState = { dependenciesAttempted: false };
  const partialSpawnFailure = new Error("partial dependency spawn");
  assert.throws(
    () => attemptPrevalidatedDependencyStart(dependencyState, () => {
      assert.equal(dependencyState.dependenciesAttempted, true);
      throw partialSpawnFailure;
    }),
    (error) => error === partialSpawnFailure,
  );
  assert.equal(dependencyState.dependenciesAttempted, true);
  assert.equal(summary().s10b_r5_executed, false);
});

test("S10BO3-011 marks partial dependency startup cleanup-eligible before spawn", () => {
  const dependencyState = { dependenciesAttempted: false };
  const partialSpawnFailure = new Error("partial dependency spawn");
  assert.throws(
    () => attemptPrevalidatedDependencyStart(dependencyState, () => {
      assert.equal(dependencyState.dependenciesAttempted, true);
      throw partialSpawnFailure;
    }),
    (error) => error === partialSpawnFailure,
  );
  assert.equal(dependencyState.dependenciesAttempted, true);
});

test("S10BO3-012 closes a partial owner-only run root without treating it as absent", async (t) => {
  const generatedRoot = await canonicalTemporaryRoot(t, "feat126-s10bo3-partial-root-");
  const runRoot = resolve(generatedRoot, runId);
  await mkdir(runRoot, { mode: 0o700 });
  await chmod(runRoot, 0o700);
  assert.equal(await preparePreflightFailureEvidenceRoots(runId, { generatedRoot }), true);
  for (const directory of [resolve(runRoot, "logs"), resolve(runRoot, "preflight-evidence")]) {
    const metadata = await lstat(directory);
    assert.equal(metadata.isDirectory(), true);
    assert.equal(metadata.mode & 0o777, 0o700);
  }
  assert.equal(
    await preparePreflightFailureEvidenceRoots(
      "12600000-0000-4000-8000-000000000071",
      { generatedRoot },
    ),
    false,
  );

  const invalidRunId = "12600000-0000-4000-8000-000000000072";
  const invalidRoot = resolve(generatedRoot, invalidRunId);
  await mkdir(invalidRoot, { mode: 0o755 });
  await chmod(invalidRoot, 0o755);
  await assert.rejects(
    preparePreflightFailureEvidenceRoots(invalidRunId, { generatedRoot }),
    codeIs("preflight_run_root_invalid"),
  );
});

test("S10BO3-013 accepts only known pre-ownership Desktop failures with incomplete descendants", () => {
  const listeners = [5432, 8443, 9443, 18080, 18081, 18082].map((port) => ({
    port,
    listening: false,
    unknown: false,
  }));
  const inventory = { containers: 0, networks: 0, volume_names: [], listeners };
  assert.equal(validateFreshResourceInventory(inventory), true);
  for (const invalid of [
    { containers: 1 },
    { networks: 1 },
    { volume_names: ["unexpected"] },
    { listeners: listeners.map((entry, index) => index === 0 ? { ...entry, unknown: true } : entry) },
    { listeners: listeners.map((entry, index) => index === 0 ? { ...entry, listening: true } : entry) },
  ]) {
    assert.throws(
      () => validateFreshResourceInventory({ ...inventory, ...invalid }),
      codeIs("orchestrator_run_resources_not_fresh"),
    );
  }

  const retainedVolumeKeys = [
    "feat126_s10_api_postgres_data",
    "feat126_s10_keycloak_postgres_data",
    "feat126_s10_caddy_data",
    "feat126_s10_caddy_config",
  ];
  const desktopSpawned = attemptFailure({
    phase: "desktop_spawned",
    run_root_present: true,
    compose_attempted: true,
    process_roles: ["api", "desktop", "fake"],
    retained_volume_keys: retainedVolumeKeys,
  });
  assert.throws(
    () => validateAttemptFailure(desktopSpawned, authority),
    codeIs("orchestrator_attempt_evidence_invalid"),
  );
  assert.equal(
    validateAttemptFailure({
      ...desktopSpawned,
      cleanup_failure_class: "orchestrator_cleanup_unknown",
    }, authority).phase,
    "desktop_spawned",
  );
  const desktopStartupLeaf = {
    ...desktopSpawned,
    failure_class: "driver_bind_failed",
    phase: "desktop_starting",
    cleanup_failure_class: null,
  };
  assert.equal(validateAttemptFailure(desktopStartupLeaf, authority).phase, "desktop_starting");
  assert.equal(validateReconcileFailureProcessState(desktopStartupLeaf), true);
  for (const failureClass of [
    "orchestrator_control_timeout",
    "orchestrator_control_eof",
    "orchestrator_control_frame_invalid",
    "orchestrator_control_frame_oversize",
    "orchestrator_control_order_invalid",
    "orchestrator_api_exited_early",
    "orchestrator_desktop_exited_early",
    "orchestrator_fake_exited_early",
  ]) {
    for (const phase of ["desktop_starting", "desktop_spawned"]) {
      const knownFailure = {
        ...desktopStartupLeaf,
        failure_class: failureClass,
        phase,
      };
      assert.equal(validateAttemptFailure(knownFailure, authority).phase, phase);
      assert.equal(validateReconcileFailureProcessState(knownFailure), true);
    }
  }

  const postReadyFailure = {
    ...desktopStartupLeaf,
    phase: "s10b_002",
    failure_class: "driver_case_failed",
    process_roles: ["api", "desktop", "fake", "host", "runtime"],
  };
  assert.equal(validateAttemptFailure(postReadyFailure, authority).phase, "s10b_002");
  const unknownDesktopStartup = {
    ...desktopStartupLeaf,
    failure_class: "orchestrator_internal_failure",
  };
  assert.throws(
    () => validateAttemptFailure(unknownDesktopStartup, authority),
    codeIs("orchestrator_attempt_evidence_invalid"),
  );
  assert.throws(
    () => validateReconcileFailureProcessState(unknownDesktopStartup),
    codeIs("orchestrator_cleanup_unknown"),
  );
  assert.throws(
    () => validateAttemptFailure({ ...attemptFailure(), no_log_required: false }, authority),
    codeIs("orchestrator_attempt_evidence_invalid"),
  );
});

test("S10BO3-014 fixes a twenty-case no-resume corrective matrix", async () => {
  assert.deepEqual(
    S10BO3_TARGETED_MATRIX,
    Array.from({ length: 20 }, (_, index) => `S10BO3-${String(index + 1).padStart(3, "0")}`),
  );
  const source = await readFile("scripts/feat-126-s10b-orchestrator.mjs", "utf8");
  const start = source.indexOf("async function reconcileClaimedAttempt");
  const end = source.indexOf("async function executeOrchestrator", start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  const reconcileSource = source.slice(start, end);
  assert.match(reconcileSource, /orchestrator_existing_run_reconciled/);
  assert.doesNotMatch(reconcileSource, /executePreflight|startDependencies|startApi|startFake|startDesktop/);
});

test("S10BO3-015 writes an immutable successful terminal closure", async (t) => {
  const { attempt } = await writeSyntheticAttemptFiles(t, "feat126-s10bo3-success-");
  const closure = attemptClosure({
    status: "passed",
    closure_kind: "success",
    failure_class: null,
    business_status: "passed",
    cleanup_scope: "run_artifacts",
    no_log_scope: "run_artifacts",
    attempt_marker_sha256: attempt.markerSha256,
  });
  assert.deepEqual(await writeAttemptClosure(attempt, authority, closure), closure);
  assert.deepEqual(await readAttemptClosure(attempt, authority), closure);
  await assert.rejects(
    writeAttemptClosure(attempt, authority, closure),
    codeIs("orchestrator_evidence_write_failed"),
  );
});

test("S10BO3-016 binds parsed preflight failure to disk evidence", () => {
  assert.equal(
    validatePreflightFailureBinding("preflight_authority_invalid", {
      failure_class: "preflight_authority_invalid",
    }),
    true,
  );
  assert.throws(
    () => validatePreflightFailureBinding("preflight_authority_invalid", {
      failure_class: "preflight_cleanup_incomplete",
    }),
    codeIs("orchestrator_preflight_failure_evidence_invalid"),
  );
});

test("S10BO3-017 captures Compose logs before cleanup and marks leaks failed", async () => {
  const context = {
    runId,
    runRoot: resolve(tmpdir(), `feat126-s10bo3-log-${runId}`),
    composeLogsRequired: true,
    secrets: new Map([["ephemeral", "never-log-secret"]]),
  };
  const project = `yijie-feat126-s10-${runId.replaceAll("-", "")}`;
  const roles = [
    "feat126-s10-api-db",
    "feat126-s10-caddy",
    "feat126-s10-keycloak",
    "feat126-s10-keycloak-db",
  ];
  function sources(ids = ["1", "2", "3", "4"].map((value) => value.repeat(12))) {
    return roles.map((serviceRole, index) => ({
      container_id: ids[index],
      project,
      feature: "FEAT-126",
      slice: "S10E",
      run_id: runId,
      data_classification: "synthetic-only",
      service_role: serviceRole,
    }));
  }
  function logsWith(targetIds, value) {
    const selected = new Set(targetIds);
    return async (containerId) => Buffer.from(selected.has(containerId) ? value : "ready\n", "utf8");
  }
  const canonicalSources = sources();
  const origins = roles.map((role) => `compose:${role}`).sort();
  const clean = await captureRuntimeLogScan(context, {
    async list() { return canonicalSources; },
    async readLogs() { return Buffer.from("ready\n", "utf8"); },
  });
  assert.equal(clean.status, "passed");
  assert.equal(clean.schema_version, 4);
  assert.deepEqual(Object.keys(clean).sort(), [
    "hit_count",
    "hit_field_class_set_sha256",
    "hit_origin_rule_field_class_reason_class_set_sha256",
    "hit_origin_rule_field_class_set_sha256",
    "hit_origin_rule_set_sha256",
    "hit_origin_set_sha256",
    "hit_reason_class_set_sha256",
    "hit_rule_set_sha256",
    "row_count",
    "run_id",
    "schema_version",
    "source_count",
    "source_set_sha256",
    "status",
  ]);
  assert.equal(clean.source_count, 4);
  assert.equal(clean.source_set_sha256, sha256(origins.join("\n")));
  assert.equal(clean.hit_origin_set_sha256, sha256(""));
  assert.equal(clean.hit_rule_set_sha256, sha256(""));
  assert.equal(clean.hit_origin_rule_set_sha256, sha256(""));
  assert.equal(clean.hit_field_class_set_sha256, sha256(""));
  assert.equal(clean.hit_origin_rule_field_class_set_sha256, sha256(""));
  assert.equal(clean.hit_reason_class_set_sha256, sha256(""));
  assert.equal(clean.hit_origin_rule_field_class_reason_class_set_sha256, sha256(""));
  const rotatedIds = ["a", "b", "c", "d"].map((value) => value.repeat(12));
  const rotated = await captureRuntimeLogScan(context, {
    async list() { return sources(rotatedIds).reverse(); },
    async readLogs() { return Buffer.from("ready\n", "utf8"); },
  });
  assert.equal(rotated.source_set_sha256, clean.source_set_sha256);
  const benign = await captureRuntimeLogScan(context, {
    async list() { return canonicalSources; },
    readLogs: logsWith(
      [canonicalSources[0].container_id],
      '{"path":"/healthz","uri":"/healthz/v2","env":"local","payload":{"status":"ready"},"argv":[]}\n' +
        '{"token":"","secret":null,"authorization":{}}\n',
    ),
  });
  assert.equal(benign.status, "passed");
  assert.equal(benign.hit_count, 0);
  const genericShapeAtCaddyOrigin = await captureRuntimeLogScan(context, {
    async list() { return canonicalSources; },
    readLogs: logsWith(
      [canonicalSources[1].container_id],
      '{"path":"/healthz","uri":"/healthz/v2","env":"local","payload":{"status":"ready"},"argv":[]}\n',
    ),
  });
  assert.equal(genericShapeAtCaddyOrigin.status, "failed");
  assert.equal(
    genericShapeAtCaddyOrigin.hit_reason_class_set_sha256,
    sha256("unclassified_caddy_system_value"),
  );
  const caddyAccessLog = await readFile(
    "tests/fixtures/feat-126-caddy-2.11.4-access-log.jsonl",
  );
  const caddyFixture = await captureRuntimeLogScan(context, {
    async list() { return canonicalSources; },
    readLogs: logsWith([canonicalSources[1].container_id], caddyAccessLog),
  });
  assert.equal(caddyFixture.status, "passed");
  assert.equal(caddyFixture.hit_count, 0);
  const caddySystemLog = await readFile(
    "tests/fixtures/feat-126-caddy-2.11.4-system-log.jsonl",
  );
  const caddySystemFixture = await captureRuntimeLogScan(context, {
    async list() { return canonicalSources; },
    readLogs: logsWith([canonicalSources[1].container_id], caddySystemLog),
  });
  assert.equal(caddySystemFixture.status, "passed");
  assert.equal(caddySystemFixture.hit_count, 0);
  assert.equal(caddySystemFixture.hit_reason_class_set_sha256, sha256(""));
  for (const invalidRoot of [
    `${JSON.stringify([JSON.parse(caddyAccessLog.toString("utf8"))])}\n`,
    '"ready"\n',
    "null\n",
  ]) {
    const invalidCaddyRoot = await captureRuntimeLogScan(context, {
      async list() { return canonicalSources; },
      readLogs: logsWith([canonicalSources[1].container_id], invalidRoot),
    });
    assert.equal(invalidCaddyRoot.schema_version, 4);
    assert.equal(invalidCaddyRoot.status, "failed");
    assert.equal(invalidCaddyRoot.hit_count, 1);
    assert.equal(
      invalidCaddyRoot.hit_reason_class_set_sha256,
      sha256("unclassified_caddy_system_value"),
    );
    assert.deepEqual(Object.keys(invalidCaddyRoot).sort(), Object.keys(caddySystemFixture).sort());
  }
  for (const nestedField of ["request", "headers", "tls", "resp_headers"]) {
    const malformedAccess = structuredClone(JSON.parse(caddyAccessLog.toString("utf8")));
    if (nestedField === "request" || nestedField === "resp_headers") {
      malformedAccess[nestedField] = null;
    } else {
      malformedAccess.request[nestedField] = null;
    }
    const invalidCaddyAccess = await captureRuntimeLogScan(context, {
      async list() { return canonicalSources; },
      readLogs: logsWith(
        [canonicalSources[1].container_id],
        `${JSON.stringify(malformedAccess)}\n`,
      ),
    });
    assert.equal(invalidCaddyAccess.schema_version, 4);
    assert.equal(invalidCaddyAccess.status, "failed");
    assert.equal(
      invalidCaddyAccess.hit_reason_class_set_sha256,
      sha256("unclassified_caddy_system_value"),
    );
    assert.deepEqual(Object.keys(invalidCaddyAccess).sort(), Object.keys(caddySystemFixture).sort());
  }
  const dynamicCaddySystemLog = caddySystemLog.toString("utf8")
    .replace("GOMAXPROCS=2", "GOMAXPROCS=3")
    .replace('"GOMEMLIMIT":268435456', '"GOMEMLIMIT":536870912')
    .replace('"previous":9223372036854776000', '"previous":1073741824')
    .replaceAll('"cache":"0x1a2b3c4d"', '"cache":"0xdeadbeef"')
    .replace('"instance":"019fbd88-cbc3-4bf1-934d-7b05cd693f80"', '"instance":"019fbd88-cbc3-4bf1-934d-7b05cd693f81"')
    .replace('"try_again":86425.5', '"try_again":43225.5')
    .replace('"try_again_in":86400', '"try_again_in":43200');
  const dynamicCaddySystemFixture = await captureRuntimeLogScan(context, {
    async list() { return canonicalSources; },
    readLogs: logsWith([canonicalSources[1].container_id], dynamicCaddySystemLog),
  });
  assert.deepEqual(dynamicCaddySystemFixture, caddySystemFixture);
  for (const [needle, replacement, reasonClasses] of [
    ["GOMAXPROCS=2", "GOMAXPROCS=0", ["unclassified_caddy_system_value"]],
    ['"GOMEMLIMIT":268435456', '"GOMEMLIMIT":1', ["unclassified_caddy_system_value"]],
    ['"cache":"0x1a2b3c4d"', '"cache":"opaque"', ["unclassified_caddy_system_value"]],
    ['"origins":["//localhost:2019","//[::1]:2019","//127.0.0.1:2019"]', '"origins":["//other:2019"]', ["unclassified_caddy_system_value"]],
    ['"address":"127.0.0.1:2019"', '"address":"0.0.0.0:2019"', ["unclassified_caddy_system_value"]],
    ['"addr":":8443"', '"addr":"0.0.0.0:8443"', ["unclassified_caddy_system_value"]],
    ['"path":"storage:pki/authorities/local/root.crt"', '"path":"/private/opaque"', ["local_machine_path_value", "unclassified_caddy_system_value"]],
    ['"logger":"http.log","msg":"server running"', '"logger":"http","msg":"server running"', ["unclassified_caddy_system_value"]],
    ['"logger":"http","msg":"enabling automatic TLS certificate management"', '"logger":"http.auto_https","msg":"enabling automatic TLS certificate management"', ["unclassified_caddy_system_value"]],
    ['"logger":"tls.obtain","msg":"acquiring lock"', '"logger":"admin","msg":"acquiring lock"', ["unclassified_caddy_system_value"]],
    ['"msg":"server running","name":"srv0"', '"msg":"server running","identifier":"localhost"', ["unclassified_caddy_system_value"]],
    ['"instance":"019fbd88-cbc3-4bf1-934d-7b05cd693f80"', '"instance":"opaque"', ["unclassified_caddy_system_value"]],
    ['"try_again":86425.5', '"try_again":1', ["unclassified_caddy_system_value"]],
    ['"try_again_in":86400', '"try_again_in":0', ["unclassified_caddy_system_value"]],
    ['"logger":"admin.api","msg":"received request"', '"logger":"admin","msg":"received request"', ["unclassified_caddy_system_value"]],
    ['"uri":"/config/"', '"uri":"/other/"', ["unclassified_caddy_system_value"]],
    ['"User-Agent":["Wget"]', '"User-Agent":["other"]', ["unclassified_caddy_system_value"]],
    ['"Connection":["close"]', '"Connection":["keep-alive"]', ["unclassified_caddy_system_value"]],
    ["(was: 208 kiB, wanted: 7168 kiB, got: 416 kiB)", "(was: 208 KiB, wanted: 7168 KiB, got: 416 KiB)", ["unclassified_caddy_system_value"]],
  ]) {
    const invalidCaddySystemFixture = await captureRuntimeLogScan(context, {
      async list() { return canonicalSources; },
      readLogs: logsWith(
        [canonicalSources[1].container_id],
        caddySystemLog.toString("utf8").replace(needle, replacement),
      ),
    });
    assert.equal(invalidCaddySystemFixture.status, "failed");
    assert.equal(
      invalidCaddySystemFixture.hit_reason_class_set_sha256,
      sha256(reasonClasses.join("\n")),
    );
  }
  const caddySystemShapeAtForeignOrigin = await captureRuntimeLogScan(context, {
    async list() { return canonicalSources; },
    readLogs: logsWith([canonicalSources[0].container_id], caddySystemLog),
  });
  assert.equal(caddySystemShapeAtForeignOrigin.status, "failed");
  assert.equal(
    caddySystemShapeAtForeignOrigin.hit_reason_class_set_sha256,
    sha256("unclassified_context_value"),
  );
  const reorderedCaddySystemFixture = await captureRuntimeLogScan(context, {
    async list() { return sources(["a", "b", "c", "d"].map((value) => value.repeat(12))).reverse(); },
    readLogs: logsWith(["b".repeat(12)], Buffer.from(
      caddySystemLog.toString("utf8").trimEnd().split("\n").reverse().join("\n") + "\n",
      "utf8",
    )),
  });
  assert.deepEqual(reorderedCaddySystemFixture, caddySystemFixture);
  const caddySensitiveShape = JSON.parse(caddyAccessLog.toString("utf8"));
  caddySensitiveShape.request.headers.Authorization = ["opaque-value"];
  const caddySensitive = await captureRuntimeLogScan(context, {
    async list() { return canonicalSources; },
    readLogs: logsWith(
      [canonicalSources[1].container_id],
      `${JSON.stringify(caddySensitiveShape)}\n`,
    ),
  });
  assert.equal(caddySensitive.status, "failed");
  assert.equal(
    caddySensitive.hit_rule_set_sha256,
    sha256(["sensitive_value_field", "unclassified_sensitive_field"].join("\n")),
  );
  assert.equal(
    caddySensitive.hit_field_class_set_sha256,
    sha256(["structured_sensitive", "structured_unclassified"].join("\n")),
  );
  assert.equal(
    caddySensitive.hit_reason_class_set_sha256,
    sha256(["sensitive_nonempty_value", "unclassified_caddy_system_value"].join("\n")),
  );
  const sensitiveValue = await captureRuntimeLogScan(context, {
    async list() { return canonicalSources; },
    readLogs: logsWith([canonicalSources[0].container_id], '{"token":"opaque-value"}\n'),
  });
  assert.equal(sensitiveValue.status, "failed");
  assert.equal(sensitiveValue.hit_count, 1);
  assert.equal(sensitiveValue.hit_origin_set_sha256, sha256(origins[0]));
  assert.equal(sensitiveValue.hit_rule_set_sha256, sha256("sensitive_value_field"));
  assert.equal(sensitiveValue.hit_field_class_set_sha256, sha256("structured_sensitive"));
  assert.equal(
    sensitiveValue.hit_origin_rule_set_sha256,
    sha256(JSON.stringify([origins[0], "sensitive_value_field"])),
  );
  assert.equal(
    sensitiveValue.hit_origin_rule_field_class_set_sha256,
    sha256(JSON.stringify([origins[0], "sensitive_value_field", "structured_sensitive"])),
  );
  assert.equal(validateRuntimeLogScan(sensitiveValue, runId).schema_version, 4);
  const sensitiveKey = await captureRuntimeLogScan(context, {
    async list() { return canonicalSources; },
    readLogs: logsWith([canonicalSources[0].container_id], '{"apiKey":"opaque-value"}\n'),
  });
  assert.equal(sensitiveKey.hit_count, 1);
  assert.equal(sensitiveKey.hit_rule_set_sha256, sha256("sensitive_value_field"));
  for (const sensitiveField of [
    "tokenValue",
    "apiTokens",
    "clientSecretValue",
    "APIKey",
    "APIKeys",
  ]) {
    const sensitiveVariant = await captureRuntimeLogScan(context, {
      async list() { return canonicalSources; },
      readLogs: logsWith(
        [canonicalSources[0].container_id],
        `${JSON.stringify({ [sensitiveField]: "opaque-value" })}\n`,
      ),
    });
    assert.equal(sensitiveVariant.hit_count, 1);
    assert.equal(sensitiveVariant.hit_rule_set_sha256, sha256("sensitive_value_field"));
  }
  const prettySensitive = await captureRuntimeLogScan(context, {
    async list() { return canonicalSources; },
    readLogs: logsWith(
      [canonicalSources[0].container_id],
      `${JSON.stringify({ nested: { tokenValue: "opaque-value" } }, null, 2)}\n`,
    ),
  });
  assert.equal(prettySensitive.hit_count, 1);
  assert.equal(prettySensitive.hit_rule_set_sha256, sha256("sensitive_value_field"));
  const prettyBenign = await captureRuntimeLogScan(context, {
    async list() { return canonicalSources; },
    readLogs: logsWith(
      [canonicalSources[0].container_id],
      `${JSON.stringify({
        path: "/healthz",
        uri: "/healthz/v2",
        env: "local",
        payload: { status: "ready" },
        argv: [],
      }, null, 2)}\n`,
    ),
  });
  assert.equal(prettyBenign.status, "passed");
  assert.equal(prettyBenign.hit_count, 0);
  for (const unclassifiedField of ["message", "msg", "content", "prompt", "binary"]) {
    const unclassifiedVariant = await captureRuntimeLogScan(context, {
      async list() { return canonicalSources; },
      readLogs: logsWith(
        [canonicalSources[1].container_id],
        `${JSON.stringify({ [unclassifiedField]: "opaque-value" })}\n`,
      ),
    });
    assert.equal(unclassifiedVariant.hit_count, 1);
    assert.equal(
      unclassifiedVariant.hit_rule_set_sha256,
      sha256("unclassified_sensitive_field"),
    );
    assert.equal(
      unclassifiedVariant.hit_reason_class_set_sha256,
      sha256("unclassified_caddy_system_value"),
    );
  }
  const unknownCaddySystemShape = await captureRuntimeLogScan(context, {
    async list() { return canonicalSources; },
    readLogs: logsWith(
      [canonicalSources[1].container_id],
      '{"logger":"admin","msg":"unknown synthetic system event"}\n',
    ),
  });
  assert.equal(unknownCaddySystemShape.status, "failed");
  assert.equal(
    unknownCaddySystemShape.hit_reason_class_set_sha256,
    sha256("unclassified_caddy_system_value"),
  );
  assert.equal(
    unknownCaddySystemShape.hit_origin_rule_field_class_reason_class_set_sha256,
    sha256(JSON.stringify([
      origins[1],
      "unclassified_sensitive_field",
      "structured_unclassified",
      "unclassified_caddy_system_value",
    ])),
  );
  const stableUnknownCaddySystemShape = await captureRuntimeLogScan(context, {
    async list() { return sources(["a", "b", "c", "d"].map((value) => value.repeat(12))).reverse(); },
    readLogs: logsWith(
      ["b".repeat(12)],
      '{"msg":"unknown synthetic system event","logger":"admin"}\n',
    ),
  });
  assert.deepEqual(stableUnknownCaddySystemShape, unknownCaddySystemShape);
  const unknownCaddyField = await captureRuntimeLogScan(context, {
    async list() { return canonicalSources; },
    readLogs: logsWith(
      [canonicalSources[1].container_id],
      '{"msg":"handled request","mystery":"opaque-value"}\n',
    ),
  });
  assert.equal(unknownCaddyField.status, "failed");
  assert.equal(
    unknownCaddyField.hit_reason_class_set_sha256,
    sha256("unclassified_caddy_system_value"),
  );
  const unknownCaddyMetadataValue = await captureRuntimeLogScan(context, {
    async list() { return canonicalSources; },
    readLogs: logsWith(
      [canonicalSources[1].container_id],
      '{"logger":"unknown.module","msg":"handled request"}\n',
    ),
  });
  assert.equal(unknownCaddyMetadataValue.status, "failed");
  assert.equal(
    unknownCaddyMetadataValue.hit_reason_class_set_sha256,
    sha256("unclassified_caddy_system_value"),
  );
  const unknownEmptyCaddyField = await captureRuntimeLogScan(context, {
    async list() { return canonicalSources; },
    readLogs: logsWith(
      [canonicalSources[1].container_id],
      '{"msg":"handled request","mystery":""}\n',
    ),
  });
  assert.equal(unknownEmptyCaddyField.status, "failed");
  assert.equal(
    unknownEmptyCaddyField.hit_reason_class_set_sha256,
    sha256("unclassified_caddy_system_value"),
  );
  const unknownUnstructuredCaddyLine = await captureRuntimeLogScan(context, {
    async list() { return canonicalSources; },
    readLogs: logsWith(
      [canonicalSources[1].container_id],
      "opaque synthetic system line\n",
    ),
  });
  assert.equal(unknownUnstructuredCaddyLine.status, "failed");
  assert.equal(
    unknownUnstructuredCaddyLine.hit_reason_class_set_sha256,
    sha256("unclassified_caddy_system_value"),
  );
  const nestedCaddySensitive = await captureRuntimeLogScan(context, {
    async list() { return canonicalSources; },
    readLogs: logsWith(
      [canonicalSources[1].container_id],
      '{"logger":"admin","context":{"token":"opaque-value"}}\n',
    ),
  });
  assert.equal(nestedCaddySensitive.status, "failed");
  assert.equal(
    nestedCaddySensitive.hit_reason_class_set_sha256,
    sha256(["sensitive_nonempty_value", "unclassified_caddy_system_value"].join("\n")),
  );
  const unclassified = await captureRuntimeLogScan(context, {
    async list() { return canonicalSources; },
    readLogs: logsWith(
      [canonicalSources[1].container_id],
      '{"payload":{"message":"not-content-free"}}\n',
    ),
  });
  assert.equal(unclassified.hit_count, 1);
  assert.equal(unclassified.hit_rule_set_sha256, sha256("unclassified_sensitive_field"));
  const unclassifiedUri = await captureRuntimeLogScan(context, {
    async list() { return canonicalSources; },
    readLogs: logsWith(
      [canonicalSources[1].container_id],
      '{"requestUri":"/v1/tasks?cursor=opaque"}\n',
    ),
  });
  assert.equal(unclassifiedUri.hit_count, 1);
  assert.equal(unclassifiedUri.hit_rule_set_sha256, sha256("unclassified_sensitive_field"));
  const absolutePath = await captureRuntimeLogScan(context, {
    async list() { return canonicalSources; },
    readLogs: logsWith([canonicalSources[2].container_id], '{"value":"/Users/local/private"}\n'),
  });
  assert.equal(absolutePath.hit_count, 1);
  assert.equal(absolutePath.hit_rule_set_sha256, sha256("absolute_local_path"));
  const absoluteFileUri = await captureRuntimeLogScan(context, {
    async list() { return canonicalSources; },
    readLogs: logsWith(
      [canonicalSources[2].container_id],
      '{"value":"file:///Users/local/private"}\n',
    ),
  });
  assert.equal(absoluteFileUri.hit_count, 1);
  assert.equal(absoluteFileUri.hit_rule_set_sha256, sha256("absolute_local_path"));
  const duplicateSensitiveKey = await captureRuntimeLogScan(context, {
    async list() { return canonicalSources; },
    readLogs: logsWith(
      [canonicalSources[3].container_id],
      '{"token":"opaque-value","token":""}\n',
    ),
  });
  assert.equal(duplicateSensitiveKey.hit_count, 1);
  assert.equal(
    duplicateSensitiveKey.hit_rule_set_sha256,
    sha256("sensitive_value_field"),
  );
  await assert.rejects(
    captureRuntimeLogScan(context, {
      async list() { return canonicalSources; },
      readLogs: logsWith([canonicalSources[2].container_id], Buffer.from([0xff])),
    }),
    codeIs("orchestrator_no_log_invalid"),
  );

  const repeated = await captureRuntimeLogScan(context, {
    async list() { return canonicalSources; },
    readLogs: logsWith(
      [canonicalSources[0].container_id, canonicalSources[1].container_id],
      "Authorization: Bearer token\n",
    ),
  });
  assert.equal(repeated.hit_count, 3);
  assert.equal(
    repeated.hit_origin_set_sha256,
    sha256(origins.slice(0, 2).join("\n")),
  );
  assert.equal(
    repeated.hit_rule_set_sha256,
    sha256(["bearer", "unclassified_sensitive_field"].join("\n")),
  );
  assert.equal(
    repeated.hit_field_class_set_sha256,
    sha256(["structured_unclassified", "unstructured_pattern"].join("\n")),
  );
  assert.equal(
    repeated.hit_reason_class_set_sha256,
    sha256(["unclassified_caddy_system_value", "unstructured_pattern_match"].join("\n")),
  );
  assert.equal(
    repeated.hit_origin_rule_set_sha256,
    sha256([
      JSON.stringify([origins[0], "bearer"]),
      JSON.stringify([origins[1], "bearer"]),
      JSON.stringify([origins[1], "unclassified_sensitive_field"]),
    ].sort().join("\n")),
  );

  const invalidSources = [
    canonicalSources.slice(0, 3),
    canonicalSources.map((source, index) => index === 3
      ? { ...source, service_role: roles[0] }
      : source),
    canonicalSources.map((source, index) => index === 3
      ? { ...source, container_id: canonicalSources[0].container_id }
      : source),
    canonicalSources.map((source, index) => index === 0
      ? { ...source, service_role: "unknown" }
      : source),
    canonicalSources.map((source, index) => index === 0
      ? { ...source, project: `${project}-foreign` }
      : source),
    canonicalSources.map((source, index) => index === 0
      ? { ...source, feature: "FEAT-125" }
      : source),
    canonicalSources.map((source, index) => index === 0
      ? { ...source, slice: "S10B" }
      : source),
    canonicalSources.map((source, index) => index === 0
      ? { ...source, run_id: "12600000-0000-4000-8000-000000000071" }
      : source),
    canonicalSources.map((source, index) => index === 0
      ? { ...source, data_classification: "unknown" }
      : source),
    canonicalSources.map((source, index) => index === 0
      ? { ...source, service_role: `${source.service_role}\textra` }
      : source),
  ];
  for (const invalid of invalidSources) {
    await assert.rejects(
      captureRuntimeLogScan(context, {
        async list() { return invalid; },
        async readLogs() { return Buffer.from("ready\n", "utf8"); },
      }),
      codeIs("orchestrator_no_log_invalid"),
    );
  }

  const v1 = {
    schema_version: 1,
    status: "passed",
    run_id: runId,
    source_count: 4,
    row_count: 4,
    hit_count: 0,
    source_set_sha256: clean.source_set_sha256,
  };
  const emptySetSha256 = sha256("");
  const v2 = {
    ...v1,
    schema_version: 2,
    hit_origin_set_sha256: emptySetSha256,
    hit_rule_set_sha256: emptySetSha256,
  };
  assert.equal(validateRuntimeLogScan(v1, runId).schema_version, 1);
  assert.equal(validateRuntimeLogScan(v2, runId).schema_version, 2);
  assert.equal(validateRuntimeLogScan({
    ...v2,
    status: "failed",
    hit_count: 1,
    hit_origin_set_sha256: sha256(origins[0]),
    hit_rule_set_sha256: sha256("sensitive_value_field"),
  }, runId).schema_version, 2);
  assert.equal(validateRuntimeLogScan(clean, runId).schema_version, 4);
  const {
    hit_reason_class_set_sha256: _v4ReasonDigest,
    hit_origin_rule_field_class_reason_class_set_sha256: _v4TupleDigest,
    ...explainableV3
  } = clean;
  explainableV3.schema_version = 3;
  assert.equal(validateRuntimeLogScan(explainableV3, runId).schema_version, 3);
  const {
    hit_field_class_set_sha256: _fieldClassDigest,
    hit_origin_rule_field_class_set_sha256: _originRuleFieldClassDigest,
    hit_reason_class_set_sha256: _reasonClassDigest,
    hit_origin_rule_field_class_reason_class_set_sha256: _originRuleFieldClassReasonClassDigest,
    ...legacyV3
  } = clean;
  legacyV3.schema_version = 3;
  assert.equal(validateRuntimeLogScan(legacyV3, runId).schema_version, 3);
  assert.throws(
    () => validateRuntimeLogScan({ ...clean, source_count: 3 }, runId),
    codeIs("orchestrator_no_log_invalid"),
  );
  assert.throws(
    () => validateRuntimeLogScan({ ...clean, source_set_sha256: sha256("foreign") }, runId),
    codeIs("orchestrator_no_log_invalid"),
  );
  assert.throws(
    () => validateRuntimeLogScan({ ...v2, hit_count: 1, status: "failed" }, runId),
    codeIs("orchestrator_no_log_invalid"),
  );
  assert.throws(
    () => validateRuntimeLogScan({ ...clean, hit_origin_rule_set_sha256: emptySetSha256, hit_count: 1, status: "failed" }, runId),
    codeIs("orchestrator_no_log_invalid"),
  );
  const {
    hit_reason_class_set_sha256: _missingReasonDigest,
    ...missingV4ReasonDigest
  } = clean;
  assert.throws(
    () => validateRuntimeLogScan(missingV4ReasonDigest, runId),
    codeIs("orchestrator_no_log_invalid"),
  );
  assert.throws(
    () => validateRuntimeLogScan({ ...clean, unexpected: true }, runId),
    codeIs("orchestrator_no_log_invalid"),
  );
});

function apiProjection(canonicalHash) {
  const entry = { count: 0, enums: [], canonical_hash: canonicalHash };
  return {
    schema_version: 1,
    status: "passed",
    profile: "feat-126-s10-local-lab",
    run_id: runId,
    denylist_hit_count: 0,
    canonical_hash: canonicalHash,
    tasks: entry,
    audit: entry,
    idempotency: entry,
  };
}

test("S10BO3-018 rejects API or fake business-boundary mutation", () => {
  const before = apiProjection("a".repeat(64));
  const fake = {
    accepted_calls: 0,
    rejected_calls: 0,
    dataset_id: "feat126-title-raw-v1",
    fixture_case_id: "normal-000",
    dataset_sha256: "e".repeat(64),
  };
  assert.throws(
    () => buildBusinessBoundaryEvidence(before, apiProjection("b".repeat(64)), fake, runId),
    codeIs("orchestrator_business_boundary_invalid"),
  );
  assert.throws(
    () => buildBusinessBoundaryEvidence(before, before, { ...fake, accepted_calls: 1 }, runId),
    codeIs("orchestrator_business_boundary_invalid"),
  );
});

test("S10BO3-019 records marker-only absent-root reconcile without resume", async (t) => {
  const { attempt } = await claimTemporaryAttempt(t, "feat126-s10bo3-reconcile-");
  const reconcile = buildAttemptReconcileEvidence(
    attempt,
    authority,
    null,
    {
      businessStatus: "not_applicable",
      cleanup: { scope: "pre_run_absence" },
      noLog: { scope: "attempt_only" },
    },
  );
  assert.equal(reconcile.status, "reconciled");
  assert.equal(reconcile.failure_class, "orchestrator_unclean_exit");
  assert.equal(reconcile.s10b_r8_executed, false);
  const scopedFailure = buildAttemptReconcileEvidence(
    attempt,
    authority,
    attemptFailure({ attempt_marker_sha256: attempt.markerSha256 }),
    {
      businessStatus: "passed",
      cleanup: { scope: "run_artifacts" },
      cleanupFailure: { code: "orchestrator_cleanup_unknown" },
      noLog: { scope: "run_artifacts" },
      noLogFailure: { code: "orchestrator_no_log_invalid" },
    },
  );
  assert.equal(validateAttemptReconcile(scopedFailure, authority).cleanup_scope, "run_artifacts");
  assert.equal(scopedFailure.no_log_scope, "run_artifacts");
});

test("S10BO3-020 requires persisted Host and Runtime ownership evidence", () => {
  assert.deepEqual(persistedOwnershipEvidenceRequiredFiles([processRecord("api", 0)]), []);
  assert.deepEqual(
    persistedOwnershipEvidenceRequiredFiles([
      processRecord("desktop", 1),
      processRecord("host", 3),
      processRecord("runtime", 4),
    ]),
    ["host-evidence.v1.json", "host-stopped-evidence.v1.json", "runtime-evidence.v1.json"],
  );
  assert.throws(
    () => persistedOwnershipEvidenceRequiredFiles([processRecord("runtime", 4)]),
    codeIs("orchestrator_existing_evidence_incomplete"),
  );
});
