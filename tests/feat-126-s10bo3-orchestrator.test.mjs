import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
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
  readAttemptReconcile,
  runStartupAbortFlow,
  scanNoLog,
  shouldRunComposeCleanup,
  validateAttemptClosure,
  validateAttemptFailure,
  validateAttemptMarker,
  validateAttemptReconcile,
  validateBusinessBoundaryEvidence,
  validateCleanupClosure,
  validateExistingProcessRecordSet,
  validateFreshResourceInventory,
  validateNoLogResult,
  validatePreflightFailureBinding,
  validateRuntimeLogScan,
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
    ["preflight", "abort", "business", "cleanup", "parent", "record", "no_log"],
  );
  assert.deepEqual(recorded, {
    failureClass: "preflight_authority_invalid",
    businessFailureClass: null,
    cleanupFailureClass: "orchestrator_cleanup_unknown",
    parentFailureClass: "orchestrator_parent_death",
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
  await assert.rejects(
    writeAttemptClosure(attempt, authority, { ...closure, failure_class: "other_failure" }),
    codeIs("orchestrator_evidence_write_failed"),
  );
});

test("S10BO3-007 establishes content-free no-log evidence when preflight never created run root", async (t) => {
  const { root, attempt, failure } = await writeSyntheticAttemptFiles(t, "feat126-s10bo3-absent-");
  await writeFile(attempt.failurePath, `${JSON.stringify(failure)}\n`, { mode: 0o600 });
  await chmod(attempt.failurePath, 0o600);
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
  assert.equal(result.file_count, 2);
  assert.equal(result.scope, "attempt_only");
  assert.equal(result.coverage, "attempt_marker_and_failure");
  assert.equal(result.row_count, 2);
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
  assert.equal(markerOnly.coverage, "attempt_marker_only");
  assert.equal(markerOnly.file_count, 1);
  assert.equal(markerOnly.row_count, 1);
  assert.equal(markerOnly.hit_count, 0);
  assert.equal(validateNoLogResult(markerOnly), true);

  await mkdir(runRoot, { mode: 0o700 });
  await chmod(runRoot, 0o700);
  await assert.rejects(scanNoLog(context), codeIs("orchestrator_no_log_invalid"));
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

test("S10BO3-013 rejects unknown inventory and phase-incomplete descendant evidence", () => {
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
    composeLogsRequired: true,
    secrets: new Map([["ephemeral", "never-log-secret"]]),
  };
  const clean = await captureRuntimeLogScan(context, {
    async list() { return ["a".repeat(12), "b".repeat(12)]; },
    async readLogs() { return Buffer.from("ready\n", "utf8"); },
  });
  assert.equal(clean.status, "passed");
  assert.equal(clean.source_count, 2);
  const leaked = await captureRuntimeLogScan(context, {
    async list() { return ["a".repeat(12)]; },
    async readLogs() { return Buffer.from("Authorization: Bearer token\n", "utf8"); },
  });
  assert.equal(leaked.status, "failed");
  assert.equal(leaked.hit_count, 1);
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
