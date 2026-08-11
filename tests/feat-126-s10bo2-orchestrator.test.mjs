import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { EventEmitter, once } from "node:events";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { PassThrough, Writable } from "node:stream";
import test from "node:test";
import { pathToFileURL } from "node:url";

import { FEAT_126_S10_API_RUNTIME_AUTHORITY } from "../scripts/feat-126-s10-api-runtime-profile.mjs";
import {
  S10BO2_STATES,
  S10BO2_TARGETED_MATRIX,
  S10BO1OrchestratorError,
  buildOrchestratorPlan,
  assessProcessCleanup,
  classifyProjectVolumes,
  closeControlWriter,
  createParentIdentityGuard,
  createControlFrameReader,
  createStartupAbortStateMachine,
  desktopEnvironment,
  encodeControlFrame,
  inspectProcessIdentity,
  loadExistingProcessRecords,
  parseControlFrame,
  parseDarwinProcessLaunchIdentity,
  readDesktopFrame,
  reconcileProcess,
  runCommand,
  runStartupAbortFlow,
  scanNoLog,
  sameProcessIdentity,
  sendAbort,
  spawnOwnedProcess,
  validateCleanupClosure,
  validateExistingProcessRecordSet,
  validateHostProcessEvidence,
  validateNoLogResult,
  validateOwnership,
  validateRuntimeProcessEvidence,
  validateStartupFailureControlFrame,
  writeFrame,
} from "../scripts/feat-126-s10b-orchestrator.mjs";

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
const environment = Object.fromEntries(
  Object.entries(repositories).map(([role, sha]) => [`FEAT126_S10B_${role.toUpperCase()}_SHA`, sha]),
);
const completed = Object.freeze([
  "authority", "ports", "secret_init", "compose", "images", "dependencies",
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
    api_binary_sha256: "a".repeat(64),
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

function cleanupResult(overrides = {}) {
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
    ...overrides,
  };
}

function noLogResult(overrides = {}) {
  return {
    schema_version: 1,
    scope: "run_artifacts",
    coverage: "all_run_log_and_evidence_sources",
    file_count: 4,
    row_count: 8,
    hit_count: 0,
    external_source_count: 4,
    external_row_count: 4,
    external_source_set_sha256: "d".repeat(64),
    pattern_set_sha256: "c".repeat(64),
    ...overrides,
  };
}

function businessBoundaryResult(overrides = {}) {
  return {
    schema_version: 1,
    status: "passed",
    scope: "api_and_fake",
    run_id: runId,
    api_before_sha256: "d".repeat(64),
    api_after_sha256: "d".repeat(64),
    fake_accepted_calls: 0,
    fake_rejected_calls: 0,
    s10b_r8_executed: false,
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

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function hostEvidence(overrides = {}) {
  return {
    schemaVersion: 1,
    runId: runId,
    role: "agent_host_child",
    pid: 201,
    ppid: 101,
    binarySha256: "a".repeat(64),
    instanceNonce: nonce,
    startedAtUnixMs: 1000,
    endedAtUnixMs: null,
    state: "ready",
    exitCode: null,
    stdoutBytes: 0,
    stderrBytes: 0,
    stdoutTruncated: false,
    stderrTruncated: false,
    logLimitBytes: 256 * 1024,
    ...overrides,
  };
}

function runtimeEvidence(overrides = {}) {
  return {
    schema_version: 1,
    run_id: runId,
    role: "runtime",
    pid: 301,
    ppid: 201,
    binary_sha256: "b".repeat(64),
    manifest_sha256: "c".repeat(64),
    nonce,
    profile: "feat-126-s10-local-lab",
    state: "ready",
    ready: true,
    ...overrides,
  };
}

function errorCode(error) {
  return error instanceof S10BO1OrchestratorError ? error.code : error?.message;
}

async function waitFor(predicate, timeoutMs = 3000) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("test wait timed out");
    await new Promise((resolveWait) => setTimeout(resolveWait, 10));
  }
}

function flowOperations(calls, overrides = {}) {
  return {
    async runPreflight() { calls.push("preflight"); return summary(); },
    async buildDesktop() { calls.push("build_desktop"); },
    async startDependencies() { calls.push("dependencies"); },
    async startApi() { calls.push("api"); },
    async startFake() { calls.push("fake"); },
    async startDesktop() { calls.push("desktop"); },
    async readDesktopFrame(kind) {
      calls.push(`read:${kind}`);
      return { kind, sequence: kind === "component_ready" ? 1 : 2 };
    },
    async readDesktopEof() { calls.push("read:eof"); },
    async readOwnership() {
      calls.push("ownership");
      return { infra: { children: ["api", "fake", "desktop"] }, desktop: { children: ["host"] }, host: { children: ["runtime"] } };
    },
    async sendAbort() { calls.push("send:abort"); },
    async waitForDesktopExit() { calls.push("desktop_exit"); },
    async initiateDesktopAbort() { calls.push("desktop_abort"); },
    async verifyBusinessBoundary() {
      calls.push("business_boundary");
      return businessBoundaryResult();
    },
    async cleanup() { calls.push("cleanup"); return cleanupResult(); },
    async recordFailure() {},
    async recordClosure() {},
    async scanNoLog() { calls.push("no_log"); return noLogResult(); },
    ...overrides,
  };
}

test("S10BO2-001 freezes a startup-only state machine and matrix", () => {
  assert.deepEqual(
    S10BO2_TARGETED_MATRIX,
    Array.from({ length: 14 }, (_, index) => `S10BO2-${String(index + 1).padStart(3, "0")}`),
  );
  assert.equal(S10BO2_STATES.includes("s10b_002"), false);
  const machine = createStartupAbortStateMachine();
  for (const state of S10BO2_STATES.slice(1)) assert.equal(machine.transition(state), state);
});

test("S10BO2-002 parses one bounded strict component_ready NDJSON frame", () => {
  const value = { schema_version: 1, run_id: runId, nonce, sequence: 1, kind: "component_ready" };
  assert.deepEqual(
    parseControlFrame(Buffer.from(`${JSON.stringify(value)}\n`), {
      runId,
      nonce,
      previousSequence: 0,
      allowedKinds: ["component_ready", "abort_complete"],
    }),
    value,
  );
  const startupFailure = {
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence: 1,
    kind: "startup_failed",
    failure_class: "driver_bind_failed",
  };
  assert.deepEqual(
    parseControlFrame(Buffer.from(`${JSON.stringify(startupFailure)}\n`), {
      runId,
      nonce,
      previousSequence: 0,
      allowedKinds: ["component_ready", "abort_complete", "startup_failed"],
    }),
    startupFailure,
  );
});

test("S10BO2-003 rejects malformed, duplicate, unknown, multiple, and oversized frames", () => {
  const valid = { schema_version: 1, run_id: runId, nonce, sequence: 1, kind: "component_ready" };
  const invalid = [
    Buffer.alloc(0),
    Buffer.from(JSON.stringify(valid)),
    Buffer.from(`${JSON.stringify(valid)}\r\n`),
    Buffer.from(`${JSON.stringify(valid)}\n${JSON.stringify(valid)}\n`),
    Buffer.from(` ${JSON.stringify(valid)}\n`),
    Buffer.from(`{"schema_version":1,"schema_version":1,"run_id":"${runId}","nonce":"${nonce}","sequence":1,"kind":"component_ready"}\n`),
    Buffer.from(`${JSON.stringify({ ...valid, payload: "forbidden" })}\n`),
    Buffer.from(`${JSON.stringify({ ...valid, kind: "case_result" })}\n`),
    Buffer.from([0xff, 0x0a]),
  ];
  for (const frame of invalid) {
    assert.throws(
      () => parseControlFrame(frame, { runId, nonce, previousSequence: 0, allowedKinds: ["component_ready", "abort_complete"] }),
      (error) => ["orchestrator_control_frame_invalid", "orchestrator_control_frame_oversize"].includes(errorCode(error)),
    );
  }
  assert.throws(
    () => parseControlFrame(Buffer.alloc(1025, 0x20), { runId, nonce, previousSequence: 0, allowedKinds: ["component_ready"] }),
    (error) => errorCode(error) === "orchestrator_control_frame_oversize",
  );

  const startupFailure = {
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence: 1,
    kind: "startup_failed",
    failure_class: "driver_control_monitor_invalid",
  };
  const validAuthority = {
    runId,
    nonce,
    previousSequence: 0,
    allowedKinds: ["component_ready", "abort_complete", "startup_failed"],
  };
  assert.deepEqual(
    validateStartupFailureControlFrame(startupFailure, validAuthority),
    startupFailure,
  );
  for (const malformedAuthority of [
    null,
    {},
    { ...validAuthority, runId: "not-a-uuid" },
    { ...validAuthority, nonce: "not-a-uuid" },
    { ...validAuthority, previousSequence: 1 },
    { ...validAuthority, allowedKinds: null },
    { ...validAuthority, allowedKinds: ["component_ready"] },
    { ...validAuthority, allowedKinds: ["startup_failed"] },
    { ...validAuthority, allowedKinds: ["startup_failed", "startup_failed"] },
    { ...validAuthority, allowedKinds: ["startup_failed", "unknown"] },
    { ...validAuthority, unexpected: true },
  ]) {
    assert.throws(
      () => validateStartupFailureControlFrame(startupFailure, malformedAuthority),
      (error) => errorCode(error) === "orchestrator_control_frame_invalid",
    );
  }
  assert.throws(
    () => validateStartupFailureControlFrame(
      { ...startupFailure, failure_class: "driver_control_eof" },
      validAuthority,
    ),
    (error) => errorCode(error) === "orchestrator_control_frame_invalid",
  );
});

test("S10BO2-004 binds direction, sequence, and exact FD3 close", async () => {
  const abort = encodeControlFrame(
    { schema_version: 1, run_id: runId, nonce, sequence: 1, kind: "abort" },
    { runId, nonce, previousSequence: 0, allowedKinds: ["abort"] },
  );
  assert.match(abort.toString("utf8"), /"kind":"abort"/);
  for (const invalid of [
    { run_id: "019fbd88-cbc3-4bf1-934d-7b05cd693f82" },
    { nonce: "019fbd88-cbc3-4bf1-934d-7b05cd693f82" },
    { sequence: 2 },
    { kind: "component_ready" },
  ]) {
    assert.throws(
      () => encodeControlFrame(
        { schema_version: 1, run_id: runId, nonce, sequence: 1, kind: "abort", ...invalid },
        { runId, nonce, previousSequence: 0, allowedKinds: ["abort"] },
      ),
      (error) => errorCode(error) === "orchestrator_control_frame_invalid",
    );
  }
  const writer = new PassThrough();
  const chunks = [];
  writer.on("data", (chunk) => chunks.push(chunk));
  const finished = once(writer, "finish");
  await sendAbort({ runId, nonce, controlWriter: writer });
  await finished;
  assert.equal(writer.writableEnded, true);
  assert.equal(chunks.length, 1);
  assert.equal(
    parseControlFrame(chunks[0], {
      runId,
      nonce,
      previousSequence: 0,
      allowedKinds: ["abort"],
    }).kind,
    "abort",
  );

  const brokenWriter = new Writable({
    write(_chunk, _encoding, callback) { callback(); },
    final(callback) { callback(new Error("EPIPE")); },
  });
  await assert.rejects(
    sendAbort({ runId, nonce, controlWriter: brokenWriter }),
    (error) => errorCode(error) === "orchestrator_control_stream_failed",
  );

  const brokenWrite = new Writable({
    write(_chunk, _encoding, callback) { callback(new Error("EPIPE")); },
  });
  await assert.rejects(
    writeFrame(brokenWrite, abort, 1000),
    (error) => errorCode(error) === "orchestrator_control_stream_failed",
  );

  const hangingWrite = new Writable({ write() {} });
  await assert.rejects(
    writeFrame(hangingWrite, abort, 20),
    (error) => errorCode(error) === "orchestrator_control_stream_failed",
  );
  const hangingClose = new Writable({
    write(_chunk, _encoding, callback) { callback(); },
    final() {},
  });
  await assert.rejects(
    closeControlWriter(hangingClose, 20),
    (error) => errorCode(error) === "orchestrator_control_stream_failed",
  );
});

test("S10BO2-005 reader preserves FD4 frame ordering across timeout, EOF, and child exit", async () => {
  const stream = new PassThrough();
  const reader = createControlFrameReader(stream, { runId, nonce });
  const first = `${JSON.stringify({ schema_version: 1, run_id: runId, nonce, sequence: 1, kind: "component_ready" })}\n`;
  stream.write(first.slice(0, 17));
  stream.write(first.slice(17));
  assert.equal((await reader.next("component_ready", 1000)).sequence, 1);
  stream.end();
  await assert.rejects(reader.next("abort_complete", 1000), (error) => errorCode(error) === "orchestrator_control_eof");

  const timeoutStream = new PassThrough();
  const timeoutReader = createControlFrameReader(timeoutStream, { runId, nonce });
  await assert.rejects(
    timeoutReader.next("component_ready", 20),
    (error) => errorCode(error) === "orchestrator_control_timeout",
  );
  timeoutReader.destroy();

  const closedStream = new PassThrough();
  const closedReader = createControlFrameReader(closedStream, { runId, nonce });
  closedStream.write(first);
  closedStream.write(`${JSON.stringify({
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence: 2,
    kind: "abort_complete",
  })}\n`);
  assert.equal((await closedReader.next("component_ready", 1000)).sequence, 1);
  assert.equal((await closedReader.next("abort_complete", 1000)).sequence, 2);
  closedStream.write(`${JSON.stringify({
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence: 3,
    kind: "abort_complete",
  })}\n`);
  closedStream.end();
  await assert.rejects(
    closedReader.expectEof(1000),
    (error) => errorCode(error) === "orchestrator_control_trailing_frame",
  );

  const failureStream = new PassThrough();
  const failureReader = createControlFrameReader(failureStream, { runId, nonce });
  failureStream.end(`${JSON.stringify({
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence: 1,
    kind: "startup_failed",
    failure_class: "driver_profile_invalid",
  })}\n`);
  await assert.rejects(
    failureReader.next("component_ready", 1000),
    (error) => errorCode(error) === "driver_profile_invalid",
  );

  function pendingChild() {
    const child = new EventEmitter();
    child.exitCode = null;
    child.signalCode = null;
    return child;
  }
  const exitAfterFrameStream = new PassThrough();
  const desktopChild = pendingChild();
  const desktopContext = {
    phase: "desktop_spawned",
    controlReader: createControlFrameReader(exitAfterFrameStream, { runId, nonce }),
    processes: {
      api: { child: pendingChild() },
      fake: { child: pendingChild() },
      desktop: { child: desktopChild },
    },
  };
  const frameBeforeExit = readDesktopFrame(desktopContext, "component_ready");
  exitAfterFrameStream.end(`${JSON.stringify({
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence: 1,
    kind: "startup_failed",
    failure_class: "driver_bind_failed",
  })}\n`);
  desktopChild.emit("exit", 1, null);
  await assert.rejects(
    frameBeforeExit,
    (error) => errorCode(error) === "driver_bind_failed",
  );
  assert.equal(desktopContext.phase, "desktop_starting");

  for (const role of ["api", "fake", "desktop"]) {
    const childExitStream = new PassThrough();
    const childExitContext = {
      phase: "desktop_spawned",
      controlReader: createControlFrameReader(childExitStream, { runId, nonce }),
      processes: {
        api: { child: pendingChild() },
        fake: { child: pendingChild() },
        desktop: { child: pendingChild() },
      },
    };
    const childExitBeforeFrame = readDesktopFrame(childExitContext, "component_ready");
    childExitContext.processes[role].child.emit("exit", 1, null);
    await assert.rejects(
      childExitBeforeFrame,
      (error) => errorCode(error) === `orchestrator_${role}_exited_early`,
    );
    childExitContext.controlReader.destroy();
  }
});

test("S10BO2-006 executes the only allowed spawn and abort order", async () => {
  const calls = [];
  const result = await runStartupAbortFlow({ runId, repositories }, flowOperations(calls));
  assert.equal(result.status, "passed");
  assert.equal(result.s10b_r8_executed, false);
  assert.deepEqual(calls, [
    "preflight", "build_desktop", "dependencies", "api", "fake", "desktop",
    "read:component_ready", "ownership", "send:abort", "read:abort_complete",
    "read:eof", "desktop_exit", "business_boundary", "cleanup", "no_log",
  ]);
});

test("S10BO2-007 unexpected exit initiates Desktop-owned abort then exact cleanup", async () => {
  const calls = [];
  const operations = flowOperations(calls, {
    async startDesktop() {
      calls.push("desktop");
      throw new S10BO1OrchestratorError("orchestrator_desktop_exited_early");
    },
    async initiateDesktopAbort() {
      calls.push("desktop_abort");
      throw new Error("abort channel closed");
    },
  });
  await assert.rejects(
    runStartupAbortFlow({ runId, repositories }, operations),
    (error) => errorCode(error) === "orchestrator_desktop_exited_early",
  );
  assert.deepEqual(calls.slice(-4), ["desktop_abort", "business_boundary", "cleanup", "no_log"]);

  const parentDeathCalls = [];
  await assert.rejects(
    runStartupAbortFlow({ runId, repositories }, flowOperations(parentDeathCalls, {
      assertParentAlive() {
        throw new S10BO1OrchestratorError("orchestrator_parent_death");
      },
    })),
    (error) => errorCode(error) === "orchestrator_parent_death",
  );
  assert.deepEqual(parentDeathCalls.slice(-3), ["business_boundary", "cleanup", "no_log"]);
});

test("S10BO2-007 detects actual parent disappearance and aborts a long command", async (t) => {
  let observedParent = 501;
  const guard = createParentIdentityGuard({
    parentPid: observedParent,
    readParentPid: () => observedParent,
    probeParent: () => true,
  });
  assert.equal(guard.isAlive(), true);
  observedParent += 1;
  assert.equal(guard.isAlive(), false);

  const moduleUrl = pathToFileURL(resolve("scripts/feat-126-s10b-orchestrator.mjs")).href;
  const grandchildSource = `
    import { createParentIdentityGuard } from ${JSON.stringify(moduleUrl)};
    const guard = createParentIdentityGuard();
    process.stdout.write("grandchild_ready\\n");
    const interval = setInterval(() => {
      if (!guard.isAlive()) {
        clearInterval(interval);
        process.stdout.write("parent_dead\\n");
        process.exit(0);
      }
    }, 20);
  `;
  const parentSource = `
    const { spawn } = require("node:child_process");
    const child = spawn(process.execPath, ["--input-type=module", "-e", ${JSON.stringify(grandchildSource)}], {
      stdio: ["ignore", "inherit", "inherit"],
    });
    child.once("spawn", () => process.stdout.write("parent_ready:" + child.pid + "\\n"));
    setInterval(() => {}, 1000);
  `;
  const parent = spawn(process.execPath, ["-e", parentSource], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  let errorOutput = "";
  parent.stdout.on("data", (chunk) => { output += chunk.toString("utf8"); });
  parent.stderr.on("data", (chunk) => { errorOutput += chunk.toString("utf8"); });
  let grandchildPid;
  t.after(() => {
    if (parent.exitCode === null && parent.signalCode === null) parent.kill("SIGKILL");
    if (grandchildPid) {
      try { process.kill(grandchildPid, "SIGKILL"); } catch {}
    }
  });
  await waitFor(() => /parent_ready:\d+/.test(output) && output.includes("grandchild_ready"));
  grandchildPid = Number(/parent_ready:(\d+)/.exec(output)[1]);
  parent.kill("SIGTERM");
  await once(parent, "exit");
  await waitFor(() => output.includes("parent_dead"));
  assert.equal(errorOutput, "");

  assert.equal(
    await runCommand(
      "parent_test",
      process.execPath,
      ["-e", 'process.stdout.write("ok")'],
      { timeout: 5000 },
    ),
    "ok",
  );
  const controller = new AbortController();
  const command = runCommand(
    "parent_test",
    process.execPath,
    ["-e", "setInterval(() => {}, 1000)"],
    { signal: controller.signal, timeout: 5000 },
  );
  controller.abort();
  await assert.rejects(
    command,
    (error) => errorCode(error) === "orchestrator_parent_death",
  );
});

test("S10BO2-008 failure is not retried, resumed, reordered, or skipped", async () => {
  const calls = [];
  let starts = 0;
  const operations = flowOperations(calls, {
    async startFake() {
      starts += 1;
      calls.push("fake");
      throw new S10BO1OrchestratorError("orchestrator_fake_not_ready");
    },
  });
  await assert.rejects(runStartupAbortFlow({ runId, repositories }, operations));
  assert.equal(starts, 1);
  assert.equal(calls.includes("desktop"), false);
  assert.equal(calls.includes("send:abort"), false);
});

test("S10BO2-009 PID reuse and missing binary identity are foreign and never signalled", async () => {
  const record = {
    pid: 91,
    ppid: 10,
    start_identity: "a".repeat(64),
    binary_sha256: "c".repeat(64),
  };
  const reused = {
    pid: 91,
    ppid: 10,
    start_identity: "b".repeat(64),
    binary_sha256: "c".repeat(64),
  };
  let stopCalls = 0;
  assert.equal(sameProcessIdentity(record, reused), false);
  assert.equal(sameProcessIdentity({ ...record, binary_sha256: undefined }, record), false);
  assert.equal(
    await reconcileProcess(record, { async inspect() { return reused; }, async stop() { stopCalls += 1; } }),
    "foreign_identity_preserved",
  );
  assert.equal(stopCalls, 0);
  assert.deepEqual(
    await assessProcessCleanup([record], async () => reused),
    { processes: 0, identityUnknown: true },
  );
});

test("S10BO2-009 Darwin kernel launch identity distinguishes same-second PID reuse", () => {
  const processHeader = "Process:         yijie-api [91]\n";
  const first = parseDarwinProcessLaunchIdentity(
    `${processHeader}Launch Time:     2026-08-09 20:00:00.101 +0800\n`,
    91,
  );
  const reused = parseDarwinProcessLaunchIdentity(
    `${processHeader}Launch Time:     2026-08-09 20:00:00.902 +0800\n`,
    91,
  );
  assert.notEqual(first, reused);
  assert.throws(
    () => parseDarwinProcessLaunchIdentity(
      `${processHeader}Launch Time:     2026-08-09 20:00:00 +0800\n`,
      91,
    ),
    (error) => errorCode(error) === "orchestrator_process_identity_unknown",
  );
});

test("S10BO2-009 captures executable digest for a real child", async (t) => {
  const child = spawn("/bin/sleep", ["5"], { stdio: "ignore" });
  t.after(() => {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  });
  await once(child, "spawn");
  const identity = await inspectProcessIdentity(child.pid);
  assert.equal(identity.pid, child.pid);
  assert.equal(identity.ppid, process.pid);
  assert.match(identity.binary_sha256, /^[0-9a-f]{64}$/);
  assert.equal(sameProcessIdentity(identity, identity), true);
  assert.deepEqual(await inspectProcessIdentity(child.pid), identity);
  child.kill("SIGTERM");
  await once(child, "exit");
});

test("S10BO2-010 reconciles exact identity once and counts actual survivors", async () => {
  const record = {
    pid: 92,
    ppid: 10,
    start_identity: "a".repeat(64),
    binary_sha256: "c".repeat(64),
  };
  let live = true;
  let stopCalls = 0;
  assert.equal(
    await reconcileProcess(record, {
      async inspect() { return live ? record : null; },
      async stop() { stopCalls += 1; live = false; },
    }),
    "stopped",
  );
  assert.equal(stopCalls, 1);
  const survivor = {
    pid: 93,
    ppid: 10,
    start_identity: "b".repeat(64),
    binary_sha256: "d".repeat(64),
  };
  assert.deepEqual(
    await assessProcessCleanup([record, survivor], async (pid) => pid === survivor.pid ? survivor : null),
    { processes: 1, identityUnknown: false },
  );
});

test("S10BO2-010 registers a live provisional child before identity rejection", async (t) => {
  const root = await mkdtemp(resolve(tmpdir(), "feat126-s10bo2-spawn-"));
  t.after(async () => { await rm(root, { recursive: true, force: true }); });
  await chmod(root, 0o700);
  const logs = resolve(root, "logs");
  const evidence = resolve(root, "evidence");
  await mkdir(logs, { mode: 0o700 });
  await mkdir(evidence, { mode: 0o700 });
  const context = { runId, evidenceRoot: evidence, processes: {}, cleanupUnknown: false };
  t.after(() => {
    const child = context.processes.api?.child;
    if (child && child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  });
  const binaryBytes = await readFile("/bin/sleep");
  const expected = sha256(binaryBytes);
  await assert.rejects(
    spawnOwnedProcess({
      role: "api",
      binary: "/bin/sleep",
      arguments_: ["5"],
      cwd: "/",
      environment: { PATH: "/usr/bin:/bin" },
      logPath: resolve(logs, "api.log"),
      inspect: async (pid) => ({
        pid,
        ppid: process.pid + 1,
        start_identity: "e".repeat(64),
        binary_sha256: expected,
      }),
    }, context),
    (error) => errorCode(error) === "orchestrator_process_parent_invalid",
  );
  assert.equal(context.processes.api.provisional, true);
  assert.equal(context.processes.api.child.pid > 1, true);
  assert.equal(context.cleanupUnknown, true);
});

test("S10BO2-010 async spawn error is observed without an unhandled event", async (t) => {
  const root = await mkdtemp(resolve(tmpdir(), "feat126-s10bo2-error-"));
  t.after(async () => { await rm(root, { recursive: true, force: true }); });
  await chmod(root, 0o700);
  const logs = resolve(root, "logs");
  const evidence = resolve(root, "evidence");
  await mkdir(logs, { mode: 0o700 });
  await mkdir(evidence, { mode: 0o700 });
  const invalidBinary = resolve(root, "not-executable");
  await writeFile(invalidBinary, "not executable\n", { mode: 0o600 });
  const context = { runId, evidenceRoot: evidence, processes: {}, cleanupUnknown: false };
  await assert.rejects(
    spawnOwnedProcess({
      role: "api",
      binary: invalidBinary,
      cwd: "/",
      environment: { PATH: "/usr/bin:/bin" },
      logPath: resolve(logs, "api.log"),
    }, context),
    (error) => errorCode(error) === "orchestrator_process_spawn_failed",
  );
  assert.equal(context.processes.api.provisional, true);
  assert.equal(context.cleanupUnknown, true);
  await new Promise((resolveWait) => setImmediate(resolveWait));
  assert.equal(context.processes.api.processError, true);
});

test("S10BO2-010 consumes a Desktop startup leaf written before identity-time exit", async (t) => {
  const root = await mkdtemp(resolve(tmpdir(), "feat126-s10bo2-startup-leaf-"));
  t.after(async () => { await rm(root, { recursive: true, force: true }); });
  await chmod(root, 0o700);
  const logs = resolve(root, "logs");
  const evidence = resolve(root, "evidence");
  await mkdir(logs, { mode: 0o700 });
  await mkdir(evidence, { mode: 0o700 });
  const context = {
    runId,
    nonce,
    phase: "desktop_spawned",
    evidenceRoot: evidence,
    processes: {},
    cleanupUnknown: false,
  };
  function pendingChild() {
    const child = new EventEmitter();
    child.exitCode = null;
    child.signalCode = null;
    return child;
  }
  context.processes.api = { child: pendingChild() };
  context.processes.fake = { child: pendingChild() };
  const frame = `${JSON.stringify({
    schema_version: 1,
    run_id: runId,
    nonce,
    sequence: 1,
    kind: "startup_failed",
    failure_class: "driver_control_monitor_invalid",
  })}\n`;
  const childSource = `require("node:fs").writeFileSync(4, ${JSON.stringify(frame)});` +
    "setTimeout(() => process.exit(0), 50);";
  const process_ = await spawnOwnedProcess({
    role: "desktop",
    binary: process.execPath,
    arguments_: ["-e", childSource],
    cwd: "/",
    environment: { PATH: "/usr/bin:/bin" },
    logPath: resolve(logs, "desktop.log"),
    extraStdio: ["pipe", "pipe"],
    deferIdentityOnExit: true,
    inspect: async () => {
      await new Promise((resolveWait) => setTimeout(resolveWait, 200));
      throw new S10BO1OrchestratorError("orchestrator_process_identity_unknown");
    },
    onSpawn(provisional) {
      context.controlReader = createControlFrameReader(provisional.child.stdio[4], context);
      context.controlWriter = provisional.child.stdio[3];
      context.pendingDesktopFrame = context.controlReader.next("component_ready");
      context.pendingDesktopFrame.catch(() => {});
    },
  }, context);
  assert.equal(process_, context.processes.desktop);
  assert.equal(process_.earlyExit, true);
  await assert.rejects(
    readDesktopFrame(context, "component_ready"),
    (error) => errorCode(error) === "driver_control_monitor_invalid",
  );
  assert.equal(context.phase, "desktop_starting");
});

test("S10BO2-011 incomplete existing-run evidence and unknown cleanup fail closed", async (t) => {
  const record = {
    pid: 93,
    ppid: 10,
    start_identity: "a".repeat(64),
    binary_sha256: "c".repeat(64),
  };
  assert.equal(
    await reconcileProcess(record, { async inspect() { throw new Error("unknown"); }, async stop() {} }),
    "unknown",
  );
  assert.throws(() => validateCleanupClosure(cleanupResult({ status: "failed", processes: 1 })), (error) => errorCode(error) === "orchestrator_cleanup_incomplete");
  const calls = [];
  const operations = flowOperations(calls, {
    async cleanup() {
      calls.push("cleanup");
      throw new S10BO1OrchestratorError("orchestrator_cleanup_unknown");
    },
  });
  await assert.rejects(
    runStartupAbortFlow({ runId, repositories }, operations),
    (error) => errorCode(error) === "orchestrator_cleanup_unknown",
  );
  assert.deepEqual(calls.slice(-3), ["business_boundary", "cleanup", "no_log"]);

  const precedenceCalls = [];
  await assert.rejects(
    runStartupAbortFlow({ runId, repositories }, flowOperations(precedenceCalls, {
      async cleanup() {
        precedenceCalls.push("cleanup");
        throw new S10BO1OrchestratorError("orchestrator_cleanup_unknown");
      },
      async scanNoLog() {
        precedenceCalls.push("no_log");
        return noLogResult({ hit_count: 1 });
      },
    })),
    (error) => errorCode(error) === "orchestrator_cleanup_unknown",
  );

  const roles = ["api", "desktop", "fake", "host", "runtime"];
  const records = roles.map(processRecord);
  assert.equal(validateExistingProcessRecordSet(records), true);
  assert.throws(
    () => validateExistingProcessRecordSet(records.slice(0, -1)),
    (error) => errorCode(error) === "orchestrator_existing_evidence_incomplete",
  );
  assert.throws(
    () => validateExistingProcessRecordSet([...records.slice(0, -1), records.at(-2)]),
    (error) => errorCode(error) === "orchestrator_existing_evidence_incomplete",
  );
  assert.throws(
    () => validateExistingProcessRecordSet(records.map((value, index) => (
      index === records.length - 1 ? { ...value, pid: records[0].pid } : value
    ))),
    (error) => errorCode(error) === "orchestrator_existing_evidence_incomplete",
  );
  assert.throws(
    () => validateExistingProcessRecordSet(records.map((value) => (
      value.role === "host" ? { ...value, ppid: 999 } : value
    ))),
    (error) => errorCode(error) === "orchestrator_existing_evidence_incomplete",
  );
  assert.throws(
    () => validateExistingProcessRecordSet(records.map((value) => (
      value.role === "api" ? { ...value, ppid: 999 } : value
    ))),
    (error) => errorCode(error) === "orchestrator_existing_evidence_incomplete",
  );
  assert.throws(
    () => validateExistingProcessRecordSet(records.map((value) => (
      ["api", "desktop", "fake"].includes(value.role)
        ? { ...value, ppid: records.at(-1).pid }
        : value
    ))),
    (error) => errorCode(error) === "orchestrator_existing_evidence_incomplete",
  );
  assert.throws(
    () => validateExistingProcessRecordSet(records.map((value) => (
      value.role === "runtime" ? { ...value, binary_sha256: "invalid" } : value
    ))),
    (error) => errorCode(error) === "orchestrator_existing_evidence_incomplete",
  );

  const temporaryAlias = await mkdtemp(resolve(tmpdir(), "feat126-s10bo2-"));
  const runRoot = await realpath(temporaryAlias);
  t.after(async () => { await rm(runRoot, { recursive: true, force: true }); });
  await chmod(runRoot, 0o700);
  const evidenceRoot = resolve(runRoot, "orchestrator-evidence");
  await mkdir(evidenceRoot, { mode: 0o700 });
  await chmod(evidenceRoot, 0o700);
  for (const evidence of records) {
    const path = resolve(evidenceRoot, `${evidence.role}-process.v1.json`);
    await writeFile(path, `${JSON.stringify(evidence)}\n`, { flag: "wx", mode: 0o600 });
    await chmod(path, 0o600);
  }
  assert.equal((await loadExistingProcessRecords(runRoot, runId)).length, 5);
  await unlink(resolve(evidenceRoot, "runtime-process.v1.json"));
  await assert.rejects(
    loadExistingProcessRecords(runRoot, runId),
    (error) => errorCode(error) === "orchestrator_existing_evidence_incomplete",
  );
});

test("S10BO2-012 validates Host and Runtime evidence without Infra ownership", () => {
  assert.equal(validateOwnership({
    infra: { children: ["api", "fake", "desktop"] },
    desktop: { children: ["host"] },
    host: { children: ["runtime"] },
  }), true);
  assert.throws(() => validateOwnership({
    infra: { children: ["api", "fake", "desktop", "runtime"] },
    desktop: { children: ["host"] },
    host: { children: ["runtime"] },
  }), (error) => errorCode(error) === "orchestrator_ownership_invalid");
  assert.throws(() => validateOwnership({
    infra: { children: ["api", "fake", "desktop"], pid: 1 },
    desktop: { children: ["host"] },
    host: { children: ["runtime"] },
  }), (error) => errorCode(error) === "orchestrator_ownership_invalid");
  assert.throws(() => validateOwnership({
    infra: { children: ["api", "fake", "desktop"] },
    desktop: { children: ["host"] },
    host: { children: ["runtime"] },
    runtime: { children: [] },
  }), (error) => errorCode(error) === "orchestrator_manifest_invalid");

  const readyHost = hostEvidence();
  const hostAuthority = {
    runId,
    desktopPid: 101,
    binarySha256: "a".repeat(64),
    expectedState: "ready",
    expectedPid: 201,
    expectedNonce: nonce,
    expectedStartedAtUnixMs: 1000,
  };
  assert.deepEqual(validateHostProcessEvidence(readyHost, hostAuthority), readyHost);
  assert.equal(validateHostProcessEvidence(hostEvidence({
    state: "stopped",
    endedAtUnixMs: 2000,
  }), { ...hostAuthority, expectedState: "stopped" }).state, "stopped");
  for (const invalid of [
    { ppid: 999 },
    { binarySha256: "d".repeat(64) },
    { instanceNonce: "019fbd88-cbc3-4bf1-934d-7b05cd693f82" },
    { state: "starting" },
    { unexpected: true },
  ]) {
    assert.throws(
      () => validateHostProcessEvidence(hostEvidence(invalid), hostAuthority),
      (error) => errorCode(error) === "orchestrator_host_evidence_invalid",
    );
  }

  const readyRuntime = runtimeEvidence();
  const runtimeAuthority = {
    runId,
    hostPid: 201,
    binarySha256: "b".repeat(64),
    manifestSha256: "c".repeat(64),
    nonce,
    profile: "feat-126-s10-local-lab",
  };
  assert.deepEqual(validateRuntimeProcessEvidence(readyRuntime, runtimeAuthority), readyRuntime);
  for (const invalid of [
    { ppid: 999 },
    { binary_sha256: "d".repeat(64) },
    { manifest_sha256: "d".repeat(64) },
    { nonce: "019fbd88-cbc3-4bf1-934d-7b05cd693f82" },
    { profile: "other" },
    { unexpected: true },
  ]) {
    assert.throws(
      () => validateRuntimeProcessEvidence(runtimeEvidence(invalid), runtimeAuthority),
      (error) => errorCode(error) === "orchestrator_runtime_evidence_invalid",
    );
  }
});

test("S10BO2-013 no-log remains mandatory on success and failure", () => {
  assert.equal(validateNoLogResult(noLogResult()), true);
  assert.throws(() => validateNoLogResult(noLogResult({ hit_count: 1 })), (error) => errorCode(error) === "orchestrator_no_log_invalid");
  assert.throws(() => validateNoLogResult(noLogResult({ file_count: 0 })), (error) => errorCode(error) === "orchestrator_no_log_invalid");
  const project = "yijie-feat126-s10-019fbd88";
  assert.deepEqual(
    classifyProjectVolumes(project, [
      `${project}_feat126_s10_api_postgres_data`,
      `${project}_feat126_s10_keycloak_postgres_data`,
      `${project}_feat126_s10_caddy_data`,
      `${project}_feat126_s10_caddy_config`,
    ]),
    { namedVolumes: 4, temporaryVolumes: 0 },
  );
  assert.deepEqual(
    classifyProjectVolumes(project, [
      `${project}_feat126_s10_api_postgres_data`,
      `${project}_feat126_s10_keycloak_postgres_data`,
      `${project}_feat126_s10_caddy_data`,
      `${project}_temporary`,
    ]),
    { namedVolumes: 3, temporaryVolumes: 1 },
  );
  assert.throws(
    () => classifyProjectVolumes(project, [
      `${project}_feat126_s10_api_postgres_data`,
      `${project}_feat126_s10_api_postgres_data`,
    ]),
    (error) => errorCode(error) === "orchestrator_volume_inventory_invalid",
  );
});

test("S10BO2-013 scans all evidence roots and fails closed when a root is missing", async (t) => {
  const temporaryAlias = await mkdtemp(resolve(tmpdir(), "feat126-s10bo2-nolog-"));
  const runRoot = await realpath(temporaryAlias);
  t.after(async () => { await rm(runRoot, { recursive: true, force: true }); });
  await chmod(runRoot, 0o700);
  const logRoot = resolve(runRoot, "logs");
  const evidenceRoot = resolve(runRoot, "orchestrator-evidence");
  const preflightEvidenceRoot = resolve(runRoot, "preflight-evidence");
  const hostRoot = resolve(runRoot, "host");
  const hostInstance = resolve(hostRoot, nonce);
  const attemptPreclaim = resolve(runRoot, "preclaim.v1.json");
  const attemptMarker = resolve(runRoot, "attempt.v1.json");
  const runtimeLogScan = {
    schema_version: 1,
    status: "passed",
    run_id: runId,
    source_count: 4,
    row_count: 0,
    hit_count: 0,
    source_set_sha256: "e".repeat(64),
  };
  for (const directory of [logRoot, evidenceRoot, preflightEvidenceRoot, hostRoot, hostInstance]) {
    await mkdir(directory, { mode: 0o700 });
    await chmod(directory, 0o700);
  }
  for (const [path, value] of [
    [resolve(logRoot, "desktop.log"), ""],
    [resolve(evidenceRoot, "desktop.json"), '{"status":"ok"}\n'],
    [resolve(preflightEvidenceRoot, "summary.json"), '{"status":"ok"}\n'],
    [resolve(evidenceRoot, "runtime-log-scan.v1.json"), `${JSON.stringify(runtimeLogScan)}\n`],
    [resolve(hostInstance, "stdout.log"), ""],
    [attemptPreclaim, '{"status":"reserved"}\n'],
    [attemptMarker, '{"status":"claimed"}\n'],
  ]) {
    await writeFile(path, value, { mode: 0o600 });
    await chmod(path, 0o600);
  }
  const context = {
    runRoot,
    logRoot,
    evidenceRoot,
    preflightEvidenceRoot,
    attempt: { preclaimPath: attemptPreclaim, markerPath: attemptMarker },
    secrets: new Map([["credential", "secret-value-never-log"]]),
    runtimeLogScan,
  };
  const clean = await scanNoLog(context);
  assert.equal(clean.file_count, 7);
  assert.equal(clean.hit_count, 0);
  assert.equal(
    (await scanNoLog({
      ...context,
      secrets: new Map([["credential", "different-secret-value"]]),
    })).pattern_set_sha256,
    clean.pattern_set_sha256,
  );
  const processContext = {
    ...context,
    processes: {
      api: {
        record: processRecord("api", 0),
        logPath: resolve(logRoot, "desktop.log"),
      },
    },
  };
  await assert.rejects(
    scanNoLog(processContext),
    (error) => errorCode(error) === "orchestrator_no_log_invalid",
  );
  const apiEvidence = resolve(evidenceRoot, "api-process.v1.json");
  await writeFile(apiEvidence, `${JSON.stringify(processRecord("api", 0))}\n`, { mode: 0o600 });
  await chmod(apiEvidence, 0o600);
  assert.equal((await scanNoLog(processContext)).hit_count, 0);

  await unlink(attemptPreclaim);
  await assert.rejects(
    scanNoLog(context),
    (error) => errorCode(error) === "orchestrator_no_log_invalid",
  );
  await writeFile(attemptPreclaim, '{"status":"reserved"}\n', { mode: 0o600 });
  await chmod(attemptPreclaim, 0o600);

  const sensitive = resolve(evidenceRoot, "leak.json");
  await writeFile(
    sensitive,
    `{"authorization":"bEaReR token","tenant":"12500000-0000-4000-8000-100000000001",` +
      `"key":"private-key","path":"${runRoot}","value":"secret-value-never-log"}\n`,
    { mode: 0o600 },
  );
  await chmod(sensitive, 0o600);
  assert.equal((await scanNoLog(context)).hit_count > 0, true);

  const summaryPath = resolve(preflightEvidenceRoot, "summary.json");
  await unlink(summaryPath);
  await assert.rejects(
    scanNoLog(context),
    (error) => errorCode(error) === "orchestrator_no_log_invalid",
  );
  await writeFile(summaryPath, '{"status":"ok"}\n', { mode: 0o600 });
  await chmod(summaryPath, 0o600);
  await rm(logRoot, { recursive: true });
  await assert.rejects(
    scanNoLog(context),
    (error) => errorCode(error) === "orchestrator_no_log_invalid",
  );
});

test("S10BO2-014 source uses direct feature Desktop with FD3/FD4 and keeps business cases disabled", async () => {
  const source = await readFile("scripts/feat-126-s10b-orchestrator.mjs", "utf8");
  const preflightSource = await readFile("scripts/feat-126-s10b-preflight.mjs", "utf8");
  const plan = buildOrchestratorPlan({ runId, environment, arguments_: [] });
  assert.equal(plan.business_cases, "disabled");
  assert.equal(plan.states.includes("s10b_002"), false);
  assert.match(source, /cargo[\s\S]*--features[\s\S]*feat126-s10-driver/);
  assert.match(source, /extraStdio:\s*\["pipe", "pipe"\]/);
  assert.match(source, /child\.stdio\[3\]/);
  assert.match(source, /child\.stdio\[4\]/);
  assert.match(source, /\/healthz\/v2/);
  assert.match(source, /vite[\s\S]*--outDir[\s\S]*frontendDistRoot/);
  assert.match(source, /CARGO_TARGET_DIR/);
  assert.match(source, /TAURI_CONFIG/);
  assert.match(source, /\/usr\/bin\/vmmap/);
  assert.match(source, /Launch Time:/);
  assert.match(source, /createParentIdentityGuard/);
  assert.doesNotMatch(source, /feat-126-s10b-api-continuation/);
  assert.doesNotMatch(source, /spawnOwnedProcess\(\{[\s\S]{0,240}role:\s*"(?:host|runtime)"/);
  assert.match(preflightSource, /FIXED_PORTS[^\n]*18081/);
  assert.doesNotMatch(preflightSource, /FIXED_PORTS[^\n]*(?:1420|1421)/);
  const projected = desktopEnvironment({
    runId,
    nonce,
    runRoot: "/tmp/feat126-run",
    secretsPath: "/tmp/feat126-run/infra-secrets.env",
    binRoot: "/tmp/feat126-bin",
    caPath: "/tmp/feat126-ca.pem",
    caSha256: "a".repeat(64),
  });
  assert.equal(projected.YIJIE_FEAT126_S10_SECURE_STORAGE_ENABLED, "false");
  assert.equal(projected.YIJIE_FEAT126_S10_EPHEMERAL_SECRET_BACKEND_ENABLED, "true");
});
