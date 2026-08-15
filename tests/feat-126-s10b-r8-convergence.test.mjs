import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Readable } from "node:stream";
import test from "node:test";

import {
  S10BO1_CASES,
  S10BO1OrchestratorError,
  S10B_R8_FAKE_GENERATIONS,
  S10B_R8_FROZEN_CASE_IDS,
  buildR8BusinessEvidence,
  captureRuntimeLogScan,
  createR8ControlFrameReader,
  desktopProductionBuildFeatures,
  r8CaseAuthority,
  runR8Flow,
  scanOpaqueNoLogFile,
  validateR8CaseEvidence,
  validateR8DefaultOffEvidence,
  verifyR8DefaultOff,
} from "../scripts/feat-126-s10b-orchestrator.mjs";
import { FEAT_126_S10_API_RUNTIME_AUTHORITY } from "../scripts/feat-126-s10-api-runtime-profile.mjs";
import { verifyHostRuntimeArtifactOnly } from "../scripts/feat-126-s10b-preflight.mjs";

const runId = "fe71bb4a-92c4-4c84-99df-133ddb3427e4";
const repositories = Object.freeze({
  governance: "1".repeat(40),
  contracts: "2".repeat(40),
  api: "3".repeat(40),
  host: "4".repeat(40),
  desktop: "5".repeat(40),
  runtime: "6".repeat(40),
  infra: "7".repeat(40),
});
const lifecycleNonces = Object.freeze([
  "cf88eafe-21d9-4f31-8fa1-c76d0143fb8c",
  "4605ac6e-b1f1-44ea-9876-843eab3608b0",
]);
const hash = "a".repeat(64);
const completed = Object.freeze([
  "authority", "ports", "host_runtime_artifact", "secret_init", "compose", "images", "dependencies",
  "tls_oidc", "identity", "migration", "bootstrap", "api_binary", "host_binary",
  "fake_binary", "probe_binary", "api_health", "api_readiness",
  "host_owned_fake_authority", "fake_readiness", "content_free_logs",
]);

function preflightSummary(
  authorityRepositories = repositories,
  artifactGate = {
    schema_version: 1,
    status: "passed",
    verifier: "host-runtime-healthcheck-artifact-only",
    host_repository_sha: authorityRepositories.host,
    runtime_repository_sha: authorityRepositories.runtime,
    runtime_binary_sha256: "8".repeat(64),
    runtime_manifest_sha256: "9".repeat(64),
  },
) {
  return {
    schema_version: 1,
    status: "passed",
    scope: "S10B-001-combined-preflight",
    run_id: runId,
    repositories: authorityRepositories,
    api_binary_sha256: hash,
    host_runtime_artifact_gate: artifactGate,
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

function noLogResult(runtimeLogScan = null, opaqueScan = null) {
  return {
    schema_version: 1,
    scope: "run_artifacts",
    coverage: "all_run_log_and_evidence_sources",
    file_count: 1,
    row_count: (runtimeLogScan?.row_count ?? 0) + (opaqueScan?.rowCount ?? 0),
    hit_count: 0,
    external_source_count: 4,
    external_row_count: runtimeLogScan?.row_count ?? 0,
    external_source_set_sha256: runtimeLogScan?.source_set_sha256 ?? "c".repeat(64),
    pattern_set_sha256: "d".repeat(64),
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

function apiProjection({ tasks = 0, audit = 0, idempotency = 0 } = {}) {
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

function frame(value) {
  return `${JSON.stringify({ schema_version: 1, run_id: runId, ...value })}\n`;
}

function caseFrame(caseId, sequence, nonce) {
  const authority = r8CaseAuthority(caseId);
  return frame({
    nonce,
    sequence,
    kind: "case_result",
    case_id: caseId,
    status: "passed",
    assertion_count: authority.assertionCount,
    assertion_set_sha256: authority.assertionSetSha256,
  });
}

function lifecycleStream(lifecycle) {
  const nonce = lifecycleNonces[lifecycle - 1];
  const beforeRestart = lifecycle === 1;
  const cases = beforeRestart
    ? S10BO1_CASES.slice(0, 3)
    : S10BO1_CASES.slice(3, -1);
  const frames = [frame({ nonce, sequence: 1, kind: "component_ready" })];
  frames.push(...cases.map((caseId, index) => caseFrame(caseId, index + 2, nonce)));
  frames.push(frame({
    nonce,
    sequence: beforeRestart ? 5 : 9,
    kind: beforeRestart ? "planned_restart" : "abort_complete",
  }));
  return Readable.from(frames);
}

async function writeRehearsalRecord(root, basename, value) {
  assert.match(basename, /^rehearsal-[a-z0-9-]+\.v1\.json$/);
  const path = join(root, basename);
  const handle = await open(path, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify({
      schema_version: 1,
      kind: "feat126-r8-convergence-rehearsal",
      status: "rehearsed",
      non_authoritative: true,
      run_id: runId,
      value,
    })}\n`);
    await handle.chmod(0o600);
    await handle.sync();
  } finally {
    await handle.close();
  }
  assert.equal((await stat(path)).mode & 0o777, 0o600);
}

function runOffline(command, arguments_, options = {}) {
  const result = spawnSync(command, arguments_, {
    cwd: options.cwd,
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      TMPDIR: process.env.TMPDIR,
      GOPATH: process.env.GOPATH,
      GOMODCACHE: process.env.GOMODCACHE,
    },
    encoding: "utf8",
    shell: false,
    windowsHide: true,
    maxBuffer: 16 * 1024 * 1024,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, `${command} failed in offline convergence rehearsal`);
  return result.stdout.trim();
}

async function verifyPinnedRuntimeArtifact() {
  const hostRepositorySha = runOffline(
    "git",
    ["rev-parse", "HEAD"],
    { cwd: resolve("../yijie-agent-host") },
  );
  const runtimeRepositorySha = runOffline(
    "git",
    ["rev-parse", "HEAD"],
    { cwd: resolve("../yijie-codex") },
  );
  const artifactGate = await verifyHostRuntimeArtifactOnly({
    host: hostRepositorySha,
    runtime: runtimeRepositorySha,
  });
  return Object.freeze({
    artifactGate,
    authorityRepositories: Object.freeze({
      ...repositories,
      host: hostRepositorySha,
      runtime: runtimeRepositorySha,
    }),
  });
}

async function createRealBboltFixture(root) {
  const sourcePath = join(root, "create-bbolt.go");
  const databasePath = join(root, "sessions.db");
  await writeFile(sourcePath, `package main
import (
  "os"
  bolt "go.etcd.io/bbolt"
)
func main() {
  db, err := bolt.Open(os.Args[1], 0600, nil)
  if err != nil { panic("open failed") }
  if err := db.Update(func(tx *bolt.Tx) error {
    bucket, err := tx.CreateBucketIfNotExists([]byte("metadata"))
    if err != nil { return err }
    if err := bucket.Put([]byte("feat126_cwd_encoding"), []byte("opaque-project-v1")); err != nil { return err }
    return bucket.Put([]byte("feat126_run_id"), []byte("${runId}"))
  }); err != nil { panic("write failed") }
  if err := db.Close(); err != nil { panic("close failed") }
}
`, { mode: 0o600 });
  runOffline("go", ["run", sourcePath, databasePath], {
    cwd: resolve("../yijie-agent-host"),
  });
  await chmod(databasePath, 0o600);
  return databasePath;
}

async function captureOfflineRuntimeLogScan(runRoot) {
  const project = `yijie-feat126-s10-${runId.replaceAll("-", "")}`;
  const roles = [
    "feat126-s10-api-db",
    "feat126-s10-caddy",
    "feat126-s10-keycloak",
    "feat126-s10-keycloak-db",
  ];
  const sources = roles.map((serviceRole, index) => ({
    container_id: String(index + 1).repeat(12),
    project,
    feature: "FEAT-126",
    slice: "S10E",
    run_id: runId,
    data_classification: "synthetic-only",
    service_role: serviceRole,
  }));
  const logs = new Map(sources.map((source) => [
    source.container_id,
    Buffer.from(source.service_role === "feat126-s10-caddy"
      ? '{"level":"info","ts":1,"msg":"serving initial configuration"}\n'
      : "ready\n"),
  ]));
  return await captureRuntimeLogScan({
    composeLogsRequired: true,
    runId,
    runRoot,
    secrets: new Map(),
    runScopedSecretPatterns: [],
    noLogAuthorityCaptureFailed: false,
  }, {
    async list() { return sources; },
    async readLogs(containerId) { return logs.get(containerId); },
  });
}

async function createDefaultOffRepositories(root) {
  const paths = {};
  const shas = {};
  for (const role of ["api", "contracts", "desktop", "governance", "host", "infra", "runtime"]) {
    const repository = join(root, `repository-${role}`);
    await mkdir(repository, { mode: 0o700 });
    await chmod(repository, 0o700);
    await writeFile(
      join(repository, "package.json"),
      `${JSON.stringify({ name: `fixture-${role}`, private: true })}\n`,
      { mode: 0o600 },
    );
    runOffline("git", ["init", "--quiet"], { cwd: repository });
    runOffline("git", ["config", "user.name", "FEAT-126 Fixture"], { cwd: repository });
    runOffline("git", ["config", "user.email", "fixture@invalid"], { cwd: repository });
    runOffline("git", ["add", "package.json"], { cwd: repository });
    runOffline("git", ["commit", "--quiet", "-m", "fixture"], { cwd: repository });
    paths[role] = repository;
    shas[role] = runOffline("git", ["rev-parse", "HEAD"], { cwd: repository });
  }
  return Object.freeze({ paths: Object.freeze(paths), shas: Object.freeze(shas) });
}

test("R8 convergence rehearsal consumes canonical parsers and all frozen S10B-001-012 authority", async (t) => {
  const rehearsalRoot = await realpath(await mkdtemp(join(tmpdir(), "feat126-r8-rehearsal-")));
  await chmod(rehearsalRoot, 0o700);
  t.after(() => rm(rehearsalRoot, { recursive: true, force: true }));
  assert.equal(rehearsalRoot.startsWith(resolve("environments/local/generated/feat-126-s10")), false);
  assert.deepEqual(S10B_R8_FROZEN_CASE_IDS, [
    "s10b_001", "s10b_002", "s10b_003", "s10b_004", "s10b_005", "s10b_006",
    "s10b_007", "s10b_008", "s10b_009", "s10b_010", "s10b_011", "s10b_012",
  ]);
  assert.equal(desktopProductionBuildFeatures(), "feat126-s10-driver,tauri/custom-protocol");
  const { artifactGate, authorityRepositories } = await verifyPinnedRuntimeArtifact();
  const databasePath = await createRealBboltFixture(rehearsalRoot);
  const opaqueScan = await scanOpaqueNoLogFile(
    databasePath,
    [{ name: "absent-canary", value: "never-written-canary" }],
    [],
    true,
  );
  assert.deepEqual(opaqueScan, { present: true, rowCount: 1, hitCount: 0 });
  assert.equal((await scanOpaqueNoLogFile(
    databasePath,
    [{ name: "marker", value: "opaque-project-v1" }],
    [],
    true,
  )).hitCount, 1);
  const runtimeLogScan = await captureOfflineRuntimeLogScan(rehearsalRoot);
  assert.equal(runtimeLogScan.schema_version, 4);
  assert.equal(runtimeLogScan.status, "passed");
  assert.equal(runtimeLogScan.hit_count, 0);
  const actualNoLog = noLogResult(runtimeLogScan, opaqueScan);
  const defaultOffRepositories = await createDefaultOffRepositories(rehearsalRoot);
  const defaultOffAuthority = {
    runId,
    repositories: defaultOffRepositories.shas,
    r8: true,
  };
  const defaultOff = await verifyR8DefaultOff(defaultOffAuthority, cleanupResult(), {
    repositories: defaultOffRepositories.paths,
    environment: {},
  });
  assert.deepEqual(validateR8DefaultOffEvidence(defaultOff, defaultOffAuthority), defaultOff);
  assert.equal(defaultOff.tracked_config_count, 7);
  assert.notEqual(
    defaultOff.tracked_config_set_sha256,
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  );

  const readers = new Map();
  const caseEvidence = [];
  const fakeAuthorities = S10B_R8_FAKE_GENERATIONS.map(fakeAuthority);
  const closures = [];
  const operations = {
    async runPreflight() {
      await writeRehearsalRecord(rehearsalRoot, "rehearsal-s10b-001.v1.json", {
        production_artifacts: true,
      });
      return preflightSummary(authorityRepositories, artifactGate);
    },
    async buildDesktop() {},
    async startDependencies() {},
    async startApi() {},
    async startFakeGeneration() {},
    async startDesktopLifecycle(lifecycle) {
      readers.set(lifecycle, createR8ControlFrameReader(lifecycleStream(lifecycle), {
        runId,
        nonce: lifecycleNonces[lifecycle - 1],
      }));
      const ready = await readers.get(lifecycle).next("component_ready");
      assert.equal(ready.sequence, 1);
    },
    async readLifecycleOwnership() {},
    async executeCase(caseId) {
      const lifecycle = caseEvidence.length < 3 ? 1 : 2;
      const result = await readers.get(lifecycle).next("case_result", caseId);
      const evidence = validateR8CaseEvidence({
        schema_version: 1,
        status: "passed",
        run_id: runId,
        ordinal: caseEvidence.length + 1,
        case_id: caseId,
        frame_sequence: result.sequence,
        assertion_count: result.assertion_count,
        assertion_set_sha256: result.assertion_set_sha256,
      }, { runId });
      caseEvidence.push(evidence);
      await writeRehearsalRecord(
        rehearsalRoot,
        `rehearsal-${caseId.replaceAll("_", "-")}.v1.json`,
        { ordinal: evidence.ordinal, assertion_set_sha256: evidence.assertion_set_sha256 },
      );
    },
    async scanNoLogCheckpoint() { return actualNoLog; },
    async completePlannedRestart() {
      assert.equal((await readers.get(1).next("planned_restart")).sequence, 5);
      assert.equal(await readers.get(1).expectEof(), true);
    },
    async completeAbort() {
      assert.equal((await readers.get(2).next("abort_complete")).sequence, 9);
      assert.equal(await readers.get(2).expectEof(), true);
    },
    async captureNoLogAuthority() {},
    async initiateDesktopAbort() {},
    async verifyR8Business() {
      return buildR8BusinessEvidence(
        apiProjection(),
        apiProjection({ tasks: 2, audit: 2, idempotency: 2 }),
        fakeAuthorities,
        caseEvidence,
        runId,
      );
    },
    async cleanup() {
      await writeRehearsalRecord(rehearsalRoot, "rehearsal-s10b-012.v1.json", {
        cleanup: "passed",
        default_off_set_sha256: defaultOff.tracked_config_set_sha256,
      });
      return cleanupResult();
    },
    async scanNoLog() { return actualNoLog; },
    async recordFailure(value) { assert.fail(`unexpected rehearsal failure: ${value.failureClass}`); },
    async recordClosure(value) { closures.push(value); },
  };

  const result = await runR8Flow({ runId, repositories: authorityRepositories, r8: true }, operations);
  assert.equal(result.status, "passed");
  assert.equal(result.state, "closed_pass");
  assert.equal(caseEvidence.length, 10);
  assert.deepEqual(closures.map(({ status }) => status), ["passed"]);
  const entries = (await readdir(rehearsalRoot))
    .filter((name) => /^rehearsal-[a-z0-9-]+\.v1\.json$/.test(name))
    .sort();
  assert.equal(entries.length, 12);
  for (const name of entries) {
    const record = JSON.parse(await readFile(join(rehearsalRoot, name), "utf8"));
    assert.equal(record.kind, "feat126-r8-convergence-rehearsal");
    assert.equal(record.status, "rehearsed");
    assert.equal(record.non_authoritative, true);
    assert.notEqual(record.status, "passed");
  }
});

function failureMatrixOperations(failurePoint, calls) {
  const fail = (code) => { throw new S10BO1OrchestratorError(code); };
  return {
    async runPreflight() { calls.push("preflight"); return preflightSummary(); },
    async buildDesktop() { calls.push("build"); },
    async startDependencies() { calls.push("dependencies"); },
    async startApi() { calls.push("api"); },
    async startFakeGeneration(specification) { calls.push(`fake:${specification.generation}`); },
    async startDesktopLifecycle(lifecycle) {
      calls.push(`desktop:${lifecycle}`);
      if (failurePoint === "lifecycle_2_start" && lifecycle === 2) {
        fail("orchestrator_control_eof");
      }
    },
    async readLifecycleOwnership(lifecycle) {
      calls.push(`ownership:${lifecycle}`);
      if (failurePoint === "lifecycle_2_ownership" && lifecycle === 2) {
        fail("orchestrator_ownership_invalid");
      }
    },
    async executeCase(caseId) { calls.push(`case:${caseId}`); },
    async scanNoLogCheckpoint(caseId) {
      calls.push(`checkpoint:${caseId}`);
      if (failurePoint === "case_no_log" && caseId === "s10b_006") {
        return { ...noLogResult(), hit_count: 1 };
      }
      return noLogResult();
    },
    async completePlannedRestart() { calls.push("planned_restart"); },
    async completeAbort() { calls.push("abort_complete"); },
    async captureNoLogAuthority() { calls.push("capture_no_log_authority"); },
    async initiateDesktopAbort() { calls.push("desktop_abort"); },
    async verifyR8Business() {
      calls.push("business");
      assert.fail("failure matrix must not reach business verification");
    },
    async cleanup() { calls.push("cleanup"); return cleanupResult(); },
    async scanNoLog() { calls.push("final_no_log"); return noLogResult(); },
    async recordFailure(value) { calls.push(`failure:${value.failureClass}`); },
    async recordClosure(value) { calls.push(`closure:${value.status}:${value.failureClass}`); },
  };
}

test("R8 convergence rehearsal injects the pre-ownership and scanner failure matrix once", async () => {
  const matrix = [
    ["lifecycle_2_start", "orchestrator_control_eof", "desktop:2"],
    ["lifecycle_2_ownership", "orchestrator_ownership_invalid", "ownership:2"],
    ["case_no_log", "orchestrator_no_log_invalid", "checkpoint:s10b_006"],
  ];
  for (const [failurePoint, expectedCode, injectedCall] of matrix) {
    const calls = [];
    await assert.rejects(
      runR8Flow(
        { runId, repositories, r8: true },
        failureMatrixOperations(failurePoint, calls),
      ),
      (error) => error?.code === expectedCode,
    );
    assert.equal(calls.filter((call) => call === injectedCall).length, 1);
    assert.equal(calls.filter((call) => call === "cleanup").length, 1);
    assert.equal(calls.filter((call) => call === "desktop_abort").length, 1);
    assert.equal(calls.filter((call) => call.startsWith("failure:")).length, 1);
    assert.equal(calls.filter((call) => call.startsWith("closure:failed:")).length, 1);
    assert.equal(calls.includes("business"), false);
    assert.equal(calls.includes("abort_complete"), false);
  }
});
