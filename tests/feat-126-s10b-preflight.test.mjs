import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  S10BPreflightError,
  readExpectedSHAs,
  validateProbeResult,
} from "../scripts/feat-126-s10b-preflight.mjs";

const RUN_ID = "12600000-0000-4000-8000-000000000057";
const DATASET_SHA = "a".repeat(64);

function validProbe(overrides = {}) {
  return {
    schema_version: 1,
    status: "ready",
    run_id: RUN_ID,
    dataset_id: "synthetic-dataset-v1",
    fixture_case_id: "case-001",
    dataset_sha256: DATASET_SHA,
    ...overrides,
  };
}

function codeIs(code) {
  return (error) => error instanceof S10BPreflightError && error.code === code;
}

test("S10BF1-001 accepts only the closed Host-owned readiness projection", () => {
  assert.deepEqual(validateProbeResult(validProbe(), RUN_ID), validProbe());
  assert.throws(
    () => validateProbeResult(validProbe({ fixture_case_id: "synthetic-dataset-v1" }), RUN_ID),
    codeIs("fake_readiness_authority_invalid"),
  );
  assert.throws(
    () => validateProbeResult({ ...validProbe(), fixture_id: "case-001" }, RUN_ID),
    codeIs("fake_readiness_authority_invalid"),
  );
  assert.throws(
    () => validateProbeResult(validProbe({ run_id: "12600000-0000-4000-8000-000000000058" }), RUN_ID),
    codeIs("fake_readiness_authority_invalid"),
  );
});

test("S10BF1-002 requires seven full immutable candidate SHAs", () => {
  const environment = {
    FEAT126_S10B_GOVERNANCE_SHA: "1".repeat(40),
    FEAT126_S10B_CONTRACTS_SHA: "2".repeat(40),
    FEAT126_S10B_API_SHA: "3".repeat(40),
    FEAT126_S10B_HOST_SHA: "4".repeat(40),
    FEAT126_S10B_DESKTOP_SHA: "5".repeat(40),
    FEAT126_S10B_RUNTIME_SHA: "6".repeat(40),
    FEAT126_S10B_INFRA_SHA: "7".repeat(40),
  };
  assert.equal(Object.keys(readExpectedSHAs(environment)).length, 7);
  assert.throws(
    () => readExpectedSHAs({ ...environment, FEAT126_S10B_HOST_SHA: "floating-branch" }),
    codeIs("preflight_authority_invalid"),
  );
});

test("S10BF1-003 exposes one runner and no operator dataset or fixture input", async () => {
  const [runner, makefile] = await Promise.all([
    readFile("scripts/feat-126-s10b-preflight.mjs", "utf8"),
    readFile("Makefile", "utf8"),
  ]);
  assert.match(makefile, /feat-126-s10b-preflight:/);
  assert.match(makefile, /node scripts\/feat-126-s10b-preflight\.mjs "\$\(RUN_ID\)"/);
  assert.doesNotMatch(makefile, /DATASET_ID|FIXTURE_CASE_ID|FIXTURE_ID/);
  assert.doesNotMatch(runner, /process\.env\[["'].*(?:DATASET|FIXTURE)/i);
  assert.doesNotMatch(runner, /process\.argv\[[^\]]+\].*(?:dataset|fixture)/i);
  assert.match(runner, /cmd\/feat126-fake-readiness/);
  assert.match(runner, /host_owned_fake_authority/);
  assert.match(runner, /s10b_r5_executed: false/);
});

test("S10BF1-004 combines accepted S10E, identity, migration, bootstrap, API and fake gates", async () => {
  const runner = await readFile("scripts/feat-126-s10b-preflight.mjs", "utf8");
  for (const gate of [
    "feat-126-s10-config",
    "feat-126-s10-verify-images",
    "feat-126-s10-up",
    "feat-126-s10-export-ca",
    "feat-126-s10-verify-runtime",
    "feat-126-s10-provision-users",
    "feat-126-s10-api-migrate",
    "feat-126-s10-api-bootstrap",
    "cmd/api-server",
    "cmd/feat126-fake-responses",
    "cmd/feat126-fake-readiness",
  ]) {
    assert.match(runner, new RegExp(gate.replaceAll("-", "\\-")));
  }
  assert.match(runner, /preflight_cleanup_incomplete/);
  assert.match(runner, /preflight_secret_leak_detected/);
  assert.doesNotMatch(runner, /docker (?:image )?pull|docker system prune|docker volume rm/);
});
