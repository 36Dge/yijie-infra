import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  chmod,
  mkdir,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import test from "node:test";

import { FEAT_126_S10_API_RUNTIME_AUTHORITY } from "../scripts/feat-126-s10-api-runtime-profile.mjs";

const INFRA_ROOT = resolve(".");
const GENERATED_ROOT = resolve("environments/local/generated/feat-126-s10");
const LAUNCHER = resolve("scripts/feat-126-s10b-api-continuation.mjs");
const DATASET_SHA = "a".repeat(64);
const COMPLETED = [
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
];
const SHA_ENV = Object.freeze({
  FEAT126_S10B_GOVERNANCE_SHA: "1".repeat(40),
  FEAT126_S10B_CONTRACTS_SHA: "2".repeat(40),
  FEAT126_S10B_API_SHA: "3".repeat(40),
  FEAT126_S10B_HOST_SHA: "4".repeat(40),
  FEAT126_S10B_DESKTOP_SHA: "5".repeat(40),
  FEAT126_S10B_RUNTIME_SHA: "6".repeat(40),
  FEAT126_S10B_INFRA_SHA: "7".repeat(40),
});
const REPOSITORIES = Object.freeze({
  governance: SHA_ENV.FEAT126_S10B_GOVERNANCE_SHA,
  contracts: SHA_ENV.FEAT126_S10B_CONTRACTS_SHA,
  api: SHA_ENV.FEAT126_S10B_API_SHA,
  host: SHA_ENV.FEAT126_S10B_HOST_SHA,
  desktop: SHA_ENV.FEAT126_S10B_DESKTOP_SHA,
  runtime: SHA_ENV.FEAT126_S10B_RUNTIME_SHA,
  infra: SHA_ENV.FEAT126_S10B_INFRA_SHA,
});

function shellQuote(value) {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function summaryFor(runId, apiBinarySha256, overrides = {}) {
  return {
    schema_version: 1,
    status: "passed",
    scope: "S10B-001-combined-preflight",
    run_id: runId,
    repositories: REPOSITORIES,
    api_binary_sha256: apiBinarySha256,
    api_runtime_authority: FEAT_126_S10_API_RUNTIME_AUTHORITY,
    fake_readiness: {
      schema_version: 1,
      status: "ready",
      run_id: runId,
      dataset_id: "feat126-title-raw-v1",
      fixture_case_id: "normal-000",
      dataset_sha256: DATASET_SHA,
    },
    completed: COMPLETED,
    cleanup: "passed",
    s10b_r5_executed: false,
    ...overrides,
  };
}

async function writeProtected(path, content, mode = 0o600) {
  await writeFile(path, content, { flag: "wx", mode });
  await chmod(path, mode);
}

async function createFixture({ summaryOverride } = {}) {
  const runId = randomUUID();
  const runRoot = join(GENERATED_ROOT, runId);
  const evidenceRoot = join(runRoot, "preflight-evidence");
  const binRoot = join(runRoot, "bin");
  const logRoot = join(runRoot, "logs");
  const harnessEvidence = join(runRoot, "harness-profile.json");
  for (const directory of [runRoot, evidenceRoot, binRoot, logRoot]) {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await chmod(directory, 0o700);
  }

  const secrets = [
    "FEAT126_S10_API_DB_PASSWORD",
    "FEAT126_S10_KEYCLOAK_DB_PASSWORD",
    "FEAT126_S10_KEYCLOAK_ADMIN_PASSWORD",
    "FEAT126_S10_SYNTHETIC_USER_A_PASSWORD",
    "FEAT126_S10_SYNTHETIC_USER_B_PASSWORD",
  ]
    .map((key, index) => `${key}=${String(index + 1).repeat(64)}`)
    .join("\n");
  await writeProtected(join(runRoot, "infra-secrets.env"), `${secrets}\n`);
  await writeProtected(
    join(runRoot, "caddy-root.crt"),
    "-----BEGIN CERTIFICATE-----\nsynthetic-test-only\n-----END CERTIFICATE-----\n",
  );
  const harness = [
    "#!/bin/sh",
    "umask 077",
    `printf '{"profile":"%s","environment":"%s","port":"%s"}\\n' "$YIJIE_API_SERVICE_PROFILE" "$YIJIE_ENV" "$YIJIE_API_PORT" > ${shellQuote(harnessEvidence)}`,
    "exit 17",
    "",
  ].join("\n");
  await writeProtected(join(binRoot, "yijie-api"), harness, 0o700);
  const apiBinarySha256 = createHash("sha256").update(harness).digest("hex");
  const summary = summaryFor(runId, apiBinarySha256, summaryOverride);
  await writeProtected(join(evidenceRoot, "summary.json"), `${JSON.stringify(summary)}\n`);

  return {
    runId,
    runRoot,
    summaryPath: join(evidenceRoot, "summary.json"),
    harnessEvidence,
    async cleanup() {
      await rm(runRoot, { recursive: true, force: true });
    },
  };
}

function invoke(runId, { arguments_: extraArguments = [], environment = {} } = {}) {
  return spawnSync(process.execPath, [LAUNCHER, runId, ...extraArguments], {
    cwd: INFRA_ROOT,
    env: { ...SHA_ENV, ...environment },
    encoding: "utf8",
    timeout: 10_000,
  });
}

function failureClass(result) {
  assert.equal(result.status, 1, result.stderr);
  return JSON.parse(result.stderr).failure_class;
}

test("closed continuation consumes summary authority and passes FEAT-126 profile to its foreground child", async () => {
  const fixture = await createFixture();
  try {
    const result = invoke(fixture.runId);
    assert.equal(result.status, 17, result.stderr);
    assert.deepEqual(JSON.parse(await readFile(fixture.harnessEvidence, "utf8")), {
      profile: "feat-126-s10-local-lab",
      environment: "nonproduction",
      port: "18080",
    });
    const log = await readFile(join(fixture.runRoot, "logs/api-continuation.log"), "utf8");
    assert.match(log, /api_continuation_started/);
    assert.match(log, /"exit_code":17/);
    assert.doesNotMatch(log, /postgres:|1111111111111111|YIJIE_API_POSTGRES_DSN/);
  } finally {
    await fixture.cleanup();
  }
});

test("continuation CLI rejects missing, malformed, extra, and profile override input", async () => {
  const missing = spawnSync(process.execPath, [LAUNCHER], {
    cwd: INFRA_ROOT,
    env: SHA_ENV,
    encoding: "utf8",
  });
  assert.equal(failureClass(missing), "continuation_arguments_invalid");
  assert.equal(failureClass(invoke("not-a-run-id")), "continuation_run_id_invalid");
  assert.equal(
    failureClass(invoke(randomUUID(), { arguments_: ["--profile=feat-125-local-lab"] })),
    "continuation_arguments_invalid",
  );

  const fixture = await createFixture();
  try {
    assert.equal(
      failureClass(
        invoke(fixture.runId, {
          environment: { YIJIE_API_SERVICE_PROFILE: "feat-125-local-lab" },
        }),
      ),
      "continuation_override_forbidden",
    );
  } finally {
    await fixture.cleanup();
  }
});

test("continuation rejects missing or stale run evidence and SHA mismatch", async () => {
  assert.equal(failureClass(invoke(randomUUID())), "continuation_artifact_invalid");

  const stale = await createFixture({ summaryOverride: { run_id: randomUUID() } });
  try {
    assert.equal(failureClass(invoke(stale.runId)), "continuation_preflight_summary_invalid");
  } finally {
    await stale.cleanup();
  }

  const mismatch = await createFixture();
  try {
    assert.equal(
      failureClass(
        invoke(mismatch.runId, {
          environment: { FEAT126_S10B_API_SHA: "8".repeat(40) },
        }),
      ),
      "continuation_preflight_summary_invalid",
    );
  } finally {
    await mismatch.cleanup();
  }
});

test("continuation rejects legacy or extended runtime authority", async () => {
  for (const authority of [
    { ...FEAT_126_S10_API_RUNTIME_AUTHORITY, service_profile: "feat-125-local-lab" },
    { ...FEAT_126_S10_API_RUNTIME_AUTHORITY, operator_override: true },
  ]) {
    const fixture = await createFixture({ summaryOverride: { api_runtime_authority: authority } });
    try {
      assert.equal(failureClass(invoke(fixture.runId)), "continuation_preflight_summary_invalid");
    } finally {
      await fixture.cleanup();
    }
  }
});

test("continuation rejects API binary replacement after preflight evidence", async () => {
  const fixture = await createFixture();
  try {
    await writeFile(
      join(fixture.runRoot, "bin/yijie-api"),
      "#!/bin/sh\nexit 0\n",
      { mode: 0o700 },
    );
    await chmod(join(fixture.runRoot, "bin/yijie-api"), 0o700);
    assert.equal(
      failureClass(invoke(fixture.runId)),
      "continuation_api_binary_digest_mismatch",
    );
  } finally {
    await fixture.cleanup();
  }
});

test("continuation rejects unsafe summary mode, symlink, and oversized evidence", async () => {
  const unsafeMode = await createFixture();
  try {
    await chmod(unsafeMode.summaryPath, 0o644);
    assert.equal(failureClass(invoke(unsafeMode.runId)), "continuation_artifact_invalid");
  } finally {
    await unsafeMode.cleanup();
  }

  const linked = await createFixture();
  try {
    const target = join(dirname(linked.summaryPath), "foreign-summary.json");
    const originalSummary = await readFile(linked.summaryPath);
    await writeProtected(target, originalSummary);
    await rm(linked.summaryPath);
    await symlink(target, linked.summaryPath);
    assert.equal(failureClass(invoke(linked.runId)), "continuation_artifact_invalid");
  } finally {
    await linked.cleanup();
  }

  const oversized = await createFixture();
  try {
    await rm(oversized.summaryPath);
    await writeProtected(oversized.summaryPath, "x".repeat(64 * 1024 + 1));
    assert.equal(failureClass(invoke(oversized.runId)), "continuation_artifact_invalid");
  } finally {
    await oversized.cleanup();
  }
});

test("continuation implementation requires summary reader and runtime builder", async () => {
  const [launcher, makefile] = await Promise.all([
    readFile("scripts/feat-126-s10b-api-continuation.mjs", "utf8"),
    readFile("Makefile", "utf8"),
  ]);
  assert.match(launcher, /readApiRuntimeAuthorityFromPreflightSummary/);
  assert.match(launcher, /buildApiRuntimeEnvironment\(\{[\s\S]*authority,/);
  assert.doesNotMatch(launcher, /feat-125-local-lab/);
  assert.match(makefile, /feat-126-s10b-api-continuation:/);
  assert.doesNotMatch(makefile, /PROFILE|ENDPOINT|DATABASE|API_BINARY/);
});
