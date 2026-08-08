import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, lstat, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import {
  S10BPreflightError,
  buildPrevalidatedDependencyArguments,
  runClosedImageResolver,
  validateResolverProtocolExports,
  validateImageResolverProcessResult,
  writeImageResolverEvidence,
} from "../scripts/feat-126-s10b-preflight.mjs";
import {
  CLOSED_RESOLVER_RESULT_MAX_BYTES,
  ClosedResolverResultError,
  DOCKER_FAILURE_CLASSES,
  DockerPreflightError,
  buildResolverProbeArgs,
  closedResolverFailure,
  closedResolverSuccess,
  mapClosedResolverFailure,
  parsePinnedImage,
  parseClosedResolverResult,
  runResolverProbe,
  validateClosedResolverResult,
} from "../scripts/verify-feat-126-s10-images.mjs";

const RUN_ID = "12600000-0000-4000-8000-000000000061";
const OTHER_RUN_ID = "12600000-0000-4000-8000-000000000062";

function successEnvelope(overrides = {}) {
  return {
    schema_version: 1,
    status: "passed",
    run_id: RUN_ID,
    image_count: 3,
    probe_count: 3,
    ...overrides,
  };
}

function failureContext(failureClass) {
  if (failureClass === "docker_cli_unavailable") {
    return { phase: "capability", target: "docker", cleanup_state: "not_applicable" };
  }
  if (
    failureClass === "docker_permission_denied" ||
    failureClass === "docker_daemon_unavailable"
  ) {
    return { phase: "probe_create", target: "caddy", cleanup_state: "unknown" };
  }
  if (failureClass === "image_not_found" || failureClass === "image_reference_unresolved") {
    return { phase: "identity_inspect", target: "postgres", cleanup_state: "not_applicable" };
  }
  if (failureClass === "image_identity_invalid") {
    return { phase: "identity_stability", target: "keycloak", cleanup_state: "not_applicable" };
  }
  if (
    failureClass === "image_repository_mismatch" ||
    failureClass === "image_digest_mismatch" ||
    failureClass === "image_platform_mismatch"
  ) {
    return { phase: "identity_validate", target: "caddy", cleanup_state: "not_applicable" };
  }
  if (failureClass === "inspect_payload_invalid") {
    return { phase: "probe_validate", target: "keycloak", cleanup_state: "unknown" };
  }
  if (failureClass === "resolver_probe_cleanup_incomplete") {
    return { phase: "probe_cleanup", target: "postgres", cleanup_state: "incomplete" };
  }
  return { phase: "probe_reconcile", target: "caddy", cleanup_state: "removed" };
}

function failureEnvelope(failureClass, overrides = {}) {
  return {
    schema_version: 1,
    status: "failed",
    run_id: RUN_ID,
    failure_class: failureClass,
    ...failureContext(failureClass),
    ...overrides,
  };
}

function processResult(envelope, status = envelope.status === "passed" ? 0 : 1) {
  return {
    status,
    signal: null,
    error: undefined,
    stdout: Buffer.from(JSON.stringify(envelope) + "\n", "utf8"),
    stderr: Buffer.alloc(0),
  };
}

function resultCodeIs(code) {
  return (error) => error instanceof ClosedResolverResultError && error.code === code;
}

function preflightCodeIs(code) {
  return (error) => error instanceof S10BPreflightError && error.code === code;
}

test("S10BEP1-001 produces and accepts only the exact closed success", () => {
  assert.deepEqual(closedResolverSuccess(RUN_ID, { imageCount: 3, probeCount: 3 }), successEnvelope());
  assert.deepEqual(
    parseClosedResolverResult(Buffer.from(JSON.stringify(successEnvelope()) + "\n"), RUN_ID),
    successEnvelope(),
  );
  for (const invalid of [
    successEnvelope({ image_count: 2 }),
    successEnvelope({ probe_count: 2 }),
    successEnvelope({ run_id: OTHER_RUN_ID }),
    { ...successEnvelope(), extra: true },
  ]) {
    assert.throws(() => validateClosedResolverResult(invalid, RUN_ID), resultCodeIs("result_invalid"));
  }
});

test("S10BEP1-002 maps every Docker leaf through one validated failure envelope", () => {
  assert.equal(DOCKER_FAILURE_CLASSES.length, 12);
  for (const failureClass of DOCKER_FAILURE_CLASSES) {
    const envelope = closedResolverFailure(
      RUN_ID,
      new DockerPreflightError(failureClass, failureContext(failureClass)),
    );
    assert.deepEqual(validateClosedResolverResult(envelope, RUN_ID), failureEnvelope(failureClass));
    assert.equal(
      mapClosedResolverFailure(failureClass),
      "preflight_image_resolver_" + failureClass,
    );
    const outcome = validateImageResolverProcessResult(processResult(envelope), RUN_ID);
    assert.equal(outcome.failureClass, "preflight_image_resolver_" + failureClass);
  }
  const unknown = closedResolverFailure(RUN_ID, new Error("secret /private/docker.sock"));
  assert.equal(unknown.failure_class, "resolver_probe_failed");
  assert.equal(JSON.stringify(unknown).includes("secret"), false);
  assert.doesNotThrow(() => validateClosedResolverResult(unknown, RUN_ID));
});

test("S10BEP1-003a rejects invalid phase, target, and cleanup combinations", () => {
  for (const invalid of [
    failureEnvelope("image_not_found", { phase: "probe_create" }),
    failureEnvelope("image_digest_mismatch", { target: "unknown" }),
    failureEnvelope("resolver_probe_cleanup_incomplete", { cleanup_state: "removed" }),
    failureEnvelope("resolver_probe_failed", { phase: "probe_cleanup" }),
    failureEnvelope("docker_cli_unavailable", {
      phase: "capability",
      target: "caddy",
      cleanup_state: "removed",
    }),
    failureEnvelope("resolver_probe_failed", {
      phase: "probe_create",
      cleanup_state: "not_applicable",
    }),
    failureEnvelope("image_platform_mismatch", { phase: "identity_inspect" }),
  ]) {
    assert.throws(() => validateClosedResolverResult(invalid, RUN_ID), resultCodeIs("result_invalid"));
  }
});

test("S10BEP1-003b uses a legal identity_validate fallback for platform mismatch", () => {
  assert.deepEqual(
    closedResolverFailure(RUN_ID, new DockerPreflightError("image_platform_mismatch")),
    failureEnvelope("image_platform_mismatch", {
      target: "docker",
    }),
  );
});

test("S10BEP1-004 rejects missing, extra, unknown, and cross-run fields", () => {
  const missing = failureEnvelope("image_not_found");
  delete missing.target;
  for (const invalid of [
    missing,
    { ...failureEnvelope("image_not_found"), raw_stderr: "forbidden" },
    failureEnvelope("image_not_found", { failure_class: "unknown" }),
    failureEnvelope("image_not_found", { run_id: OTHER_RUN_ID }),
    failureEnvelope("image_not_found", { status: "passed" }),
    failureEnvelope("image_not_found", { schema_version: 2 }),
  ]) {
    assert.throws(() => validateClosedResolverResult(invalid, RUN_ID), resultCodeIs("result_invalid"));
  }
});

test("S10BEP1-005 enforces UTF-8, single-line framing, and the 2048-byte cap", () => {
  for (const invalid of [
    Buffer.alloc(0),
    Buffer.from("\0"),
    Buffer.from("{}\r\n"),
    Buffer.from("{}\n{}\n"),
    Buffer.from("not-json\n"),
    Buffer.from([0xff]),
    Buffer.from(JSON.stringify(successEnvelope()), "utf8"),
    Buffer.from(
      '{"schema_version":1,"schema_version":1,"status":"passed","run_id":"' +
        RUN_ID +
        '","image_count":3,"probe_count":3}\n',
    ),
  ]) {
    assert.throws(() => parseClosedResolverResult(invalid, RUN_ID), resultCodeIs("result_invalid"));
  }
  assert.throws(
    () => parseClosedResolverResult(Buffer.alloc(CLOSED_RESOLVER_RESULT_MAX_BYTES + 1), RUN_ID),
    resultCodeIs("result_oversize"),
  );
});

test("S10BEP1-003c preserves a validation leaf after successful probe cleanup", () => {
  const image = parsePinnedImage(
    "example.test/yijie/image:1.0.0@sha256:" + "a".repeat(64),
  );
  const probe = buildResolverProbeArgs({ image, runId: RUN_ID, ordinal: 0, volumes: [] });
  const containerId = "c".repeat(64);
  const ownedContainer = {
    Id: containerId,
    Name: "/" + probe.name,
    Config: { Image: image.reference, Labels: probe.labels },
    State: { Running: false },
  };
  let call = 0;
  const runDocker = () => {
    call += 1;
    if (call === 1 || call === 6) {
      return { status: 1, signal: null, error: undefined, stdout: "", stderr: "no such container" };
    }
    if (call === 2) {
      return { status: 0, signal: null, error: undefined, stdout: containerId, stderr: "" };
    }
    if (call === 3) {
      return { status: 0, signal: null, error: undefined, stdout: "not-json", stderr: "" };
    }
    if (call === 4) {
      return {
        status: 0,
        signal: null,
        error: undefined,
        stdout: JSON.stringify(ownedContainer),
        stderr: "",
      };
    }
    return { status: 0, signal: null, error: undefined, stdout: "", stderr: "" };
  };

  let producerError;
  assert.throws(
    () => runResolverProbe({ image, identity: { volumes: [] }, runId: RUN_ID, ordinal: 0, runDocker }),
    (error) => {
      producerError = error;
      return (
        error instanceof DockerPreflightError &&
        error.code === "inspect_payload_invalid" &&
        error.resolverContext.phase === "probe_validate" &&
        error.resolverContext.target === "docker" &&
        error.resolverContext.cleanup_state === "removed"
      );
    },
  );
  assert.deepEqual(
    closedResolverFailure(RUN_ID, producerError),
    failureEnvelope("inspect_payload_invalid", {
      phase: "probe_validate",
      target: "docker",
      cleanup_state: "removed",
    }),
  );
});

test("S10BEP1-011 maps an opaque cleanup inspect failure to the cleanup leaf", () => {
  const image = parsePinnedImage(
    "example.test/yijie/image:1.0.0@sha256:" + "a".repeat(64),
  );
  const probe = buildResolverProbeArgs({ image, runId: RUN_ID, ordinal: 0, volumes: [] });
  const containerId = "c".repeat(64);
  let call = 0;
  const runDocker = () => {
    call += 1;
    if (call === 1) {
      return { status: 1, signal: null, error: undefined, stdout: "", stderr: "no such container" };
    }
    if (call === 2) {
      return { status: 1, signal: null, error: undefined, stdout: "", stderr: "create failed" };
    }
    if (call === 3) {
      return {
        status: 0,
        signal: null,
        error: undefined,
        stdout: JSON.stringify({
          Id: containerId,
          Name: "/" + probe.name,
          Config: { Image: image.reference, Labels: probe.labels },
          State: { Running: false },
        }),
        stderr: "",
      };
    }
    return {
      status: 1,
      signal: null,
      error: undefined,
      stdout: "",
      stderr: "opaque cleanup failure",
    };
  };

  assert.throws(
    () => runResolverProbe({ image, identity: { volumes: [] }, runId: RUN_ID, ordinal: 0, runDocker }),
    (error) =>
      error instanceof DockerPreflightError &&
      error.code === "resolver_probe_cleanup_incomplete" &&
      error.resolverContext.phase === "probe_cleanup" &&
      error.resolverContext.cleanup_state === "incomplete",
  );
});

test("S10BEP1-006 requires exact exit, signal, and stderr relations", () => {
  assert.throws(
    () => validateImageResolverProcessResult(processResult(successEnvelope(), 1), RUN_ID),
    preflightCodeIs("preflight_image_resolver_process_failed"),
  );
  assert.throws(
    () =>
      validateImageResolverProcessResult(
        processResult(failureEnvelope("image_not_found"), 0),
        RUN_ID,
      ),
    preflightCodeIs("preflight_image_resolver_process_failed"),
  );
  for (const result of [
    { ...processResult(successEnvelope()), signal: "SIGTERM", status: null },
    { ...processResult(successEnvelope()), error: Object.assign(new Error("spawn"), { code: "ENOENT" }) },
  ]) {
    assert.throws(
      () => validateImageResolverProcessResult(result, RUN_ID),
      preflightCodeIs(
        result.stderr?.length
          ? "preflight_image_resolver_result_invalid"
          : "preflight_image_resolver_process_failed",
      ),
    );
  }
  assert.throws(
    () => validateImageResolverProcessResult(
      { ...processResult(successEnvelope()), stderr: Buffer.from("raw child error") },
      RUN_ID,
    ),
    preflightCodeIs("preflight_image_resolver_result_invalid"),
  );
  assert.throws(
    () =>
      validateImageResolverProcessResult(
        { ...processResult(successEnvelope()), stdout: Buffer.from("human output\n") },
        RUN_ID,
      ),
    preflightCodeIs("preflight_image_resolver_result_invalid"),
  );
});

test("S10BEP1-007 separates timeout and buffer overflow without retry", () => {
  assert.throws(
    () =>
      validateImageResolverProcessResult(
        { ...processResult(successEnvelope()), error: Object.assign(new Error("timeout"), { code: "ETIMEDOUT" }) },
        RUN_ID,
      ),
    preflightCodeIs("preflight_image_resolver_timeout"),
  );
  assert.throws(
    () =>
      validateImageResolverProcessResult(
        { ...processResult(successEnvelope()), error: Object.assign(new Error("buffer"), { code: "ENOBUFS" }) },
        RUN_ID,
      ),
    preflightCodeIs("preflight_image_resolver_result_oversize"),
  );
});

test("S10BEP1-008 writes create-new owner-only evidence and never overwrites", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "yijie-s10bep1-evidence-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, "image-resolver-result.v1.json");
  await writeImageResolverEvidence(path, successEnvelope());
  const metadata = await lstat(path);
  assert.equal(metadata.isFile(), true);
  assert.equal(metadata.mode & 0o777, 0o600);
  assert.equal(await readFile(path, "utf8"), JSON.stringify(successEnvelope()) + "\n");
  await assert.rejects(
    () => writeImageResolverEvidence(path, failureEnvelope("image_not_found")),
    preflightCodeIs("preflight_image_resolver_evidence_failed"),
  );
  assert.equal(await readFile(path, "utf8"), JSON.stringify(successEnvelope()) + "\n");

  const target = join(root, "target");
  const link = join(root, "link");
  await writeFile(target, "unchanged", { mode: 0o600 });
  await symlink(target, link);
  await assert.rejects(
    () => writeImageResolverEvidence(link, successEnvelope()),
    preflightCodeIs("preflight_image_resolver_evidence_failed"),
  );
  assert.equal(await readFile(target, "utf8"), "unchanged");

  const wrongMode = join(root, "wrong-mode");
  await writeFile(wrongMode, "unchanged", { mode: 0o600 });
  await chmod(wrongMode, 0o644);
  await assert.rejects(
    () => writeImageResolverEvidence(wrongMode, successEnvelope()),
    preflightCodeIs("preflight_image_resolver_evidence_failed"),
  );
  assert.equal(await readFile(wrongMode, "utf8"), "unchanged");
});

test("S10BEP1-009 parent writes a validated envelope before surfacing a leaf", async () => {
  const envelope = failureEnvelope("image_digest_mismatch");
  const writes = [];
  await assert.rejects(
    () =>
      runClosedImageResolver(RUN_ID, "/fixed/evidence", {
        spawnResolver: () => processResult(envelope),
        writeEvidence: async (path, value) => writes.push({ path, value }),
      }),
    preflightCodeIs("preflight_image_resolver_image_digest_mismatch"),
  );
  assert.equal(writes.length, 1);
  assert.equal(writes[0].path, "/fixed/evidence/image-resolver-result.v1.json");
  assert.deepEqual(writes[0].value, envelope);
});

test("S10BEP1-010 parent uses fixed closed-mode invocation and accepts new/new success", async () => {
  let calls = 0;
  let written;
  const envelope = await runClosedImageResolver(RUN_ID, "/fixed/evidence", {
    spawnResolver: (command, args, options) => {
      calls += 1;
      assert.equal(command, process.execPath);
      assert.equal(args[0], resolve("scripts/verify-feat-126-s10-images.mjs"));
      assert.deepEqual(args.slice(1), ["--closed-result-v1", RUN_ID]);
      assert.equal(options.timeout, 120_000);
      assert.equal(options.maxBuffer, 4096);
      assert.deepEqual(options.stdio, ["ignore", "pipe", "pipe"]);
      return processResult(successEnvelope());
    },
    writeEvidence: async (path, value) => {
      written = { path, value };
    },
  });
  assert.equal(calls, 1);
  assert.deepEqual(envelope, successEnvelope());
  assert.equal(written.path, "/fixed/evidence/image-resolver-result.v1.json");
});

test("S10BEP1-012 closed child emits no stderr and no raw diagnostic", () => {
  const script = resolve("scripts/verify-feat-126-s10-images.mjs");
  const result = spawnSync(
    process.execPath,
    [script, "--closed-result-v1", RUN_ID],
    {
      cwd: resolve("."),
      env: { PATH: "/definitely/missing" },
      encoding: null,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  assert.equal(result.status, 1);
  assert.equal(result.stderr.length, 0);
  const envelope = parseClosedResolverResult(result.stdout, RUN_ID);
  assert.equal(envelope.status, "failed");
  assert.equal(envelope.failure_class, "docker_cli_unavailable");
  assert.equal(JSON.stringify(envelope).includes("/definitely/missing"), false);
});

test("S10BEP1-013 preserves the default human CLI and fixed parent authority", async () => {
  const [resolver, preflight, makefile, compose] = await Promise.all([
    readFile("scripts/verify-feat-126-s10-images.mjs", "utf8"),
    readFile("scripts/feat-126-s10b-preflight.mjs", "utf8"),
    readFile("Makefile", "utf8"),
    readFile("scripts/feat-126-s10-compose.sh", "utf8"),
  ]);
  assert.match(resolver, /process\.argv\[2\] === "--closed-result-v1"/);
  assert.match(resolver, /no-start resolver probes/);
  assert.match(makefile, /node scripts\/verify-feat-126-s10-images\.mjs "\$\(RUN_ID\)"/);
  assert.match(compose, /verify-feat-126-s10-images\.mjs" "\$run_id"/);
  assert.match(preflight, /process\.execPath/);
  assert.match(preflight, /import \* as resolverProtocol/);
  assert.match(preflight, /validateResolverProtocolExports/);
  assert.match(preflight, /"--closed-result-v1"/);
  assert.match(preflight, /startPrevalidatedDependencies\(runId, secretsPath\)/);
  assert.match(preflight, /image-resolver-result\.v1\.json/);
  const closedResolverIndex = preflight.indexOf(
    "await runClosedImageResolver(runId, evidenceRoot);",
  );
  const configRecheckIndex = preflight.indexOf(
    'runCommand("dependencies", "make", [\n      "feat-126-s10-config"',
  );
  const fixedStartIndex = preflight.indexOf(
    "startPrevalidatedDependencies(runId, secretsPath);",
  );
  assert.ok(closedResolverIndex >= 0);
  assert.ok(configRecheckIndex > closedResolverIndex);
  assert.ok(fixedStartIndex > configRecheckIndex);
  assert.doesNotMatch(preflight, /compose_config_recheck/);
  assert.doesNotMatch(preflight, /process\.env.*(?:RESOLVER|RESULT|PHASE|TARGET|CLEANUP)/);
  assert.doesNotMatch(makefile, /up-prevalidated/);
  assert.doesNotMatch(compose, /up-prevalidated/);
  assert.throws(
    () => validateResolverProtocolExports({}),
    preflightCodeIs("preflight_image_resolver_result_invalid"),
  );
  assert.throws(
    () => buildPrevalidatedDependencyArguments(RUN_ID, "/operator/override.env"),
    preflightCodeIs("preflight_dependencies_authority_invalid"),
  );
});
