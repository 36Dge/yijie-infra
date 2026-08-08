#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

import { FEAT_126_S10_IMAGES } from "./compose-model.mjs";
import YAML from "yaml";

const PIN_PATTERN = /^(?<repository>.+):(?<tag>[^/:@]+)@(?<digest>sha256:[a-f0-9]{64})$/;
const IMAGE_ID_PATTERN = /^sha256:[a-f0-9]{64}$/;
const CONTAINER_ID_PATTERN = /^[a-f0-9]{64}$/;
const RUN_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_OUTPUT_BYTES = 1024 * 1024;
export const CLOSED_RESOLVER_RESULT_SCHEMA_VERSION = 1;
export const CLOSED_RESOLVER_RESULT_MAX_BYTES = 2048;
export const CLOSED_RESOLVER_SPAWN_BUFFER_BYTES = 4096;
export const CLOSED_RESOLVER_TIMEOUT_MS = 120_000;

export const RESOLVER_PHASES = Object.freeze([
  "capability",
  "identity_parse",
  "identity_inspect",
  "identity_validate",
  "identity_stability",
  "probe_precheck",
  "probe_create",
  "probe_reconcile",
  "probe_validate",
  "probe_cleanup",
]);

export const RESOLVER_TARGETS = Object.freeze([
  "docker",
  "postgres",
  "keycloak",
  "caddy",
]);

export const RESOLVER_CLEANUP_STATES = Object.freeze([
  "not_applicable",
  "absent",
  "removed",
  "incomplete",
  "unknown",
]);

export const DOCKER_FAILURE_CLASSES = Object.freeze([
  "docker_cli_unavailable",
  "docker_permission_denied",
  "docker_daemon_unavailable",
  "image_not_found",
  "image_reference_unresolved",
  "image_identity_invalid",
  "image_repository_mismatch",
  "image_digest_mismatch",
  "image_platform_mismatch",
  "inspect_payload_invalid",
  "resolver_probe_failed",
  "resolver_probe_cleanup_incomplete",
]);

const FAILURE_CLASS_SET = new Set(DOCKER_FAILURE_CLASSES);
const RESOLVER_PHASE_SET = new Set(RESOLVER_PHASES);
const RESOLVER_TARGET_SET = new Set(RESOLVER_TARGETS);
const RESOLVER_CLEANUP_SET = new Set(RESOLVER_CLEANUP_STATES);
const resolverContextKey = (phase, target, cleanupState) =>
  phase + "\u0000" + target + "\u0000" + cleanupState;
const targetContexts = (phase, cleanupStates) =>
  RESOLVER_TARGETS.flatMap((target) =>
    cleanupStates.map((cleanupState) => resolverContextKey(phase, target, cleanupState)),
  );
const dockerFailureContexts = [
  resolverContextKey("capability", "docker", "not_applicable"),
  ...targetContexts("identity_inspect", ["not_applicable"]),
  ...targetContexts("probe_precheck", ["unknown"]),
  ...targetContexts("probe_create", ["unknown"]),
  ...targetContexts("probe_reconcile", ["unknown"]),
  ...targetContexts("probe_validate", ["unknown", "removed"]),
  ...targetContexts("probe_cleanup", ["incomplete", "unknown"]),
];
const inspectPayloadContexts = [
  resolverContextKey("capability", "docker", "not_applicable"),
  ...targetContexts("identity_inspect", ["not_applicable"]),
  ...targetContexts("probe_precheck", ["unknown"]),
  ...targetContexts("probe_reconcile", ["unknown"]),
  ...targetContexts("probe_validate", ["unknown", "removed"]),
  ...targetContexts("probe_cleanup", ["incomplete", "unknown"]),
];
const identityInvalidContexts = [
  resolverContextKey("identity_parse", "docker", "not_applicable"),
  ...targetContexts("identity_inspect", ["not_applicable"]),
  ...targetContexts("identity_validate", ["not_applicable"]),
  ...targetContexts("identity_stability", ["not_applicable"]),
];
const identityInspectContexts = targetContexts("identity_inspect", ["not_applicable"]);
const identityValidateContexts = targetContexts("identity_validate", ["not_applicable"]);
const resolverProbeContexts = [
  ...RESOLVER_TARGETS.flatMap((target) => [
    resolverContextKey("probe_precheck", target, "not_applicable"),
    resolverContextKey("probe_precheck", target, "unknown"),
    ...["probe_create", "probe_reconcile"].flatMap((phase) =>
      ["absent", "removed", "unknown"].map((cleanupState) =>
        resolverContextKey(phase, target, cleanupState),
      ),
    ),
    resolverContextKey("probe_validate", target, "removed"),
  ]),
];

// Each failure class is an explicit set of legal tuples. Keeping tuples
// together prevents an invalid phase/target/cleanup Cartesian product from
// becoming a valid evidence record.
export const RESOLVER_FAILURE_CONTEXTS = Object.freeze({
  docker_cli_unavailable: Object.freeze(dockerFailureContexts),
  docker_permission_denied: Object.freeze(dockerFailureContexts),
  docker_daemon_unavailable: Object.freeze(dockerFailureContexts),
  image_not_found: Object.freeze(identityInspectContexts),
  image_reference_unresolved: Object.freeze(identityInspectContexts),
  image_identity_invalid: Object.freeze(identityInvalidContexts),
  image_repository_mismatch: Object.freeze([
    ...identityInspectContexts,
    ...identityValidateContexts,
  ]),
  image_digest_mismatch: Object.freeze([
    ...identityInspectContexts,
    ...identityValidateContexts,
  ]),
  image_platform_mismatch: Object.freeze(identityValidateContexts),
  inspect_payload_invalid: Object.freeze(inspectPayloadContexts),
  resolver_probe_failed: Object.freeze(resolverProbeContexts),
  resolver_probe_cleanup_incomplete: Object.freeze(
    targetContexts("probe_cleanup", ["incomplete", "unknown"]),
  ),
});
const STATIC_LABELS = Object.freeze({
  "ai.yijie.feature": "FEAT-126",
  "ai.yijie.slice": "S10BD1",
  "ai.yijie.data-classification": "synthetic-only",
});

export class DockerPreflightError extends Error {
  constructor(code, context = {}) {
    if (!FAILURE_CLASS_SET.has(code)) {
      throw new TypeError("unknown closed Docker failure class");
    }
    super("FEAT-126 Docker preflight failed: " + code);
    this.name = "DockerPreflightError";
    this.code = code;
    this.resolverContext = Object.freeze({ ...context });
  }
}

function fail(code, context = {}) {
  throw new DockerPreflightError(code, context);
}

function annotateFailure(error, context, { override = false } = {}) {
  if (!(error instanceof DockerPreflightError)) {
    return error;
  }
  const existing = error.resolverContext ?? {};
  error.resolverContext = Object.freeze({
    phase: override ? context.phase : existing.phase ?? context.phase,
    target: override ? context.target : existing.target ?? context.target,
    cleanup_state: override
      ? context.cleanup_state
      : existing.cleanup_state ?? context.cleanup_state,
  });
  return error;
}

function withFailureContext(context, operation) {
  try {
    return operation();
  } catch (error) {
    const annotated = annotateFailure(error, context);
    if (
      context.phase === "probe_cleanup" &&
      annotated instanceof DockerPreflightError &&
      annotated.code === "resolver_probe_failed"
    ) {
      throw new DockerPreflightError("resolver_probe_cleanup_incomplete", {
        phase: "probe_cleanup",
        target: context.target,
        cleanup_state: context.cleanup_state,
      });
    }
    throw annotated;
  }
}

function targetForImage(image) {
  const repository = image?.repository ?? "";
  if (repository === "postgres" || repository.startsWith("postgres/")) return "postgres";
  if (repository.includes("keycloak")) return "keycloak";
  if (repository === "caddy" || repository.startsWith("caddy/")) return "caddy";
  return "docker";
}

const CLOSED_SUCCESS_KEYS = Object.freeze([
  "image_count",
  "probe_count",
  "run_id",
  "schema_version",
  "status",
]);
const CLOSED_FAILURE_KEYS = Object.freeze([
  "cleanup_state",
  "failure_class",
  "phase",
  "run_id",
  "schema_version",
  "status",
  "target",
]);
const CLOSED_RESULT_ERROR_CODES = new Set(["result_invalid", "result_oversize"]);

export class ClosedResolverResultError extends Error {
  constructor(code) {
    if (!CLOSED_RESULT_ERROR_CODES.has(code)) {
      throw new TypeError("unknown closed resolver result error");
    }
    super(code);
    this.name = "ClosedResolverResultError";
    this.code = code;
  }
}

function resultFail(code = "result_invalid") {
  throw new ClosedResolverResultError(code);
}

function exactKeys(value, expected) {
  return JSON.stringify(Object.keys(value).sort()) === JSON.stringify(expected);
}

function validFailureContext(failureClass, phase, target, cleanupState) {
  const allowed = RESOLVER_FAILURE_CONTEXTS[failureClass];
  return (
    allowed !== undefined &&
    RESOLVER_PHASE_SET.has(phase) &&
    RESOLVER_TARGET_SET.has(target) &&
    RESOLVER_CLEANUP_SET.has(cleanupState) &&
    allowed.includes(resolverContextKey(phase, target, cleanupState))
  );
}

export function validateClosedResolverResult(value, expectedRunId) {
  if (
    value === null ||
    Array.isArray(value) ||
    typeof value !== "object" ||
    !RUN_ID_PATTERN.test(expectedRunId ?? "") ||
    value.schema_version !== CLOSED_RESOLVER_RESULT_SCHEMA_VERSION ||
    value.run_id !== expectedRunId
  ) {
    resultFail();
  }

  if (value.status === "passed") {
    if (
      !exactKeys(value, CLOSED_SUCCESS_KEYS) ||
      value.image_count !== 3 ||
      value.probe_count !== 3
    ) {
      resultFail();
    }
  } else if (value.status === "failed") {
    if (
      !exactKeys(value, CLOSED_FAILURE_KEYS) ||
      !FAILURE_CLASS_SET.has(value.failure_class) ||
      !validFailureContext(
        value.failure_class,
        value.phase,
        value.target,
        value.cleanup_state,
      )
    ) {
      resultFail();
    }
  } else {
    resultFail();
  }

  return Object.freeze({ ...value });
}

export function parseClosedResolverResult(output, expectedRunId) {
  const bytes = Buffer.isBuffer(output) ? output : Buffer.from(output ?? "", "utf8");
  if (bytes.length === 0) resultFail();
  if (bytes.length > CLOSED_RESOLVER_RESULT_MAX_BYTES) resultFail("result_oversize");

  let framed;
  try {
    framed = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    resultFail();
  }
  if (framed.includes("\0") || framed.includes("\r")) resultFail();
  if (!framed.endsWith("\n")) resultFail();
  const body = framed.slice(0, -1);
  if (body.length === 0 || body.includes("\n") || body !== body.trim()) resultFail();

  let value;
  try {
    // The YAML parser is used only as a duplicate-key detector; JSON.parse
    // remains the syntax and value authority for this wire format.
    YAML.parse(body, { version: "1.2", uniqueKeys: true });
    value = JSON.parse(body);
  } catch {
    resultFail();
  }
  return validateClosedResolverResult(value, expectedRunId);
}

export function closedResolverSuccess(runId, result) {
  return validateClosedResolverResult(
    {
      schema_version: CLOSED_RESOLVER_RESULT_SCHEMA_VERSION,
      status: "passed",
      run_id: runId,
      image_count: result?.imageCount,
      probe_count: result?.probeCount,
    },
    runId,
  );
}

function defaultFailureContext(failureClass) {
  if (failureClass === "docker_cli_unavailable") {
    return { phase: "capability", target: "docker", cleanup_state: "not_applicable" };
  }
  if (
    failureClass === "image_platform_mismatch"
  ) {
    return { phase: "identity_validate", target: "docker", cleanup_state: "not_applicable" };
  }
  if (failureClass.startsWith("image_") || failureClass === "inspect_payload_invalid") {
    return { phase: "identity_inspect", target: "docker", cleanup_state: "not_applicable" };
  }
  if (failureClass === "resolver_probe_cleanup_incomplete") {
    return { phase: "probe_cleanup", target: "docker", cleanup_state: "unknown" };
  }
  if (failureClass === "resolver_probe_failed") {
    return { phase: "probe_reconcile", target: "docker", cleanup_state: "unknown" };
  }
  return { phase: "capability", target: "docker", cleanup_state: "not_applicable" };
}

export function closedResolverFailure(runId, error) {
  const failureClass =
    error instanceof DockerPreflightError ? error.code : "resolver_probe_failed";
  const fallback = defaultFailureContext(failureClass);
  const context = error instanceof DockerPreflightError ? error.resolverContext : {};
  return validateClosedResolverResult(
    {
      schema_version: CLOSED_RESOLVER_RESULT_SCHEMA_VERSION,
      status: "failed",
      run_id: runId,
      failure_class: failureClass,
      phase: context?.phase ?? fallback.phase,
      target: context?.target ?? fallback.target,
      cleanup_state: context?.cleanup_state ?? fallback.cleanup_state,
    },
    runId,
  );
}

export function mapClosedResolverFailure(failureClass) {
  if (!FAILURE_CLASS_SET.has(failureClass)) resultFail();
  return "preflight_image_resolver_" + failureClass;
}

function writeClosedResolverResult(value) {
  const output = Buffer.from(JSON.stringify(value) + "\n", "utf8");
  if (output.length > CLOSED_RESOLVER_RESULT_MAX_BYTES) resultFail("result_oversize");
  process.stdout.write(output);
}

function executeDocker(args) {
  return spawnSync("docker", args, {
    encoding: "utf8",
    maxBuffer: MAX_OUTPUT_BYTES,
    shell: false,
    windowsHide: true,
  });
}

function text(value) {
  return typeof value === "string" ? value : "";
}

function succeeded(result) {
  return !result?.error && result?.status === 0;
}

function diagnostic(result) {
  return ((result?.error?.code ?? "") + " " + text(result?.stderr)).toLowerCase();
}

function classifyCommonFailure(result, fallback) {
  const detail = diagnostic(result);
  if (result?.error?.code === "ENOBUFS") {
    fail("inspect_payload_invalid");
  }
  if (result?.error?.code === "ENOENT") {
    fail("docker_cli_unavailable");
  }
  if (
    result?.error?.code === "EACCES" ||
    result?.error?.code === "EPERM" ||
    /permission denied|operation not permitted|access is denied/.test(detail)
  ) {
    fail("docker_permission_denied");
  }
  if (
    /cannot connect|is the docker daemon running|docker daemon is not running|daemon unavailable|error during connect|connection refused|dial unix|failed to connect to the docker api|docker engine is stopped/.test(
      detail,
    )
  ) {
    fail("docker_daemon_unavailable");
  }
  fail(fallback);
}

function parseSingleJson(output) {
  const normalized = text(output).trim();
  if (
    normalized.length === 0 ||
    normalized.length > MAX_OUTPUT_BYTES ||
    normalized.includes("\n") ||
    normalized.includes("\r")
  ) {
    fail("inspect_payload_invalid");
  }
  try {
    const parsed = JSON.parse(normalized);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      fail("inspect_payload_invalid");
    }
    return parsed;
  } catch (error) {
    if (error instanceof DockerPreflightError) {
      throw error;
    }
    fail("inspect_payload_invalid");
  }
}

export function parsePinnedImage(reference) {
  const match = PIN_PATTERN.exec(reference);
  if (!match?.groups) {
    fail("image_identity_invalid");
  }
  const { repository, tag, digest } = match.groups;
  return Object.freeze({
    reference,
    repository,
    tag,
    digest,
    tagReference: repository + ":" + tag,
    digestReference: repository + "@" + digest,
  });
}

export function expectedImmutableImages(imageMap = FEAT_126_S10_IMAGES) {
  const byDigest = new Map();
  for (const reference of Object.values(imageMap)) {
    const parsed = parsePinnedImage(reference);
    const existing = byDigest.get(parsed.digestReference);
    if (existing && existing.reference !== parsed.reference) {
      fail("image_identity_invalid");
    }
    byDigest.set(parsed.digestReference, parsed);
  }
  return [...byDigest.values()];
}

export function parseInspectOutput(output) {
  return parseSingleJson(output);
}

export function verifyDockerExecutionCapability({ runDocker = executeDocker } = {}) {
  const result = runDocker(["version", "--format", "{{json .Server}}"]);
  if (!succeeded(result)) {
    classifyCommonFailure(result, "docker_daemon_unavailable");
  }
  const server = parseSingleJson(result.stdout);
  if (
    typeof server.Arch !== "string" ||
    server.Arch.length === 0 ||
    typeof server.Os !== "string" ||
    server.Os.length === 0
  ) {
    fail("inspect_payload_invalid");
  }
  return Object.freeze({ architecture: server.Arch, os: server.Os });
}

function digestRepository(reference) {
  const marker = reference.lastIndexOf("@sha256:");
  return marker > 0 ? reference.slice(0, marker) : "";
}

function validateRepoDigests(repoDigests, image) {
  if (!Array.isArray(repoDigests) || repoDigests.some((value) => typeof value !== "string")) {
    fail("image_identity_invalid");
  }
  if (repoDigests.includes(image.digestReference)) {
    return;
  }
  if (repoDigests.some((value) => digestRepository(value) === image.repository)) {
    fail("image_digest_mismatch");
  }
  fail("image_repository_mismatch");
}

export function validateImageSnapshot(snapshot, image, capability) {
  if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) {
    fail("image_identity_invalid");
  }
  if (!IMAGE_ID_PATTERN.test(snapshot.Id ?? "")) {
    fail("image_identity_invalid");
  }
  validateRepoDigests(snapshot.RepoDigests, image);
  if (snapshot.Descriptor?.digest === undefined) {
    fail("image_identity_invalid");
  }
  if (snapshot.Descriptor.digest !== image.digest) {
    fail("image_digest_mismatch");
  }
  if (
    snapshot.Os !== "linux" ||
    snapshot.Os !== capability.os ||
    snapshot.Architecture !== capability.architecture
  ) {
    fail("image_platform_mismatch");
  }
  const declaredVolumes = snapshot.Config?.Volumes;
  if (
    declaredVolumes !== undefined &&
    (!declaredVolumes || typeof declaredVolumes !== "object" || Array.isArray(declaredVolumes))
  ) {
    fail("image_identity_invalid");
  }
  return Object.freeze({
    id: snapshot.Id,
    descriptor: snapshot.Descriptor.digest,
    repoDigests: [...snapshot.RepoDigests].sort(),
    os: snapshot.Os,
    architecture: snapshot.Architecture,
    volumes: Object.keys(declaredVolumes ?? {}).sort(),
  });
}

function stableIdentity(first, second) {
  if (JSON.stringify(first) !== JSON.stringify(second)) {
    fail("image_identity_invalid");
  }
}

function inspectTagDiagnostic(image, runDocker) {
  const result = runDocker([
    "image",
    "inspect",
    image.tagReference,
    "--format",
    "{{json .}}",
  ]);
  if (!succeeded(result)) {
    const detail = diagnostic(result);
    if (result?.error?.code === "ENOBUFS") {
      fail("inspect_payload_invalid");
    }
    if (/permission denied|operation not permitted|access is denied/.test(detail)) {
      fail("docker_permission_denied");
    }
    if (
      /cannot connect|is the docker daemon running|docker daemon is not running|daemon unavailable|error during connect|connection refused|dial unix/.test(
        detail,
      )
    ) {
      fail("docker_daemon_unavailable");
    }
    fail("image_not_found");
  }
  const snapshot = parseSingleJson(result.stdout);
  validateRepoDigests(snapshot.RepoDigests, image);
  fail("image_reference_unresolved");
}

function inspectExactImage(image, runDocker) {
  const result = runDocker([
    "image",
    "inspect",
    image.reference,
    "--format",
    "{{json .}}",
  ]);
  if (!succeeded(result)) {
    const detail = diagnostic(result);
    if (result?.error?.code === "ENOBUFS") {
      fail("inspect_payload_invalid");
    }
    if (result?.error?.code === "ENOENT") {
      fail("docker_cli_unavailable");
    }
    if (/permission denied|operation not permitted|access is denied/.test(detail)) {
      fail("docker_permission_denied");
    }
    if (
      /cannot connect|is the docker daemon running|docker daemon is not running|daemon unavailable|error during connect|connection refused|dial unix/.test(
        detail,
      )
    ) {
      fail("docker_daemon_unavailable");
    }
    return inspectTagDiagnostic(image, runDocker);
  }
  return parseSingleJson(result.stdout);
}

function probeName(runId, ordinal) {
  return (
    "yijie-feat126-s10bd1-" +
    runId.replaceAll("-", "") +
    "-" +
    String(ordinal + 1).padStart(2, "0")
  );
}

function probeLabels(runId, image) {
  return Object.freeze({
    ...STATIC_LABELS,
    "ai.yijie.run-id": runId,
    "ai.yijie.image-pin": image.reference,
  });
}

export function buildResolverProbeArgs({ image, runId, ordinal, volumes = [] }) {
  if (!RUN_ID_PATTERN.test(runId ?? "")) {
    fail("resolver_probe_failed");
  }
  const name = probeName(runId, ordinal);
  const labels = probeLabels(runId, image);
  const args = ["container", "create", "--pull=never", "--name", name];
  for (const [key, value] of Object.entries(labels)) {
    args.push("--label", key + "=" + value);
  }
  args.push("--network", "none");
  for (const volume of [...volumes].sort()) {
    if (
      typeof volume !== "string" ||
      !/^\/(?:[A-Za-z0-9._-]+\/?)+$/.test(volume) ||
      volume.split("/").includes("..")
    ) {
      fail("resolver_probe_failed");
    }
    args.push("--tmpfs", volume + ":rw,noexec,nosuid,nodev");
  }
  args.push(image.reference);
  return Object.freeze({ args: Object.freeze(args), labels, name });
}

function inspectContainer(name, runDocker, { allowMissing = false } = {}) {
  const result = runDocker([
    "container",
    "inspect",
    name,
    "--format",
    "{{json .}}",
  ]);
  if (succeeded(result)) {
    return parseSingleJson(result.stdout);
  }
  if (allowMissing && /no such container|not found/.test(diagnostic(result))) {
    return null;
  }
  classifyCommonFailure(result, "resolver_probe_failed");
}

export function validateProbeContainer(container, context) {
  const { containerId, image, labels, name, volumes } = context;
  if (
    !container ||
    container.Id !== containerId ||
    container.Name !== "/" + name ||
    container.Config?.Image !== image.reference ||
    container.State?.Running !== false ||
    container.HostConfig?.NetworkMode !== "none"
  ) {
    fail("resolver_probe_failed");
  }
  for (const [key, value] of Object.entries(labels)) {
    if (container.Config?.Labels?.[key] !== value) {
      fail("resolver_probe_failed");
    }
  }
  if ((container.Mounts ?? []).some((mount) => mount?.Type === "volume")) {
    fail("resolver_probe_failed");
  }
  const tmpfs = container.HostConfig?.Tmpfs ?? {};
  if (volumes.some((volume) => typeof tmpfs[volume] !== "string")) {
    fail("resolver_probe_failed");
  }
  if (Object.keys(container.HostConfig?.PortBindings ?? {}).length !== 0) {
    fail("resolver_probe_failed");
  }
  if (Object.keys(container.NetworkSettings?.Ports ?? {}).length !== 0) {
    fail("resolver_probe_failed");
  }
}

function isOwnedProbe(container, context) {
  return (
    container?.Id === context.containerId &&
    container?.Name === "/" + context.name &&
    container?.Config?.Image === context.image.reference &&
    container?.State?.Running === false &&
    Object.entries(context.labels).every(
      ([key, value]) => container?.Config?.Labels?.[key] === value,
    )
  );
}

function cleanupOwnedProbe(context, runDocker) {
  const current = inspectContainer(context.name, runDocker, { allowMissing: true });
  if (!current) {
    return;
  }
  if (!isOwnedProbe(current, context)) {
    fail("resolver_probe_cleanup_incomplete");
  }
  const removed = runDocker(["container", "rm", context.containerId]);
  if (!succeeded(removed)) {
    classifyCommonFailure(removed, "resolver_probe_cleanup_incomplete");
  }
  if (inspectContainer(context.name, runDocker, { allowMissing: true }) !== null) {
    fail("resolver_probe_cleanup_incomplete");
  }
}

export function runResolverProbe({
  image,
  identity,
  runId,
  ordinal,
  runDocker = executeDocker,
}) {
  const target = targetForImage(image);
  const probe = withFailureContext(
    { phase: "probe_precheck", target, cleanup_state: "not_applicable" },
    () =>
      buildResolverProbeArgs({
        image,
        runId,
        ordinal,
        volumes: identity.volumes,
      }),
  );
  const existing = withFailureContext(
    { phase: "probe_precheck", target, cleanup_state: "unknown" },
    () => inspectContainer(probe.name, runDocker, { allowMissing: true }),
  );
  if (existing !== null) {
    fail("resolver_probe_failed", {
      phase: "probe_precheck",
      target,
      cleanup_state: "unknown",
    });
  }

  const created = withFailureContext(
    { phase: "probe_create", target, cleanup_state: "unknown" },
    () => runDocker(probe.args),
  );
  if (!succeeded(created)) {
    const detail = diagnostic(created);
    if (/permission denied|operation not permitted|access is denied/.test(detail)) {
      fail("docker_permission_denied", {
        phase: "probe_create",
        target,
        cleanup_state: "unknown",
      });
    }
    if (
      /cannot connect|is the docker daemon running|docker daemon is not running|daemon unavailable|error during connect|connection refused|dial unix/.test(
        detail,
      )
    ) {
      fail("docker_daemon_unavailable", {
        phase: "probe_create",
        target,
        cleanup_state: "unknown",
      });
    }
    const reconciled = withFailureContext(
      { phase: "probe_reconcile", target, cleanup_state: "unknown" },
      () => inspectContainer(probe.name, runDocker, { allowMissing: true }),
    );
    let cleanupState = "absent";
    if (reconciled) {
      const reconciledId = text(reconciled.Id).replace(/^sha256:/, "");
      withFailureContext(
        { phase: "probe_cleanup", target, cleanup_state: "incomplete" },
        () => cleanupOwnedProbe({ ...probe, containerId: reconciledId, image }, runDocker),
      );
      cleanupState = "removed";
    }
    fail("resolver_probe_failed", {
      phase: "probe_create",
      target,
      cleanup_state: cleanupState,
    });
  }

  const containerId = text(created.stdout).trim();
  if (!CONTAINER_ID_PATTERN.test(containerId)) {
    const reconciled = withFailureContext(
      { phase: "probe_reconcile", target, cleanup_state: "unknown" },
      () => inspectContainer(probe.name, runDocker, { allowMissing: true }),
    );
    let cleanupState = "absent";
    if (reconciled) {
      const reconciledId = text(reconciled.Id).replace(/^sha256:/, "");
      withFailureContext(
        { phase: "probe_cleanup", target, cleanup_state: "incomplete" },
        () => cleanupOwnedProbe({ ...probe, containerId: reconciledId, image }, runDocker),
      );
      cleanupState = "removed";
    }
    fail("resolver_probe_failed", {
      phase: "probe_reconcile",
      target,
      cleanup_state: cleanupState,
    });
  }
  const context = { ...probe, containerId, image, volumes: identity.volumes };
  let validationError;
  try {
    withFailureContext(
      { phase: "probe_validate", target, cleanup_state: "unknown" },
      () =>
        validateProbeContainer(
          inspectContainer(probe.name, runDocker),
          context,
        ),
    );
  } catch (error) {
    validationError = error;
  }
  withFailureContext(
    { phase: "probe_cleanup", target, cleanup_state: "incomplete" },
    () => cleanupOwnedProbe(context, runDocker),
  );
  if (validationError) {
    throw annotateFailure(
      validationError,
      {
        phase: "probe_validate",
        target,
        cleanup_state: "removed",
      },
      { override: true },
    );
  }
}

export function verifyLocalImageAvailability({
  imageMap = FEAT_126_S10_IMAGES,
  runDocker = executeDocker,
  runId,
  resolverProbe = true,
} = {}) {
  if (resolverProbe && !RUN_ID_PATTERN.test(runId ?? "")) {
    fail("resolver_probe_failed", {
      phase: "probe_precheck",
      target: "docker",
      cleanup_state: "not_applicable",
    });
  }
  const capability = withFailureContext(
    { phase: "capability", target: "docker", cleanup_state: "not_applicable" },
    () => verifyDockerExecutionCapability({ runDocker }),
  );
  const expected = withFailureContext(
    { phase: "identity_parse", target: "docker", cleanup_state: "not_applicable" },
    () => expectedImmutableImages(imageMap),
  );
  for (const [ordinal, image] of expected.entries()) {
    const target = targetForImage(image);
    const firstSnapshot = withFailureContext(
      { phase: "identity_inspect", target, cleanup_state: "not_applicable" },
      () => inspectExactImage(image, runDocker),
    );
    const first = withFailureContext(
      { phase: "identity_validate", target, cleanup_state: "not_applicable" },
      () => validateImageSnapshot(firstSnapshot, image, capability),
    );
    const secondSnapshot = withFailureContext(
      { phase: "identity_inspect", target, cleanup_state: "not_applicable" },
      () => inspectExactImage(image, runDocker),
    );
    const second = withFailureContext(
      { phase: "identity_validate", target, cleanup_state: "not_applicable" },
      () => validateImageSnapshot(secondSnapshot, image, capability),
    );
    withFailureContext(
      { phase: "identity_stability", target, cleanup_state: "not_applicable" },
      () => stableIdentity(first, second),
    );
    if (resolverProbe) {
      withFailureContext(
        { phase: "probe_reconcile", target, cleanup_state: "unknown" },
        () => runResolverProbe({ image, identity: first, runId, ordinal, runDocker }),
      );
    }
  }
  return Object.freeze({
    imageCount: expected.length,
    probeCount: resolverProbe ? expected.length : 0,
  });
}

function main() {
  const runId = process.argv[2] ?? "";
  const result = verifyLocalImageAvailability({ runId });
  process.stdout.write(
    "Verified " +
      result.imageCount +
      " immutable identities and " +
      result.probeCount +
      " no-start resolver probes; no pull performed\n",
  );
}

function closedMain() {
  const runId = process.argv[3] ?? "";
  if (process.argv.length !== 4 || !RUN_ID_PATTERN.test(runId)) {
    process.exitCode = 1;
    return;
  }
  try {
    writeClosedResolverResult(
      closedResolverSuccess(runId, verifyLocalImageAvailability({ runId })),
    );
  } catch (error) {
    try {
      writeClosedResolverResult(closedResolverFailure(runId, error));
    } catch {
      // Invalid protocol construction remains silent and fail-closed.
    }
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv[2] === "--closed-result-v1") {
    closedMain();
  } else {
    try {
      main();
    } catch (error) {
      const code =
        error instanceof DockerPreflightError ? error.code : "resolver_probe_failed";
      process.stderr.write("FEAT-126 Docker preflight failed: " + code + "\n");
      process.exitCode = 1;
    }
  }
}
