#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

import { FEAT_126_S10_IMAGES } from "./compose-model.mjs";

const PIN_PATTERN = /^(?<repository>.+):(?<tag>[^/:@]+)@(?<digest>sha256:[a-f0-9]{64})$/;
const IMAGE_ID_PATTERN = /^sha256:[a-f0-9]{64}$/;
const CONTAINER_ID_PATTERN = /^[a-f0-9]{64}$/;
const RUN_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_OUTPUT_BYTES = 1024 * 1024;

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
const STATIC_LABELS = Object.freeze({
  "ai.yijie.feature": "FEAT-126",
  "ai.yijie.slice": "S10BD1",
  "ai.yijie.data-classification": "synthetic-only",
});

export class DockerPreflightError extends Error {
  constructor(code) {
    if (!FAILURE_CLASS_SET.has(code)) {
      throw new TypeError("unknown closed Docker failure class");
    }
    super("FEAT-126 Docker preflight failed: " + code);
    this.name = "DockerPreflightError";
    this.code = code;
  }
}

function fail(code) {
  throw new DockerPreflightError(code);
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
  const probe = buildResolverProbeArgs({
    image,
    runId,
    ordinal,
    volumes: identity.volumes,
  });
  if (inspectContainer(probe.name, runDocker, { allowMissing: true }) !== null) {
    fail("resolver_probe_failed");
  }

  const created = runDocker(probe.args);
  if (!succeeded(created)) {
    const detail = diagnostic(created);
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
    const reconciled = inspectContainer(probe.name, runDocker, { allowMissing: true });
    if (reconciled) {
      const reconciledId = text(reconciled.Id).replace(/^sha256:/, "");
      cleanupOwnedProbe({ ...probe, containerId: reconciledId, image }, runDocker);
    }
    fail("resolver_probe_failed");
  }

  const containerId = text(created.stdout).trim();
  if (!CONTAINER_ID_PATTERN.test(containerId)) {
    const reconciled = inspectContainer(probe.name, runDocker, { allowMissing: true });
    if (reconciled) {
      const reconciledId = text(reconciled.Id).replace(/^sha256:/, "");
      cleanupOwnedProbe({ ...probe, containerId: reconciledId, image }, runDocker);
    }
    fail("resolver_probe_failed");
  }
  const context = { ...probe, containerId, image, volumes: identity.volumes };
  let validationError;
  try {
    validateProbeContainer(inspectContainer(probe.name, runDocker), context);
  } catch (error) {
    validationError = error;
  }
  cleanupOwnedProbe(context, runDocker);
  if (validationError) {
    throw validationError;
  }
}

export function verifyLocalImageAvailability({
  imageMap = FEAT_126_S10_IMAGES,
  runDocker = executeDocker,
  runId,
  resolverProbe = true,
} = {}) {
  if (resolverProbe && !RUN_ID_PATTERN.test(runId ?? "")) {
    fail("resolver_probe_failed");
  }
  const capability = verifyDockerExecutionCapability({ runDocker });
  const expected = expectedImmutableImages(imageMap);
  for (const [ordinal, image] of expected.entries()) {
    const first = validateImageSnapshot(inspectExactImage(image, runDocker), image, capability);
    const second = validateImageSnapshot(inspectExactImage(image, runDocker), image, capability);
    stableIdentity(first, second);
    if (resolverProbe) {
      runResolverProbe({ image, identity: first, runId, ordinal, runDocker });
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

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main();
  } catch (error) {
    const code =
      error instanceof DockerPreflightError ? error.code : "resolver_probe_failed";
    process.stderr.write("FEAT-126 Docker preflight failed: " + code + "\n");
    process.exitCode = 1;
  }
}
