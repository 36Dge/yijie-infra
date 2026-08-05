#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

import { FEAT_126_S10_IMAGES } from "./compose-model.mjs";

const PIN_PATTERN = /^(?<repository>.+):(?<tag>[^/:@]+)@(?<digest>sha256:[a-f0-9]{64})$/;
const IMAGE_ID_PATTERN = /^sha256:[a-f0-9]{64}$/;
const MAX_INSPECT_BYTES = 1024 * 1024;

export function parsePinnedImage(reference) {
  const match = PIN_PATTERN.exec(reference);
  if (!match?.groups) {
    throw new Error("FEAT-126 S10 image pin is malformed");
  }
  const { repository, tag, digest } = match.groups;
  return Object.freeze({
    reference,
    repository,
    tag,
    digest,
    digestReference: `${repository}@${digest}`,
  });
}

export function expectedImmutableImages(imageMap = FEAT_126_S10_IMAGES) {
  const byDigestReference = new Map();
  for (const reference of Object.values(imageMap)) {
    const parsed = parsePinnedImage(reference);
    const existing = byDigestReference.get(parsed.digestReference);
    if (existing && existing.reference !== parsed.reference) {
      throw new Error("FEAT-126 S10 image authority contains conflicting version tags");
    }
    byDigestReference.set(parsed.digestReference, parsed);
  }
  return [...byDigestReference.values()];
}

export function parseInspectOutput(output) {
  const normalized = typeof output === "string" ? output.trim() : "";
  if (
    normalized.length === 0 ||
    normalized.length > MAX_INSPECT_BYTES ||
    normalized.includes("\n") ||
    normalized.includes("\r")
  ) {
    throw new Error("local immutable image inspection returned an invalid result");
  }
  try {
    return JSON.parse(normalized);
  } catch {
    throw new Error("local immutable image inspection returned invalid JSON");
  }
}

function inspectLocalDigest(digestReference) {
  const result = spawnSync(
    "docker",
    ["image", "inspect", digestReference, "--format", "{{json .}}"],
    {
      encoding: "utf8",
      maxBuffer: MAX_INSPECT_BYTES,
      shell: false,
      windowsHide: true,
    },
  );
  if (result.error || result.status !== 0) {
    throw new Error("required immutable image is unavailable locally; refusing to pull");
  }
  return parseInspectOutput(result.stdout);
}

export function verifyLocalImageAvailability({
  imageMap = FEAT_126_S10_IMAGES,
  inspect = inspectLocalDigest,
} = {}) {
  const expected = expectedImmutableImages(imageMap);
  for (const image of expected) {
    const inspected = inspect(image.digestReference);
    if (!inspected || typeof inspected !== "object" || !IMAGE_ID_PATTERN.test(inspected.Id ?? "")) {
      throw new Error("local immutable image identity is invalid");
    }
    if (!Array.isArray(inspected.RepoDigests) || !inspected.RepoDigests.includes(image.digestReference)) {
      throw new Error("local immutable image repository digest does not match the reviewed pin");
    }
    if (inspected.Descriptor?.digest !== undefined && inspected.Descriptor.digest !== image.digest) {
      throw new Error("local immutable image descriptor does not match the reviewed pin");
    }
  }
  return expected.length;
}

function main() {
  const count = verifyLocalImageAvailability();
  process.stdout.write(`Verified ${count} FEAT-126 immutable local image identities; no pull performed\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`FEAT-126 image availability check failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
