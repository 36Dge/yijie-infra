#!/usr/bin/env node

import { chmod, lstat, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { parse, stringify } from "yaml";

import {
  inspectCaCertificate,
  validateFeat125LocalLabConfig,
} from "./feat-125-local-config.mjs";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const templatePath = resolve(
  repositoryRoot,
  "environments/local/feat-125.local-lab.template.yaml",
);
const caPath = resolve(
  repositoryRoot,
  "environments/local/generated/feat-125-caddy-root.crt",
);
const outputPath = resolve(
  repositoryRoot,
  "environments/local/feat-125.local-lab.yaml",
);
const apiRepository = resolve(repositoryRoot, "../yijie-api");
const desktopRepository = resolve(repositoryRoot, "../yijie-desktop");
const [apiInput, desktopInput] = process.argv.slice(2);
const apiReference = normalizeReference(apiInput);
const desktopReference = normalizeReference(desktopInput);

if (!apiReference || !desktopReference) {
  throw new Error(
    "usage: render-feat-125-local-config.mjs " +
      "API_REFERENCE DESKTOP_REFERENCE\n" +
      "reference: commit:<full-sha> or candidate:<base-full-sha>:<worktree-sha256>",
  );
}
try {
  const outputStats = await lstat(outputPath);
  if (outputStats.isSymbolicLink() || !outputStats.isFile()) {
    throw new Error("refusing to replace a non-regular local-lab configuration path");
  }
} catch (error) {
  if (error.code !== "ENOENT") {
    throw error;
  }
}

const config = parse(await readFile(templatePath, "utf8"));
const ca = await inspectCaCertificate(caPath);
config.api.implementation_evidence = evidenceFromReference(apiReference);
config.desktop.implementation_evidence = evidenceFromReference(desktopReference);
config.tls.ca_certificate_sha256 = ca.sha256;
await validateFeat125LocalLabConfig(config, {
  mode: "local-lab",
  expectedApiReference: apiReference,
  expectedDesktopReference: desktopReference,
  apiRepository,
  desktopRepository,
});

const temporaryPath = `${outputPath}.tmp`;
await writeFile(temporaryPath, stringify(config, { lineWidth: 0 }), {
  encoding: "utf8",
  flag: "wx",
  mode: 0o600,
});
await chmod(temporaryPath, 0o600);
await rename(temporaryPath, outputPath);
console.log(`Rendered ignored local-lab configuration: ${outputPath}`);

function normalizeReference(value) {
  if (/^[a-f0-9]{40}$/.test(value ?? "")) {
    return `commit:${value}`;
  }
  if (/^commit:[a-f0-9]{40}$/.test(value ?? "")) {
    return value;
  }
  if (/^candidate:[a-f0-9]{40}:[a-f0-9]{64}$/.test(value ?? "")) {
    return value;
  }
  return undefined;
}

function evidenceFromReference(reference) {
  const [state, first, second] = reference.split(":");
  if (state === "commit") {
    return {
      state: "committed",
      full_commit: first,
      base_commit: null,
      candidate_tree_sha256: null,
    };
  }
  return {
    state: "reviewed_worktree_candidate",
    full_commit: null,
    base_commit: first,
    candidate_tree_sha256: second,
  };
}
