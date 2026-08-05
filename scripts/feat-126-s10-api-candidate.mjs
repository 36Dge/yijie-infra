#!/usr/bin/env node

import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const REPOSITORY_ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const RUN_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const FULL_SHA_PATTERN = /^[0-9a-f]{40}$/;
const MAX_AUTHORITY_BYTES = 1024;
export const API_CANDIDATE_AUTHORITY_FILE = "api-candidate-authority.json";

function fail() {
  throw new Error("FEAT-126 S10 API candidate authority is invalid");
}

function requireOwnerOnly(metadata, mode, kind) {
  if (
    (kind === "directory" && !metadata.isDirectory()) ||
    (kind === "file" && !metadata.isFile()) ||
    metadata.isSymbolicLink() ||
    metadata.uid !== process.geteuid() ||
    (metadata.mode & 0o777) !== mode ||
    (kind === "file" && metadata.nlink !== 1)
  ) {
    fail();
  }
}

function inspectGitRepository(apiRepository) {
  const head = spawnSync("git", ["-C", apiRepository, "rev-parse", "HEAD"], {
    encoding: "utf8",
    shell: false,
    windowsHide: true,
    maxBuffer: 64 * 1024,
  });
  const status = spawnSync(
    "git",
    ["-C", apiRepository, "status", "--porcelain", "--untracked-files=all"],
    { encoding: "utf8", shell: false, windowsHide: true, maxBuffer: 1024 * 1024 },
  );
  if (head.error || head.status !== 0 || status.error || status.status !== 0) fail();
  return { head: head.stdout.trim(), dirty: status.stdout.length !== 0 };
}

function validateDocument(value, runId, apiFullCommit) {
  if (
    value === null ||
    Array.isArray(value) ||
    typeof value !== "object" ||
    JSON.stringify(Object.keys(value).sort()) !==
      JSON.stringify(["api_full_commit", "run_id", "schema_version"]) ||
    value.schema_version !== 1 ||
    value.run_id !== runId ||
    value.api_full_commit !== apiFullCommit
  ) {
    fail();
  }
  return Object.freeze(value);
}

async function validateExistingAuthority(path, runId, apiFullCommit) {
  const pathMetadata = await lstat(path).catch(() => fail());
  requireOwnerOnly(pathMetadata, 0o600, "file");
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW).catch(() => fail());
  try {
    const handleMetadata = await handle.stat();
    requireOwnerOnly(handleMetadata, 0o600, "file");
    if (
      handleMetadata.dev !== pathMetadata.dev ||
      handleMetadata.ino !== pathMetadata.ino ||
      handleMetadata.size <= 0 ||
      handleMetadata.size > MAX_AUTHORITY_BYTES
    ) {
      fail();
    }
    const text = await handle.readFile("utf8");
    let value;
    try {
      value = JSON.parse(text);
    } catch {
      fail();
    }
    return validateDocument(value, runId, apiFullCommit);
  } finally {
    await handle.close();
  }
}

export async function ensureApiCandidateAuthority({
  runId,
  apiRepository,
  apiFullCommit,
  runRoot = resolve(REPOSITORY_ROOT, "environments/local/generated/feat-126-s10", runId ?? ""),
  inspectRepository = inspectGitRepository,
} = {}) {
  if (
    !RUN_ID_PATTERN.test(runId ?? "") ||
    !FULL_SHA_PATTERN.test(apiFullCommit ?? "") ||
    typeof apiRepository !== "string" ||
    apiRepository.length === 0
  ) {
    fail();
  }

  const resolvedRunRoot = resolve(runRoot);
  const runRootMetadata = await lstat(resolvedRunRoot).catch(() => fail());
  requireOwnerOnly(runRootMetadata, 0o700, "directory");
  if ((await realpath(resolvedRunRoot).catch(() => fail())) !== resolvedRunRoot) fail();

  const repository = inspectRepository(apiRepository);
  if (repository.head !== apiFullCommit || repository.dirty) fail();

  const authorityPath = resolve(resolvedRunRoot, API_CANDIDATE_AUTHORITY_FILE);
  if (resolve(authorityPath, "..") !== resolvedRunRoot) fail();
  const document = Object.freeze({
    schema_version: 1,
    run_id: runId,
    api_full_commit: apiFullCommit,
  });
  const body = `${JSON.stringify(document)}\n`;

  let handle;
  try {
    handle = await open(
      authorityPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
  } catch (error) {
    if (error?.code === "EEXIST") {
      return validateExistingAuthority(authorityPath, runId, apiFullCommit);
    }
    fail();
  }
  try {
    await handle.writeFile(body, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  return validateExistingAuthority(authorityPath, runId, apiFullCommit);
}

async function main() {
  if (process.argv.length !== 5) fail();
  await ensureApiCandidateAuthority({
    runId: process.argv[2],
    apiRepository: process.argv[3],
    apiFullCommit: process.argv[4],
  });
  process.stdout.write("Validated the run-scoped FEAT-126 S10 API candidate authority\n");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => {
    process.stderr.write("FEAT-126 S10 API candidate authority validation failed\n");
    process.exitCode = 1;
  });
}
