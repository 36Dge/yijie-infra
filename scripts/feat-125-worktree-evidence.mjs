#!/usr/bin/env node

import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, readFile, readlink } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);

export async function computeWorktreeReference(
  input,
  {
    afterFirstSnapshot = async () => {},
    gitBufferImpl,
    lstatImpl = lstat,
    readFileImpl = readFile,
    readlinkImpl = readlink,
  } = {},
) {
  const repository = resolve(input);
  const gitBuffer = gitBufferImpl ?? ((args) => runGitBuffer(repository, args));
  const baseCommit = (await gitBuffer(["rev-parse", "HEAD"])).toString("utf8").trim();
  if (!/^[a-f0-9]{40}$/.test(baseCommit)) {
    throw new Error("repository HEAD must resolve to a full lowercase commit SHA");
  }

  const before = await gitBuffer(["status", "--porcelain=v1", "-z", "--untracked-files=all"]);
  if (before.length === 0) {
    await afterFirstSnapshot();
    const afterBase = (await gitBuffer(["rev-parse", "HEAD"])).toString("utf8").trim();
    const after = await gitBuffer(["status", "--porcelain=v1", "-z", "--untracked-files=all"]);
    if (afterBase !== baseCommit || after.length !== 0) {
      throw new Error("repository changed while candidate evidence was being computed; retry review");
    }
    return `commit:${baseCommit}`;
  }

  const first = await snapshotDigest(repository, baseCommit, gitBuffer, {
    lstatImpl,
    readFileImpl,
    readlinkImpl,
  });
  await afterFirstSnapshot();
  const second = await snapshotDigest(repository, baseCommit, gitBuffer, {
    lstatImpl,
    readFileImpl,
    readlinkImpl,
  });
  const afterBase = (await gitBuffer(["rev-parse", "HEAD"])).toString("utf8").trim();
  const after = await gitBuffer(["status", "--porcelain=v1", "-z", "--untracked-files=all"]);
  if (afterBase !== baseCommit || !before.equals(after) || first !== second) {
    throw new Error("repository changed while candidate evidence was being computed; retry review");
  }
  return `candidate:${baseCommit}:${first}`;
}

async function snapshotDigest(repository, baseCommit, gitBuffer, fileSystem) {
  const trackedDiff = await gitBuffer(["diff", "--binary", "--no-ext-diff", "HEAD", "--", "."]);
  const untrackedOutput = await gitBuffer(["ls-files", "--others", "--exclude-standard", "-z"]);
  const untracked = splitNull(untrackedOutput).sort(Buffer.compare);
  const digest = createHash("sha256");
  digest.update("feat-125-reviewed-worktree-v1\0");
  addFrame(digest, "base", Buffer.from(baseCommit));
  addFrame(digest, "tracked-diff", trackedDiff);

  for (const encodedPath of untracked) {
    const relativePath = encodedPath.toString("utf8");
    const absolutePath = resolve(repository, relativePath);
    const stats = await fileSystem.lstatImpl(absolutePath);
    addFrame(digest, "untracked-path", encodedPath);
    if (stats.isSymbolicLink()) {
      addFrame(digest, "untracked-kind", Buffer.from("symlink"));
      addFrame(digest, "untracked-content", Buffer.from(await fileSystem.readlinkImpl(absolutePath)));
    } else if (stats.isFile()) {
      addFrame(digest, "untracked-kind", Buffer.from(stats.mode & 0o111 ? "file+x" : "file"));
      addFrame(digest, "untracked-content", await fileSystem.readFileImpl(absolutePath));
    } else {
      throw new Error(`unsupported untracked candidate entry: ${relativePath}`);
    }
  }
  return digest.digest("hex");
}

async function runGitBuffer(repository, args) {
  const { stdout } = await execFile("git", ["-C", repository, ...args], {
    encoding: "buffer",
    maxBuffer: 128 * 1024 * 1024,
  });
  return stdout;
}

function splitNull(value) {
  const entries = [];
  let start = 0;
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] === 0) {
      if (index > start) {
        entries.push(value.subarray(start, index));
      }
      start = index + 1;
    }
  }
  return entries;
}

function addFrame(hash, label, value) {
  hash.update(`${label}\0${value.length}\0`);
  hash.update(value);
  hash.update("\0");
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (!process.argv[2]) {
    throw new Error("usage: feat-125-worktree-evidence.mjs REPOSITORY");
  }
  console.log(await computeWorktreeReference(process.argv[2]));
}
