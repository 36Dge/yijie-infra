import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";

import { computeWorktreeReference } from "../scripts/feat-125-worktree-evidence.mjs";

const execFile = promisify(execFileCallback);

test("worktree evidence is stable and distinguishes committed from reviewed dirty state", async () => {
  const fixture = await createRepository();
  try {
    const committed = await computeWorktreeReference(fixture.path);
    assert.equal(committed, `commit:${fixture.commit}`);

    await writeFile(join(fixture.path, "tracked.txt"), "reviewed change\n");
    await writeFile(join(fixture.path, "untracked.txt"), "reviewed untracked\n");
    const first = await computeWorktreeReference(fixture.path);
    const second = await computeWorktreeReference(fixture.path);
    assert.match(first, new RegExp(`^candidate:${fixture.commit}:[a-f0-9]{64}$`));
    assert.equal(first, second);
  } finally {
    await rm(fixture.path, { recursive: true });
  }
});

test("worktree evidence rejects same-status content changes between full snapshots", async () => {
  const fixture = await createRepository();
  try {
    const tracked = join(fixture.path, "tracked.txt");
    await writeFile(tracked, "first dirty value\n");
    await assert.rejects(
      computeWorktreeReference(fixture.path, {
        afterFirstSnapshot: async () => writeFile(tracked, "second dirty value\n"),
      }),
      /repository changed while candidate evidence was being computed/,
    );
  } finally {
    await rm(fixture.path, { recursive: true });
  }
});

async function createRepository() {
  const path = await mkdtemp(join(tmpdir(), "yijie-feat125-evidence-"));
  await git(path, ["init", "--quiet"]);
  await git(path, ["config", "user.name", "FEAT-125 Test"]);
  await git(path, ["config", "user.email", "feat125-test@example.invalid"]);
  await writeFile(join(path, "tracked.txt"), "committed\n");
  await git(path, ["add", "tracked.txt"]);
  await git(path, ["commit", "--quiet", "-m", "fixture"]);
  const { stdout } = await git(path, ["rev-parse", "HEAD"]);
  return { path, commit: stdout.trim() };
}

function git(path, args) {
  return execFile("git", ["-C", path, ...args], { encoding: "utf8" });
}
