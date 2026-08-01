import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { validateFeat125LocalSecrets } from "../scripts/feat-125-local-secrets.mjs";

const validBody = [
  `FEAT125_KEYCLOAK_DB_PASSWORD=${"a".repeat(64)}`,
  `FEAT125_KEYCLOAK_ADMIN_PASSWORD=${"b".repeat(64)}`,
  `FEAT125_SYNTHETIC_USER_A_PASSWORD=${"c".repeat(64)}`,
  `FEAT125_SYNTHETIC_USER_B_PASSWORD=${"d".repeat(64)}`,
  "",
].join("\n");

test("local secrets accept only four distinct generated values in a protected file", async () => {
  await withSecretsFile(validBody, 0o600, async (path) => {
    const values = await validateFeat125LocalSecrets(path);
    assert.equal(values.size, 4);
  });
});

test("local secrets reject group-readable permissions", async () => {
  await withSecretsFile(validBody, 0o640, async (path) => {
    await assert.rejects(validateFeat125LocalSecrets(path), /permissions must be 0600 or stricter/);
  });
});

test("local secrets reject unsupported keys and shell syntax", async () => {
  const body = `${validBody}UNAPPROVED_COMMAND=$(id)\n`;
  await withSecretsFile(body, 0o600, async (path) => {
    await assert.rejects(validateFeat125LocalSecrets(path), /unsupported or duplicate/);
  });
});

test("local secrets reject any reused credential values", async () => {
  const value = "c".repeat(64);
  const body = [
    `FEAT125_KEYCLOAK_DB_PASSWORD=${value}`,
    `FEAT125_KEYCLOAK_ADMIN_PASSWORD=${value}`,
    `FEAT125_SYNTHETIC_USER_A_PASSWORD=${"d".repeat(64)}`,
    `FEAT125_SYNTHETIC_USER_B_PASSWORD=${"e".repeat(64)}`,
    "",
  ].join("\n");
  await withSecretsFile(body, 0o600, async (path) => {
    await assert.rejects(validateFeat125LocalSecrets(path), /distinct generated value/);
  });
});

test("secret publication is atomic no-clobber and stop/status do not require the secrets file", async () => {
  const [initializer, composeHelper] = await Promise.all([
    readFile(new URL("../scripts/init-feat-125-local-secrets.sh", import.meta.url), "utf8"),
    readFile(new URL("../scripts/feat-125-local-compose.sh", import.meta.url), "utf8"),
  ]);
  assert.match(initializer, /ln "\$temporary_file" "\$secrets_file"/);
  assert.doesNotMatch(initializer, /\bmv "\$temporary_file" "\$secrets_file"/);

  const validationIndex = composeHelper.indexOf("validate-feat-125-local-secrets.mjs");
  const upBranchIndex = composeHelper.indexOf("  up)");
  const stopBranchIndex = composeHelper.indexOf("  stop)");
  assert.ok(validationIndex > upBranchIndex);
  assert.ok(validationIndex < stopBranchIndex);
});

async function withSecretsFile(body, mode, callback) {
  const directory = await mkdtemp(join(tmpdir(), "yijie-feat125-secrets-"));
  const path = join(directory, "secrets.env");
  try {
    await writeFile(path, body, { encoding: "utf8", mode: 0o600 });
    await chmod(path, mode);
    await callback(path);
  } finally {
    await rm(directory, { recursive: true });
  }
}
