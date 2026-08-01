import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const helperPath = resolve(repositoryRoot, "scripts/feat-125-local-ca-trust-macos.sh");
const caPath = resolve(
  repositoryRoot,
  "environments/local/generated/feat-125-caddy-root.crt",
);

test("macOS CA helper normalizes the padded default Keychain path", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("macOS-only Keychain helper");
    return;
  }

  const fixtureRoot = await mkdtemp(resolve(tmpdir(), "feat-125-keychain-test-"));
  t.after(() => rm(fixtureRoot, { recursive: true, force: true }));
  const binDirectory = resolve(fixtureRoot, "bin");
  const keychainPath = resolve(fixtureRoot, "Login Keychain.keychain-db");
  await mkdir(binDirectory);
  await writeFile(keychainPath, "test-only keychain placeholder", { mode: 0o600 });

  const fingerprint = execFileSync(
    "openssl",
    ["x509", "-in", caPath, "-noout", "-fingerprint", "-sha1"],
    { encoding: "utf8" },
  )
    .trim()
    .split("=")
    .at(-1)
    .replaceAll(":", "");

  const securityMock = resolve(binDirectory, "security");
  await writeFile(
    securityMock,
    `#!/usr/bin/env bash
set -euo pipefail
case "\${1:-}" in
  default-keychain)
    printf '    "%s"    \\n' "$FEAT125_TEST_KEYCHAIN"
    ;;
  find-certificate)
    printf 'SHA-1 hash: %s\\n' "$FEAT125_TEST_FINGERPRINT"
    ;;
  trust-settings-export)
    /usr/bin/plutil -create xml1 "$2"
    /usr/bin/plutil -insert trustList -dictionary "$2"
    if [[ "$FEAT125_TEST_TRUSTED" == "1" ]]; then
      /usr/bin/plutil -insert "trustList.$FEAT125_TEST_FINGERPRINT" -dictionary "$2"
    fi
    ;;
  *)
    exit 64
    ;;
esac
`,
    { mode: 0o700 },
  );
  await chmod(securityMock, 0o700);

  const result = spawnSync("bash", [helperPath, "status"], {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${binDirectory}:${process.env.PATH}`,
      FEAT125_TEST_FINGERPRINT: fingerprint,
      FEAT125_TEST_KEYCHAIN: keychainPath,
      FEAT125_TEST_TRUSTED: "1",
    },
  });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, new RegExp(`trusted in ${escapeRegExp(keychainPath)}`));

  const installedWithoutTrust = spawnSync("bash", [helperPath, "status"], {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${binDirectory}:${process.env.PATH}`,
      FEAT125_TEST_FINGERPRINT: fingerprint,
      FEAT125_TEST_KEYCHAIN: keychainPath,
      FEAT125_TEST_TRUSTED: "0",
    },
  });
  assert.equal(installedWithoutTrust.status, 1, installedWithoutTrust.stderr);
  assert.match(installedWithoutTrust.stdout, /is not trusted/);
});

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
