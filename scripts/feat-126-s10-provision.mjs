#!/usr/bin/env node

import { lstat, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { provisionFeat125LocalUsers } from "./feat-125-local-provision.mjs";
import { validateFeat126S10Secrets } from "./feat-126-s10-secrets.mjs";

const REPOSITORY_ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const runId = process.argv[2];
if (
  process.argv.length !== 3 ||
  !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
    runId ?? "",
  )
) {
  throw new Error("usage: feat-126-s10-provision.mjs CANONICAL_LOWERCASE_UUIDV4");
}

const runRoot = resolve(
  REPOSITORY_ROOT,
  "environments/local/generated/feat-126-s10",
  runId,
);
const secretsPath = resolve(runRoot, "infra-secrets.env");
const caPath = resolve(runRoot, "caddy-root.crt");
if (resolve(process.env.NODE_EXTRA_CA_CERTS ?? "") !== caPath) {
  throw new Error("NODE_EXTRA_CA_CERTS must point to this run's exported public CA");
}

const caStats = await lstat(caPath);
if (!caStats.isFile() || caStats.isSymbolicLink() || (caStats.mode & 0o077) !== 0) {
  throw new Error("FEAT-126 S10 public CA must be an owner-only regular non-symlink file");
}
if (caStats.size === 0 || caStats.size > 65_536) {
  throw new Error("FEAT-126 S10 public CA size is invalid");
}
const caText = await readFile(caPath, "utf8");
if (
  caText.includes("PRIVATE KEY") ||
  (caText.match(/-----BEGIN CERTIFICATE-----/g) ?? []).length !== 1 ||
  (caText.match(/-----END CERTIFICATE-----/g) ?? []).length !== 1
) {
  throw new Error("FEAT-126 S10 public CA must contain exactly one certificate and no private key");
}

const sourceSecrets = await validateFeat126S10Secrets(secretsPath);
const mappedSecrets = new Map([
  ["FEAT125_KEYCLOAK_ADMIN_PASSWORD", sourceSecrets.get("FEAT126_S10_KEYCLOAK_ADMIN_PASSWORD")],
  [
    "FEAT125_SYNTHETIC_USER_A_PASSWORD",
    sourceSecrets.get("FEAT126_S10_SYNTHETIC_USER_A_PASSWORD"),
  ],
  [
    "FEAT125_SYNTHETIC_USER_B_PASSWORD",
    sourceSecrets.get("FEAT126_S10_SYNTHETIC_USER_B_PASSWORD"),
  ],
]);

const result = await provisionFeat125LocalUsers({
  secrets: mappedSecrets,
  administratorUsername: "feat126-s10-admin",
});
console.log(`Provisioned ${result.provisionedUsers} reviewed synthetic users for FEAT-126 S10E.`);
