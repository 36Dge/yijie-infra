import { lstat, readFile } from "node:fs/promises";

const EXPECTED_KEYS = new Set([
  "FEAT125_KEYCLOAK_DB_PASSWORD",
  "FEAT125_KEYCLOAK_ADMIN_PASSWORD",
  "FEAT125_SYNTHETIC_USER_A_PASSWORD",
  "FEAT125_SYNTHETIC_USER_B_PASSWORD",
]);
const GENERATED_SECRET_PATTERN = /^[a-f0-9]{64}$/;

export async function validateFeat125LocalSecrets(path) {
  const stats = await lstat(path);
  if (!stats.isFile() || stats.isSymbolicLink()) {
    throw new Error("FEAT-125 local secrets must be a regular non-symlink file");
  }
  if ((stats.mode & 0o077) !== 0) {
    throw new Error("FEAT-125 local secrets file permissions must be 0600 or stricter");
  }
  if (typeof process.getuid === "function" && stats.uid !== process.getuid()) {
    throw new Error("FEAT-125 local secrets file must be owned by the current user");
  }
  if (stats.size === 0 || stats.size > 4096) {
    throw new Error("FEAT-125 local secrets file must be between 1 byte and 4 KiB");
  }

  const text = await readFile(path, "utf8");
  const entries = new Map();
  for (const [index, rawLine] of text.split("\n").entries()) {
    if (rawLine === "" && index === text.split("\n").length - 1) {
      continue;
    }
    if (!rawLine || rawLine.startsWith("#") || rawLine.trim() !== rawLine) {
      throw new Error(`invalid FEAT-125 local secrets line ${index + 1}`);
    }
    const separator = rawLine.indexOf("=");
    if (separator <= 0) {
      throw new Error(`invalid FEAT-125 local secrets line ${index + 1}`);
    }
    const key = rawLine.slice(0, separator);
    const value = rawLine.slice(separator + 1);
    if (!EXPECTED_KEYS.has(key) || entries.has(key)) {
      throw new Error(`unsupported or duplicate FEAT-125 local secret key: ${key}`);
    }
    if (!GENERATED_SECRET_PATTERN.test(value)) {
      throw new Error(`${key} must be a generated 256-bit lowercase hexadecimal value`);
    }
    entries.set(key, value);
  }

  for (const key of EXPECTED_KEYS) {
    if (!entries.has(key)) {
      throw new Error(`missing FEAT-125 local secret key: ${key}`);
    }
  }
  if (new Set(entries.values()).size !== EXPECTED_KEYS.size) {
    throw new Error("Every FEAT-125 local credential must use a distinct generated value");
  }
  return entries;
}
