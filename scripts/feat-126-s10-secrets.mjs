import { lstat, readFile } from "node:fs/promises";

export const FEAT_126_S10_SECRET_KEYS = Object.freeze([
  "FEAT126_S10_API_DB_PASSWORD",
  "FEAT126_S10_KEYCLOAK_DB_PASSWORD",
  "FEAT126_S10_KEYCLOAK_ADMIN_PASSWORD",
  "FEAT126_S10_SYNTHETIC_USER_A_PASSWORD",
  "FEAT126_S10_SYNTHETIC_USER_B_PASSWORD",
]);

const EXPECTED_KEYS = new Set(FEAT_126_S10_SECRET_KEYS);
const GENERATED_SECRET_PATTERN = /^[a-f0-9]{64}$/;

export async function validateFeat126S10Secrets(path) {
  const stats = await lstat(path);
  if (!stats.isFile() || stats.isSymbolicLink()) {
    throw new Error("FEAT-126 S10 secrets must be a regular non-symlink file");
  }
  if ((stats.mode & 0o077) !== 0) {
    throw new Error("FEAT-126 S10 secrets file permissions must be 0600 or stricter");
  }
  if (typeof process.getuid === "function" && stats.uid !== process.getuid()) {
    throw new Error("FEAT-126 S10 secrets file must be owned by the current user");
  }
  if (stats.size === 0 || stats.size > 4096) {
    throw new Error("FEAT-126 S10 secrets file must be between 1 byte and 4 KiB");
  }

  const text = await readFile(path, "utf8");
  const lines = text.split("\n");
  const entries = new Map();
  for (const [index, rawLine] of lines.entries()) {
    if (rawLine === "" && index === lines.length - 1) {
      continue;
    }
    if (!rawLine || rawLine.startsWith("#") || rawLine.trim() !== rawLine) {
      throw new Error(`invalid FEAT-126 S10 secrets line ${index + 1}`);
    }
    const separator = rawLine.indexOf("=");
    if (separator <= 0) {
      throw new Error(`invalid FEAT-126 S10 secrets line ${index + 1}`);
    }
    const key = rawLine.slice(0, separator);
    const value = rawLine.slice(separator + 1);
    if (!EXPECTED_KEYS.has(key) || entries.has(key)) {
      throw new Error(`unsupported or duplicate FEAT-126 S10 secret key: ${key}`);
    }
    if (!GENERATED_SECRET_PATTERN.test(value)) {
      throw new Error(`${key} must be a generated 256-bit lowercase hexadecimal value`);
    }
    entries.set(key, value);
  }

  for (const key of EXPECTED_KEYS) {
    if (!entries.has(key)) {
      throw new Error(`missing FEAT-126 S10 secret key: ${key}`);
    }
  }
  if (new Set(entries.values()).size !== EXPECTED_KEYS.size) {
    throw new Error("Every FEAT-126 S10 credential must use a distinct generated value");
  }
  return entries;
}
