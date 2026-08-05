import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, realpath } from "node:fs/promises";

const MAX_API_BINARY_BYTES = 256 * 1024 * 1024;

export class Feat126S10ApiBinaryError extends Error {
  constructor() {
    super("api_binary_invalid");
    this.code = "api_binary_invalid";
  }
}

function fail() {
  throw new Feat126S10ApiBinaryError();
}

function ownedByCurrentUser(metadata) {
  return typeof process.getuid !== "function" || metadata.uid === process.getuid();
}

export async function inspectApiBinary(path) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = await handle.stat();
    if (
      !metadata.isFile() ||
      metadata.isSymbolicLink() ||
      !ownedByCurrentUser(metadata) ||
      metadata.nlink !== 1 ||
      metadata.size < 1 ||
      metadata.size > MAX_API_BINARY_BYTES ||
      (metadata.mode & 0o100) === 0 ||
      (metadata.mode & 0o7022) !== 0 ||
      (await realpath(path)) !== path
    ) {
      fail();
    }
    const content = await handle.readFile();
    return Object.freeze({
      sha256: createHash("sha256").update(content).digest("hex"),
      device: metadata.dev,
      inode: metadata.ino,
      mode: metadata.mode,
      size: metadata.size,
      modified_ms: metadata.mtimeMs,
    });
  } catch (error) {
    if (error instanceof Feat126S10ApiBinaryError) throw error;
    fail();
  } finally {
    await handle?.close();
  }
}

export function sameApiBinarySnapshot(left, right) {
  return (
    left?.sha256 === right?.sha256 &&
    left?.device === right?.device &&
    left?.inode === right?.inode &&
    left?.mode === right?.mode &&
    left?.size === right?.size &&
    left?.modified_ms === right?.modified_ms
  );
}
