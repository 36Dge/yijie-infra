import { lstat, open } from "node:fs/promises";

const MAX_RESULTS_BYTES = 128 * 1024;
const RESULT_KEYS = [
  "authorization_diff",
  "authorization_revision",
  "request_id",
  "role",
  "state_changed",
  "tenant_id",
  "user_id",
];
const EXPECTED = [
  ["12500000-0000-4000-8000-000000000001", "12500000-0000-4000-8000-100000000001", "tenant_owner"],
  ["12500000-0000-4000-8000-000000000001", "12500000-0000-4000-8000-100000000002", "tenant_member"],
  ["12500000-0000-4000-8000-000000000002", "12500000-0000-4000-8000-100000000001", "tenant_member"],
  ["12500000-0000-4000-8000-000000000002", "12500000-0000-4000-8000-100000000002", "tenant_owner"],
];
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function fail() {
  throw new Error("FEAT-126 S10 bootstrap results are invalid");
}

export function validateBootstrapResults(text) {
  if (typeof text !== "string" || Buffer.byteLength(text) > MAX_RESULTS_BYTES) fail();
  const lines = text.trimEnd().split("\n");
  if (lines.length !== 8 || lines.some((line) => line.length === 0)) fail();

  for (let index = 0; index < lines.length; index += 1) {
    let result;
    try {
      result = JSON.parse(lines[index]);
    } catch {
      fail();
    }
    if (result === null || Array.isArray(result) || typeof result !== "object") fail();
    if (JSON.stringify(Object.keys(result).sort()) !== JSON.stringify(RESULT_KEYS)) fail();
    if (!UUID_PATTERN.test(result.request_id.replace(/^feat-125-bootstrap-/, ""))) fail();

    const expected = EXPECTED[index % EXPECTED.length];
    if (result.user_id !== expected[0] || result.tenant_id !== expected[1] || result.role !== expected[2]) fail();
    if (!Array.isArray(result.authorization_diff) ||
        result.authorization_diff.some((entry) => typeof entry !== "string" || entry.length === 0)) fail();

    if (index < EXPECTED.length) {
      const expectedRevision = index < 2 ? 2 : 3;
      if (result.state_changed !== true || result.authorization_revision !== expectedRevision ||
          result.authorization_diff.length === 0) fail();
    } else if (result.state_changed !== false || result.authorization_revision !== 3 ||
               result.authorization_diff.length !== 0) {
      fail();
    }
  }

  return {
    schema_version: 1,
    profile: "feat-126-s10-local-lab",
    manifests: 4,
    executions: 8,
    changed: 4,
    unchanged: 4,
    final_authorization_revision: 3,
    content_classification: "synthetic_only",
  };
}

export async function validateBootstrapResultsFile(path) {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || metadata.size > MAX_RESULTS_BYTES) fail();
  const handle = await open(path, "r");
  try {
    return validateBootstrapResults(await handle.readFile("utf8"));
  } finally {
    await handle.close();
  }
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  if (process.argv.length !== 3) {
    process.stderr.write("usage: verify-feat-126-s10-bootstrap-results <results.jsonl>\n");
    process.exitCode = 2;
  } else {
    try {
      const summary = await validateBootstrapResultsFile(process.argv[2]);
      process.stdout.write(`${JSON.stringify(summary)}\n`);
    } catch {
      process.stderr.write("FEAT-126 S10 bootstrap result verification failed\n");
      process.exitCode = 1;
    }
  }
}
