import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

test("local API database preparation is exact idempotent and non-destructive", async () => {
  const script = await readFile(
    new URL("../scripts/prepare-feat-125-local-api-db.sh", import.meta.url),
    "utf8",
  );

  assert.match(script, /readonly database_name="yijie_api_feat125_local"/);
  assert.match(script, /readonly container_name="yijie-postgres"/);
  assert.match(script, /WHERE datname = 'yijie_api_feat125_local'/);
  assert.match(script, /createdb/);
  assert.match(script, /--owner "\$database_owner"/);
  assert.doesNotMatch(script, /dropdb|DROP DATABASE|docker volume|\brm\b|\bsource\b/);
});
