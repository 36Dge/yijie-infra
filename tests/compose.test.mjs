import assert from "node:assert/strict";
import test from "node:test";
import { loadCompose, validateCompose } from "../scripts/compose-model.mjs";

test("local Compose model has isolated API and knowledge databases", async () => {
  const compose = await loadCompose();
  assert.doesNotThrow(() => validateCompose(compose));
  assert.deepEqual(compose.services.postgres.ports, ["127.0.0.1:5432:5432"]);
  assert.deepEqual(compose.services.redis.ports, ["127.0.0.1:6379:6379"]);
  assert.deepEqual(compose.services.pgvector.ports, ["127.0.0.1:5433:5432"]);
  assert.ok(compose.services.pgvector.volumes.some((volume) => volume.includes("001-enable-vector.sql")));
});
