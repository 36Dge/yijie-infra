import assert from "node:assert/strict";
import test from "node:test";
import { loadCompose, validateCompose } from "../scripts/compose-model.mjs";

test("local Compose model has isolated API and knowledge databases", async () => {
  const compose = await loadCompose();
  assert.doesNotThrow(() => validateCompose(compose));
  assert.deepEqual(compose.services.postgres.ports, ["5432:5432"]);
  assert.deepEqual(compose.services.pgvector.ports, ["5433:5432"]);
});
