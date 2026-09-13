import assert from "node:assert/strict";
import test from "node:test";
import {
  loadWorkflowLocal, validateWorkflowImages, validateWorkflowLifecycle,
  validateWorkflowLocal, validateWorkflowSecrets, validateWorkflowTopology,
  validateWorkflowState, validateWorkflowPgQualifier, validateWorkflowCasSource,
  validateWorkflowRebuildImages,
  validateWorkflowEditorOverlay, validateWorkflowEditorRegistration, validateWorkflowEditorReadiness,
} from "../scripts/workflow-local-model.mjs";

// Read the real candidate only. No Docker execution, synthetic executables,
// permission changes, failure injection, or hostile resource fixtures.
const model = await loadWorkflowLocal();

test("workflow stack has a stable private six-service data set and one loopback gateway", () => {
  assert.doesNotThrow(() => validateWorkflowTopology(model.compose));
});

test("workflow credentials stay in exact read-only files with separate native and Coze access", () => {
  assert.doesNotThrow(() => validateWorkflowSecrets(model.compose));
});

test("dependency and builder images retain the reviewed version, digest and local platform", () => {
  assert.doesNotThrow(() => validateWorkflowImages(model.images));
});

test("workflow lifecycle retains ownership and stops in dependency order without force escalation", () => {
  assert.doesNotThrow(() => validateWorkflowLifecycle(model.lifecycle, model.ignored));
});

test("normal reopening checks the port, records one epoch and derives authenticated readiness", () => {
  assert.doesNotThrow(() => validateWorkflowState(model.lifecycle));
});

test("build then reopen retains known old images for cleanup and requires current images for ready", () => {
  assert.doesNotThrow(() => validateWorkflowRebuildImages(model.lifecycle));
});

test("PG qualification has three private mounts, a fixed internal image and natural stop observation", () => {
  assert.doesNotThrow(() => validateWorkflowPgQualifier(model.lifecycle));
});

test("CAS qualification uses two normal concurrent saves and real source-validated readback", () => {
  assert.doesNotThrow(() => validateWorkflowCasSource(model.cas));
});

test("readiness probes use the real application entrypoints and migrations are explicit", () => {
  assert.deepEqual(model.compose.services["coze-workflow"].healthcheck.test, ["CMD", "/workflow-local-server", "-check-ready"]);
  assert.deepEqual(model.compose.services["workflow-api"].healthcheck.test, ["CMD", "/usr/local/bin/workflow-local-server", "--check-ready"]);
  assert.match(model.lifecycle, /\['-migrate-local'\]/);
  assert.match(model.lifecycle, /\['\/usr\/local\/bin\/workflow-local-migrate', 'up'\]/);
  assert.match(model.lifecycle, /'prepare-workflow-schema\.py'|'yijie-coze\/scripts\/yijie\/prepare-workflow-schema\.py'/);
  assert.doesNotMatch(model.lifecycle, /['"](?:--rm|--force-recreate|--renew-anon-volumes)['"]/);
});

test("the complete candidate satisfies the static review without claiming runtime qualification", () => {
  assert.doesNotThrow(() => validateWorkflowLocal(model));
});

test("editor overlay adds only one public read-only mount and three opt-in API inputs", () => {
  assert.doesNotThrow(() => validateWorkflowEditorOverlay(model.editor));
});

test("editor registration pins canonical bundle, independent candidate and consumer locks while stopped", () => {
  assert.doesNotThrow(() => validateWorkflowEditorRegistration(model.lifecycle));
});

test("editor readiness checks public bytes after existing authenticated API readiness", () => {
  assert.doesNotThrow(() => validateWorkflowEditorReadiness(model.lifecycle));
});
