#!/usr/bin/env node
// FEAT-153 ordinary two-writer CAS qualification. No service lifecycle actions.
import { createHash, randomUUID } from "node:crypto";
import { constants, readFileSync } from "node:fs";
import { lstat, open } from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { execFileSync } from "node:child_process";
import { workflowValidators } from "../../yijie-contracts/scripts/workflow-schema-validator.mjs";

const workspace = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const contracts = path.join(workspace, "yijie-contracts");
const maxBytes = 524288;
class QualificationError extends Error {}
const require = (condition, message) => { if (!condition) throw new QualificationError(message); };

export function sourceValidators() {
  // These canonical commands are read-only and verify the actual providers'
  // current consumed artifacts; they never regenerate or rewrite their locks.
  for (const consumer of ["api", "coze"]) {
    execFileSync(process.execPath, [path.join(contracts, "scripts/sync-workflow-consumer.mjs"), consumer, "--check"], { stdio: "pipe" });
  }
  const original = process.cwd();
  try {
    process.chdir(contracts);
    return workflowValidators().components;
  } finally {
    process.chdir(original);
  }
}

async function credential(filePath) {
  require(typeof filePath === "string" && path.isAbsolute(filePath) && path.normalize(filePath) === filePath, "credential_path_invalid");
  const before = await lstat(filePath, { bigint: true });
  const valid = info => info.isFile() && info.uid === BigInt(process.geteuid()) && info.nlink === 1n && (info.mode & 0o777n) === 0o600n && info.size > 0n && info.size <= 1024n;
  const stable = (a, b) => valid(b) && a.dev === b.dev && a.ino === b.ino && a.mode === b.mode && a.uid === b.uid && a.gid === b.gid && a.size === b.size && a.mtimeNs === b.mtimeNs;
  require(valid(before), "credential_file_invalid");
  const file = await open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  let data;
  try {
    const descriptor = await file.stat({ bigint: true });
    require(stable(before, descriptor), "credential_file_changed");
    const buffer = Buffer.alloc(1025);
    let total = 0;
    while (total < buffer.length) {
      const { bytesRead } = await file.read(buffer, total, buffer.length - total, total);
      if (!bytesRead) break;
      total += bytesRead;
    }
    const after = await file.stat({ bigint: true });
    require(total <= 1024 && BigInt(total) === after.size && stable(descriptor, after) && stable(after, await lstat(filePath, { bigint: true })), "credential_file_changed");
    data = JSON.parse(buffer.subarray(0, total).toString("utf8"));
  } finally {
    await file.close();
  }
  const schema = JSON.parse(readFileSync(path.join(workspace, "yijie-api/config/workflow-local-runtime.schema.json"), "utf8"));
  require(data && typeof data === "object" && !Array.isArray(data) && JSON.stringify(Object.keys(data).sort()) === JSON.stringify([...schema.required].sort()), "credential_shape_invalid");
  for (const [key, definition] of Object.entries(schema.properties)) {
    require(definition.type === "integer" ? Number.isInteger(data[key]) : typeof data[key] === definition.type, "credential_shape_invalid");
    if (definition.const !== undefined) require(data[key] === definition.const, "credential_schema_version_invalid");
    if (definition.pattern) require(new RegExp(definition.pattern).test(data[key]), "credential_value_invalid");
  }
  return data;
}

function client(keys, validates) {
  return async function request(method, route, requestSchema, body, responseSchema, expectedStatus, editorSecret) {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    if (payload) require(payload.length <= maxBytes && validates[requestSchema]?.(body), "request_source_mismatch");
    const headers = { Authorization: "Bearer " + keys.token, "X-Yijie-Run-Epoch": keys.run_epoch };
    if (payload) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = payload.length;
    }
    if (editorSecret) headers["X-Yijie-Editor-Session"] = editorSecret;
    // node:http with a fixed host and independent sockets neither follows
    // redirects nor consults ambient proxy configuration.
    return new Promise((resolve, reject) => {
      const req = http.request({ hostname: "127.0.0.1", port: 18888, path: route, method, headers, agent: false }, res => {
        const parts = [];
        let size = 0;
        res.on("data", chunk => {
          size += chunk.length;
          if (size > maxBytes) res.destroy(new QualificationError("response_size_exceeded"));
          else parts.push(chunk);
        });
        res.once("error", () => reject(new QualificationError("response_unavailable")));
        res.once("end", () => {
          try {
            require(res.headers["content-type"] === "application/json" && res.headers["cache-control"] === "no-store", "response_headers_mismatch");
            const value = JSON.parse(Buffer.concat(parts).toString("utf8"));
            const status = res.statusCode;
            const name = status === 200 || status === 201 ? responseSchema : "ErrorResponse";
            require(validates[name]?.(value), "response_source_mismatch");
            require(expectedStatus.includes(status), "unexpected_http_status");
            resolve({ status, value });
          } catch {
            reject(new QualificationError("response_source_or_status_mismatch"));
          }
        });
      });
      req.setTimeout(40000, () => req.destroy(new QualificationError("request_deadline")));
      req.once("error", () => reject(new QualificationError("request_unavailable_query_original_operations")));
      req.end(payload);
    });
  };
}

export async function qualifyCAS(evidencePath) {
  require(process.env.YIJIE_ENV === "local" && process.env.YIJIE_LOCAL_PROFILE === "demo_fast" && process.env.YIJIE_WORKFLOW_ENABLED === "true" && process.env.YIJIE_API_SERVICE_PROFILE === "feat-153-workflow-local", "local_workflow_profile_required");
  require(path.isAbsolute(evidencePath) && path.normalize(evidencePath) === evidencePath, "absolute_evidence_path_required");
  const validates = sourceValidators();
  const keys = await credential(process.env.YIJIE_WORKFLOW_CREDENTIAL_FILE);
  const request = client(keys, validates);
  const artifact = {
    schema_version: 1, qualification: "ordinary_mysql_concurrent_cas", complete: false,
    source_lock_sha256: createHash("sha256").update(readFileSync(path.join(contracts, "compatibility/workflow-local/source.lock.json"))).digest("hex"),
    create_operation_id: randomUUID(), save_operation_ids: [randomUUID(), randomUUID()],
    workflow: null, observations: [], receipts: [], session_closed: false,
  };
  const out = await open(evidencePath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  let session;
  let failure;
  let interrupted = false;
  const onStop = () => { interrupted = true; };
  process.on("SIGINT", onStop);
  process.on("SIGTERM", onStop);
  const continueNormally = () => require(!interrupted, "normal_stop_requested");
  try {
    const { value: status } = await request("GET", "/v1/workflow-local/status", undefined, undefined, "ServiceStatus", [200]);
    require(status.ready && status.state === "ready" && status.protocol_version === 1 && status.run_epoch === keys.run_epoch, "service_not_ready");
    continueNormally();
    const { value: created } = await request("POST", "/v1/workflows", "CreateRequest", { name: "FEAT-153 普通并发 CAS W2 " + randomUUID().slice(0, 8), operation_id: artifact.create_operation_id }, "Workflow", [201]);
    artifact.workflow = created;
    artifact.original_revision = created.revision;
    continueNormally();
    session = (await request("POST", "/v1/workflow-local/editor-sessions", "EditorOpenRequest", { workflow_id: created.workflow_id }, "EditorSessionSecret", [201])).value;
    require(session.workflow_id === created.workflow_id && session.run_epoch === keys.run_epoch, "editor_scope_mismatch");
    const route = "/v1/workflows/" + encodeURIComponent(created.workflow_id);
    const saves = artifact.save_operation_ids.map((operation_id, index) => ({ name: created.name + (index === 0 ? " A" : " B"), canvas: created.canvas, expected_revision: created.revision, operation_id }));
    continueNormally();
    // Both requests start before awaiting either result; each uses its own TCP
    // socket. These are ordinary legal edits, not a injected database failure.
    const results = await Promise.allSettled(saves.map(save => request("PUT", route, "SaveRequest", save, "Workflow", [200, 409], session.secret)));
    artifact.observations = results.map((result, index) => ({ operation_id: saves[index].operation_id, transport_completed: result.status === "fulfilled", ...(result.status === "fulfilled" ? { http_status: result.value.status, ...(result.value.status === 409 ? { error_code: result.value.value.code } : { revision: result.value.value.revision }) } : {}) }));
    require(results.every(result => result.status === "fulfilled"), "cas_transport_unavailable_query_original_operations");
    const winner = results.findIndex(result => result.value.status === 200);
    const loser = results.findIndex(result => result.value.status === 409);
    require(winner >= 0 && loser >= 0 && winner !== loser, "cas_did_not_select_exactly_one_writer");
    const saved = results[winner].value.value;
    const conflict = results[loser].value.value;
    require(conflict.code === "revision_conflict" && conflict.operation_id === saves[loser].operation_id, "cas_conflict_receipt_identity_mismatch");
    require(saved.workflow_id === created.workflow_id && saved.revision !== created.revision && saved.name === saves[winner].name && saved.canvas === saves[winner].canvas, "cas_winner_content_mismatch");
    artifact.winner_operation_id = saves[winner].operation_id;
    artifact.loser_operation_id = saves[loser].operation_id;
    artifact.workflow = saved;
    continueNormally();
    const { value: readback } = await request("GET", route, undefined, undefined, "Workflow", [200]);
    require(readback.workflow_id === saved.workflow_id && readback.revision === saved.revision && readback.name === saved.name && readback.canvas === saved.canvas, "cas_persisted_draft_differs_from_winner");
    artifact.workflow = readback;
    for (const [id, phase] of [[artifact.create_operation_id, "completed"], [artifact.winner_operation_id, "completed"], [artifact.loser_operation_id, "rejected"]]) {
      continueNormally();
      const { value: receipt } = await request("GET", "/v1/workflow-local/operations/" + id, undefined, undefined, "OperationReceipt", [200]);
      require(receipt.operation_id === id && receipt.phase === phase && (receipt.workflow_id === undefined || receipt.workflow_id === created.workflow_id), "cas_operation_readback_mismatch");
      if (id === artifact.winner_operation_id) require(receipt.revision === saved.revision, "cas_winner_receipt_revision_mismatch");
      if (id === artifact.loser_operation_id) require(receipt.error?.code === "revision_conflict", "cas_rejected_receipt_reason_mismatch");
      artifact.receipts.push(receipt);
    }
    continueNormally();
    artifact.complete = true;
  } catch (error) {
    failure = error instanceof QualificationError ? error : new QualificationError("qualification_unavailable");
    artifact.failure = failure.message;
  } finally {
    if (session) {
      try {
        const { value: closed } = await request("DELETE", "/v1/workflow-local/editor-sessions/" + encodeURIComponent(session.session_id), undefined, undefined, "CloseResult", [200]);
        require(closed.closed === true, "session_close_not_confirmed");
        artifact.session_closed = true;
      } catch {
        failure ??= new QualificationError("normal_session_close_unavailable");
        artifact.failure = failure.message;
      }
    }
    session = undefined;
    artifact.complete = artifact.complete && artifact.session_closed && !failure;
    try {
      await out.writeFile(JSON.stringify(artifact, null, 2) + "\n");
      await out.sync();
    } finally {
      await out.close();
      process.off("SIGINT", onStop);
      process.off("SIGTERM", onStop);
    }
  }
  if (failure) throw failure;
  require(artifact.complete, "cas_qualification_incomplete");
  return artifact;
}

async function main() {
  const { values } = parseArgs({ options: { evidence: { type: "string" }, "check-source": { type: "boolean" } }, allowPositionals: false, strict: true });
  if (values["check-source"]) {
    require(!values.evidence, "choose_source_check_or_qualification");
    sourceValidators();
    console.log("CAS source/consumer validation: PASS; no credentials read or HTTP calls made");
    return;
  }
  require(typeof values.evidence === "string", "absolute_evidence_path_required");
  const result = await qualifyCAS(values.evidence);
  console.log("CAS_QUALIFICATION_PASS: workflow_id=" + result.workflow.workflow_id + "; one save committed, one ordinary revision conflict; original receipts read; E closed");
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  main().catch(error => {
    console.error("CAS_QUALIFICATION_INCOMPLETE:", error instanceof QualificationError ? error.message : "source_or_local_environment_unavailable");
    process.exitCode = 1;
  });
}
