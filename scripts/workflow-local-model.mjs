import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import YAML from "yaml";

export const WORKFLOW_PROJECT = "yijie-feat153-workflow";
export const WORKFLOW_SERVICES = Object.freeze([
  "workflow-postgres", "coze-workflow-mysql", "coze-workflow-redis",
  "coze-workflow-minio", "coze-workflow", "workflow-api",
]);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const IMAGE_VARIABLES = Object.freeze({
  "workflow-postgres": "POSTGRES_IMAGE", "coze-workflow-mysql": "MYSQL_IMAGE",
  "coze-workflow-redis": "REDIS_IMAGE", "coze-workflow-minio": "MINIO_IMAGE",
  "coze-workflow": "COZE_IMAGE", "workflow-api": "API_IMAGE",
});
const PRIVATE_MOUNTS = Object.freeze({
  "workflow-postgres": ["postgres-password"],
  "coze-workflow-mysql": ["mysql-root-password", "mysql-password"],
  "coze-workflow-redis": ["redis.conf", "redis-password"],
  "coze-workflow-minio": ["minio-access", "minio-secret"],
  "coze-workflow": ["k-ac.json", "mysql-dsn", "redis-password", "minio-access", "minio-secret"],
  "workflow-api": ["k-na.json", "k-ac.json", "postgres-dsn"],
});
const PERSISTENCE = Object.freeze({
  "workflow-postgres": "postgres-data:/var/lib/postgresql/data",
  "coze-workflow-mysql": "mysql-data:/var/lib/mysql",
  "coze-workflow-redis": "redis-data:/data",
  "coze-workflow-minio": "minio-data:/data",
});
const REVIEWED_IMAGES = Object.freeze({
  go: "golang:1.26.5-bookworm", postgres: "postgres:16.13-alpine",
  mysql: "mysql:8.4.5", redis: "redis:8.0.3-alpine",
  minio: "quay.io/minio/minio:RELEASE.2025-06-13T11-33-47Z",
});
const ENVIRONMENT_KEYS = Object.freeze({
  "workflow-postgres": ["POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD_FILE"],
  "coze-workflow-mysql": ["MYSQL_DATABASE", "MYSQL_USER", "MYSQL_ROOT_PASSWORD_FILE", "MYSQL_PASSWORD_FILE"],
  "coze-workflow-redis": [],
  "coze-workflow-minio": ["MINIO_ROOT_USER_FILE", "MINIO_ROOT_PASSWORD_FILE"],
  "coze-workflow": ["YIJIE_ENV", "YIJIE_LOCAL_PROFILE", "YIJIE_WORKFLOW_ENABLED", "YIJIE_WORKFLOW_NETWORK_SCOPE", "YIJIE_WORKFLOW_COZE_LISTEN_ADDR", "YIJIE_WORKFLOW_COZE_CREDENTIAL_FILE", "YIJIE_WORKFLOW_MYSQL_DSN_FILE", "YIJIE_WORKFLOW_REDIS_PASSWORD_FILE", "YIJIE_WORKFLOW_MINIO_ACCESS_FILE", "YIJIE_WORKFLOW_MINIO_SECRET_FILE", "REDIS_ADDR", "MINIO_ENDPOINT", "STORAGE_BUCKET"],
  "workflow-api": ["YIJIE_ENV", "YIJIE_LOCAL_PROFILE", "YIJIE_WORKFLOW_ENABLED", "YIJIE_API_SERVICE_PROFILE", "YIJIE_WORKFLOW_NETWORK_SCOPE", "YIJIE_WORKFLOW_CREDENTIAL_FILE", "YIJIE_WORKFLOW_COZE_CREDENTIAL_FILE", "YIJIE_WORKFLOW_POSTGRES_DSN_FILE", "YIJIE_WORKFLOW_COZE_URL"],
});

function require(ok, message) {
  if (!ok) throw new Error(message);
}
function exact(actual, expected, label) {
  require(Array.isArray(actual) && actual.length === expected.length &&
    [...actual].sort().every((item, i) => item === [...expected].sort()[i]), `${label} differs from the reviewed boundary`);
}
function equal(actual, expected, label) {
  require(JSON.stringify(actual) === JSON.stringify(expected), `${label} differs from the reviewed boundary`);
}

export async function loadWorkflowLocal(root = ROOT) {
  const [composeText, lifecycle, lockText, ignored, cas, editorText] = await Promise.all([
    readFile(path.join(root, "compose/workflow-local.yml"), "utf8"),
    readFile(path.join(root, "scripts/workflow-local.py"), "utf8"),
    readFile(path.join(root, "config/workflow-local/images.lock.json"), "utf8"),
    readFile(path.join(root, ".gitignore"), "utf8"),
    readFile(path.join(root, "scripts/workflow-local-cas.mjs"), "utf8"),
    readFile(path.join(root, "compose/workflow-editor.yml"), "utf8"),
  ]);
  // YAML merge is explicit: the security/lifecycle anchor must actually be evaluated.
  return { compose: YAML.parse(composeText, { merge: true }), lifecycle, images: JSON.parse(lockText), ignored, cas, editor: YAML.parse(editorText) };
}

export function validateWorkflowTopology(compose) {
  require(compose?.name === WORKFLOW_PROJECT, "Use the stable dedicated workflow project, not a run-specific data namespace");
  exact(Object.keys(compose.services ?? {}), WORKFLOW_SERVICES, "Workflow services");
  exact(Object.keys(compose.networks ?? {}), ["workflow-private", "workflow-edge"], "Workflow networks");
  equal(compose.networks["workflow-private"], { internal: true }, "Private network");
  equal(compose.networks["workflow-edge"], { driver: "bridge", driver_opts: { "com.docker.network.bridge.host_binding_ipv4": "127.0.0.1" } }, "Dedicated loopback gateway bridge");
  exact(Object.keys(compose.volumes ?? {}), ["postgres-data", "mysql-data", "redis-data", "minio-data"], "Persistent volumes");
  for (const volume of Object.values(compose.volumes)) {
    require(volume === null || Object.keys(volume).length === 0, "Volumes must remain project-scoped and cannot adopt external data");
  }
  for (const name of WORKFLOW_SERVICES) {
    const service = compose.services[name];
    exact(service.networks, name === "workflow-api" ? ["workflow-private", "workflow-edge"] : ["workflow-private"], `${name} networks`);
    exact(service.ports ?? [], name === "workflow-api" ? ["127.0.0.1:18888:18888"] : [], `${name} host ports`);
    require(service.container_name === undefined && service.network_mode === undefined && service.pid === undefined && service.ipc === undefined,
      `${name} must use project-scoped container and namespace isolation`);
    require(service.privileged !== true && service.devices === undefined && service.extra_hosts === undefined,
      `${name} cannot acquire host access`);
    require(service.restart === "no" && service.stop_signal === "SIGTERM", `${name} must have explicit normal lifecycle control`);
    exact(service.security_opt, ["no-new-privileges:true"], `${name} security options`);
    equal(service.labels, {
      "ai.yijie.feature": "FEAT-153", "ai.yijie.dataset": "workflow-local-v1",
      "ai.yijie.run-epoch": "${WORKFLOW_EPOCH:?required}",
    }, `${name} owner labels`);
    require(service.image?.startsWith("${" + IMAGE_VARIABLES[name] + ":?") && service.image.endsWith("}"), `${name} requires an image from the reviewed lock/build state`);
    require(service.build === undefined && service.env_file === undefined, `${name} cannot silently build or import another environment`);
    exact(Object.keys(service.environment ?? {}), ENVIRONMENT_KEYS[name], `${name} environment inputs`);
    if (name !== "coze-workflow-redis") require(service.entrypoint === undefined, `${name} must retain its locked image entrypoint`);
    require(Array.isArray(service.healthcheck?.test) && service.healthcheck.test.length > 1 &&
      service.healthcheck.disable !== true && service.healthcheck.interval && service.healthcheck.timeout,
    `${name} requires a bounded health probe`);
    require(/^(?:512m|1g|2g)$/.test(String(service.mem_limit)), `${name} requires the reviewed memory bound`);
  }
  equal(compose.services["coze-workflow"].depends_on, {
    "coze-workflow-mysql": { condition: "service_healthy" },
    "coze-workflow-redis": { condition: "service_healthy" },
    "coze-workflow-minio": { condition: "service_healthy" },
  }, "Coze dependencies");
  equal(compose.services["workflow-api"].depends_on, {
    "workflow-postgres": { condition: "service_healthy" }, "coze-workflow": { condition: "service_healthy" },
  }, "API dependencies");
}

export function validateWorkflowSecrets(compose) {
  for (const name of WORKFLOW_SERVICES) {
    const service = compose.services[name];
    const target = ["workflow-api", "coze-workflow"].includes(name) ? "/run/workflow-private/" : "/run/private/";
    const mounts = PRIVATE_MOUNTS[name].map(file => "${WORKFLOW_PRIVATE:?required}/" + file + ":" + target + file + ":ro");
    if (PERSISTENCE[name]) mounts.push(PERSISTENCE[name]);
    if (name === "coze-workflow-mysql") mounts.push("${WORKFLOW_GENERATED:?required}/upstream-schema.sql:/docker-entrypoint-initdb.d/001-upstream.sql:ro");
    exact(service.volumes, mounts, `${name} mounts`);
    for (const [key, value] of Object.entries(service.environment ?? {})) {
      if (/(?:PASSWORD|SECRET|CREDENTIAL|DSN|ACCESS)/.test(key)) {
        require(key.endsWith("_FILE") && typeof value === "string" && value.startsWith(target), `${name} must receive private inputs only through the specific file mount`);
        require(mounts.some(mount => mount.endsWith(":" + value + ":ro")), `${name} private input must have its own read-only mount`);
      }
    }
    exact(service.cap_add ?? [], name === "coze-workflow-redis" ? ["DAC_OVERRIDE"] : [], `${name} additional capabilities`);
  }
  const redis = compose.services["coze-workflow-redis"];
  require(redis.user === "0:0", "Redis uses the explicitly reviewed root reader for owner-only private files");
  exact(redis.cap_drop, ["ALL"], "Redis capability reduction");
  equal(redis.entrypoint, ["redis-server"], "Redis normal executable entrypoint");
  equal(redis.command, ["/run/private/redis.conf"], "Redis private config path");
  for (const name of ["workflow-api", "coze-workflow"]) {
    const service = compose.services[name];
    require(service.user === "${WORKFLOW_UID:?required}:${WORKFLOW_GID:?required}", `${name} must match the private file owner`);
    require(service.read_only === true, `${name} needs a read-only root filesystem`);
    exact(service.cap_drop, ["ALL"], `${name} capabilities`);
    require(service.tmpfs?.length === 1 && /^\/tmp:rw,noexec,nosuid,size=(?:32|64)m$/.test(service.tmpfs[0]), `${name} only has the bounded temporary mount`);
    for (const [key, value] of Object.entries({ YIJIE_ENV: "local", YIJIE_LOCAL_PROFILE: "demo_fast", YIJIE_WORKFLOW_ENABLED: "true", YIJIE_WORKFLOW_NETWORK_SCOPE: "container" })) {
      require(service.environment?.[key] === value, `${name} must use the exact opt-in environment`);
    }
  }
  require(compose.services["coze-workflow"].environment.YIJIE_WORKFLOW_CREDENTIAL_FILE === undefined,
    "Coze must never receive the native-to-API credential");
  require(compose.services["workflow-api"].environment.YIJIE_API_SERVICE_PROFILE === "feat-153-workflow-local" &&
    compose.services["workflow-api"].environment.YIJIE_WORKFLOW_COZE_URL === "http://coze-workflow:18889", "API profile and upstream are fixed");
  require(compose.services["coze-workflow"].environment.YIJIE_WORKFLOW_COZE_LISTEN_ADDR === "0.0.0.0:18889", "Coze internal container listener must be reachable without host publication");
  require(compose.services["workflow-postgres"].environment.POSTGRES_DB === "yijie_workflow_local" &&
    compose.services["coze-workflow-mysql"].environment.MYSQL_DATABASE === "coze_workflow_local", "Database names must remain dedicated");
}

export function validateWorkflowImages(lock) {
  require(lock?.schema_version === 1 && lock.feature === "FEAT-153", "Image lock identity is required");
  exact(Object.keys(lock.images ?? {}), Object.keys(REVIEWED_IMAGES), "Image lock entries");
  for (const [name, version] of Object.entries(REVIEWED_IMAGES)) {
    const pin = lock.images[name];
    require(pin.reference?.startsWith(version + "@sha256:") && /^[a-f0-9]{64}$/.test(pin.reference.slice((version + "@sha256:").length)), `${name} requires the reviewed vendor/version and immutable digest`);
    require(/^sha256:[a-f0-9]{64}$/.test(pin.image_id) && pin.architecture === "arm64" && pin.os === "linux", `${name} requires an exact local image ID and platform record`);
  }
}

export function validateWorkflowLifecycle(source, ignored) {
  // Narrow static guards for this reviewed controller; these complement manual
  // control-flow review and do not claim to prove arbitrary Python semantics.
  require(source.includes("PROJECT = '" + WORKFLOW_PROJECT + "'"), "Lifecycle project identity must match Compose");
  require(source.includes("SERVICES = " + JSON.stringify(WORKFLOW_SERVICES).replaceAll('"', "'").replaceAll(",", ", ")),
    "Lifecycle service set must match the reviewed six-service model");
  require(source.includes("'environments/local/generated/feat-153'") && /^environments\/local\/generated\/$/m.test(ignored), "All generated credentials/state/logs must remain ignored");
  require(source.includes("os.O_NOFOLLOW") && source.includes("os.O_EXCL") && source.includes("0o600") && source.includes("secrets.token_hex(32)"), "Private artifacts require owner-only creation and runtime random secrets");
  require(source.includes("stat.S_ISREG") && source.includes("st_uid == os.geteuid()") && source.includes("st_nlink == 1"), "Private reads need file identity checks");
  require(source.includes("'--host', SOCKET") && source.includes("'DOCKER_HOST'") && source.includes("'DOCKER_CONTEXT'") && source.includes("env.pop(key, None)"), "Docker calls must use the fixed local socket without inherited remote context");
  require(source.includes("Path.home() / 'Applications/Docker.app'") && source.includes("Path('/Applications/Docker.app')") && source.includes("'Contents/Resources/bin/docker'") && source.includes("'Contents/Resources/cli-plugins/docker-compose'"), "Lifecycle must use either original Docker Desktop bundle without a PATH fallback");
  require(source.includes("'--project-name', PROJECT") && source.includes("'compose/workflow-local.yml'"), "Compose calls must be constrained to this project and source file");
  require(source.includes("'--no-recreate'") && source.includes("'--pull', 'never'"), "Startup cannot implicitly replace containers or pull floating images");
  require(source.includes("['stop', '--signal', 'SIGTERM', '--timeout', '-1', *targets]"), "Stop must use explicit SIGTERM and unlimited grace on exact container IDs");
  require(source.includes("for stage in [['workflow-api'], ['coze-workflow'], DEPS]"), "Dependencies must stay alive while API and native engine drain");
  require(source.includes("except subprocess.TimeoutExpired:") && source.includes("STOP_PENDING") && source.includes("'pending_stop'") && source.includes("'containers': targets"), "A bounded observation must retain the normal stop operation identity");
  require(source.includes("validate_owned(items, state") && source.includes("item['id'] in prior") && source.includes("labels.get('ai.yijie.run-epoch') == state['run_epoch']"), "Actions must validate recorded owned container IDs and epoch");
  require(source.includes("labels.get('com.docker.compose.project') == PROJECT") && source.includes("item['image_id'] == expected"), "Ownership must also match the project and exact expected image");
  require(source.includes("c['state']['OOMKilled']") && source.includes("c['state']['ExitCode'] != 0"), "Normal stop cannot be claimed for OOM or nonzero exits");
  require(source.includes("sock.bind(('127.0.0.1', 18888))") && source.includes("sock.close()"), "Port conflict detection must not replace the existing listener");
  require(source.includes("'--label', 'ai.yijie.source-digest='") && source.includes("candidate(folder) == digest") && source.includes("local['Id'] == item['image_id']"), "Activation must use verified image IDs and unchanged source candidates");
  require(!/\b(?:os\.kill|os\.killpg|\w+\.kill|\w+\.terminate)\s*\(/.test(source), "Lifecycle cannot force or signal arbitrary host processes");
  require(!/['"](?:kill|prune|down|--force|--force-recreate|--remove-orphans|--volumes|--renew-anon-volumes|--abort-on-container-exit|--abort-on-container-failure)['"]/.test(source), "Lifecycle cannot force-stop, recreate, or remove shared/persistent data");
  require(!/subprocess\.run\([^\n]*\btimeout\s*=/.test(source), "subprocess.run timeouts must not kill CLI children");
  require(!/(?:shell\s*=\s*True|os\.system\s*\(|os\.chmod\s*\(|os\.chown\s*\()/.test(source), "Lifecycle must not use shell execution or alter existing permissions");
  require(!/print\([^\n]*(?:secret|token|password|dsn|result\.stdout|values)/i.test(source.replace(/^\s*print\((?:'[^'\n]*'|"[^"\n]*")\)\s*$/gm, "")), "Lifecycle must not print credential values or unfiltered command output");
}

function pythonFunction(source, name) {
  const start = source.indexOf("\ndef " + name + "(");
  require(start >= 0, `Reviewed controller function ${name} is missing`);
  const next = source.indexOf("\ndef ", start + 1);
  return source.slice(start, next < 0 ? undefined : next);
}

export function validateWorkflowState(source) {
  const up = pythonFunction(source, "up");
  require(up.indexOf("require_free_port()") >= 0 && up.indexOf("require_free_port()") < up.indexOf("output(['rm'"), "Port preflight must precede any removal or credential rotation");
  require(up.indexOf("c['state']['OOMKilled']") < up.indexOf("output(['rm'") && up.indexOf("c['state']['ExitCode'] != 0") < up.indexOf("output(['rm'"), "Abnormal exited containers must remain available before reopening");
  const rotation = up.slice(up.indexOf("state['run_epoch'] ="));
  require(rotation.includes("state['credentials_pending'] = True") && rotation.indexOf("write_json(STATE, state)") < rotation.indexOf("complete_credentials(state)"), "The selected new epoch must be recorded before rotating credential files");
  const pair = pythonFunction(source, "credential_pair");
  require(pair.includes("item['run_epoch'] == state['run_epoch']") && pair.includes("result[0]['token'] != result[1]['token']"), "Both private credentials must match state and remain independent");
  const writer = pythonFunction(source, "private_write");
  require(writer.includes("os.fsync(out.fileno())") && writer.includes("os.replace(temporary, path)") && !writer.includes("os.O_TRUNC"), "Private state and credentials must use complete atomic replacement");
  const ready = pythonFunction(source, "observed_ready");
  require(ready.includes("for service in SERVICES") && ready.includes("com.docker.compose.oneoff") && ready.includes("'healthy'") && ready.includes("HTTPConnection('127.0.0.1', 18888, timeout=3)"), "Ready requires every primary service and the real fixed host gateway");
  require(ready.includes("'/v1/workflow-local/status'") && ready.includes("'Authorization': 'Bearer '") && ready.includes("status.get('run_epoch') == state['run_epoch']") && ready.includes("status.get('ready') is True"), "Host readiness must use the source status fields and this epoch's machine identity");
  const logged = pythonFunction(source, "run_logged");
  require(logged.includes("state['active_child']") && logged.includes("process.pid") && logged.includes("while True:") && logged.includes("except KeyboardInterrupt:"), "A normal interruption must retain child identity and wait before recording owned IDs");
  const popen = source.split("\n").filter(line => line.includes("subprocess.Popen("));
  require(popen.length === 2 && popen.every(line => line.includes("start_new_session=True")), "CLI processes must not inherit terminal cancellation signals");
  require(pythonFunction(source, "run_owned").includes("finally:") && pythonFunction(source, "run_owned").includes("record(state, allow_new=True)"), "Owned lifecycle operations must record created IDs on completion");
}

export function validateWorkflowPgQualifier(source) {
  const qualifier = pythonFunction(source, "qualify_pg");
  const ownership = pythonFunction(source, "validate_owned");
  const stop = pythonFunction(source, "stop");
  require(ownership.includes("service in [*SERVICES, 'workflow-pg-test']") && pythonFunction(source, "expected_image").includes("'workflow-pg-test': 'api-test'"), "PG runner is a separately owned auxiliary service with the exact test image");
  require(qualifier.includes("observed_ready(state, items)") && qualifier.includes("secure_read(artifact, 524288)") && qualifier.includes("evidence.get('complete') is True"), "PG qualification requires current readiness and bounded completed HTTP evidence");
  require(qualifier.includes("for source in ['k-na.json', 'k-ac.json', 'postgres-dsn']") && qualifier.includes("',dst=/run/workflow-private/' + source + ',readonly'"), "PG runner receives exactly the three reviewed private files read-only");
  require(qualifier.includes("network = PROJECT + '_workflow-private'") && qualifier.includes("get('Internal') is True") && qualifier.includes("get('com.docker.compose.project') == PROJECT"), "PG runner network must be the verified owned internal network");
  for (const option of ["'--pull', 'never'", "'--restart', 'no'", "'--user'", "'--read-only'", "'--cap-drop', 'ALL'", "'--security-opt', 'no-new-privileges:true'", "'--memory', '2g'", "'--cpus', '2'", "'--pids-limit', '256'", "'/tmp:rw,exec,nosuid,nodev,size=1g,mode=1777'"]) {
    require(qualifier.includes(option), "PG runner is missing a reviewed resource or isolation boundary");
  }
  require(qualifier.includes("args.append(build['image_id'])") && qualifier.includes("'GOPROXY': 'off'") && qualifier.includes("'GOSUMDB': 'off'"), "PG tests use the exact built image and cached dependencies without downloads");
  require(!/['"](?:--rm|--publish|-p|--privileged|--cap-add|--entrypoint)['"]/.test(qualifier), "PG qualification cannot broaden execution or remove its container");
  require(qualifier.includes("finally:") && qualifier.includes("own[0]['state']['ExitCode'] == 0") && qualifier.includes("not own[0]['state']['OOMKilled']"), "PG pass requires the retained container's actual normal exit");
  require(stop.indexOf("while any(") >= 0 && stop.indexOf("'workflow-pg-test'") < stop.indexOf("for stage in"), "The controller must first observe PG completion naturally");
  require(stop.includes("time.monotonic() + 20") && stop.includes("PG qualification is still finishing normally"), "PG observation timeout cannot escalate to a stop signal");
}

export function validateWorkflowRebuildImages(source) {
  const ownership = pythonFunction(source, "validate_owned");
  require(ownership.includes("prior = {i['id']: i for i in state.get('containers', [])}") && ownership.includes("recorded = prior.get(item['id'])"), "Ownership must retain the recorded immutable image for each known container ID");
  require(ownership.includes("recorded['image_id'] if recorded is not None else expected_image(service, state)") && ownership.includes("require(allow_new or item['id'] in prior"), "Known containers can be cleaned after rebuild; unknown containers still require explicit admission and the new image");
  require(ownership.includes("recorded['labels'].get('com.docker.compose.service') == service") && ownership.includes("labels.get('ai.yijie.run-epoch') == state['run_epoch']"), "Recorded image handling cannot weaken service or epoch ownership");
  require(pythonFunction(source, "observed_ready").includes("primary[0]['image_id'] != expected_image(service, state)"), "A recorded old container cannot claim readiness for a newly built candidate");
}

export function validateWorkflowCasSource(source) {
  require(source.includes("workflow-schema-validator.mjs") && source.includes('consumer, "--check"'), "CAS qualification must use canonical source validation and consumer checks");
  require(source.includes('hostname: "127.0.0.1", port: 18888') && source.includes("agent: false"), "CAS writers require the fixed gateway and independent normal sockets");
  require(source.includes("save_operation_ids: [randomUUID(), randomUUID()]") && source.includes("expected_revision: created.revision") && source.includes("Promise.allSettled(saves.map("), "CAS must compare two ordinary writes to the same initial revision");
  require(source.includes('conflict.code === "revision_conflict"') && source.includes("readback.revision === saved.revision") && source.includes('artifact.loser_operation_id, "rejected"'), "CAS must read back the winner and both real operation outcomes");
  require(source.includes('request("DELETE", "/v1/workflow-local/editor-sessions/"') && source.includes("artifact.complete && artifact.session_closed && !failure"), "CAS pass requires normal session cleanup");
  require(source.includes('if (values["check-source"])') && source.includes("sourceValidators();"), "CAS needs a read-only source-check entrypoint");
  require(!/artifact\.(?:secret|token|headers|session)\s*=/.test(source), "CAS artifact must never persist credentials or raw session data");
}

export function validateWorkflowEditorOverlay(overlay) {
  exact(Object.keys(overlay), ["services"], "Editor overlay top-level fields");
  exact(Object.keys(overlay.services ?? {}), ["workflow-api"], "Editor overlay services");
  const api = overlay.services["workflow-api"];
  exact(Object.keys(api), ["environment", "volumes"], "Editor overlay API fields");
  equal(api.environment, {
    YIJIE_WORKFLOW_EDITOR_ENABLED: "true",
    YIJIE_WORKFLOW_EDITOR_BUNDLE_DIR: "/opt/yijie/workflow-editor",
    YIJIE_WORKFLOW_EDITOR_MANIFEST_SHA256: "${WORKFLOW_EDITOR_MANIFEST_SHA256:?registered editor required}",
  }, "Editor deployment environment");
  equal(api.volumes, [{ type: "bind", source: "${WORKFLOW_EDITOR_BUNDLE:?registered editor required}",
    target: "/opt/yijie/workflow-editor", read_only: true, bind: { create_host_path: false } }], "Editor public asset mount");
}

export function validateWorkflowEditorRegistration(source) {
  const register = pythonFunction(source, "editor");
  require(register.includes("state['phase'] == 'stopped'") && register.includes("c['state']['Running']") && register.includes("c['state']['OOMKilled']") && register.includes("c['state']['ExitCode'] != 0"), "Editor registration requires normal completed shutdown");
  require(register.includes("state.setdefault('editor_registrations', [])") && register.includes("registered = editor_snapshot(state)") && register.includes("render(state)"), "Editor registration must retain canonical bundle evidence and render only after validation");
  require(!/credentials\(|complete_credentials\(|PRIVATE|docker_args\(|compose_args\(/.test(register), "Editor registration cannot rotate credentials or invoke service lifecycle operations");
  const snapshot = pythonFunction(source, "editor_snapshot");
  for (const text of ["config/workflow-editor-assets.schema.json", "schema['required']", "files_spec['items']['required']", "limits['total_asset_bytes']", "fields['path']['pattern']", "len(content) == asset['bytes']", "hashlib.sha256(content).hexdigest() == asset['sha256']", "'scripts/yijie/workflow-editor.mjs'), 'check'", "['api', 'coze', 'desktop']", "consumer, '--check'", "compatibility/workflow-local/source.lock.json", "'manifest_source_digest': manifest['source_digest']", "'coze_candidate': sampled_candidate", "candidate(coze) == sampled_candidate", "'consumer_lock_sha256': consumer_hashes"]) {
    require(snapshot.includes(text), "Editor registration is missing an authoritative artifact/source verification boundary");
  }
  require(snapshot.includes("sampled_candidate = candidate(coze)") && snapshot.includes("manifest['source_commit'] == commit"), "Bundle provenance needs an independent current candidate and base commit");
  const reader = pythonFunction(source, "public_bytes");
  require(reader.includes("os.O_NOFOLLOW") && reader.includes("path.resolve() == path") && reader.includes("signature(before) == signature(after) == signature(current)"), "Public artifact reads must keep path, descriptor and byte stability");
  const verify = pythonFunction(source, "verify_editor");
  require(verify.includes("if registered is None:") && verify.includes("editor_snapshot(state) == registered"), "Only registered bundles require exact repeat verification");
  for (const name of ["build", "up"]) {
    const phase = pythonFunction(source, name);
    require(phase.split("verify_editor(state)").length === 3, `${name} must verify editor provenance before and after normal execution`);
    require(phase.indexOf("verify_editor(state)") < phase.indexOf("verify_images()"), `${name} must reject editor drift before image or service activation`);
  }
  const compose = pythonFunction(source, "compose_args");
  require(compose.includes("if read_state().get('editor') is not None:") && compose.includes("files += ['-f', str(EDITOR_OVERLAY)]"), "The extra Compose file must remain explicitly registration-gated");
  require(source.includes("EDITOR_BUNDLE = WORKSPACE / 'yijie-coze/bin/workflow-editor/dist'") && source.includes("EDITOR_OVERLAY = ROOT / 'compose/workflow-editor.yml'"), "Editor artifacts and overlay cannot be caller-selected paths");
}

export function validateWorkflowEditorReadiness(source) {
  const ready = pythonFunction(source, "observed_ready");
  require(ready.includes("status.get('state') == 'ready' and observed_editor(state)"), "Editor readiness must follow the existing authenticated source status");
  const editorReady = pythonFunction(source, "observed_editor");
  require(editorReady.includes("if registered is None:") && editorReady.includes("return True"), "API-only default must retain existing readiness");
  for (const text of ["HTTPConnection('127.0.0.1', 18888, timeout=3)", "connection.request('GET', '/editor/'", "response.read(entry['bytes'] + 1)", "hashlib.sha256(body).hexdigest() == entry['sha256']", "'Cache-Control': 'no-store'", "'X-Content-Type-Options': 'nosniff'", "connect-src 'none'", "frame-ancestors http://localhost:1420 tauri://localhost", "connection.close()"]) {
    require(editorReady.includes(text), "Editor readiness must verify the fixed public response, digest and security policy");
  }
  require(!/Authorization|token|credential_pair|PRIVATE/.test(editorReady), "Public editor readiness cannot send a machine or editor credential");
}

export function validateWorkflowLocal(model) {
  validateWorkflowTopology(model.compose);
  validateWorkflowSecrets(model.compose);
  validateWorkflowImages(model.images);
  validateWorkflowLifecycle(model.lifecycle, model.ignored);
  validateWorkflowState(model.lifecycle);
  validateWorkflowPgQualifier(model.lifecycle);
  validateWorkflowRebuildImages(model.lifecycle);
  validateWorkflowCasSource(model.cas);
  validateWorkflowEditorOverlay(model.editor);
  validateWorkflowEditorRegistration(model.lifecycle);
  validateWorkflowEditorReadiness(model.lifecycle);
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    validateWorkflowLocal(await loadWorkflowLocal());
    console.log("FEAT-153 workflow static model passed; Docker/runtime readiness was not executed.");
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
