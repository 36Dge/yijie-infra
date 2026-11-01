#!/usr/bin/env python3
"""Routine desktop lifecycle v1: original containers, no backup or task replay.

The fixed desktop entry owns this interface. The reviewed recovery controller
and its explicit protective-copy path remain separate and unchanged.
"""
import argparse
import fcntl
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("workflow_session_controller", ROOT / "scripts/workflow-local.py")
ctl = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ctl
spec.loader.exec_module(ctl)
sys.path.insert(0, str(ROOT / "scripts"))
import workflow_recovery as review

SESSION = ctl.GENERATED / "desktop-session.json"
EVENTS = ctl.GENERATED / "desktop-session-events.jsonl"
V1_SOURCE = "d9cd7937c9bb853726efd4a6cd4c8b9fa2a7a72ee5c3f8e6be5c2b79ba989bd8"
SOURCE_KEY = "yijie-infra/scripts/workflow-session.py"


def configuration_hash(config, host):
    # Docker restores omitted DNS lists as [] when the daemon opens existing
    # containers. Only these three empty-list encodings are equivalent. Real
    # DNS entries and every other configuration field still affect the hash.
    host = dict(host)
    for key in ("Dns", "DnsOptions", "DnsSearch"):
        if key in host and host[key] is None:
            host[key] = []
    return review.digest(review.canonical({"config": config, "host": host}))


def identity_details(items):
    identities, legacy = {}, {}
    for item in json.loads(ctl.output(["inspect", *[c["id"] for c in items]])):
        config, host = item["Config"], item["HostConfig"]
        identities[item["Id"]] = {"image_id": item["Image"], "configuration_sha256": configuration_hash(config, host),
                                  "networks": {name: v["NetworkID"] for name, v in item["NetworkSettings"]["Networks"].items()}}
        old_host = dict(host)
        for key in ("Dns", "DnsOptions", "DnsSearch"):
            if old_host.get(key) == []:
                old_host[key] = None
        legacy[item["Id"]] = {review.digest(review.canonical({"config": config, "host": host})),
                              review.digest(review.canonical({"config": config, "host": old_host}))}
    return identities, legacy


def boot_session():
    return subprocess.check_output(["/usr/sbin/sysctl", "-n", "kern.boottime"], text=True).strip()


def save_session(phase, value):
    ctl.write_json(SESSION, {"phase": phase, "boot_session": boot_session(), "snapshot": value})


def event(name, **fields):
    # Bounded lifecycle facts only; no query rows or credential values.
    import os
    fd = os.open(EVENTS, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as out:
        out.write(json.dumps({"event": name, "at_ms": int(time.time() * 1000), **fields}) + "\n")
        out.flush()
        os.fsync(out.fileno())


def snapshot(state, items):
    sources = review.sources(ctl)
    sources[SOURCE_KEY] = review.digest(Path(__file__).read_bytes())
    return {"schema_version": 2, "run_epoch": state["run_epoch"],
            "containers": sorted(c["id"] for c in items),
            "primaries": {s: c["id"] for s, c in review.select_primaries(ctl, items).items()},
            "identities": identity_details(items)[0], "bound_files": review.bound_files(ctl, items),
            "assets": review.check_old_assets(ctl, state.get("editor")), "sources": sources}


def upgrade_v1(old, state, items):
    original = old["snapshot"]
    if original.get("schema_version") != 1:
        return old
    ctl.require(original["sources"].get(SOURCE_KEY) == V1_SOURCE and old["phase"] in {"ready", "stopped"},
                "旧会话记录不属于可升级的已验证版本。")
    now = snapshot(state, items)
    _, legacy = identity_details(items)
    adjusted = json.loads(json.dumps(original))
    for key, identity in adjusted["identities"].items():
        ctl.require(key in legacy and identity["configuration_sha256"] in legacy[key], "容器配置变化超出空 DNS 列表的兼容表示。")
        identity["configuration_sha256"] = now["identities"][key]["configuration_sha256"]
    adjusted["schema_version"] = 2
    adjusted["sources"][SOURCE_KEY] = now["sources"][SOURCE_KEY]
    ctl.require(adjusted == now, "旧容器、来源或数据身份发生变化；未升级会话记录。")
    # Preserve the old metadata as evidence. This copies no database/volume data.
    review.immutable_json(ctl.GENERATED / "desktop-session-v1.json", old)
    updated = {**old, "snapshot": now}
    ctl.write_json(SESSION, updated)
    event("session-format-v2", original_metadata_sha256=review.digest(review.canonical(old)), copied_data_bytes=0)
    return updated


def check_restart_states(items):
    """0 is a clean stop; 255 is a Docker VM shutdown observation, not PASS.

Both require the same identity and storage review. All other failures, OOMs,
unknown one-offs and nonterminal operations stop the routine path.
"""
    ctl.require(all(not c["state"]["Running"] and not c["state"]["OOMKilled"] for c in items),
                "服务仍在运行或曾发生内存异常；请检查，未自动重启。")
    for item in items:
        oneoff = str(item["labels"].get("com.docker.compose.oneoff", "false")).lower() == "true"
        ctl.require(item["state"]["ExitCode"] in ({0} if oneoff else {0, 255}),
                    "服务存在需要检查的退出状态；未自动恢复或备份。")


def state_and_items():
    state = ctl.read_state()
    ctl.require(not state.get("recovery_active") and not state.get("active_child"),
                "另一个恢复或生命周期步骤尚未完成。")
    items = ctl.all_containers()
    ctl.validate_owned(items, state)
    ctl.require({c["id"] for c in items} == {c["id"] for c in state["containers"]},
                "原容器清单发生变化；未启动其他数据集。")
    return state, items


def ensure():
    state, items = state_and_items()
    old = json.loads(ctl.secure_read(SESSION, 4 * 1024 * 1024)) if SESSION.exists() else None
    if old:
        old = upgrade_v1(old, state, items)
    ctl.require(not old or old.get("phase") != "starting", "上次启动检查未完成，请先检查记录；不会自动重试任务。")
    if state["phase"] == "ready" and ctl.observed_ready(state, items):
        save_session("ready", snapshot(state, items))
        print("WORKFLOW_SESSION_READY: existing services reused; no data copied")
        return
    ctl.require(old and old.get("phase") in {"ready", "stopped"}, "缺少原服务的就绪记录，请先完成一次正常启动。")
    ctl.require(old["snapshot"] == snapshot(state, items), "原服务身份、配置或代码发生变化，请按项目更新流程处理。")
    check_restart_states(items)
    if state.get("pending_stop") and old.get("boot_session") and old["boot_session"] != boot_session():
        # A PID from the preceding macOS boot cannot own a current stop. Keep the
        # old observation before clearing only this pending command, not exits.
        event("previous-boot-stop-observed", pending_stop=state["pending_stop"])
        state.pop("pending_stop")
        ctl.write_json(ctl.STATE, state)
    ctl.require(not state.get("pending_stop"), "服务仍有待完成的正常退出，请等待清理完成。")
    ctl.require_free_port()
    ctl.credential_pair(state)
    record = {"phase": "starting", "boot_session": boot_session(), "snapshot": old["snapshot"], "attempted": []}
    ctl.write_json(SESSION, record)
    event("start-reviewed-containers", exits={c["name"]: c["state"]["ExitCode"] for c in items}, copied_bytes=0)
    primaries = record["snapshot"]["primaries"]

    def start_services(services):
        for service in services:
            state_now, current = state_and_items()
            ctl.require(record["snapshot"] == snapshot(state_now, current), "启动时原服务身份发生变化。")
            record["attempted"].append(service)
            ctl.write_json(SESSION, record)
            ctl.require(ctl.run_logged(["start", primaries[service]], "session-start-" + service, state=state_now) == 0,
                        "服务启动未完成，已保留现场。")
            deadline = time.monotonic() + 120
            while True:
                current = next(c for c in ctl.all_containers() if c["id"] == primaries[service])
                ctl.require(current["state"]["Running"] and not current["state"]["OOMKilled"], "服务启动后退出，请检查日志。")
                if current["health"] == "healthy":
                    break
                ctl.require(time.monotonic() < deadline, "服务仍未就绪，已保留运行状态；未强制停止。")
                time.sleep(0.5)

    start_services(ctl.DEPS)
    before = review.read_storage(ctl, {"primaries": primaries})
    review.review_storage(ctl, before)
    event("storage-review-passed")
    start_services(["coze-workflow", "workflow-api"])
    state, items = state_and_items()
    ctl.require(ctl.observed_ready(state, items), "工作流带凭据健康检查未通过。")
    after = review.read_storage(ctl, {"primaries": primaries})
    review.review_storage(ctl, after)
    ctl.require(review.canonical(before["coze"]) == review.canonical(after["coze"]), "启动改变了工作流记录，请检查。")
    review.load_policy(ctl.WORKSPACE / review.API_POLICY, "session_startup_policy").review_startup(before["api"], after["api"])
    state["phase"] = "ready"
    ctl.record(state)
    save_session("ready", snapshot(state, items))
    event("ready", copied_bytes=0, tasks_replayed=0)
    print("WORKFLOW_SESSION_READY: original data verified; no backup, migration or task replay")


def stop():
    desktop = str(ROOT.parent / "yijie-desktop") + "/"
    rows = subprocess.check_output(["ps", "-axo", "comm="], text=True).splitlines()
    ctl.require(not any(Path(row).name in {"yijie-desktop", "yijie-agent-host"} and desktop in row for row in rows),
                "请先正常退出易界客户端，服务将在客户端清理完成后停止。")
    ctl.stop()
    state, items = state_and_items()
    ctl.require(state["phase"] == "stopped", "服务还在正常退出，请等待；不会强制结束。")
    save_session("stopped", snapshot(state, items))
    event("normal-stop-complete", copied_bytes=0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["ensure", "stop"])
    args = parser.parse_args()
    # The same controller lock serializes both old and new lifecycle entries.
    with open(ctl.GENERATED / "controller.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        globals()[args.action]()


if __name__ == "__main__":
    try:
        main()
    except (ctl.WorkflowError, ValueError, OSError, subprocess.CalledProcessError):
        print("WORKFLOW_SESSION_PENDING: 原服务未通过启动或退出检查；数据和日志已保留，未自动备份、清理或重试任务。", file=sys.stderr)
        sys.exit(1)
