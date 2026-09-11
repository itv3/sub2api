#!/usr/bin/env python3
"""Codex CLI 升级审计索引：登记并复核一次升级留下的全部账本。

用途
----
一次 Codex CLI 画像升级会在采集机上留下四类账本：

1. ``UpgradeTimingLedger``（``control/*/UpgradeTimingLedger`` 与 ``control/*/timing``）；
2. 监督器逐命令 run（``campaigns/*/.supervisor/run-*``）；
3. ``campaign-run`` 父监督器 run（``control/*/run-*``，内含 ``campaign-run-manifest.json``）；
4. ``campaign-run`` 清单草稿（``control/`` 顶层的 ``*manifest*.json``、``*.json.part``、``*inner*.json``）。

这四类账本各有自己的 sequence、摘要链与 checkpoint head，不能拼接。本脚本不改写任何原始
文件，只生成一份不可变的合并索引（consolidated index）：逐文件登记路径、字节数与 SHA-256，
登记每份账本的事件头、生产者工具与重放／审计结果，并写入相互引用（Campaign ID、run ID、
owner nonce）。索引自身用 ``identity_sha256`` 封印。

重放纪律
--------
``UpgradeTimingLedger`` 的重放必须使用各收据 ``producer.tool`` 记录的那一份工具副本；用其他
版本会被账本工具以「生成器身份漂移」拒绝。生产者工具缺失或重放失败时，索引如实记录
``not_replayable`` 与原因，不伪造结果。监督器 run 的审计统一使用 ``--tool-root`` 指定的
当前工具树中的 ``codex_upgrade_supervisor.py audit``。

本脚本只依赖标准库，不导入 ``tools/official_client_capture`` 中的任何模块，因此不改变
Campaign 受管工具身份。

子命令
------
``generate``  遍历证据根，生成索引；
``check``     重新计算索引中每个文件的 SHA-256 与索引自摘要，可选重新执行重放／审计。
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "codex-upgrade-audit-index/v1"
IDENTITY_ALGORITHM = (
    "sha256(json.dumps(payload_without_identity_sha256, ensure_ascii=False, "
    "sort_keys=True, separators=(',', ':')))"
)
SUPERVISOR_TOOL = "codex_upgrade_supervisor.py"
SUPERVISOR_RUN_FILES = (
    "state.json",
    "events.ndjson",
    "watchdog-heartbeats.ndjson",
    "minute-ledger.ndjson",
    "stop-request.json",
    "stop-receipt.json",
    "heartbeat.json",
)
SUBPROCESS_TIMEOUT_SECONDS = 300


class AuditIndexError(RuntimeError):
    """索引生成或校验失败。"""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _identity_sha256(payload: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in payload.items() if key != "identity_sha256"}
    return hashlib.sha256(_canonical_bytes(unsigned)).hexdigest()


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AuditIndexError(f"无法读取 JSON：{path}：{error}") from error


def _try_load_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None


def _relative(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def _file_entries(root: Path, base: Path) -> list[dict[str, Any]]:
    """递归登记目录下全部普通文件，按相对路径排序。"""

    entries: list[dict[str, Any]] = []
    for current, dirnames, filenames in os.walk(base):
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(current) / name
            if not path.is_file() or path.is_symlink():
                continue
            entries.append(
                {
                    "path": _relative(root, path),
                    "bytes": path.stat().st_size,
                    "sha256": _sha256_file(path),
                }
            )
    return entries


def _run(command: list[str], cwd: Path | None = None) -> dict[str, Any]:
    """执行只读子命令，返回退出码与截断后的输出。"""

    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"exit_code": None, "stdout": "", "stderr": str(error)[:2000]}
    return {
        "exit_code": completed.returncode,
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-2000:],
    }


def _summarize_json_stdout(stdout: str, keys: tuple[str, ...]) -> dict[str, Any] | None:
    try:
        payload = json.loads(stdout.strip())
    except (ValueError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    return {key: payload.get(key) for key in keys if key in payload}


def _tool_checkout_root(tool: Path) -> Path | None:
    """由 ``.../tools/official_client_capture/x.py`` 推出仓库副本根目录。"""

    parent = tool.parent
    if parent.name != "official_client_capture" or parent.parent.name != "tools":
        return None
    return parent.parent.parent


# ---------------------------------------------------------------------------
# UpgradeTimingLedger
# ---------------------------------------------------------------------------


def _ledger_producer(ledger_dir: Path) -> tuple[dict[str, Any] | None, Path | None]:
    """从最新一份收据（或 checkpoint）读取生产者工具坐标。"""

    receipts = sorted((ledger_dir / "receipts").glob("*.json")) if (ledger_dir / "receipts").is_dir() else []
    receipts += sorted(ledger_dir.glob("*checkpoint*.json"))
    producer: dict[str, Any] | None = None
    receipt_path: Path | None = None
    fallback: tuple[dict[str, Any], Path] | None = None
    for candidate in reversed(receipts):
        payload = _try_load_json(candidate)
        if not isinstance(payload, dict) or not isinstance(payload.get("producer"), dict):
            continue
        tool = str(payload["producer"].get("tool") or "")
        # 账本 receipts/ 里可能混有环境收据等其他工具签发的文件；重放只认计时账本工具签发的最新一份。
        if tool.endswith("codex_upgrade_timing_ledger.py"):
            producer = payload["producer"]
            receipt_path = candidate
            break
        if fallback is None:
            fallback = (payload["producer"], candidate)
    if producer is None and fallback is not None:
        producer, receipt_path = fallback
    return producer, receipt_path


def _ledger_event_head(ledger_dir: Path) -> dict[str, Any]:
    events_dir = ledger_dir / "events"
    events = sorted(events_dir.glob("*.json")) if events_dir.is_dir() else []
    if not events:
        return {"event_count": 0, "last_event": None}
    last = events[-1]
    payload = _try_load_json(last) or {}
    phases = sorted(
        {
            str(item.get("phase"))
            for item in (_try_load_json(event) or {} for event in events)
            if isinstance(item, dict) and item.get("phase")
        }
    )
    stop_events = 0
    for event in events:
        item = _try_load_json(event)
        if isinstance(item, dict) and item.get("event_type") == "stop_the_line":
            stop_events += 1
    return {
        "event_count": len(events),
        "phases": phases,
        "stop_the_line_events": stop_events,
        "last_event": {
            "file": last.name,
            "file_sha256": _sha256_file(last),
            "sequence": payload.get("sequence"),
            "event_id": payload.get("event_id"),
            "event_type": payload.get("event_type"),
            "phase": payload.get("phase"),
            "recorded_at_utc": payload.get("recorded_at_utc"),
            "root_cause_id": payload.get("root_cause_id"),
        },
    }


def _replay_ledger(
    ledger_dir: Path, producer: dict[str, Any] | None, receipt_path: Path | None, *, replay: bool
) -> dict[str, Any]:
    if not replay:
        return {"status": "skipped", "reason": "generate --no-replay"}
    if not producer or not isinstance(producer.get("tool"), str):
        return {"status": "not_replayable", "reason": "收据未记录 producer.tool"}
    tool = Path(producer["tool"])
    if not tool.is_file():
        return {"status": "not_replayable", "reason": f"生产者工具副本不存在：{tool}"}
    if tool.name != "codex_upgrade_timing_ledger.py":
        return {
            "status": "not_replayable",
            "reason": f"最新收据由 {tool.name} 生成，不是计时账本工具",
            "producer_tool": str(tool),
        }
    checkout = _tool_checkout_root(tool)
    status_result = _run([sys.executable, str(tool), "status", "--ledger-dir", str(ledger_dir)], cwd=checkout)
    result: dict[str, Any] = {
        "tool": str(tool),
        "tool_sha256": _sha256_file(tool),
        "status_exit_code": status_result["exit_code"],
        "status_summary": _summarize_json_stdout(
            status_result["stdout"],
            ("active_phase", "status", "head_sequence", "head_sha256", "last_event_id", "total_live_request_count"),
        ),
    }
    if receipt_path is not None and receipt_path.parent.name == "receipts":
        replay_result = _run(
            [
                sys.executable,
                str(tool),
                "replay",
                "--ledger-dir",
                str(ledger_dir),
                "--receipt",
                f"receipts/{receipt_path.name}",
            ],
            cwd=checkout,
        )
        result["replay_receipt"] = f"receipts/{receipt_path.name}"
        result["replay_exit_code"] = replay_result["exit_code"]
        result["replay_summary"] = _summarize_json_stdout(
            replay_result["stdout"], ("active_phase", "status", "head_sequence", "head_sha256")
        )
        failure = replay_result["stderr"].strip() or replay_result["stdout"].strip()
    else:
        result["replay_receipt"] = None
        result["replay_exit_code"] = None
        result["replay_summary"] = None
        failure = status_result["stderr"].strip() or status_result["stdout"].strip()
    ok_status = status_result["exit_code"] == 0
    ok_replay = result["replay_exit_code"] in (0, None)
    if ok_status and ok_replay:
        result["status"] = "replayed"
    else:
        result["status"] = "not_replayable"
        result["reason"] = failure[-600:]
    return result


def _index_timing_ledgers(root: Path, *, replay: bool) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    dirs = sorted(root.glob("control/*/UpgradeTimingLedger")) + sorted(root.glob("control/*/timing"))
    for ledger_dir in dirs:
        if not ledger_dir.is_dir():
            continue
        plan = _try_load_json(ledger_dir / "ledger.json") or {}
        producer, receipt_path = _ledger_producer(ledger_dir)
        receipts_dir = ledger_dir / "receipts"
        entries.append(
            {
                "kind": "upgrade_timing_ledger" if ledger_dir.name == "UpgradeTimingLedger" else "timing_dir",
                "id": ledger_dir.parent.name,
                "path": _relative(root, ledger_dir),
                "plan": {
                    "schema_version": plan.get("schema_version"),
                    "upgrade_id": plan.get("upgrade_id"),
                    "campaign_purpose": plan.get("campaign_purpose"),
                    "evidence_decision": plan.get("evidence_decision"),
                    "created_at_utc": plan.get("created_at_utc"),
                    "total_budget_minutes": plan.get("total_budget_minutes"),
                },
                "event_head": _ledger_event_head(ledger_dir),
                "receipts": sorted(p.name for p in receipts_dir.glob("*.json")) if receipts_dir.is_dir() else [],
                "producer": producer,
                "replay": _replay_ledger(ledger_dir, producer, receipt_path, replay=replay),
                "files": _file_entries(root, ledger_dir),
                "references": {"campaign_id": plan.get("upgrade_id")},
            }
        )
    return entries


# ---------------------------------------------------------------------------
# 监督器 run 与 campaign-run
# ---------------------------------------------------------------------------


def _audit_run(run_dir: Path, tool_root: Path | None, *, replay: bool) -> dict[str, Any]:
    if not replay:
        return {"status": "skipped", "reason": "generate --no-replay"}
    if tool_root is None:
        return {"status": "not_audited", "reason": "未提供 --tool-root"}
    tool = tool_root / SUPERVISOR_TOOL
    if not tool.is_file():
        return {"status": "not_audited", "reason": f"监督器工具不存在：{tool}"}
    result = _run([sys.executable, str(tool), "audit", "--state-dir", str(run_dir)])
    summary = _summarize_json_stdout(
        result["stdout"],
        (
            "schema_version",
            "state",
            "audit_incomplete",
            "classification_counts",
            "integrity_errors",
            "event_count",
            "minute_record_count",
            "watchdog_heartbeat_count",
            "coverage_start_epoch",
            "coverage_end_epoch",
        ),
    )
    payload: dict[str, Any] = {
        "tool": str(tool),
        "tool_sha256": _sha256_file(tool),
        "exit_code": result["exit_code"],
        "summary": summary,
    }
    if result["exit_code"] == 0 and summary is not None:
        payload["status"] = "audited"
    else:
        payload["status"] = "not_audited"
        payload["reason"] = (result["stderr"].strip() or result["stdout"].strip())[-600:]
    return payload


def _run_references(run_dir: Path) -> dict[str, Any]:
    stop = _try_load_json(run_dir / "stop-receipt.json") or {}
    state = _try_load_json(run_dir / "state.json") or {}
    return {
        "run_id": run_dir.name,
        "campaign_id": stop.get("campaign_id") or state.get("campaign_id"),
        "owner_nonce": stop.get("owner_nonce") or state.get("owner_nonce"),
        "phase": stop.get("phase") or state.get("phase"),
        "stop_reason": stop.get("reason"),
        "stop_event_type": stop.get("event_type"),
        "detected_at_utc": stop.get("detected_at_utc"),
    }


def _index_supervisor_runs(root: Path, tool_root: Path | None, *, replay: bool) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for run_dir in sorted(root.glob("campaigns/*/.supervisor/run-*")):
        if not run_dir.is_dir():
            continue
        entries.append(
            {
                "kind": "supervisor_run",
                "id": run_dir.name,
                "path": _relative(root, run_dir),
                "supervisor_dir": _relative(root, run_dir.parent),
                "references": _run_references(run_dir),
                "audit": _audit_run(run_dir, tool_root, replay=replay),
                "files": _file_entries(root, run_dir),
            }
        )
    return entries


def _index_campaign_runs(root: Path, tool_root: Path | None, *, replay: bool) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for manifest in sorted(root.glob("control/*/run-*/campaign-run-manifest.json")):
        run_dir = manifest.parent
        payload = _try_load_json(manifest) or {}
        inner = payload.get("manifest") if isinstance(payload.get("manifest"), dict) else {}
        entries.append(
            {
                "kind": "campaign_run",
                "id": run_dir.name,
                "path": _relative(root, run_dir),
                "control_dir": run_dir.parent.name,
                "manifest": {
                    "schema_version": payload.get("schema_version"),
                    "manifest_sha256": payload.get("manifest_sha256"),
                    "file_sha256": _sha256_file(manifest),
                    "campaign_id": inner.get("campaign_id"),
                    "phase": inner.get("phase"),
                    "no_op": inner.get("no_op"),
                    "action_count": len(inner.get("actions", [])) if isinstance(inner.get("actions"), list) else None,
                },
                "references": _run_references(run_dir),
                "audit": _audit_run(run_dir, tool_root, replay=replay),
                "files": _file_entries(root, run_dir),
            }
        )
    return entries


def _index_campaign_run_drafts(root: Path) -> list[dict[str, Any]]:
    control = root / "control"
    candidates: set[Path] = set()
    for pattern in ("*manifest*.json", "*.json.part", "*inner*.json"):
        candidates.update(p for p in control.glob(pattern) if p.is_file() and not p.is_symlink())
    entries: list[dict[str, Any]] = []
    for path in sorted(candidates):
        entries.append(
            {
                "kind": "campaign_run_draft",
                "id": path.name,
                "path": _relative(root, path),
                "draft": True,
                "files": [{"path": _relative(root, path), "bytes": path.stat().st_size, "sha256": _sha256_file(path)}],
            }
        )
    return entries


# ---------------------------------------------------------------------------
# generate / check
# ---------------------------------------------------------------------------


def _archive_entry(archive: Path | None) -> dict[str, Any] | None:
    if archive is None:
        return None
    if not archive.is_file():
        raise AuditIndexError(f"归档文件不存在：{archive}")
    return {"path": str(archive), "bytes": archive.stat().st_size, "sha256": _sha256_file(archive)}


def _totals(ledgers: list[dict[str, Any]]) -> dict[str, Any]:
    kinds: dict[str, int] = {}
    files = 0
    total_bytes = 0
    replayed = 0
    not_replayable = 0
    audited = 0
    not_audited = 0
    stop_events = 0
    for entry in ledgers:
        kinds[entry["kind"]] = kinds.get(entry["kind"], 0) + 1
        files += len(entry.get("files", []))
        total_bytes += sum(item["bytes"] for item in entry.get("files", []))
        replay = entry.get("replay") or {}
        audit = entry.get("audit") or {}
        replayed += replay.get("status") == "replayed"
        not_replayable += replay.get("status") == "not_replayable"
        audited += audit.get("status") == "audited"
        not_audited += audit.get("status") == "not_audited"
        stop_events += (entry.get("event_head") or {}).get("stop_the_line_events", 0) or 0
    return {
        "ledgers_by_kind": dict(sorted(kinds.items())),
        "file_count": files,
        "byte_count": total_bytes,
        "timing_ledgers_replayed": replayed,
        "timing_ledgers_not_replayable": not_replayable,
        "runs_audited": audited,
        "runs_not_audited": not_audited,
        "timing_ledger_stop_the_line_events": stop_events,
    }


def generate(args: argparse.Namespace) -> int:
    root = Path(args.evidence_root)
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise AuditIndexError("--evidence-root 必须是现有的非符号链接绝对目录")
    tool_root = Path(args.tool_root).resolve() if args.tool_root else None
    replay = not args.no_replay
    ledgers = (
        _index_timing_ledgers(root, replay=replay)
        + _index_supervisor_runs(root, tool_root, replay=replay)
        + _index_campaign_runs(root, tool_root, replay=replay)
        + _index_campaign_run_drafts(root)
    )
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "identity_algorithm": IDENTITY_ALGORITHM,
        "issued_at_utc": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "target_version": args.target_version,
        "baseline_version": args.baseline_version,
        "campaign_id": args.campaign_id,
        "evidence_root": str(root.resolve()),
        "evidence_host": args.evidence_host,
        "supervisor_tool_root": str(tool_root) if tool_root else None,
        "archive": _archive_entry(Path(args.archive) if args.archive else None),
        "policy": {
            "raw_ledgers": "原始账本原样保留在 evidence_root，本索引只登记摘要与重放／审计结果，不拼接事件。",
            "replay": "UpgradeTimingLedger 只用各收据 producer.tool 记录的工具副本重放；失败如实登记 not_replayable。",
            "audit": "监督器 run 与 campaign-run 用 supervisor_tool_root 的 codex_upgrade_supervisor.py audit 只读审计。",
        },
        "ledgers": ledgers,
        "totals": _totals(ledgers),
    }
    payload["identity_sha256"] = _identity_sha256(payload)
    output = Path(args.output)
    if output.exists():
        raise AuditIndexError(f"输出已存在，不得覆盖：{output}")
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "identity_sha256": payload["identity_sha256"], "totals": payload["totals"]}, ensure_ascii=False))
    return 0


def check(args: argparse.Namespace) -> int:
    index_path = Path(args.index)
    payload = _load_json(index_path)
    if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
        raise AuditIndexError("索引 schema 不匹配")
    problems: list[str] = []
    if payload.get("identity_sha256") != _identity_sha256(payload):
        problems.append("identity_sha256 与内容不一致")
    root = Path(args.evidence_root) if args.evidence_root else None
    checked_files = 0
    if root is not None:
        for entry in payload.get("ledgers", []):
            for item in entry.get("files", []):
                path = root / item["path"]
                if not path.is_file():
                    problems.append(f"文件缺失：{item['path']}")
                    continue
                checked_files += 1
                if path.stat().st_size != item["bytes"] or _sha256_file(path) != item["sha256"]:
                    problems.append(f"文件摘要漂移：{item['path']}")
        archive = payload.get("archive")
        if isinstance(archive, dict):
            archive_path = Path(archive["path"])
            if not archive_path.is_file():
                problems.append(f"归档缺失：{archive['path']}")
            elif _sha256_file(archive_path) != archive["sha256"]:
                problems.append("归档摘要漂移")
        if args.replay:
            tool_root = Path(args.tool_root).resolve() if args.tool_root else (
                Path(payload["supervisor_tool_root"]) if payload.get("supervisor_tool_root") else None
            )
            for entry in payload.get("ledgers", []):
                entry_dir = root / entry["path"]
                if entry["kind"] in ("upgrade_timing_ledger", "timing_dir"):
                    producer, receipt_path = _ledger_producer(entry_dir)
                    fresh = _replay_ledger(entry_dir, producer, receipt_path, replay=True)
                    if fresh.get("status") != (entry.get("replay") or {}).get("status"):
                        problems.append(f"重放状态变化：{entry['path']}：{fresh.get('status')}")
                elif entry["kind"] in ("supervisor_run", "campaign_run"):
                    fresh = _audit_run(entry_dir, tool_root, replay=True)
                    if fresh.get("status") != (entry.get("audit") or {}).get("status"):
                        problems.append(f"审计状态变化：{entry['path']}：{fresh.get('status')}")
    report = {
        "index": str(index_path),
        "identity_sha256": payload.get("identity_sha256"),
        "checked_files": checked_files,
        "problems": problems,
        "status": "passed" if not problems else "failed",
    }
    print(json.dumps(report, ensure_ascii=False))
    return 0 if not problems else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="生成或复核 Codex CLI 升级审计索引")
    commands = parser.add_subparsers(dest="command", required=True)
    gen = commands.add_parser("generate", help="遍历证据根生成不可变审计索引")
    gen.add_argument("--evidence-root", required=True, help="采集机证据根绝对路径，如 /root/oauth-capture")
    gen.add_argument("--target-version", required=True)
    gen.add_argument("--baseline-version", required=True)
    gen.add_argument("--campaign-id", required=True, help="最终 Campaign ID")
    gen.add_argument("--evidence-host", default=None, help="证据所在主机标识，只作说明")
    gen.add_argument("--tool-root", default=None, help="当前工具树 tools/official_client_capture 的绝对路径，用于监督器审计")
    gen.add_argument("--archive", default=None, help="审计归档 tar.gz 绝对路径；提供时登记其字节数与 SHA-256")
    gen.add_argument("--no-replay", action="store_true", help="只登记摘要，不执行重放与审计")
    gen.add_argument("--output", required=True, help="索引输出路径，不得已存在")
    chk = commands.add_parser("check", help="复核索引：自摘要、逐文件摘要，可选重放")
    chk.add_argument("--index", required=True)
    chk.add_argument("--evidence-root", default=None, help="提供时逐文件复核摘要；省略时只复核自摘要")
    chk.add_argument("--replay", action="store_true", help="重新执行重放与审计并比对状态")
    chk.add_argument("--tool-root", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "generate":
            return generate(args)
        return check(args)
    except AuditIndexError as error:
        print(f"审计索引失败：{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
