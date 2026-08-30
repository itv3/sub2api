#!/usr/bin/env python3
"""维护并重放 Codex 官方客户端升级的只追加 UpgradeTimingLedger。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any


PLAN_SCHEMA = "codex-upgrade-timing-ledger-plan/v1"
EVENT_SCHEMA = "codex-upgrade-timing-ledger-event/v1"
RECEIPT_SCHEMA = "codex-upgrade-timing-ledger-receipt/v1"
PRODUCER_SCHEMA = "codex-upgrade-timing-ledger-producer/v1"
PRODUCER_VERSION = "1"
PHASE_ORDER = ("VC-0", "VC-1", "VC-2", "VC-3", "VC-4", "VC-5", "VC-6")
DEFAULT_STAGE_BUDGETS = {
    "VC-0": 45,
    "VC-1": 75,
    "VC-2": 75,
    "VC-3": 75,
    "VC-4": 90,
    "VC-5": 75,
    "VC-6": 75,
}
DEFAULT_TOTAL_BUDGET_MINUTES = 360
DEFAULT_RETRY_LIMIT = 2
PURPOSES = frozenset({"validation_only", "production_replacement"})
EVIDENCE_DECISIONS = frozenset({"reuse", "recapture"})
EVENT_TYPES = frozenset(
    {
        "stage_started",
        "stage_completed",
        "attempt_started",
        "attempt_failed",
        "attempt_completed",
        "receipt_passed",
        "stop_the_line",
        "recovery_verified",
        "upgrade_completed",
    }
)
RECOVERY_ROLES = ("clean_p0", "offline_regression", "tool_fix")
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
MAX_JSON_BYTES = 4 * 1024 * 1024


class TimingLedgerError(ValueError):
    """计时台账不完整、超时、发生漂移或违反重试纪律。"""


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        .encode("utf-8")
        + b"\n"
    )


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not RFC3339_RE.fullmatch(value):
        raise TimingLedgerError(f"{label}不是带时区 RFC3339 时间")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise TimingLedgerError(f"{label}不是有效时间") from error
    if parsed.tzinfo is None:
        raise TimingLedgerError(f"{label}缺少时区")
    return parsed.astimezone(timezone.utc)


def _safe_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SAFE_ID_RE.fullmatch(value):
        raise TimingLedgerError(f"{label}不是安全标识")
    return value


def _expect(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TimingLedgerError(f"{label}必须是对象")
    actual = set(value)
    if actual != fields:
        raise TimingLedgerError(
            f"{label}字段不闭合：缺失={sorted(fields - actual)}，"
            f"多余={sorted(actual - fields)}"
        )
    return value


def _private_ledger(path: Path, *, must_exist: bool) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise TimingLedgerError("ledger dir 必须是非符号链接绝对路径")
    if must_exist:
        if not path.is_dir():
            raise TimingLedgerError("ledger dir 不存在")
        resolved = path.resolve(strict=True)
        if stat.S_IMODE(resolved.stat().st_mode) != 0o700:
            raise TimingLedgerError("ledger dir 权限必须是 0700")
        return resolved
    if path.exists():
        raise TimingLedgerError("ledger dir 已存在，禁止覆盖")
    parent = path.parent.resolve(strict=True)
    if path.parent.is_symlink() or not parent.is_dir():
        raise TimingLedgerError("ledger dir 父目录不可信")
    return path


def _relative(root: Path, value: str, label: str) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise TimingLedgerError(f"{label}必须是 ledger 内 POSIX 相对路径")
    parsed = PurePosixPath(value)
    if (
        parsed.is_absolute()
        or str(parsed) != value
        or any(part in {"", ".", ".."} for part in parsed.parts)
    ):
        raise TimingLedgerError(f"{label}路径不规范")
    current = root
    for part in parsed.parts:
        current /= part
        if current.is_symlink():
            raise TimingLedgerError(f"{label}路径包含符号链接")
    try:
        current.resolve(strict=current.exists()).relative_to(root)
    except (OSError, RuntimeError, ValueError) as error:
        raise TimingLedgerError(f"{label}越过 ledger dir") from error
    return current


def _load_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    if not path.is_file() or path.is_symlink():
        raise TimingLedgerError(f"{label}不是可信普通文件")
    metadata = path.stat()
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise TimingLedgerError(f"{label}权限必须是 0600")
    if metadata.st_size <= 0 or metadata.st_size > MAX_JSON_BYTES:
        raise TimingLedgerError(f"{label}大小非法")
    raw = path.read_bytes()
    try:
        payload = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise TimingLedgerError(f"{label}不是合法 UTF-8 JSON") from error
    if not isinstance(payload, dict):
        raise TimingLedgerError(f"{label}顶层必须是对象")
    return payload, raw


def _write_once(path: Path, payload: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise TimingLedgerError(f"输出已存在，禁止覆盖：{path}")
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise TimingLedgerError("输出父目录不可信")
    if stat.S_IMODE(path.parent.stat().st_mode) != 0o700:
        raise TimingLedgerError("输出父目录权限必须是 0700")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_canonical(payload))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _producer() -> dict[str, str]:
    tool = Path(__file__).resolve()
    return {
        "schema_version": PRODUCER_SCHEMA,
        "tool": str(tool),
        "tool_sha256": _sha256_file(tool),
        "version": PRODUCER_VERSION,
    }


def _validate_plan(plan: dict[str, Any]) -> dict[str, Any]:
    _expect(
        plan,
        {
            "schema_version",
            "upgrade_id",
            "created_at_utc",
            "started_at_utc",
            "baseline_version",
            "target_version",
            "campaign_purpose",
            "evidence_decision",
            "total_budget_minutes",
            "stage_budgets_minutes",
            "same_root_cause_retry_limit",
            "producer",
        },
        "ledger plan",
    )
    if plan.get("schema_version") != PLAN_SCHEMA:
        raise TimingLedgerError("ledger plan schema_version 不匹配")
    _safe_id(plan.get("upgrade_id"), "upgrade_id")
    created = _timestamp(plan.get("created_at_utc"), "created_at_utc")
    started = _timestamp(plan.get("started_at_utc"), "started_at_utc")
    if created != started:
        raise TimingLedgerError("计时必须从台账创建时连续开始")
    for field in ("baseline_version", "target_version"):
        if not isinstance(plan.get(field), str) or not VERSION_RE.fullmatch(plan[field]):
            raise TimingLedgerError(f"{field} 不是三段式版本号")
    if plan["baseline_version"] == plan["target_version"]:
        raise TimingLedgerError("baseline 与 target 版本不得相同")
    if plan.get("campaign_purpose") not in PURPOSES:
        raise TimingLedgerError("campaign_purpose 非法")
    if plan.get("evidence_decision") not in EVIDENCE_DECISIONS:
        raise TimingLedgerError("P0 必须冻结唯一 reuse／recapture 决定")
    total = plan.get("total_budget_minutes")
    if not isinstance(total, int) or isinstance(total, bool) or total <= 0 or total > 360:
        raise TimingLedgerError("总墙钟预算必须为 1～360 分钟")
    budgets = plan.get("stage_budgets_minutes")
    if not isinstance(budgets, dict) or list(budgets) != list(PHASE_ORDER):
        raise TimingLedgerError("阶段预算必须按 VC-0～VC-6 完整排序")
    for phase, default in DEFAULT_STAGE_BUDGETS.items():
        value = budgets.get(phase)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0 or value > default:
            raise TimingLedgerError(f"{phase} 预算必须为正数且不得宽于文档上限 {default}")
    if plan.get("same_root_cause_retry_limit") != DEFAULT_RETRY_LIMIT:
        raise TimingLedgerError("同根因重试上限必须固定为 2")
    if plan.get("producer") != _producer():
        raise TimingLedgerError("计时台账生成器身份漂移")
    return plan


def _load_plan(root: Path) -> tuple[dict[str, Any], bytes]:
    plan, raw = _load_json(root / "ledger.json", "ledger plan")
    return _validate_plan(plan), raw


def _validate_binding(root: Path, value: Any, label: str) -> dict[str, Any]:
    binding = _expect(value, {"role", "path", "sha256"}, label)
    role = _safe_id(binding.get("role"), f"{label}.role")
    path = _relative(root, binding.get("path"), f"{label}.path")
    expected = binding.get("sha256")
    if not isinstance(expected, str) or not SHA256_RE.fullmatch(expected):
        raise TimingLedgerError(f"{label}.sha256 非法")
    if not path.is_file() or path.is_symlink() or _sha256_file(path) != expected:
        raise TimingLedgerError(f"{label}引用缺失或摘要漂移")
    return {
        "role": role,
        "path": binding["path"],
        "sha256": expected,
        "bytes": path.stat().st_size,
    }


def _load_events(root: Path, *, limit: int | None = None) -> list[tuple[dict[str, Any], bytes]]:
    events_root = root / "events"
    if not events_root.is_dir() or events_root.is_symlink():
        raise TimingLedgerError("events 目录缺失或不可信")
    paths = sorted(events_root.iterdir())
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise TimingLedgerError("events 目录只能包含普通文件")
    expected_names = [f"{index:06d}.json" for index in range(1, len(paths) + 1)]
    if [path.name for path in paths] != expected_names:
        raise TimingLedgerError("event 序号不连续或存在额外文件")
    if limit is not None:
        if limit <= 0 or limit > len(paths):
            raise TimingLedgerError("receipt 绑定的 event head 越界")
        paths = paths[:limit]
    return [_load_json(path, f"event {path.name}") for path in paths]


def _validate_event_shape(root: Path, event: dict[str, Any], sequence: int) -> dict[str, Any]:
    _expect(
        event,
        {
            "schema_version",
            "sequence",
            "event_id",
            "recorded_at_utc",
            "phase",
            "event_type",
            "attempt_id",
            "root_cause_id",
            "live_request_count",
            "receipts",
            "next_action",
            "previous_event_sha256",
        },
        f"event {sequence}",
    )
    if event.get("schema_version") != EVENT_SCHEMA or event.get("sequence") != sequence:
        raise TimingLedgerError(f"event {sequence} schema 或序号不一致")
    _safe_id(event.get("event_id"), f"event {sequence}.event_id")
    _timestamp(event.get("recorded_at_utc"), f"event {sequence}.recorded_at_utc")
    if event.get("phase") not in PHASE_ORDER or event.get("event_type") not in EVENT_TYPES:
        raise TimingLedgerError(f"event {sequence} phase 或 event_type 非法")
    for field in ("attempt_id", "root_cause_id"):
        value = event.get(field)
        if value is not None:
            _safe_id(value, f"event {sequence}.{field}")
    count = event.get("live_request_count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise TimingLedgerError(f"event {sequence}.live_request_count 非法")
    receipts = event.get("receipts")
    if not isinstance(receipts, list):
        raise TimingLedgerError(f"event {sequence}.receipts 必须是数组")
    roles = [item.get("role") for item in receipts if isinstance(item, dict)]
    if roles != sorted(roles) or len(set(roles)) != len(roles):
        raise TimingLedgerError(f"event {sequence}.receipts 必须按 role 唯一排序")
    normalized = [_validate_binding(root, item, f"event {sequence}.receipts") for item in receipts]
    if event["event_type"] == "recovery_verified" and tuple(roles) != RECOVERY_ROLES:
        raise TimingLedgerError("recovery_verified 必须绑定工具修复、离线回归和干净 P0 三份收据")
    if event["event_type"] != "recovery_verified" and roles and event["event_type"] not in {"receipt_passed", "stop_the_line", "upgrade_completed"}:
        raise TimingLedgerError(f"{event['event_type']} 不接受 receipts")
    next_action = event.get("next_action")
    if next_action is not None and (not isinstance(next_action, str) or not next_action.strip()):
        raise TimingLedgerError(f"event {sequence}.next_action 非法")
    previous = event.get("previous_event_sha256")
    if sequence == 1:
        if previous is not None:
            raise TimingLedgerError("首个 event 的 previous_event_sha256 必须为空")
    elif not isinstance(previous, str) or not SHA256_RE.fullmatch(previous):
        raise TimingLedgerError(f"event {sequence}.previous_event_sha256 非法")
    return {**event, "receipts": normalized}


def _summarize(
    root: Path,
    plan: dict[str, Any],
    raw_events: list[tuple[dict[str, Any], bytes]],
    *,
    as_of: datetime,
) -> dict[str, Any]:
    if not raw_events:
        raise TimingLedgerError("UpgradeTimingLedger 至少需要一个 event")
    event_ids: set[str] = set()
    attempts: dict[str, dict[str, Any]] = {}
    failure_counts: dict[str, int] = {}
    active_phase: str | None = None
    active_phase_started: datetime | None = None
    stopped = False
    completed = False
    total_live_requests = 0
    last_time: datetime | None = None
    previous_raw: bytes | None = None
    last_successful_receipt: dict[str, Any] | None = None
    last_event: dict[str, Any] | None = None
    for sequence, (event, raw) in enumerate(raw_events, 1):
        normalized = _validate_event_shape(root, event, sequence)
        recorded = _timestamp(normalized["recorded_at_utc"], "event time")
        if recorded < _timestamp(plan["started_at_utc"], "started_at_utc"):
            raise TimingLedgerError("event 早于台账开始时间")
        if last_time is not None and recorded < last_time:
            raise TimingLedgerError("event 时间发生倒退")
        if previous_raw is not None and normalized["previous_event_sha256"] != _sha256_bytes(previous_raw):
            raise TimingLedgerError("event 摘要链断裂")
        if normalized["event_id"] in event_ids:
            raise TimingLedgerError("event_id 重复")
        event_ids.add(normalized["event_id"])
        event_type = normalized["event_type"]
        phase = normalized["phase"]
        if completed:
            raise TimingLedgerError("upgrade_completed 后禁止追加 event")
        if stopped and event_type != "recovery_verified":
            raise TimingLedgerError("stop_the_line 后只能记录 recovery_verified")
        if event_type == "stage_started":
            if active_phase is not None or normalized["attempt_id"] is not None or normalized["root_cause_id"] is not None:
                raise TimingLedgerError("stage_started 身份或阶段状态非法")
            active_phase = phase
            active_phase_started = recorded
        elif event_type == "stage_completed":
            if active_phase != phase or any(item["status"] == "active" for item in attempts.values()):
                raise TimingLedgerError("stage_completed 与当前阶段或 attempt 状态不一致")
            active_phase = None
            active_phase_started = None
        elif event_type == "attempt_started":
            attempt_id = normalized["attempt_id"]
            if active_phase != phase or attempt_id is None or attempt_id in attempts:
                raise TimingLedgerError("attempt_started 与当前阶段或 attempt 身份不一致")
            cause = normalized["root_cause_id"]
            if cause is not None and failure_counts.get(cause, 0) >= plan["same_root_cause_retry_limit"]:
                raise TimingLedgerError("同一根因已连续失败两次，禁止第三次 attempt")
            attempts[attempt_id] = {"status": "active", "root_cause_id": cause}
        elif event_type in {"attempt_failed", "attempt_completed"}:
            attempt_id = normalized["attempt_id"]
            if attempt_id is None or attempts.get(attempt_id, {}).get("status") != "active":
                raise TimingLedgerError(f"{event_type} 没有对应的 active attempt")
            if event_type == "attempt_failed":
                cause = normalized["root_cause_id"]
                if cause is None:
                    raise TimingLedgerError("attempt_failed 必须登记 root_cause_id")
                attempts[attempt_id] = {"status": "failed", "root_cause_id": cause}
                failure_counts[cause] = failure_counts.get(cause, 0) + 1
            else:
                attempts[attempt_id]["status"] = "completed"
        elif event_type == "stop_the_line":
            if not normalized["next_action"]:
                raise TimingLedgerError("stop_the_line 必须冻结唯一下一动作")
            stopped = True
        elif event_type == "recovery_verified":
            cause = normalized["root_cause_id"]
            if not stopped or cause is None or failure_counts.get(cause, 0) < plan["same_root_cause_retry_limit"]:
                raise TimingLedgerError("recovery_verified 没有对应的两次同根因失败停线")
            failure_counts[cause] = 0
            stopped = False
        elif event_type == "upgrade_completed":
            if active_phase != phase or any(item["status"] == "active" for item in attempts.values()):
                raise TimingLedgerError("upgrade_completed 时仍有未关闭阶段或 attempt")
            completed = True
        if normalized["receipts"]:
            last_successful_receipt = normalized["receipts"][-1]
        total_live_requests += normalized["live_request_count"]
        last_time = recorded
        previous_raw = raw
        last_event = normalized
    assert last_event is not None and last_time is not None and previous_raw is not None
    if as_of < last_time:
        raise TimingLedgerError("检查时间早于最新 event")
    started = _timestamp(plan["started_at_utc"], "started_at_utc")
    total_elapsed = max(0, int((as_of - started).total_seconds()))
    total_deadline = started + timedelta(minutes=plan["total_budget_minutes"])
    stage_elapsed = None
    stage_deadline = None
    if active_phase is not None and active_phase_started is not None:
        stage_elapsed = max(0, int((as_of - active_phase_started).total_seconds()))
        stage_deadline = active_phase_started + timedelta(
            minutes=plan["stage_budgets_minutes"][active_phase]
        )
    budget_exceeded = as_of >= total_deadline or (
        stage_deadline is not None and as_of >= stage_deadline
    )
    retry_stop_required = any(
        count >= plan["same_root_cause_retry_limit"] for count in failure_counts.values()
    )
    status = (
        "complete"
        if completed
        else "stopped"
        if stopped
        else "stop_required"
        if budget_exceeded or retry_stop_required
        else "active"
    )
    return {
        "status": status,
        "upgrade_id": plan["upgrade_id"],
        "baseline_version": plan["baseline_version"],
        "target_version": plan["target_version"],
        "campaign_purpose": plan["campaign_purpose"],
        "evidence_decision": plan["evidence_decision"],
        "active_phase": active_phase,
        "head_sequence": len(raw_events),
        "head_sha256": _sha256_bytes(previous_raw),
        "total_elapsed_seconds": total_elapsed,
        "stage_elapsed_seconds": stage_elapsed,
        "total_deadline_at_utc": total_deadline.isoformat(timespec="seconds"),
        "stage_deadline_at_utc": (
            stage_deadline.isoformat(timespec="seconds") if stage_deadline else None
        ),
        "total_live_request_count": total_live_requests,
        "same_root_cause_failures": dict(sorted(failure_counts.items())),
        "last_successful_receipt": last_successful_receipt,
        "last_event_id": last_event["event_id"],
        "next_action": last_event["next_action"],
    }


def inspect_ledger(root: Path, *, now: str | None = None, limit: int | None = None) -> dict[str, Any]:
    root = _private_ledger(root, must_exist=True)
    plan, _ = _load_plan(root)
    events = _load_events(root, limit=limit)
    observed = _timestamp(now or _utc_now(), "检查时间")
    return _summarize(root, plan, events, as_of=observed)


def create_ledger(
    root: Path,
    *,
    upgrade_id: str,
    baseline_version: str,
    target_version: str,
    campaign_purpose: str,
    evidence_decision: str,
    started_at_utc: str | None = None,
    total_budget_minutes: int = DEFAULT_TOTAL_BUDGET_MINUTES,
    stage_budgets_minutes: dict[str, int] | None = None,
) -> dict[str, Any]:
    root = _private_ledger(root, must_exist=False)
    started = started_at_utc or _utc_now()
    plan = {
        "schema_version": PLAN_SCHEMA,
        "upgrade_id": upgrade_id,
        "created_at_utc": started,
        "started_at_utc": started,
        "baseline_version": baseline_version,
        "target_version": target_version,
        "campaign_purpose": campaign_purpose,
        "evidence_decision": evidence_decision,
        "total_budget_minutes": total_budget_minutes,
        "stage_budgets_minutes": stage_budgets_minutes or dict(DEFAULT_STAGE_BUDGETS),
        "same_root_cause_retry_limit": DEFAULT_RETRY_LIMIT,
        "producer": _producer(),
    }
    _validate_plan(plan)
    root.mkdir(mode=0o700)
    (root / "events").mkdir(mode=0o700)
    (root / "receipts").mkdir(mode=0o700)
    _write_once(root / "ledger.json", plan)
    initial = {
        "schema_version": EVENT_SCHEMA,
        "sequence": 1,
        "event_id": "doc-pre-p0-started",
        "recorded_at_utc": started,
        "phase": "VC-0",
        "event_type": "stage_started",
        "attempt_id": None,
        "root_cause_id": None,
        "live_request_count": 0,
        "receipts": [],
        "next_action": "完成 DOC-PRE／P0 并清零工具阻断",
        "previous_event_sha256": None,
    }
    _validate_event_shape(root, initial, 1)
    _write_once(root / "events" / "000001.json", initial)
    return inspect_ledger(root, now=started)


def append_event(
    root: Path,
    *,
    event_id: str,
    phase: str,
    event_type: str,
    attempt_id: str | None = None,
    root_cause_id: str | None = None,
    live_request_count: int = 0,
    receipts: list[dict[str, str]] | None = None,
    next_action: str | None = None,
    recorded_at_utc: str | None = None,
) -> dict[str, Any]:
    root = _private_ledger(root, must_exist=True)
    plan, _ = _load_plan(root)
    raw_events = _load_events(root)
    recorded_raw = recorded_at_utc or _utc_now()
    recorded = _timestamp(recorded_raw, "recorded_at_utc")
    current = _summarize(root, plan, raw_events, as_of=recorded)
    if current["status"] in {"stop_required", "stopped"} and event_type not in {
        "stop_the_line",
        "recovery_verified",
    }:
        raise TimingLedgerError("计时或重试门禁已要求停线，禁止继续追加执行事件")
    sequence = len(raw_events) + 1
    event = {
        "schema_version": EVENT_SCHEMA,
        "sequence": sequence,
        "event_id": event_id,
        "recorded_at_utc": recorded_raw,
        "phase": phase,
        "event_type": event_type,
        "attempt_id": attempt_id,
        "root_cause_id": root_cause_id,
        "live_request_count": live_request_count,
        "receipts": sorted(receipts or [], key=lambda item: item["role"]),
        "next_action": next_action,
        "previous_event_sha256": _sha256_bytes(raw_events[-1][1]),
    }
    candidate_raw = _canonical(event)
    _summarize(root, plan, [*raw_events, (event, candidate_raw)], as_of=recorded)
    _write_once(root / "events" / f"{sequence:06d}.json", event)
    return inspect_ledger(root, now=recorded_raw)


def build_checkpoint(root: Path, *, observed_at_utc: str | None = None) -> dict[str, Any]:
    root = _private_ledger(root, must_exist=True)
    plan, plan_raw = _load_plan(root)
    events = _load_events(root)
    observed = observed_at_utc or _utc_now()
    summary = _summarize(
        root, plan, events, as_of=_timestamp(observed, "observed_at_utc")
    )
    return {
        "schema_version": RECEIPT_SCHEMA,
        "observed_at_utc": observed,
        "ledger_plan": {
            "path": "ledger.json",
            "sha256": _sha256_bytes(plan_raw),
            "bytes": len(plan_raw),
        },
        "event_head": {
            "sequence": summary["head_sequence"],
            "sha256": summary["head_sha256"],
        },
        "summary": summary,
        "producer": _producer(),
    }


def checkpoint(root: Path, output_relative: str) -> dict[str, Any]:
    root = _private_ledger(root, must_exist=True)
    output = _relative(root, output_relative, "checkpoint output")
    receipt = build_checkpoint(root)
    _write_once(output, receipt)
    return receipt


def replay(root: Path, receipt_relative: str) -> dict[str, Any]:
    root = _private_ledger(root, must_exist=True)
    path = _relative(root, receipt_relative, "checkpoint receipt")
    receipt, raw = _load_json(path, "checkpoint receipt")
    _expect(
        receipt,
        {"schema_version", "observed_at_utc", "ledger_plan", "event_head", "summary", "producer"},
        "checkpoint receipt",
    )
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        raise TimingLedgerError("checkpoint receipt schema_version 不匹配")
    plan_binding = _expect(receipt.get("ledger_plan"), {"path", "sha256", "bytes"}, "ledger_plan")
    plan_path = _relative(root, plan_binding.get("path"), "ledger_plan.path")
    if (
        plan_path != root / "ledger.json"
        or plan_binding.get("sha256") != _sha256_file(plan_path)
        or plan_binding.get("bytes") != plan_path.stat().st_size
    ):
        raise TimingLedgerError("checkpoint 绑定的 ledger plan 漂移")
    head = _expect(receipt.get("event_head"), {"sequence", "sha256"}, "event_head")
    sequence = head.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence <= 0:
        raise TimingLedgerError("checkpoint event head 非法")
    plan, plan_raw = _load_plan(root)
    events = _load_events(root, limit=sequence)
    summary = _summarize(
        root,
        plan,
        events,
        as_of=_timestamp(receipt.get("observed_at_utc"), "observed_at_utc"),
    )
    expected = {
        "schema_version": RECEIPT_SCHEMA,
        "observed_at_utc": receipt["observed_at_utc"],
        "ledger_plan": {
            "path": "ledger.json",
            "sha256": _sha256_bytes(plan_raw),
            "bytes": len(plan_raw),
        },
        "event_head": {"sequence": sequence, "sha256": summary["head_sha256"]},
        "summary": summary,
        "producer": _producer(),
    }
    if head.get("sha256") != summary["head_sha256"] or _canonical(expected) != raw:
        raise TimingLedgerError("UpgradeTimingLedger checkpoint 重放结果不一致")
    return receipt


def assert_usable(
    root: Path,
    receipt_relative: str,
    *,
    baseline_version: str,
    target_version: str,
    campaign_purpose: str,
    required_phase: str | None = None,
) -> dict[str, Any]:
    """重放冻结 checkpoint，并以当前墙钟确认台账仍可继续。"""

    receipt = replay(root, receipt_relative)
    summary = inspect_ledger(root)
    expected = {
        "baseline_version": baseline_version,
        "target_version": target_version,
        "campaign_purpose": campaign_purpose,
    }
    if any(summary.get(key) != value for key, value in expected.items()):
        raise TimingLedgerError("UpgradeTimingLedger 与 Campaign 版本或用途不一致")
    if summary["status"] != "active":
        raise TimingLedgerError(f"UpgradeTimingLedger 当前状态为 {summary['status']}，必须停线")
    if required_phase is not None and summary["active_phase"] != required_phase:
        raise TimingLedgerError(
            f"UpgradeTimingLedger 当前阶段为 {summary['active_phase']}，要求 {required_phase}"
        )
    if receipt["summary"]["status"] != "active":
        raise TimingLedgerError("冻结 checkpoint 在生成时已非 active")
    return summary


def _receipt_arguments(values: list[str]) -> list[dict[str, str]]:
    receipts: list[dict[str, str]] = []
    for value in values:
        role, separator, path = value.partition("=")
        if not separator or not role or not path:
            raise TimingLedgerError("--receipt 必须为 ROLE=RELATIVE_PATH")
        receipts.append({"role": role, "path": path, "sha256": ""})
    return receipts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create_parser = commands.add_parser("create", help="创建只写一次的 UpgradeTimingLedger")
    create_parser.add_argument("--ledger-dir", type=Path, required=True)
    create_parser.add_argument("--upgrade-id", required=True)
    create_parser.add_argument("--baseline-version", required=True)
    create_parser.add_argument("--target-version", required=True)
    create_parser.add_argument("--campaign-purpose", choices=sorted(PURPOSES), required=True)
    create_parser.add_argument("--evidence-decision", choices=sorted(EVIDENCE_DECISIONS), required=True)
    create_parser.add_argument("--total-budget-minutes", type=int, default=DEFAULT_TOTAL_BUDGET_MINUTES)
    append_parser = commands.add_parser("append", help="追加一个不可覆盖的计时事件")
    append_parser.add_argument("--ledger-dir", type=Path, required=True)
    append_parser.add_argument("--event-id", required=True)
    append_parser.add_argument("--phase", choices=PHASE_ORDER, required=True)
    append_parser.add_argument("--event-type", choices=sorted(EVENT_TYPES), required=True)
    append_parser.add_argument("--attempt-id")
    append_parser.add_argument("--root-cause-id")
    append_parser.add_argument("--live-request-count", type=int, default=0)
    append_parser.add_argument("--receipt", action="append", default=[])
    append_parser.add_argument("--next-action")
    checkpoint_parser = commands.add_parser("checkpoint", help="封存当前 event head 的可重放 checkpoint")
    checkpoint_parser.add_argument("--ledger-dir", type=Path, required=True)
    checkpoint_parser.add_argument("--output", required=True)
    replay_parser = commands.add_parser("replay", help="独立重放历史 checkpoint")
    replay_parser.add_argument("--ledger-dir", type=Path, required=True)
    replay_parser.add_argument("--receipt", required=True)
    status_parser = commands.add_parser("status", help="按当前墙钟只读检查计时状态")
    status_parser.add_argument("--ledger-dir", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "create":
            result = create_ledger(
                arguments.ledger_dir,
                upgrade_id=arguments.upgrade_id,
                baseline_version=arguments.baseline_version,
                target_version=arguments.target_version,
                campaign_purpose=arguments.campaign_purpose,
                evidence_decision=arguments.evidence_decision,
                total_budget_minutes=arguments.total_budget_minutes,
            )
        elif arguments.command == "append":
            bindings = _receipt_arguments(arguments.receipt)
            root = _private_ledger(arguments.ledger_dir, must_exist=True)
            for binding in bindings:
                path = _relative(root, binding["path"], "receipt")
                if not path.is_file() or path.is_symlink():
                    raise TimingLedgerError(f"receipt 不存在：{binding['path']}")
                binding["sha256"] = _sha256_file(path)
            result = append_event(
                root,
                event_id=arguments.event_id,
                phase=arguments.phase,
                event_type=arguments.event_type,
                attempt_id=arguments.attempt_id,
                root_cause_id=arguments.root_cause_id,
                live_request_count=arguments.live_request_count,
                receipts=bindings,
                next_action=arguments.next_action,
            )
        elif arguments.command == "checkpoint":
            result = checkpoint(arguments.ledger_dir, arguments.output)["summary"]
        elif arguments.command == "replay":
            result = replay(arguments.ledger_dir, arguments.receipt)["summary"]
        else:
            result = inspect_ledger(arguments.ledger_dir)
    except (OSError, TimingLedgerError) as error:
        print(f"UpgradeTimingLedger 失败：{error}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
