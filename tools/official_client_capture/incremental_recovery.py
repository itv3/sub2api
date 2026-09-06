#!/usr/bin/env python3
"""官方客户端升级的组件级增量恢复原语。

该模块只处理确定性计划和本地 checkpoint，不执行网络请求。调用方负责提供
组件文件摘要、Job／门禁依赖以及实际执行函数。历史结果从不覆盖；命中缓存时
必须显式记录 ``reused``，从而可以还原一轮恢复究竟执行了什么。
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping


SCHEMA_VERSION = "codex-upgrade-incremental/v1"
CHECKPOINT_SCHEMA = "codex-upgrade-incremental-checkpoint/v1"
CANONICAL_CHECKPOINT_SCHEMA = "codex-upgrade-canonical-checkpoint/v1"
CANONICAL_IMPORT_RECEIPT_SCHEMA = "codex-upgrade-canonical-import/v1"
SHA256_HEX_LENGTH = 64
MAX_CHECKPOINT_RECORD_BYTES = 4 * 1024 * 1024
MAX_CHECKPOINT_RECORDS = 100_000
SAFE_ID_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CHECKPOINT_STATUSES = frozenset(
    {"pending", "passed", "complete", "failed", "blocked", "reused"}
)
CANONICAL_RULE_CLASSIFICATIONS = frozenset(
    {"inherit", "change", "condition_change", "add", "delete"}
)
CANONICAL_AFFECTED_CLASSIFICATIONS = frozenset(
    {"change", "condition_change", "add", "delete"}
)
CANONICAL_PHASES = frozenset(
    {"VC-0", "VC-1", "VC-2", "VC-3", "VC-4", "VC-5", "VC-6"}
)


class IncrementalRecoveryError(ValueError):
    """增量计划、依赖图或 checkpoint 不可信。"""


class WallClockTimeoutError(IncrementalRecoveryError):
    """一次受管 attempt 超过显式墙钟预算。"""

    def __init__(
        self,
        operation: str,
        *,
        elapsed_seconds: float,
        budget_seconds: float,
    ) -> None:
        self.operation = str(operation)
        self.elapsed_seconds = float(elapsed_seconds)
        self.budget_seconds = float(budget_seconds)
        super().__init__(
            f"墙钟预算已到期：{self.operation} "
            f"（{self.elapsed_seconds:.3f}s/{self.budget_seconds:.3f}s）"
        )


class WallClockDeadline:
    """使用单调时钟管理一次 attempt 的全阶段 deadline。

    该对象不依赖墙上时间，也不允许通过重试或子阶段重新计时。调用方必须在
    每个外部命令、重试退避和大循环边界调用 :meth:`check`；到期统一抛出
    ``WallClockTimeoutError``，由上层写入停线收据。
    """

    def __init__(
        self,
        budget_seconds: int | float,
        *,
        label: str = "attempt",
        clock: Any = time.monotonic,
    ) -> None:
        if isinstance(budget_seconds, bool) or not isinstance(
            budget_seconds, (int, float)
        ):
            raise IncrementalRecoveryError("墙钟预算必须是数字")
        budget = float(budget_seconds)
        if not math.isfinite(budget) or budget <= 0:
            raise IncrementalRecoveryError("墙钟预算必须为正有限数")
        if not isinstance(label, str) or not label.strip() or len(label) > 128:
            raise IncrementalRecoveryError("墙钟预算标签非法")
        if not callable(clock):
            raise IncrementalRecoveryError("单调时钟必须可调用")
        self.budget_seconds = budget
        self.label = label.strip()
        self._clock = clock
        self.started_monotonic = float(clock())
        self.deadline_monotonic = self.started_monotonic + budget

    @property
    def elapsed_seconds(self) -> float:
        return max(0.0, float(self._clock()) - self.started_monotonic)

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.deadline_monotonic - float(self._clock()))

    @property
    def expired(self) -> bool:
        return self.remaining_seconds <= 0

    def check(self, operation: str | None = None) -> float:
        """检查 deadline 并返回剩余秒数；到期立即失败关闭。"""

        remaining = self.remaining_seconds
        if remaining <= 0:
            raise WallClockTimeoutError(
                operation or self.label,
                elapsed_seconds=self.elapsed_seconds,
                budget_seconds=self.budget_seconds,
            )
        return remaining

    def bounded_timeout(
        self,
        requested_seconds: int | float,
        *,
        operation: str | None = None,
        minimum_seconds: float = 0.001,
    ) -> float:
        """把单步 timeout 收紧到全局剩余预算内。"""

        if isinstance(requested_seconds, bool) or not isinstance(
            requested_seconds, (int, float)
        ):
            raise IncrementalRecoveryError("单步 timeout 必须是数字")
        requested = float(requested_seconds)
        if not math.isfinite(requested) or requested <= 0:
            raise IncrementalRecoveryError("单步 timeout 必须为正有限数")
        if isinstance(minimum_seconds, bool) or not isinstance(
            minimum_seconds, (int, float)
        ):
            raise IncrementalRecoveryError("最小 timeout 必须是数字")
        minimum = max(0.0, float(minimum_seconds))
        remaining = self.check(operation)
        # subprocess.wait 接受极小正数；若剩余时间小于 minimum，仍返回剩余值，
        # 让调用方得到 TimeoutExpired 后执行进程组清理。
        return min(requested, max(remaining, 1e-9))

    def sleep(self, seconds: int | float, *, operation: str = "retry backoff") -> None:
        """在全局 deadline 内退避，禁止睡眠越过预算。"""

        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
            raise IncrementalRecoveryError("退避时长必须是数字")
        delay = float(seconds)
        if not math.isfinite(delay) or delay < 0:
            raise IncrementalRecoveryError("退避时长非法")
        remaining = self.check(operation)
        time.sleep(min(delay, remaining))
        self.check(operation)


def terminate_process_group(
    process: subprocess.Popen[Any],
    *,
    deadline: WallClockDeadline | None = None,
    term_grace_seconds: float = 2.0,
    kill_grace_seconds: float = 1.0,
) -> None:
    """有界地终止一个外部命令及其整个进程组。

    采集命令可能再派生 relay、curl 或容器子进程；只调用
    ``Popen.terminate`` 会留下孤儿进程，进而继续占用出口和磁盘。这里先发
    ``SIGTERM``，宽限期后无条件发 ``SIGKILL``。宽限期也受 attempt 剩余
    deadline 限制，不能因为清理动作把全局墙钟预算拖长。
    """

    if process.poll() is not None:
        return

    def remaining_cap(requested: float) -> float:
        if deadline is None:
            return max(0.001, requested)
        return min(max(0.001, requested), max(0.001, deadline.remaining_seconds))

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (AttributeError, OSError, ProcessLookupError):
        try:
            process.terminate()
        except (AttributeError, OSError, ProcessLookupError):
            pass
    try:
        process.wait(timeout=remaining_cap(term_grace_seconds))
        return
    except (subprocess.TimeoutExpired, OSError, ProcessLookupError):
        pass

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (AttributeError, OSError, ProcessLookupError):
        try:
            process.kill()
        except (AttributeError, OSError, ProcessLookupError):
            pass
    try:
        process.wait(timeout=remaining_cap(kill_grace_seconds))
    except (subprocess.TimeoutExpired, OSError, ProcessLookupError):
        # 上层会把未回收的状态视为失败；这里不能再次无限等待。
        pass


def run_bounded_subprocess(
    argv: Iterable[str],
    *,
    timeout: int | float,
    deadline: WallClockDeadline,
    operation: str,
    check: bool = False,
    capture_output: bool = True,
    text: bool = False,
    encoding: str | None = None,
    errors: str | None = None,
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    stdin: Any = subprocess.DEVNULL,
    heartbeat: Any | None = None,
) -> subprocess.CompletedProcess[Any]:
    """在单步 timeout 与 attempt 全局 deadline 的交集内执行命令。

    与 ``subprocess.run(timeout=...)`` 不同，本函数按 heartbeat 间隔切片
    等待，并在每个切片重新检查单调 deadline；到期会回收整个进程组并抛出
    :class:`WallClockTimeoutError`，所以同步探针也不能绕过 watchdog。
    """

    if not isinstance(operation, str) or not operation.strip():
        raise IncrementalRecoveryError("外部命令操作标签不能为空")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise IncrementalRecoveryError("外部命令 timeout 必须是数字")
    requested = float(timeout)
    if not math.isfinite(requested) or requested <= 0:
        raise IncrementalRecoveryError("外部命令 timeout 必须为正有限数")
    command = list(argv)
    if not command or not all(isinstance(item, str) and item for item in command):
        raise IncrementalRecoveryError("外部命令参数非法")
    deadline.check(operation)
    stdout_target: Any = subprocess.PIPE if capture_output else None
    stderr_target: Any = subprocess.PIPE if capture_output else None
    process = subprocess.Popen(
        command,
        stdin=stdin,
        stdout=stdout_target,
        stderr=stderr_target,
        cwd=cwd,
        env=dict(env) if env is not None else None,
        text=text,
        encoding=encoding,
        errors=errors,
        start_new_session=True,
        shell=False,
    )
    started = time.monotonic()
    step_deadline = started + requested
    interval = float(getattr(deadline, "heartbeat_seconds", 30.0))
    if not math.isfinite(interval) or interval <= 0:
        interval = 30.0
    while True:
        try:
            remaining_global = deadline.check(operation)
        except WallClockTimeoutError:
            terminate_process_group(process, deadline=deadline)
            raise
        remaining_step = step_deadline - time.monotonic()
        if remaining_step <= 0:
            terminate_process_group(process, deadline=deadline)
            raise subprocess.TimeoutExpired(command, requested)
        wait_for = min(remaining_global, remaining_step, interval)
        try:
            stdout, stderr = process.communicate(timeout=max(0.001, wait_for))
        except subprocess.TimeoutExpired:
            if heartbeat is not None:
                try:
                    heartbeat(operation)
                except BaseException:
                    terminate_process_group(process, deadline=deadline)
                    raise
            # 先检查全局预算，再判断是否只是 heartbeat 切片。
            try:
                deadline.check(operation)
            except WallClockTimeoutError:
                terminate_process_group(process, deadline=deadline)
                raise
            if time.monotonic() >= step_deadline:
                terminate_process_group(process, deadline=deadline)
                raise subprocess.TimeoutExpired(command, requested)
            continue
        # 命令已退出，但收集输出和调度回到 Python 期间仍可能越过 deadline。
        deadline.check(operation)
        result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        if check and result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode,
                command,
                output=result.stdout,
                stderr=result.stderr,
            )
        return result


def normalize_root_cause(value: Any) -> str:
    """规范化可审计的失败根因键；不把完整日志写入状态机。"""

    if not isinstance(value, str):
        raise IncrementalRecoveryError("失败根因必须是字符串")
    normalized = " ".join(value.strip().split())
    if not normalized or len(normalized) > 512:
        raise IncrementalRecoveryError("失败根因为空或过长")
    return normalized


def failure_root_cause(result: Mapping[str, Any]) -> str:
    """从结果提取稳定根因；调用方可显式提供 ``root_cause``。"""

    if not isinstance(result, Mapping):
        raise IncrementalRecoveryError("失败结果必须是对象")
    explicit = result.get("root_cause")
    if explicit is not None:
        return normalize_root_cause(explicit)
    error_type = result.get("error_type") or result.get("type") or "failure"
    message = result.get("error") or result.get("message") or "unknown"
    return normalize_root_cause(f"{error_type}: {message}")


def failure_circuit(
    attempts: Iterable[Mapping[str, Any]],
    *,
    threshold: int = 2,
) -> dict[str, Any]:
    """计算同根因连续失败熔断状态。

    只看按时间顺序提供的 attempt 终态；成功或不同根因会打断当前 streak。
    达到阈值后调用方必须停线，不能再自动创建第三次 live attempt。
    """

    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
        raise IncrementalRecoveryError("failure circuit threshold 非法")
    streak_root: str | None = None
    streak = 0
    history: list[dict[str, Any]] = []
    for attempt in attempts:
        if not isinstance(attempt, Mapping):
            raise IncrementalRecoveryError("失败 attempt 必须是对象")
        status = attempt.get("status")
        if not isinstance(status, str) or not status:
            raise IncrementalRecoveryError("失败 attempt 缺少 status")
        if status in {"failed", "blocked"}:
            root = failure_root_cause(attempt)
            if root == streak_root:
                streak += 1
            else:
                streak_root, streak = root, 1
            history.append({"root_cause": root, "streak": streak, "status": status})
        else:
            streak_root, streak = None, 0
            history.append({"root_cause": None, "streak": 0, "status": status})
    return {
        "threshold": threshold,
        "root_cause": streak_root,
        "consecutive_failures": streak,
        "stop_the_line": streak >= threshold,
        "history": history,
    }


def canonical_bytes(value: Any, *, newline: bool = False) -> bytes:
    """以固定 JSON 编码计算所有机器摘要。"""

    raw = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return raw + (b"\n" if newline else b"")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value))


def file_digest(path: Path) -> str:
    """读取单个普通文件摘要；不允许符号链接。"""

    if path.is_symlink() or not path.is_file():
        raise IncrementalRecoveryError(f"文件不是可信普通文件：{path}")
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _validate_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise IncrementalRecoveryError(f"{label} 不是小写 SHA-256")
    return value


def _validate_identifier(
    value: Any,
    label: str,
    *,
    allow_colon: bool = False,
) -> str:
    """校验收据中用于索引的稳定标识符。"""

    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or any(
            character not in SAFE_ID_CHARS and not (allow_colon and character == ":")
            for character in value
        )
    ):
        raise IncrementalRecoveryError(f"{label} 标识符非法")
    return value


def normalize_entries(entries: Iterable[Mapping[str, Any]]) -> list[dict[str, str]]:
    """规范化组件文件清单并拒绝路径、摘要重复。"""

    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in entries:
        if not isinstance(item, Mapping):
            raise IncrementalRecoveryError("组件文件条目必须是对象")
        if set(item) != {"path", "sha256"}:
            raise IncrementalRecoveryError("组件文件条目字段不闭合")
        path = item.get("path")
        if not isinstance(path, str) or not path or "\\" in path:
            raise IncrementalRecoveryError("组件文件路径非法")
        parsed = PurePosixPath(path)
        if parsed.is_absolute() or str(parsed) != path or any(
            part in {"", ".", ".."} for part in parsed.parts
        ):
            raise IncrementalRecoveryError(f"组件文件路径不规范：{path}")
        if path in seen:
            raise IncrementalRecoveryError(f"组件文件路径重复：{path}")
        seen.add(path)
        normalized.append({"path": path, "sha256": _validate_sha(item.get("sha256"), path)})
    return sorted(normalized, key=lambda value: value["path"])


def build_component_identities(
    entries: Iterable[Mapping[str, Any]],
    assignments: Mapping[str, str] | None = None,
    *,
    default_component: str = "shared",
) -> dict[str, Any]:
    """按组件生成互不耦合的摘要。

    ``assignments`` 是路径到组件的显式映射；未登记路径落到
    ``default_component``，调用方可以据此实现 fail-close。组件摘要只依赖
    自己的文件集合，单个组件变化不会改变其他组件的摘要。
    """

    normalized = normalize_entries(entries)
    assignments = dict(assignments or {})
    for path, component in assignments.items():
        if not isinstance(path, str) or not isinstance(component, str):
            raise IncrementalRecoveryError("组件映射必须使用字符串")
        _validate_identifier(component, "组件")
    unknown_assignments = set(assignments) - {item["path"] for item in normalized}
    if unknown_assignments:
        raise IncrementalRecoveryError(
            "组件映射包含清单外路径：" + ",".join(sorted(unknown_assignments))
        )
    grouped: dict[str, list[dict[str, str]]] = {}
    for entry in normalized:
        component = assignments.get(entry["path"], default_component)
        _validate_identifier(component, "组件")
        grouped.setdefault(component, []).append(entry)
    components = {
        name: {
            "entry_count": len(values),
            "entries": values,
            "sha256": digest({"entries": values}),
        }
        for name, values in sorted(grouped.items())
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "component_count": len(components),
        "components": components,
        # 仅供审计和旧收据兼容；选择重跑时不得读取它。
        "all_sha256": digest({"entries": normalized}),
    }


def component_drift(
    before: Mapping[str, Any], after: Mapping[str, Any]
) -> dict[str, Any]:
    """返回组件级变化，不因无关组件变化而扩大结果。"""

    def index(value: Mapping[str, Any], label: str) -> dict[str, tuple[str, list[dict[str, str]]]]:
        if not isinstance(value, Mapping):
            raise IncrementalRecoveryError(f"{label} 不是对象")
        raw = value.get("components")
        if not isinstance(raw, Mapping):
            raise IncrementalRecoveryError(f"{label} 缺少 components")
        if (
            not isinstance(value.get("component_count"), int)
            or isinstance(value.get("component_count"), bool)
            or value.get("component_count") != len(raw)
        ):
            raise IncrementalRecoveryError(f"{label} component_count 不一致")
        schema_version = value.get("schema_version")
        if schema_version is not None and schema_version != SCHEMA_VERSION:
            raise IncrementalRecoveryError(f"{label} schema_version 不支持")
        all_sha = value.get("all_sha256")
        if all_sha is not None:
            _validate_sha(all_sha, f"{label}.all_sha256")
        output: dict[str, tuple[str, list[dict[str, str]]]] = {}
        for name, item in raw.items():
            _validate_identifier(name, f"{label}组件")
            if not isinstance(item, Mapping):
                raise IncrementalRecoveryError(f"{label}.{name} 不是对象")
            if set(item) != {"entry_count", "entries", "sha256"}:
                raise IncrementalRecoveryError(f"{label}.{name} 字段不闭合")
            entries = item.get("entries")
            if not isinstance(entries, list):
                raise IncrementalRecoveryError(f"{label}.{name}.entries 不是数组")
            normalized = normalize_entries(entries)
            if normalized != entries:
                raise IncrementalRecoveryError(f"{label}.{name}.entries 未规范化")
            if item.get("entry_count") != len(entries):
                raise IncrementalRecoveryError(f"{label}.{name}.entry_count 不一致")
            sha = _validate_sha(item.get("sha256"), f"{label}.{name}.sha256")
            if sha != digest({"entries": entries}):
                raise IncrementalRecoveryError(f"{label}.{name}.sha256 不一致")
            output[name] = (sha, entries)
        all_entries: list[dict[str, str]] = [
            entry for _, entries in output.values() for entry in entries
        ]
        try:
            normalized_all = normalize_entries(all_entries)
        except IncrementalRecoveryError as error:
            raise IncrementalRecoveryError(f"{label}组件路径重复或非法") from error
        if len(normalized_all) != len(all_entries):
            raise IncrementalRecoveryError(f"{label}组件路径重复")
        if all_sha is not None and all_sha != digest({"entries": normalized_all}):
            raise IncrementalRecoveryError(f"{label}.all_sha256 不一致")
        return output

    old, new = index(before, "before"), index(after, "after")
    names = sorted(set(old) | set(new))
    changed = [name for name in names if old.get(name, (None, []))[0] != new.get(name, (None, []))[0]]
    paths: dict[str, list[str]] = {}
    for name in changed:
        old_paths = {str(item.get("path")): str(item.get("sha256")) for item in old.get(name, ("", []))[1]}
        new_paths = {str(item.get("path")): str(item.get("sha256")) for item in new.get(name, ("", []))[1]}
        paths[name] = sorted(
            path for path in set(old_paths) | set(new_paths) if old_paths.get(path) != new_paths.get(path)
        )
    return {
        "changed_components": changed,
        "changed_paths": paths,
        "from_all_sha256": before.get("all_sha256"),
        "to_all_sha256": after.get("all_sha256"),
    }


def dependency_digest(dependencies: Iterable[Mapping[str, Any] | str]) -> str:
    """对直接依赖排序后计算摘要。"""

    normalized: list[dict[str, str]] = []
    for dependency in dependencies:
        if isinstance(dependency, str):
            identifier = _validate_identifier(dependency, "依赖", allow_colon=True)
            normalized.append({"id": identifier, "status": "", "result_sha256": ""})
            continue
        if not isinstance(dependency, Mapping):
            raise IncrementalRecoveryError("依赖必须是字符串或对象")
        identifier = dependency.get("id")
        _validate_identifier(identifier, "依赖 ID", allow_colon=True)
        status = dependency.get("status", "")
        result_sha = dependency.get("result_sha256", "")
        if not isinstance(status, str):
            raise IncrementalRecoveryError(f"依赖 {identifier} 的 status 非法")
        if not isinstance(result_sha, str):
            raise IncrementalRecoveryError(f"依赖 {identifier} 的 result_sha256 非法")
        if result_sha:
            _validate_sha(result_sha, f"依赖 {identifier} 的 result_sha256")
        normalized.append(
            {"id": identifier, "status": status, "result_sha256": result_sha}
        )
    normalized.sort(key=lambda item: (item["id"], item["status"], item["result_sha256"]))
    if len({item["id"] for item in normalized}) != len(normalized):
        raise IncrementalRecoveryError("依赖 ID 重复")
    return digest(normalized)


def result_key(
    *,
    component: str,
    item_id: str,
    input_sha256: str,
    environment_sha256: str,
    dependency_sha256: str,
) -> str:
    """构造与时间戳无关的缓存键。"""

    if (
        not isinstance(component, str)
        or not isinstance(item_id, str)
        or not component
        or not item_id
    ):
        raise IncrementalRecoveryError("result_key 缺少组件或 item_id")
    for label, value in (
        ("input_sha256", input_sha256),
        ("environment_sha256", environment_sha256),
        ("dependency_sha256", dependency_sha256),
    ):
        _validate_sha(value, label)
    _validate_identifier(component, "result_key 组件")
    _validate_identifier(item_id, "result_key item_id", allow_colon=True)
    return digest(
        {
            "component": component,
            "item_id": item_id,
            "input_sha256": input_sha256,
            "environment_sha256": environment_sha256,
            "dependency_sha256": dependency_sha256,
        }
    )


def topological_order(graph: Mapping[str, Iterable[str]]) -> list[str]:
    """返回确定性拓扑序；发现环时失败关闭。"""

    if not isinstance(graph, Mapping):
        raise IncrementalRecoveryError("依赖图必须是对象")
    normalized_graph: dict[str, tuple[str, ...]] = {}
    for raw_node, raw_dependencies in graph.items():
        node = _validate_identifier(raw_node, "依赖图节点")
        if isinstance(raw_dependencies, (str, bytes)):
            raise IncrementalRecoveryError(f"节点 {node} 的依赖必须是数组")
        try:
            dependencies = tuple(
                _validate_identifier(item, f"节点 {node} 的依赖")
                for item in raw_dependencies
            )
        except TypeError as error:
            raise IncrementalRecoveryError(f"节点 {node} 的依赖不可迭代") from error
        if len(set(dependencies)) != len(dependencies):
            raise IncrementalRecoveryError(f"节点 {node} 的依赖重复")
        normalized_graph[node] = dependencies
    nodes = set(normalized_graph)
    for dependencies in normalized_graph.values():
        nodes.update(dependencies)
    state: dict[str, int] = {}
    output: list[str] = []

    def visit(node: str) -> None:
        marker = state.get(node, 0)
        if marker == 1:
            raise IncrementalRecoveryError(f"依赖图存在环：{node}")
        if marker == 2:
            return
        state[node] = 1
        for dependency in sorted(normalized_graph.get(node, ())):
            visit(dependency)
        state[node] = 2
        output.append(node)

    for node in sorted(nodes):
        visit(node)
    return output


def select_rerun(
    *,
    graph: Mapping[str, Iterable[str]],
    node_components: Mapping[str, Iterable[str]],
    previous_results: Mapping[str, Mapping[str, Any]] | None,
    changed_components: Iterable[str] = (),
    force_nodes: Iterable[str] = (),
    high_risk: bool = False,
) -> dict[str, Any]:
    """计算失败项与受影响下游的最小执行集合。

    ``graph[node]`` 表示该节点依赖的节点。高风险时只扩大到当前图，不会
    触碰其他 Persona／其他调用方未登记的节点。
    """

    order = topological_order(graph)
    components = {
        _validate_identifier(item, "变化组件") for item in changed_components
    }
    forced = {_validate_identifier(item, "强制节点") for item in force_nodes}
    if not forced.issubset(set(order)):
        raise IncrementalRecoveryError("强制节点不在依赖图中")
    previous = previous_results or {}
    if not isinstance(previous, Mapping):
        raise IncrementalRecoveryError("previous_results 必须是对象")
    normalized_components: dict[str, set[str]] = {}
    for raw_node, raw_components in node_components.items():
        node = _validate_identifier(raw_node, "Job 节点")
        if node not in set(order):
            raise IncrementalRecoveryError(f"Job 节点不在依赖图中：{node}")
        if isinstance(raw_components, (str, bytes)):
            raise IncrementalRecoveryError(f"Job {node} 的组件必须是数组")
        try:
            values = {_validate_identifier(item, f"Job {node} 的组件") for item in raw_components}
        except TypeError as error:
            raise IncrementalRecoveryError(f"Job {node} 的组件不可迭代") from error
        normalized_components[node] = values
    for node in order:
        normalized_components.setdefault(node, set())
    unknown_previous = set(previous) - set(order)
    if unknown_previous:
        raise IncrementalRecoveryError(
            "previous_results 包含未知节点：" + ",".join(sorted(unknown_previous))
        )
    failed = {
        node
        for node, result in previous.items()
        if isinstance(result, Mapping) and result.get("status") in {"failed", "blocked"}
    }
    malformed = {
        node for node, result in previous.items() if not isinstance(result, Mapping)
    }
    if malformed:
        raise IncrementalRecoveryError("previous_results 节点结果不是对象")

    # 失败项本身也是失效根节点。即使它没有发生工具漂移，其下游门禁仍然
    # 依赖该结果，必须随失败项一起重跑，不能错误复用旧的通过结论。
    affected = set(forced) | failed
    # high_risk 由调用方用来记录审计语义；闭集始终只由显式组件和当前图计算，
    # 不得因为一个布尔开关把图外项目带进来。
    if not isinstance(high_risk, bool):
        raise IncrementalRecoveryError("high_risk 必须是布尔值")
    affected.update(
        node for node in order if components.intersection(normalized_components[node])
    )

    # 依赖节点变化会使所有下游结果失效；反向闭包只在当前图内计算。
    changed = True
    while changed:
        changed = False
        for node in order:
            if node in affected:
                continue
            if any(dependency in affected for dependency in graph.get(node, ())):
                affected.add(node)
                changed = True

    execute = [
        node
        for node in order
        if node in affected
        or node in failed
        or node not in previous
        or previous[node].get("status") not in {"passed", "complete"}
    ]
    reused = [
        node
        for node in order
        if node not in execute
        and previous[node].get("status") in {"passed", "complete"}
    ]
    unknown: list[str] = []
    failed_ordered = [node for node in order if node in failed]
    affected_ordered = [node for node in order if node in affected]
    execute_reasons = {
        node: (
            "previous_failure"
            if node in failed
            else "affected_dependency"
            if node in affected
            else "missing_previous_result"
            if node not in previous
            else "non_passed_previous_result"
        )
        for node in execute
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "order": order,
        "execute": execute,
        "reused": reused,
        "failed": failed_ordered,
        "affected": affected_ordered,
        "unknown": unknown,
        "changed_components": sorted(components),
        "high_risk": bool(high_risk),
        # 这是计划事实，不是新的通过结论。调用方在该值为 True 时必须在
        # reservation／探针之前写 incremental-noop，并直接结束本次恢复。
        "no_op": not execute,
        "no_op_reason": "no_failed_or_affected_items" if not execute else None,
        "reasons": execute_reasons,
        "plan_sha256": digest(
            {
                "order": order,
                "execute": execute,
                "reused": reused,
                "failed": failed_ordered,
                "affected": affected_ordered,
                "unknown": unknown,
                "reasons": execute_reasons,
                "changed_components": sorted(components),
                "high_risk": bool(high_risk),
                "no_op": not execute,
                "no_op_reason": "no_failed_or_affected_items" if not execute else None,
            }
        ),
    }


class CheckpointStore:
    """追加式 checkpoint 存储。

    每条记录单独落盘，写入后通过 ``os.replace`` 原子发布；同一个 item 只能
    成功一次，后续状态必须使用新的序号和前序摘要，避免覆盖历史。
    """

    def __init__(self, root: Path, *, create: bool = True):
        if not isinstance(root, Path) or not root.is_absolute() or root.is_symlink():
            raise IncrementalRecoveryError("checkpoint 根必须是绝对非符号链接目录")
        if create:
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
        elif not root.is_dir():
            raise IncrementalRecoveryError("checkpoint 根不存在或不是目录")
        if root.is_symlink() or stat.S_IMODE(root.stat().st_mode) != 0o700:
            raise IncrementalRecoveryError("checkpoint 根权限必须为 0700")
        resolved = root.resolve(strict=True)
        if resolved.is_symlink() or not resolved.is_dir():
            raise IncrementalRecoveryError("checkpoint 根不是可信目录")
        self.root = resolved

    def _paths(self) -> list[Path]:
        paths = sorted(self.root.iterdir(), key=lambda path: path.name)
        output: list[Path] = []
        for path in paths:
            if path.is_symlink() or not path.is_file():
                raise IncrementalRecoveryError(f"checkpoint 目录含非普通文件：{path.name}")
            if not re_fullmatch_checkpoint_name(path.name):
                if path.name.startswith(".") and path.name.endswith(".tmp"):
                    raise IncrementalRecoveryError(f"checkpoint 存在未清理临时文件：{path.name}")
                raise IncrementalRecoveryError(f"checkpoint 文件名非法：{path.name}")
            output.append(path)
        if len(output) > MAX_CHECKPOINT_RECORDS:
            raise IncrementalRecoveryError("checkpoint 记录数量超过上限")
        return output

    def records(self) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        previous_digest: str | None = None
        latest_status: dict[str, str] = {}
        for expected_sequence, path in enumerate(self._paths(), 1):
            metadata = path.stat()
            if os.geteuid() != metadata.st_uid or stat.S_IMODE(metadata.st_mode) != 0o600:
                raise IncrementalRecoveryError(f"checkpoint 权限或属主非法：{path.name}")
            if path.stat().st_size > MAX_CHECKPOINT_RECORD_BYTES:
                raise IncrementalRecoveryError(f"checkpoint 记录过大：{path.name}")
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                raise IncrementalRecoveryError(f"checkpoint 不可读：{path}") from error
            if not isinstance(payload, dict):
                raise IncrementalRecoveryError(f"checkpoint 顶层不是对象：{path}")
            if payload.get("schema_version") != CHECKPOINT_SCHEMA:
                raise IncrementalRecoveryError(f"checkpoint schema_version 非法：{path.name}")
            if payload.get("checkpoint_sequence") != expected_sequence:
                raise IncrementalRecoveryError(f"checkpoint 序号不连续：{path.name}")
            if payload.get("previous_checkpoint_sha256") != previous_digest:
                raise IncrementalRecoveryError(f"checkpoint 摘要链断裂：{path.name}")
            recorded = payload.get("checkpoint_sha256")
            _validate_sha(recorded, f"{path.name}.checkpoint_sha256")
            unsigned = dict(payload)
            unsigned.pop("checkpoint_sha256", None)
            if digest(unsigned) != recorded:
                raise IncrementalRecoveryError(f"checkpoint 自摘要不一致：{path.name}")
            _validate_identifier(payload.get("item_id"), f"{path.name}.item_id")
            status = payload.get("status")
            if status not in CHECKPOINT_STATUSES:
                raise IncrementalRecoveryError(f"checkpoint 状态非法：{path.name}")
            item_id = str(payload["item_id"])
            # 同一 Job 可以在失败后追加成功记录；已经通过的记录是终态，
            # 后续再写任何状态都意味着试图覆盖成功事实，必须拒绝。
            if item_id in latest_status and latest_status[item_id] in {
                "passed",
                "complete",
                "reused",
            }:
                raise IncrementalRecoveryError(
                    f"checkpoint 已通过项不可再次写入：{item_id}"
                )
            disposition = payload.get("disposition")
            if disposition is not None and disposition not in {"executed", "reused"}:
                raise IncrementalRecoveryError(f"checkpoint disposition 非法：{path.name}")
            for field in ("result_sha256", "result_key"):
                if payload.get(field) is not None:
                    _validate_sha(payload[field], f"{path.name}.{field}")
            output.append(payload)
            previous_digest = recorded
            latest_status[item_id] = status
        return output

    def latest_by_item(self) -> dict[str, dict[str, Any]]:
        """返回每个 item 的最后一条记录（读取时已完成链校验）。"""

        latest: dict[str, dict[str, Any]] = {}
        for record in self.records():
            latest[str(record["item_id"])] = record
        return latest

    def record_path(self, sequence: int) -> Path:
        """返回已校验的单条 checkpoint 路径。"""

        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
            raise IncrementalRecoveryError("checkpoint 序号非法")
        path = self.root / f"{sequence:08d}.json"
        if path.is_symlink() or not path.is_file():
            raise IncrementalRecoveryError(f"checkpoint 记录不存在：{sequence}")
        # 读取会校验整条链，避免调用方仅凭文件名建立错误绑定。
        records = self.records()
        if sequence > len(records):
            raise IncrementalRecoveryError(f"checkpoint 序号越界：{sequence}")
        return path

    def append(self, record: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(record, Mapping):
            raise IncrementalRecoveryError("checkpoint 记录必须是对象")
        reserved = {"checkpoint_sequence", "checkpoint_sha256"}
        if reserved.intersection(record):
            raise IncrementalRecoveryError("checkpoint 序号和摘要由存储器生成")
        payload = dict(record)
        if payload.get("schema_version") not in {None, CHECKPOINT_SCHEMA}:
            raise IncrementalRecoveryError("checkpoint schema_version 不受支持")
        payload["schema_version"] = CHECKPOINT_SCHEMA
        _validate_identifier(payload.get("item_id"), "checkpoint item_id")
        if payload.get("status") not in CHECKPOINT_STATUSES:
            raise IncrementalRecoveryError("checkpoint status 非法")
        disposition = payload.get("disposition")
        if disposition is not None and disposition not in {"executed", "reused"}:
            raise IncrementalRecoveryError("checkpoint disposition 非法")
        previous = self.records()
        previous_digest = (
            str(previous[-1].get("checkpoint_sha256"))
            if previous and previous[-1].get("checkpoint_sha256")
            else None
        )
        if payload.get("previous_checkpoint_sha256") != previous_digest:
            raise IncrementalRecoveryError("checkpoint 前序摘要不连续")
        payload["checkpoint_sequence"] = len(previous) + 1
        payload["checkpoint_sha256"] = digest(payload)
        name = f"{payload['checkpoint_sequence']:08d}.json"
        destination = self.root / name
        if destination.exists() or destination.is_symlink():
            raise IncrementalRecoveryError(f"checkpoint 序号已存在：{name}")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{name}.", suffix=".tmp", dir=self.root
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            if temporary.stat().st_size > MAX_CHECKPOINT_RECORD_BYTES:
                raise IncrementalRecoveryError("checkpoint 记录过大")
            # hard-link 发布具备 O_EXCL 等价语义：并发 writer 不能覆盖已发布记录。
            try:
                os.link(temporary, destination)
            except FileExistsError as error:
                raise IncrementalRecoveryError(f"checkpoint 序号已存在：{name}") from error
            temporary.unlink()
            directory_descriptor = os.open(
                self.root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        # 重新从磁盘校验，保证返回值与已发布记录完全一致。
        return self.records()[-1]


def re_fullmatch_checkpoint_name(name: str) -> bool:
    """避免为单个简单文件名引入正则依赖。"""

    return (
        isinstance(name, str)
        and len(name) == 13
        and name[:8].isdigit()
        and name[8:] == ".json"
        and int(name[:8]) > 0
    )


def canonical_rule_partition(
    migration: Mapping[str, Any],
) -> dict[str, Any]:
    """从规则迁移清单计算唯一的受影响／继承规则集合。

    该函数只读取迁移项，不根据文件数、工具摘要或历史证据体积扩大执行集合。
    ``delete`` 使用旧规则编号，其余决策使用目标规则编号。
    """

    entries = migration.get("entries")
    if not isinstance(entries, list) or not entries:
        raise IncrementalRecoveryError("规则迁移清单 entries 不能为空")
    affected: list[str] = []
    inherited: list[str] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries, 1):
        if not isinstance(entry, Mapping):
            raise IncrementalRecoveryError(f"规则迁移项 {index} 必须是对象")
        classification = entry.get("classification")
        if classification not in CANONICAL_RULE_CLASSIFICATIONS:
            raise IncrementalRecoveryError(
                f"规则迁移项 {index} 不是可执行的最终决策"
            )
        field = "baseline_rule" if classification == "delete" else "target_rule"
        rule_id = entry.get(field)
        _validate_identifier(rule_id, f"规则迁移项 {index}.{field}")
        normalized = str(rule_id)
        if normalized in seen:
            raise IncrementalRecoveryError(f"规则迁移规则重复：{normalized}")
        seen.add(normalized)
        if classification in CANONICAL_AFFECTED_CLASSIFICATIONS:
            affected.append(normalized)
        else:
            inherited.append(normalized)
    return {
        "total_rule_count": len(entries),
        "affected_rule_ids": sorted(affected),
        "inherited_rule_ids": sorted(inherited),
    }


def _canonical_item_ids(value: Any, label: str) -> list[str]:
    if not isinstance(value, list):
        raise IncrementalRecoveryError(f"{label} 必须是数组")
    output: list[str] = []
    for item in value:
        _validate_identifier(item, label)
        output.append(str(item))
    if len(output) != len(set(output)):
        raise IncrementalRecoveryError(f"{label} 含重复项")
    return output


def _validate_canonical_checkpoint(
    payload: Mapping[str, Any],
    *,
    expected_sequence: int,
    previous_digest: str | None,
) -> dict[str, Any]:
    """验证一条聚合 checkpoint；不打开其引用的原始证据。"""

    required = {
        "schema_version",
        "checkpoint_sequence",
        "previous_checkpoint_sha256",
        "checkpoint_sha256",
        "recorded_at_utc",
        "campaign",
        "phase",
        "migration",
        "plan",
        "items",
        "evidence_manifest",
        "deadline",
        "source",
        "metrics",
    }
    if set(payload) != required:
        raise IncrementalRecoveryError("canonical checkpoint 字段不闭合")
    if payload.get("schema_version") != CANONICAL_CHECKPOINT_SCHEMA:
        raise IncrementalRecoveryError("canonical checkpoint schema_version 非法")
    if payload.get("checkpoint_sequence") != expected_sequence:
        raise IncrementalRecoveryError("canonical checkpoint 序号不连续")
    if payload.get("previous_checkpoint_sha256") != previous_digest:
        raise IncrementalRecoveryError("canonical checkpoint 摘要链断裂")
    recorded = payload.get("checkpoint_sha256")
    _validate_sha(recorded, "canonical checkpoint.checkpoint_sha256")
    unsigned = dict(payload)
    unsigned.pop("checkpoint_sha256", None)
    if digest(unsigned) != recorded:
        raise IncrementalRecoveryError("canonical checkpoint 自摘要不一致")
    recorded_at = payload.get("recorded_at_utc")
    if not isinstance(recorded_at, str) or not recorded_at.endswith("Z"):
        raise IncrementalRecoveryError("canonical checkpoint 时间非法")

    campaign = payload.get("campaign")
    if not isinstance(campaign, Mapping) or set(campaign) != {
        "campaign_id",
        "campaign_manifest_sha256",
        "baseline_version",
        "target_version",
        "candidate_id",
        "attempt_id",
    }:
        raise IncrementalRecoveryError("canonical checkpoint Campaign 身份不闭合")
    for field in ("campaign_id", "candidate_id", "attempt_id"):
        _validate_identifier(campaign.get(field), f"Campaign.{field}")
    _validate_sha(
        campaign.get("campaign_manifest_sha256"),
        "Campaign.campaign_manifest_sha256",
    )
    for field in ("baseline_version", "target_version"):
        value = campaign.get(field)
        if not isinstance(value, str) or not value:
            raise IncrementalRecoveryError(f"Campaign.{field} 非法")

    if payload.get("phase") not in CANONICAL_PHASES:
        raise IncrementalRecoveryError("canonical checkpoint phase 非法")
    migration = payload.get("migration")
    if not isinstance(migration, Mapping) or set(migration) != {
        "manifest_sha256",
        "total_rule_count",
        "affected_rule_ids",
        "inherited_rule_ids",
    }:
        raise IncrementalRecoveryError("canonical checkpoint 规则分区不闭合")
    _validate_sha(migration.get("manifest_sha256"), "migration.manifest_sha256")
    affected = _canonical_item_ids(
        migration.get("affected_rule_ids"), "affected_rule_ids"
    )
    inherited = _canonical_item_ids(
        migration.get("inherited_rule_ids"), "inherited_rule_ids"
    )
    total = migration.get("total_rule_count")
    if (
        not isinstance(total, int)
        or isinstance(total, bool)
        or total < 1
        or set(affected).intersection(inherited)
        or total != len(affected) + len(inherited)
    ):
        raise IncrementalRecoveryError("canonical checkpoint 规则分区不一致")

    plan = payload.get("plan")
    if not isinstance(plan, Mapping) or set(plan) != {
        "execute_item_ids",
        "reused_item_ids",
    }:
        raise IncrementalRecoveryError("canonical checkpoint 执行计划不闭合")
    execute = _canonical_item_ids(plan.get("execute_item_ids"), "execute_item_ids")
    reused = _canonical_item_ids(plan.get("reused_item_ids"), "reused_item_ids")
    if set(execute).intersection(reused):
        raise IncrementalRecoveryError("execute/reuse 集合相交")

    items = payload.get("items")
    if not isinstance(items, list):
        raise IncrementalRecoveryError("canonical checkpoint items 必须是数组")
    item_ids: list[str] = []
    for index, item in enumerate(items, 1):
        if not isinstance(item, Mapping) or set(item) != {
            "item_id",
            "status",
            "disposition",
            "result_sha256",
            "result_key",
            "source",
            "details",
        }:
            raise IncrementalRecoveryError(f"canonical item {index} 字段不闭合")
        _validate_identifier(item.get("item_id"), f"canonical item {index}.item_id")
        item_id = str(item["item_id"])
        item_ids.append(item_id)
        if item.get("status") not in {"passed", "complete", "reused"}:
            raise IncrementalRecoveryError(f"canonical item {item_id} 尚未通过")
        if item.get("disposition") not in {"executed", "reused"}:
            raise IncrementalRecoveryError(f"canonical item {item_id} disposition 非法")
        for field in ("result_sha256", "result_key"):
            value = item.get(field)
            if value is not None:
                _validate_sha(value, f"canonical item {item_id}.{field}")
        source = item.get("source")
        if not isinstance(source, Mapping) or set(source) != {"path", "sha256", "bytes"}:
            raise IncrementalRecoveryError(f"canonical item {item_id} 来源不闭合")
        path = source.get("path")
        size = source.get("bytes")
        if not isinstance(path, str) or not path or "\x00" in path:
            raise IncrementalRecoveryError(f"canonical item {item_id} 来源路径非法")
        _validate_sha(source.get("sha256"), f"canonical item {item_id}.source.sha256")
        if not isinstance(size, int) or isinstance(size, bool) or size < 1:
            raise IncrementalRecoveryError(f"canonical item {item_id} 来源大小非法")
        details = item.get("details")
        if not isinstance(details, Mapping):
            raise IncrementalRecoveryError(f"canonical item {item_id} details 非法")
    if len(item_ids) != len(set(item_ids)) or set(item_ids) != set(reused):
        raise IncrementalRecoveryError(
            "canonical 已通过 items 必须精确等于 reused_item_ids"
        )

    evidence_manifest = payload.get("evidence_manifest")
    if evidence_manifest is not None:
        if not isinstance(evidence_manifest, Mapping) or set(evidence_manifest) != {
            "path",
            "sha256",
            "bytes",
        }:
            raise IncrementalRecoveryError("EvidenceManifest 引用不闭合")
        _validate_sha(evidence_manifest.get("sha256"), "EvidenceManifest.sha256")
        if (
            not isinstance(evidence_manifest.get("path"), str)
            or not evidence_manifest.get("path")
            or not isinstance(evidence_manifest.get("bytes"), int)
            or isinstance(evidence_manifest.get("bytes"), bool)
            or evidence_manifest.get("bytes") < 1
        ):
            raise IncrementalRecoveryError("EvidenceManifest 引用非法")

    deadline = payload.get("deadline")
    if not isinstance(deadline, Mapping) or set(deadline) != {
        "started_at_epoch",
        "budget_seconds",
        "deadline_at_epoch",
    }:
        raise IncrementalRecoveryError("canonical checkpoint deadline 不闭合")
    start = deadline.get("started_at_epoch")
    budget = deadline.get("budget_seconds")
    end = deadline.get("deadline_at_epoch")
    if (
        isinstance(start, bool)
        or not isinstance(start, (int, float))
        or isinstance(budget, bool)
        or not isinstance(budget, (int, float))
        or isinstance(end, bool)
        or not isinstance(end, (int, float))
        or not all(math.isfinite(float(value)) for value in (start, budget, end))
        or float(start) <= 0
        or float(budget) <= 0
        or abs((float(start) + float(budget)) - float(end)) > 0.001
    ):
        raise IncrementalRecoveryError("canonical checkpoint deadline 非法")

    source = payload.get("source")
    if not isinstance(source, Mapping) or set(source) != {
        "kind",
        "legacy_object_types",
        "receipt_refs",
    }:
        raise IncrementalRecoveryError("canonical checkpoint source 不闭合")
    if source.get("kind") not in {"native", "historical-import"}:
        raise IncrementalRecoveryError("canonical checkpoint source.kind 非法")
    legacy_types = source.get("legacy_object_types")
    receipt_refs = source.get("receipt_refs")
    if (
        not isinstance(legacy_types, list)
        or not all(isinstance(value, str) and value for value in legacy_types)
        or len(legacy_types) != len(set(legacy_types))
        or not isinstance(receipt_refs, list)
        or not all(isinstance(value, Mapping) for value in receipt_refs)
    ):
        raise IncrementalRecoveryError("canonical checkpoint 历史来源非法")
    for index, reference in enumerate(receipt_refs, 1):
        if set(reference) != {"path", "sha256", "bytes"}:
            raise IncrementalRecoveryError(f"历史来源 {index} 字段不闭合")
        _validate_sha(reference.get("sha256"), f"历史来源 {index}.sha256")
        if (
            not isinstance(reference.get("path"), str)
            or not reference.get("path")
            or not isinstance(reference.get("bytes"), int)
            or isinstance(reference.get("bytes"), bool)
            or reference.get("bytes") < 1
        ):
            raise IncrementalRecoveryError(f"历史来源 {index} 非法")

    metrics = payload.get("metrics")
    if not isinstance(metrics, Mapping) or set(metrics) != {
        "scanned_bytes",
        "live_request_count",
    }:
        raise IncrementalRecoveryError("canonical checkpoint metrics 不闭合")
    if any(
        not isinstance(metrics.get(field), int)
        or isinstance(metrics.get(field), bool)
        or metrics.get(field) < 0
        for field in ("scanned_bytes", "live_request_count")
    ):
        raise IncrementalRecoveryError("canonical checkpoint metrics 非法")
    return dict(payload)


class CanonicalCheckpointStore:
    """新流程唯一的 Campaign 聚合 checkpoint 存储。"""

    def __init__(self, root: Path, *, create: bool = True):
        if not isinstance(root, Path) or not root.is_absolute() or root.is_symlink():
            raise IncrementalRecoveryError(
                "canonical checkpoint 根必须是绝对非符号链接目录"
            )
        if create:
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
        elif not root.is_dir():
            raise IncrementalRecoveryError("canonical checkpoint 根不存在")
        if root.is_symlink() or stat.S_IMODE(root.stat().st_mode) != 0o700:
            raise IncrementalRecoveryError("canonical checkpoint 根权限必须为 0700")
        self.root = root.resolve(strict=True)

    def _paths(self) -> list[Path]:
        paths = sorted(self.root.iterdir(), key=lambda path: path.name)
        for path in paths:
            if path.is_symlink() or not path.is_file() or not re_fullmatch_checkpoint_name(path.name):
                raise IncrementalRecoveryError(
                    f"canonical checkpoint 目录含非法文件：{path.name}"
                )
        return paths

    def records(self) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        previous: str | None = None
        for sequence, path in enumerate(self._paths(), 1):
            metadata = path.stat()
            if (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size > MAX_CHECKPOINT_RECORD_BYTES
            ):
                raise IncrementalRecoveryError(
                    f"canonical checkpoint 权限或大小非法：{path.name}"
                )
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                raise IncrementalRecoveryError(
                    f"canonical checkpoint 不可读：{path.name}"
                ) from error
            if not isinstance(payload, Mapping):
                raise IncrementalRecoveryError("canonical checkpoint 顶层不是对象")
            validated = _validate_canonical_checkpoint(
                payload,
                expected_sequence=sequence,
                previous_digest=previous,
            )
            output.append(validated)
            previous = str(validated["checkpoint_sha256"])
        return output

    def latest(self) -> dict[str, Any] | None:
        records = self.records()
        return records[-1] if records else None

    def append(self, record: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(record, Mapping):
            raise IncrementalRecoveryError("canonical checkpoint 必须是对象")
        if {"checkpoint_sequence", "checkpoint_sha256"}.intersection(record):
            raise IncrementalRecoveryError("canonical checkpoint 序号和摘要由存储器生成")
        previous_records = self.records()
        previous_digest = (
            str(previous_records[-1]["checkpoint_sha256"])
            if previous_records
            else None
        )
        payload = dict(record)
        payload["schema_version"] = CANONICAL_CHECKPOINT_SCHEMA
        payload["checkpoint_sequence"] = len(previous_records) + 1
        payload["previous_checkpoint_sha256"] = previous_digest
        payload["checkpoint_sha256"] = digest(payload)
        validated = _validate_canonical_checkpoint(
            payload,
            expected_sequence=len(previous_records) + 1,
            previous_digest=previous_digest,
        )
        name = f"{validated['checkpoint_sequence']:08d}.json"
        destination = self.root / name
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{name}.", suffix=".tmp", dir=self.root
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(
                    json.dumps(validated, ensure_ascii=False, sort_keys=True, indent=2)
                    + "\n"
                )
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, destination)
            except FileExistsError as error:
                raise IncrementalRecoveryError(
                    f"canonical checkpoint 序号已存在：{name}"
                ) from error
            directory_descriptor = os.open(
                self.root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        finally:
            temporary.unlink(missing_ok=True)
        return self.records()[-1]
