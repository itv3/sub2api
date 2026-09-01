#!/usr/bin/env python3
"""官方客户端升级的组件级增量恢复原语。

该模块只处理确定性计划和本地 checkpoint，不执行网络请求。调用方负责提供
组件文件摘要、Job／门禁依赖以及实际执行函数。历史结果从不覆盖；命中缓存时
必须显式记录 ``reused``，从而可以还原一轮恢复究竟执行了什么。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping


SCHEMA_VERSION = "codex-upgrade-incremental/v1"
CHECKPOINT_SCHEMA = "codex-upgrade-incremental-checkpoint/v1"
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


class IncrementalRecoveryError(ValueError):
    """增量计划、依赖图或 checkpoint 不可信。"""


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
            }
        ),
    }


class CheckpointStore:
    """追加式 checkpoint 存储。

    每条记录单独落盘，写入后通过 ``os.replace`` 原子发布；同一个 item 只能
    成功一次，后续状态必须使用新的序号和前序摘要，避免覆盖历史。
    """

    def __init__(self, root: Path):
        if not isinstance(root, Path) or not root.is_absolute() or root.is_symlink():
            raise IncrementalRecoveryError("checkpoint 根必须是绝对非符号链接目录")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if root.is_symlink() or stat.S_IMODE(root.stat().st_mode) != 0o700:
            raise IncrementalRecoveryError("checkpoint 根权限必须为 0700")
        self.root = root.resolve(strict=True)

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
