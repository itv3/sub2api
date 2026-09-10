"""冻结台账 successor 的一次性生成。

上游合并后，仓库内多套冻结摘要台账（transition／successor／ledger／receipt 收据）会
逐一失效。Go 与 Python 门禁承接这些失效的方式是同一张“可审计 successor 图”：从
``docs/egress/maintenance/*.json`` 中抽取显式登记的 ``path → from → to`` 摘要边，再计算
传递闭包。本模块按完全相同的抽边规则复算冻结覆盖集合，对一个提交区间（或工作树）
里命中冻结覆盖的路径一次性生成 successor 收据，并对少数需要额外动作的台账给出精确
待办。

设计约束：

- 抽边规则必须与 ``backend/internal/officialegress`` 中的 ``loadAuditedSourceSuccessorEdges``
  逐字一致，否则工具认为“已承接”而门禁仍会失败。
- 只承接“已登记摘要 → 当前摘要”的精确边；前序摘要不在已登记集合中时视为链断裂，
  一律 fail-close，不允许凭空补边。
- successor 收据本身不进入它所描述的提交；它引用的收据也不得在本区间内变化。
  这两条一起消除 v0.2.3 合并时出现的“移出、重算、加回”自引用循环。
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import (
    SAFE_ID_RE,
    bind_identity,
    expect_git_object,
    expect_object,
    load_json,
    pretty_bytes,
    safe_relative_path,
    sha256_bytes,
    sha256_file,
    validate_identity,
    write_once,
)
from .errors import UpstreamMergeError
from .gitops import assert_git_repository, git_output, run_git

MAINTENANCE_ROOT = "docs/egress/maintenance"
FREEZE_REGISTRY_RELATIVE = f"{MAINTENANCE_ROOT}/freeze-registry.json"
FREEZE_REGISTRY_SCHEMA = "official-egress-freeze-registry/v1"
FREEZE_SUCCESSOR_SCHEMA = "official-egress-upstream-freeze-successor/v1"
# 与 Go 侧 loadAuditedSourceSuccessorEdges 相同：只读取 schema_version 含这些标记的收据。
LEDGER_SCHEMA_MARKERS = ("successor", "transition", "ledger", "receipt")
PREDECESSOR_SCALAR_KEYS = ("predecessor_sha256", "from_sha256")
SUCCESSOR_SCALAR_KEYS = ("to_sha256", "current_sha256", "head_sha256")
FREEZE_VERIFICATION = [
    "go test ./internal/officialegress -run 'Frozen|Transition|Successor|Drift|Retirement' -count=1",
    "go test ./internal/service -run 'Frozen|Transition|Successor|Drift' -count=1",
    "make check-egress-spec-ci",
]
REGISTRY_ACTION_KINDS = {
    "python_receipt_list",
    "script_constant",
    "single_hop_file",
    "manual_required",
}


@dataclass(frozen=True)
class FrozenEdge:
    """一条显式登记的摘要边。"""

    path: str
    from_sha256: str
    to_sha256: str


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _load_strict_json(path: Path) -> Any | None:
    """按 Go Decoder 语义读取：解析失败或尾部有多余 JSON 都视为不可用。"""

    try:
        raw = path.read_bytes()
    except OSError:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


class _EdgeCollector:
    """复刻 Go 侧的递归抽边：任何带非空 path 与 reason 的对象都可能登记边。"""

    def __init__(self) -> None:
        self.edges: dict[tuple[str, str, str], set[str]] = {}
        # known 只由成对边建立，对应 Go 侧 knownDigestsByPath，用于快照展开。
        self.known: dict[str, set[str]] = {}
        # registered 收集每条路径出现过的全部合法摘要（含只有后继、没有前序的
        # 新增文件条目），用于“前序摘要是否被登记过”的链断裂判定。
        self.registered: dict[str, set[str]] = {}
        self.receipts: dict[str, set[str]] = {}
        self.snapshots: list[tuple[str, str]] = []

    def register(self, path: str, digest: str, receipt: str) -> None:
        if not path.strip() or not _is_sha256(digest):
            return
        self.registered.setdefault(path, set()).add(digest)
        self.receipts.setdefault(path, set()).add(receipt)

    def add(self, path: str, from_digest: str, to_digest: str, receipt: str) -> None:
        if not path.strip() or not _is_sha256(from_digest) or not _is_sha256(to_digest):
            return
        if from_digest == to_digest:
            return
        key = (path, from_digest, to_digest)
        self.edges.setdefault(key, set()).add(receipt)
        known = self.known.setdefault(path, set())
        known.add(from_digest)
        known.add(to_digest)

    def visit(self, value: Any, receipt: str) -> None:
        if isinstance(value, list):
            for item in value:
                self.visit(item, receipt)
            return
        if not isinstance(value, dict):
            return
        path = value.get("path")
        reason = value.get("reason")
        if isinstance(path, str) and isinstance(reason, str) and path.strip() and reason.strip():
            predecessors: list[str] = []
            successors: list[str] = []
            listed = value.get("predecessor_sha256s")
            if isinstance(listed, list):
                predecessors.extend(item for item in listed if isinstance(item, str))
            for key in PREDECESSOR_SCALAR_KEYS:
                digest = value.get(key)
                if isinstance(digest, str):
                    predecessors.append(digest)
            for key in SUCCESSOR_SCALAR_KEYS:
                digest = value.get(key)
                if isinstance(digest, str):
                    successors.append(digest)
            before = value.get("before")
            if isinstance(before, dict) and isinstance(before.get("sha256"), str):
                predecessors.append(before["sha256"])
            after = value.get("after")
            if isinstance(after, dict) and isinstance(after.get("sha256"), str):
                successors.append(after["sha256"])
                if "existence" in after:
                    self.snapshots.append((path, after["sha256"]))
            for digest in (*predecessors, *successors):
                self.register(path, digest, receipt)
            for predecessor in predecessors:
                for successor in successors:
                    self.add(path, predecessor, successor, receipt)
        for child in value.values():
            self.visit(child, receipt)


def load_frozen_edges(repository_root: Path) -> tuple[list[FrozenEdge], dict[str, set[str]], dict[str, set[str]]]:
    """返回（边列表，路径→已登记摘要集合，路径→登记收据集合）。

    边列表与 Go 侧 loadAuditedSourceSuccessorEdges 逐条一致；已登记摘要集合比 Go 的
    knownDigestsByPath 更宽，额外包含只有后继摘要的新增文件条目，因为这些路径下次
    被修改时同样需要一条从其登记摘要出发的承接边。
    """

    root = assert_git_repository(repository_root)
    maintenance = root / MAINTENANCE_ROOT
    if not maintenance.is_dir():
        raise UpstreamMergeError(f"冻结台账目录不存在：{maintenance}")
    collector = _EdgeCollector()
    for candidate in sorted(maintenance.glob("*.json")):
        if candidate.is_symlink() or not candidate.is_file():
            continue
        document = _load_strict_json(candidate)
        if not isinstance(document, dict):
            continue
        schema = document.get("schema_version")
        if not isinstance(schema, str) or not any(marker in schema for marker in LEDGER_SCHEMA_MARKERS):
            continue
        receipt = candidate.relative_to(root).as_posix()
        collector.visit(document, receipt)
    # Codex CLI 0.151 worktree successor 是一个已封存快照：任何已登记历史摘要都可
    # 承接到该快照。Go 侧把这一语义展开为有限边，这里保持一致。
    snapshot_receipt = f"{MAINTENANCE_ROOT}/codex-cli-0151-worktree-successor.json"
    for path, after in collector.snapshots:
        for digest in sorted(collector.known.get(path, set())):
            collector.add(path, digest, after, snapshot_receipt)
    edges = [
        FrozenEdge(path=path, from_sha256=from_digest, to_sha256=to_digest)
        for (path, from_digest, to_digest) in sorted(collector.edges)
    ]
    registered = {path: set(digests) for path, digests in collector.registered.items()}
    for path, digests in collector.known.items():
        registered.setdefault(path, set()).update(digests)
    receipts = {path: set(sources) for path, sources in collector.receipts.items()}
    for (path, _from, _to), sources in collector.edges.items():
        receipts.setdefault(path, set()).update(sources)
    return edges, registered, receipts


def _diff_name_status(repository_root: Path, *refs: str) -> list[dict[str, str]]:
    """解析 ``git diff --name-status``；只传 before 时表示与当前工作树比较。"""

    raw = subprocess.check_output(
        ["git", "diff", "--name-status", "--find-renames", "-z", *refs],
        cwd=repository_root,
    )
    fields = [field.decode("utf-8", errors="strict") for field in raw.split(b"\0") if field]
    changes: list[dict[str, str]] = []
    index = 0
    while index < len(fields):
        status_code = fields[index]
        index += 1
        kind = status_code[0]
        if kind in {"R", "C"}:
            if index + 1 >= len(fields):
                raise UpstreamMergeError("Git rename/copy 差异记录不完整")
            old_path, path = fields[index], fields[index + 1]
            index += 2
            safe_relative_path(old_path, "changed old path")
            safe_relative_path(path, "changed path")
            changes.append({"status": kind, "path": path, "old_path": old_path})
            continue
        if index >= len(fields):
            raise UpstreamMergeError("Git 差异记录缺少路径")
        path = fields[index]
        index += 1
        safe_relative_path(path, "changed path")
        if kind not in {"A", "D", "M", "T"}:
            raise UpstreamMergeError(f"不支持的 Git 差异状态：{status_code} {path}")
        changes.append({"status": kind, "path": path, "old_path": ""})
    changes.sort(key=lambda item: item["path"])
    return changes


def _blob_digest_at(repository_root: Path, commit: str, relative: str) -> str | None:
    """提交中普通文件内容的 SHA-256；路径不存在或不是 blob 时返回 None。"""

    verify = run_git(repository_root, "rev-parse", "--verify", f"{commit}:{relative}", check=False)
    if verify.returncode != 0:
        return None
    object_id = verify.stdout.strip()
    if git_output(repository_root, "cat-file", "-t", object_id) != "blob":
        return None
    content = subprocess.run(
        ["git", "cat-file", "blob", object_id],
        cwd=repository_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if content.returncode != 0:
        return None
    return sha256_bytes(content.stdout)


def _worktree_digest(repository_root: Path, relative: str) -> str | None:
    path = repository_root / Path(*relative.split("/"))
    if path.is_symlink() or not path.is_file():
        return None
    return sha256_file(path)


def load_freeze_registry(repository_root: Path) -> dict[str, Any]:
    """读取并校验冻结台账注册表；缺失或身份漂移都 fail-close。"""

    root = assert_git_repository(repository_root)
    path = root / Path(*FREEZE_REGISTRY_RELATIVE.split("/"))
    if path.is_symlink() or not path.is_file():
        raise UpstreamMergeError(f"冻结台账注册表不存在：{FREEZE_REGISTRY_RELATIVE}")
    document = expect_object(load_json(path, "FreezeRegistry"), "FreezeRegistry")
    if document.get("schema_version") != FREEZE_REGISTRY_SCHEMA:
        raise UpstreamMergeError("FreezeRegistry schema_version 非法")
    validate_identity(document, "FreezeRegistry")
    rules = document.get("rules")
    if not isinstance(rules, list) or not rules:
        raise UpstreamMergeError("FreezeRegistry.rules 必须是非空数组")
    seen: set[str] = set()
    for index, raw in enumerate(rules):
        rule = expect_object(raw, f"FreezeRegistry.rules[{index}]")
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not SAFE_ID_RE.match(rule_id) or rule_id in seen:
            raise UpstreamMergeError(f"FreezeRegistry.rules[{index}].id 非法或重复")
        seen.add(rule_id)
        match = expect_object(rule.get("match"), f"FreezeRegistry.rules[{index}].match")
        if not any(isinstance(match.get(key), list) and match[key] for key in ("prefixes", "paths", "receipt_paths")):
            raise UpstreamMergeError(f"FreezeRegistry.rules[{index}].match 没有任何匹配条件")
        action = expect_object(rule.get("action"), f"FreezeRegistry.rules[{index}].action")
        if action.get("kind") not in REGISTRY_ACTION_KINDS:
            raise UpstreamMergeError(f"FreezeRegistry.rules[{index}].action.kind 非法")
        if not isinstance(action.get("instruction"), str) or not action["instruction"].strip():
            raise UpstreamMergeError(f"FreezeRegistry.rules[{index}].action.instruction 不能为空")
        verification = rule.get("verification")
        if not isinstance(verification, list) or not all(isinstance(item, str) and item for item in verification):
            raise UpstreamMergeError(f"FreezeRegistry.rules[{index}].verification 非法")
    return document


def _receipt_path_index(repository_root: Path, receipts_by_path: dict[str, set[str]]) -> dict[str, set[str]]:
    """反查：登记收据 → 它登记过的路径集合。"""

    index: dict[str, set[str]] = {}
    for path, receipts in receipts_by_path.items():
        for receipt in receipts:
            index.setdefault(receipt, set()).add(path)
    return index


def _rule_matches(rule: dict[str, Any], path: str, receipt_index: dict[str, set[str]]) -> bool:
    match = rule["match"]
    for suffix in match.get("exclude_suffixes", []) or []:
        if isinstance(suffix, str) and path.endswith(suffix):
            return False
    for prefix in match.get("exclude_prefixes", []) or []:
        if isinstance(prefix, str) and path.startswith(prefix):
            return False
    if any(isinstance(prefix, str) and path.startswith(prefix) for prefix in match.get("prefixes", []) or []):
        return True
    if path in (match.get("paths") or []):
        return True
    for receipt in match.get("receipt_paths", []) or []:
        if isinstance(receipt, str) and path in receipt_index.get(receipt, set()):
            return True
    return False


def plan_freeze_successor(
    repository_root: Path,
    before_commit: str,
    after_commit: str | None = None,
) -> dict[str, Any]:
    """计算 before..after（或 before..工作树）中命中冻结覆盖的路径及其精确边。"""

    root = assert_git_repository(repository_root)
    before = expect_git_object(before_commit, "freeze before commit")
    if git_output(root, "cat-file", "-t", before) != "commit":
        raise UpstreamMergeError("freeze before 必须是 commit")
    after: str | None = None
    if after_commit is not None:
        after = expect_git_object(after_commit, "freeze after commit")
        if git_output(root, "cat-file", "-t", after) != "commit":
            raise UpstreamMergeError("freeze after 必须是 commit")
        if before == after:
            raise UpstreamMergeError("freeze before/after 不得相同")
        ancestry = run_git(root, "merge-base", "--is-ancestor", before, after, check=False)
        if ancestry.returncode != 0:
            raise UpstreamMergeError("freeze after commit 必须是 before 的后继")
        changes = _diff_name_status(root, before, after)
    else:
        changes = _diff_name_status(root, before)
    edges, known, receipts_by_path = load_frozen_edges(root)
    registry = load_freeze_registry(root)
    receipt_index = _receipt_path_index(root, receipts_by_path)

    hits: list[dict[str, Any]] = []
    unregistered: list[str] = []
    broken: list[dict[str, Any]] = []
    manual_actions: list[dict[str, Any]] = []
    deleted_frozen: list[str] = []
    def note_rule_actions(path: str) -> None:
        # 注册表规则描述的是“目录级摘要”等收据边之外的冻结，必须对每个变化路径
        # 判定，而不只对已登记收据边的路径判定；否则改一个目录内的新文件会漏报。
        for rule in registry["rules"]:
            if _rule_matches(rule, path, receipt_index):
                manual_actions.append(
                    {
                        "rule_id": rule["id"],
                        "path": path,
                        "action_kind": rule["action"]["kind"],
                        "file": rule["action"].get("file"),
                        "instruction": rule["action"]["instruction"],
                        "verification": list(rule["verification"]),
                    }
                )

    for change in changes:
        path = change["path"]
        old_path = change["old_path"] or path
        note_rule_actions(path)
        frozen_paths = [candidate for candidate in {path, old_path} if candidate in known]
        if not frozen_paths:
            unregistered.append(path)
            continue
        if change["status"] == "D":
            # 通用 successor 图只能表达“摘要到摘要”，删除冻结路径必须人工处置。
            deleted_frozen.append(path)
            continue
        before_digest = _blob_digest_at(root, before, old_path)
        after_digest = _blob_digest_at(root, after, path) if after is not None else _worktree_digest(root, path)
        if after_digest is None:
            raise UpstreamMergeError(f"无法读取冻结路径的当前内容：{path}")
        if before_digest is None or before_digest not in known.get(old_path, set()):
            broken.append(
                {
                    "path": path,
                    "old_path": change["old_path"],
                    "before_sha256": before_digest,
                    "registered_sha256_count": len(known.get(old_path, set())),
                }
            )
            continue
        if before_digest == after_digest:
            continue
        source_receipts = sorted(receipts_by_path.get(old_path, set()) | receipts_by_path.get(path, set()))
        hits.append(
            {
                "path": path,
                "old_path": change["old_path"],
                "status": change["status"],
                "predecessor_sha256s": [before_digest],
                "to_sha256": after_digest,
                "source_receipts": source_receipts,
            }
        )
    hits.sort(key=lambda item: item["path"])
    manual_actions.sort(key=lambda item: (item["rule_id"], item["path"]))
    return {
        "mode": "commit" if after is not None else "worktree",
        "before_commit": before,
        "after_commit": after,
        "frozen_path_count": len(known),
        "frozen_edge_count": len(edges),
        "changed_path_count": len(changes),
        "frozen_hits": hits,
        "unregistered_paths": sorted(unregistered),
        "deleted_frozen_paths": sorted(deleted_frozen),
        "broken_chain": broken,
        "required_manual_actions": manual_actions,
        "registry_rule_count": len(registry["rules"]),
    }


def _assert_no_self_binding(
    repository_root: Path,
    plan: dict[str, Any],
    output_relative: str | None,
) -> None:
    """successor 不得进入其描述的提交，也不得引用本区间内变化的收据。"""

    changed = {item["path"] for item in plan["frozen_hits"]} | set(plan["unregistered_paths"]) | set(plan["deleted_frozen_paths"])
    changed |= {item["path"] for item in plan["broken_chain"]}
    referenced: set[str] = set()
    for hit in plan["frozen_hits"]:
        referenced.update(hit["source_receipts"])
    overlap = sorted(referenced & changed)
    if overlap:
        raise UpstreamMergeError(
            "冻结 successor 引用的收据在本区间内发生变化，存在自引用风险；"
            "请先封存源码提交，再单独提交收据：" + ", ".join(overlap)
        )
    if output_relative is None:
        return
    if plan["after_commit"] is not None:
        probe = run_git(
            repository_root,
            "rev-parse",
            "--verify",
            f"{plan['after_commit']}:{output_relative}",
            check=False,
        )
        if probe.returncode == 0:
            raise UpstreamMergeError(f"输出收据已存在于 after 提交树中，违反“先源码后收据”顺序：{output_relative}")
    if output_relative in changed:
        raise UpstreamMergeError(f"输出收据不得出现在它描述的变化集合中：{output_relative}")


def generate_freeze_successor(
    repository_root: Path,
    before_commit: str,
    after_commit: str | None,
    output_path: Path | None,
    *,
    tag: str,
    reason: str | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """在最终 revision 一次性生成全部冻结台账的 successor 收据。"""

    root = assert_git_repository(repository_root)
    if not isinstance(tag, str) or not SAFE_ID_RE.match(tag):
        raise UpstreamMergeError("freeze tag 必须是安全标识")
    plan = plan_freeze_successor(root, before_commit, after_commit)
    output_relative: str | None = None
    if output_path is not None:
        if not output_path.is_absolute():
            raise UpstreamMergeError("freeze successor 输出必须是绝对路径")
        resolved_output = Path(output_path.parent.resolve(strict=False) / output_path.name)
        try:
            output_relative = resolved_output.relative_to(root.resolve()).as_posix()
        except ValueError:
            output_relative = None
        if output_relative is not None and not output_relative.startswith(MAINTENANCE_ROOT + "/"):
            raise UpstreamMergeError(f"仓库内的 freeze successor 只能写入 {MAINTENANCE_ROOT}/")
    elif not dry_run:
        raise UpstreamMergeError("非 dry-run 模式必须指定 --output")

    if plan["broken_chain"]:
        listed = ", ".join(item["path"] for item in plan["broken_chain"])
        raise UpstreamMergeError(
            "冻结路径的前序摘要不在任何已登记收据中，链断裂，禁止凭空补边：" + listed
        )
    _assert_no_self_binding(root, plan, output_relative)

    default_reason = reason or (
        f"按上游合并流程规则在最终 revision 一次性登记冻结台账的精确后继摘要（{tag}）；"
        "旧收据保持只读，不改变官方客户端画像、Persona、wire 或生产代码。"
    )
    transitions = [
        {
            "path": hit["path"],
            "old_path": hit["old_path"],
            "status": hit["status"],
            "predecessor_sha256s": hit["predecessor_sha256s"],
            "to_sha256": hit["to_sha256"],
            "source_receipts": hit["source_receipts"],
            "reason": f"{default_reason} path={hit['path']}",
        }
        for hit in plan["frozen_hits"]
    ]
    verification = list(FREEZE_VERIFICATION)
    for action in plan["required_manual_actions"]:
        for command in action["verification"]:
            if command not in verification:
                verification.append(command)
    if plan["required_manual_actions"] or plan["deleted_frozen_paths"]:
        result = "manual_actions_required"
    else:
        result = "passed_local_evidence_successor"
    document = bind_identity(
        {
            "schema_version": FREEZE_SUCCESSOR_SCHEMA,
            "issued_at_utc": time.strftime("%Y-%m-%dT%H:%M:00Z", time.gmtime()),
            "base_commit": plan["before_commit"],
            "current_commit": plan["after_commit"],
            "scope": f"upstream-{tag}-freeze-successor",
            "mode": plan["mode"],
            "frozen_path_count": plan["frozen_path_count"],
            "frozen_edge_count": plan["frozen_edge_count"],
            "changed_path_count": plan["changed_path_count"],
            "transitions": transitions,
            "unregistered_path_count": len(plan["unregistered_paths"]),
            "unregistered_paths": plan["unregistered_paths"],
            "deleted_frozen_paths": plan["deleted_frozen_paths"],
            "required_manual_actions": plan["required_manual_actions"],
            "verification": verification,
            "safety": {
                "live_account_used": False,
                "official_egress_profile_changed": False,
                "production_config_changed": False,
                "wire_or_persona_selection_changed": False,
                "deployment_performed": False,
            },
            "result": result,
        }
    )
    if dry_run:
        return {"dry_run": True, "output": None, **document}
    if not transitions and not plan["required_manual_actions"] and not plan["deleted_frozen_paths"]:
        raise UpstreamMergeError("区间内没有命中冻结覆盖的路径变化，也没有注册表待办，无需生成 successor")
    assert output_path is not None
    write_once(output_path, pretty_bytes(document), mode=0o644)
    return {
        "result": result,
        "output": str(output_path),
        "scope": document["scope"],
        "identity_sha256": document["identity_sha256"],
        "transition_count": len(transitions),
        "unregistered_path_count": len(plan["unregistered_paths"]),
        "deleted_frozen_path_count": len(plan["deleted_frozen_paths"]),
        "manual_action_count": len(plan["required_manual_actions"]),
        "verification": verification,
    }
