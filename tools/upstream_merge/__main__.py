"""完整 Sub2API 上游合并命令行入口。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Sequence

from .canonical import bind_identity, canonical_bytes, expect_object, load_json, write_json_once
from .baseline import seal_baseline_acceptance, validate_baseline_acceptance
from .contracts import create_plan, load_plan
from .errors import UpstreamMergeError
from .freeze import generate_freeze_successor
from .workflow import (
    apply_candidate_to_managed_branch,
    carry_forward_inventory,
    finalize_upstream_merge,
    generate_change_decision_suggestion,
    generate_impact_matrix,
    replay_upstream_merge,
    preflight_revisions,
    run_verification_gates,
    run_preflight,
    scan_surfaces,
    seal_candidate_disposition,
    seal_change_decision,
    seal_merge,
    seal_source_candidate,
    seal_surfaces,
    generate_source_transition,
    validate_source_transition,
    start_merge,
)


def _absolute(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("路径必须是绝对路径")
    return path


def _add_repository(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--repository",
        type=_absolute,
        default=Path.cwd().resolve(),
        help="Sub2API fork 仓库绝对路径；默认当前目录",
    )


def _add_plan(parser: argparse.ArgumentParser) -> None:
    _add_repository(parser)
    parser.add_argument("--plan", required=True, type=_absolute, help="完整 v2 计划绝对路径")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m tools.upstream_merge",
        description="Sub2API 上游合并 U-0～U-6 受管状态机",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser("plan-create", help="从请求生成完整 U-0 计划")
    _add_repository(create)
    create.add_argument("--request", required=True, type=_absolute)

    preflight = commands.add_parser(
        "preflight",
        help="正式 U-0 前在临时 detached worktree 执行离线预检",
    )
    _add_repository(preflight)
    preflight.add_argument("--request", required=True, type=_absolute)
    preflight.add_argument(
        "--output",
        type=_absolute,
        help="可选的非权威预检报告路径；不会覆盖既有文件",
    )

    baseline = commands.add_parser(
        "baseline-seal",
        help="将基线功能/证据检查草稿绑定到当前干净提交并封存",
    )
    _add_repository(baseline)
    baseline.add_argument("--input", required=True, type=_absolute)
    baseline.add_argument("--output", required=True, type=_absolute)

    baseline_validate = commands.add_parser(
        "baseline-validate",
        help="只读校验基线验收收据及其当前提交绑定",
    )
    _add_repository(baseline_validate)
    baseline_validate.add_argument("--receipt", required=True, type=_absolute)

    transition = commands.add_parser(
        "source-transition",
        help="从 Git 差异生成追加式 source-transition 链尾节点",
    )
    _add_repository(transition)
    transition.add_argument("--before", required=True, help="前序提交完整 SHA-1")
    transition.add_argument("--after", required=True, help="当前提交完整 SHA-1")
    transition.add_argument("--output", required=True, type=_absolute)
    transition.add_argument("--predecessor-register", type=_absolute)
    transition.add_argument("--reason")

    transition_validate = commands.add_parser(
        "source-transition-validate",
        help="复算 source-transition 链尾及其文件摘要",
    )
    _add_repository(transition_validate)
    transition_validate.add_argument("--transition", required=True, type=_absolute)

    freeze = commands.add_parser(
        "freeze-successor-generate",
        help="在最终 revision 一次性生成全部冻结台账的 successor 收据",
    )
    _add_repository(freeze)
    freeze.add_argument("--before", required=True, help="源码变化前的提交完整 SHA-1")
    freeze.add_argument(
        "--after",
        help="源码最终提交完整 SHA-1；省略时以当前工作树为后继状态",
    )
    freeze.add_argument("--tag", required=True, help="上游 tag 或批次标识，用于 scope 与文件命名")
    freeze.add_argument(
        "--output",
        type=_absolute,
        help="收据绝对路径，仓库内只能写入 docs/egress/maintenance/；--dry-run 时可省略",
    )
    freeze.add_argument("--reason", help="统一原因；每条 transition 会追加 path")
    freeze.add_argument(
        "--dry-run",
        action="store_true",
        help="只输出冻结命中、未登记路径与特殊待办，不落盘",
    )

    validate = commands.add_parser("plan-validate", help="只读复算完整计划")
    _add_plan(validate)

    identity = commands.add_parser(
        "identity-seal",
        help="为人工决策草稿增加 identity_sha256，并写入新文件",
    )
    identity.add_argument("--input", required=True, type=_absolute)
    identity.add_argument("--output", required=True, type=_absolute)

    merge_start = commands.add_parser("merge-start", help="U-1 创建隔离 worktree 并开始合并")
    _add_plan(merge_start)

    merge_seal = commands.add_parser("merge-seal", help="U-1 封存冲突台账和双父 merge commit")
    _add_plan(merge_seal)
    merge_seal.add_argument("--conflict-decisions", type=_absolute)

    source_seal = commands.add_parser("source-seal", help="U-2 生成 overlay 并封存 source candidate")
    _add_plan(source_seal)
    source_seal.add_argument("--source-changes", type=_absolute)

    surface_scan = commands.add_parser("surface-scan", help="U-2 复算入口和 source-to-sink 差异")
    _add_plan(surface_scan)

    carry = commands.add_parser(
        "inventory-carry-forward",
        help="U-2 仅在相应发送面零差异时沿用 Inventory",
    )
    _add_plan(carry)
    carry.add_argument("--client", required=True, choices=("claude", "codex"))
    carry.add_argument("--kind", required=True, choices=("ingress", "egress"))

    surface_seal = commands.add_parser("surface-seal", help="U-2 封存两个 Persona 的发送面闭集")
    _add_plan(surface_seal)
    surface_seal.add_argument("--decisions", type=_absolute)

    impact_generate = commands.add_parser("impact-generate", help="U-3 生成完整影响矩阵")
    _add_plan(impact_generate)

    impact_suggest = commands.add_parser(
        "impact-suggest",
        aliases=["change-decision-suggest"],
        help="U-3 按版本化组件映射生成安全分级 ChangeDecision 草稿",
    )
    _add_plan(impact_suggest)
    impact_suggest.add_argument("--output", required=True, type=_absolute)


    impact_seal = commands.add_parser("impact-seal", help="U-3 封存逐文件与调用边处置")
    _add_plan(impact_seal)
    impact_seal.add_argument("--decision", required=True, type=_absolute)

    revision_preflight = commands.add_parser(
        "revision-preflight",
        help="只读复核最新 U-2/U-3 收据及可选 source-transition 链",
    )
    _add_plan(revision_preflight)
    revision_preflight.add_argument(
        "--transition",
        action="append",
        type=_absolute,
        help="要复核的 source-transition 链尾；可重复指定",
    )

    gates = commands.add_parser("gates-run", help="U-4 执行全部固定门禁并生成 attempt 收据")
    _add_plan(gates)
    gates.add_argument("--attempt-id", required=True)
    gates.add_argument(
        "--only",
        help="只执行指定门禁 id 或 category（逗号分隔）；其余从上一 attempt 复用",
    )
    gates.add_argument(
        "--from-attempt",
        help="上一 attempt 的安全标识、目录或 evidence root 内的 receipt.json",
    )

    disposition = commands.add_parser("disposition-seal", help="U-5 封存 candidate/Campaign 处置")
    _add_plan(disposition)
    disposition.add_argument("--input", required=True, type=_absolute)
    disposition.add_argument("--verification-receipt", required=True, type=_absolute)

    apply_parser = commands.add_parser(
        "apply",
        help="U-6 显式快进受维护分支；不会推送远端",
    )
    _add_plan(apply_parser)

    finalize = commands.add_parser("finalize", help="U-6 生成 UpstreamMergeReceipt")
    _add_plan(finalize)

    replay = commands.add_parser("replay", help="独立重建并核对 UpstreamMergeReceipt")
    _add_plan(replay)
    replay.add_argument("--receipt", required=True, type=_absolute)
    replay.add_argument(
        "--rerun-gates",
        metavar="ATTEMPT_ID",
        help="在全新隔离 worktree 重跑全部门禁，并以指定的新 attempt 封存",
    )
    return parser


def _loaded(arguments: argparse.Namespace):
    return load_plan(arguments.plan, arguments.repository)


def execute(arguments: argparse.Namespace) -> dict[str, Any]:
    command = arguments.command
    if command == "plan-create":
        plan = create_plan(arguments.request, arguments.repository)
        return {
            "result": "created",
            "plan": str(plan.path),
            "plan_id": plan.plan_id,
            "identity_sha256": plan.identity,
        }
    if command == "preflight":
        report = run_preflight(arguments.request, arguments.repository, arguments.output)
        return {
            "result": report["result"],
            "plan_id": report["plan_id"],
            "identity_sha256": report["identity_sha256"],
            "report": str(arguments.output) if arguments.output else None,
            "blockers": report["blockers"],
        }
    if command == "baseline-seal":
        receipt = seal_baseline_acceptance(
            arguments.repository,
            arguments.input,
            arguments.output,
        )
        return {
            "result": receipt["result"],
            "receipt": str(arguments.output),
            "commit": receipt["repository"]["commit"],
            "tree": receipt["repository"]["tree"],
            "known_drift_count": len(receipt["evidence"]["known_drift"]),
            "identity_sha256": receipt["identity_sha256"],
        }
    if command == "baseline-validate":
        receipt = validate_baseline_acceptance(arguments.repository, arguments.receipt)
        return {
            "result": receipt["result"],
            "receipt": str(arguments.receipt),
            "commit": receipt["repository"]["commit"],
            "tree": receipt["repository"]["tree"],
            "known_drift_count": len(receipt["evidence"]["known_drift"]),
            "identity_sha256": receipt["identity_sha256"],
        }
    if command == "source-transition":
        return generate_source_transition(
            arguments.repository,
            arguments.before,
            arguments.after,
            arguments.output,
            predecessor_register=arguments.predecessor_register,
            reason=arguments.reason,
        )
    if command == "source-transition-validate":
        return validate_source_transition(arguments.repository, arguments.transition)
    if command == "freeze-successor-generate":
        return generate_freeze_successor(
            arguments.repository,
            arguments.before,
            arguments.after,
            arguments.output,
            tag=arguments.tag,
            reason=arguments.reason,
            dry_run=arguments.dry_run,
        )
    if command == "identity-seal":
        draft = expect_object(load_json(arguments.input, "identity draft"), "identity draft")
        if "identity_sha256" in draft:
            raise UpstreamMergeError("identity draft 已含 identity_sha256，禁止覆盖或重复签名")
        sealed = bind_identity(draft)
        write_json_once(arguments.output, sealed)
        return {
            "result": "sealed",
            "output": str(arguments.output),
            "identity_sha256": sealed["identity_sha256"],
        }
    plan = _loaded(arguments)
    if command == "plan-validate":
        return {
            "result": "valid",
            "plan_id": plan.plan_id,
            "identity_sha256": plan.identity,
        }
    if command == "merge-start":
        return start_merge(plan)
    if command == "merge-seal":
        return seal_merge(plan, arguments.conflict_decisions)
    if command == "source-seal":
        return seal_source_candidate(plan, arguments.source_changes)
    if command == "surface-scan":
        return scan_surfaces(plan)
    if command == "inventory-carry-forward":
        return carry_forward_inventory(plan, arguments.client, arguments.kind)
    if command == "surface-seal":
        return seal_surfaces(plan, arguments.decisions)
    if command == "impact-generate":
        return generate_impact_matrix(plan)
    if command in {"impact-suggest", "change-decision-suggest"}:
        suggestion = generate_change_decision_suggestion(plan, arguments.output)
        return {
            "result": suggestion["result"],
            "output": str(arguments.output),
            "auto_accepted_count": suggestion["auto_accepted_count"],
            "manual_required_count": suggestion["manual_required_count"],
            "unresolved_paths": suggestion["unresolved_paths"],
        }
    if command == "impact-seal":
        return seal_change_decision(plan, arguments.decision)
    if command == "revision-preflight":
        return preflight_revisions(plan, arguments.transition)
    if command == "gates-run":
        return run_verification_gates(
            plan,
            arguments.attempt_id,
            only=arguments.only,
            from_attempt=arguments.from_attempt,
        )
    if command == "disposition-seal":
        return seal_candidate_disposition(
            plan,
            arguments.input,
            arguments.verification_receipt,
        )
    if command == "apply":
        return apply_candidate_to_managed_branch(plan)
    if command == "finalize":
        return finalize_upstream_merge(plan)
    if command == "replay":
        return replay_upstream_merge(
            plan,
            arguments.receipt,
            arguments.rerun_gates,
        )
    raise UpstreamMergeError(f"未处理命令：{command}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        result = execute(parser.parse_args(argv))
    except UpstreamMergeError as error:
        print(f"上游合并工具拒绝：{error}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"上游合并工具系统错误：{error}", file=sys.stderr)
        return 3
    sys.stdout.buffer.write(canonical_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
