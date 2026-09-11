"""旧恢复逻辑的兼容边界。

本模块不生成任何 Campaign、attempt、epoch 或 transition 收据。它只登记
历史兼容入口，并要求调用方显式声明正在执行离线历史兼容派发。正式流程
必须使用 campaign-run，不能通过本模块绕过父监督器。
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Callable


# 这些命令会创建旧恢复写入对象；它们不是新流程的动作类型。
LEGACY_WRITE_COMMANDS = frozenset(
    {
        "successor",
        "control-epoch",
        "evaluation-transition",
        "terminal-transition-preflight",
    }
)

# 旧写入实现的唯一符号清单。实现暂时保留给历史离线夹具，正式路径不得调用。
LEGACY_WRITE_SYMBOLS = {
    "successor": "create_successor_campaign",
    "control-epoch": "create_control_epoch",
    "evaluation-transition": "create_phase_evaluation_transition",
    "terminal-transition-preflight": "create_terminal_transition_preflight",
}

# 这些是正式校验链仍需读取的历史辅助函数，不能随旧写入入口一起删除。
# 清单按当前正式 roots 的静态调用图维护；删除前必须先更新并通过回放测试。
LEGACY_READONLY_SYMBOLS = frozenset(
    {
        "_load_classification_candidate_reuse_transition",
        "_successor_job_execution_matches",
        "_runtime_successor_recovery_source",
        "_control_epoch_source_campaign_dir",
        "_successor_uses_reclassified_historical_plan_binding",
        "_successor_abandoned_attempt",
        "_successor_runtime_configuration",
        "_control_epoch_path",
        "_control_epoch_runtime_repair_path",
        "_control_epoch_runtime_repair_amendment_path",
        "_control_epoch_files",
        "_official_sealed_control_epoch_source_context",
        "_is_official_sealed_control_epoch_source",
        "_control_epoch_required_phase",
        "_control_epoch_previous_controls",
        "_control_epoch_source_context",
        "_control_epoch_empty_boundary",
        "_control_epoch_stop_checkpoint",
        "_control_epoch_invariants",
        "_control_epoch_failed_scope_production_paths",
        "_control_epoch_final_execution_scope",
        "_control_epoch_final_execution_authorization",
        "_load_control_epoch_receipt",
        "_control_epoch_zero_boundary",
        "_load_control_epoch_runtime_repair",
        "_assert_recovery_rehearsal_uses_successor_controls",
        "_successor_incremental_noop_preflight",
        "_successor_incremental_noop_preflight_from_coordinates",
        "_successor_reason_ancestor",
        "_imported_stage_evaluation_transition_source",
        "_successor_copy_expectations",
        "_evaluation_transition_preview_path",
        "_evaluation_transition_path",
        "_phase_evaluation_transition_index",
        "_phase_evaluation_transition_source",
        "_phase_evaluation_recovery_successor_operations",
        "_terminal_transition_file_binding",
        "_terminal_transition_attempt_inventory",
        "_terminal_transition_supervisor_audit",
        "_terminal_transition_preflight_facts",
        "_validate_terminal_transition_preflight_receipt",
        "_build_phase_evaluation_transition_preview",
        "_historical_phase_evaluation_transition_frozen_state",
        "_validate_phase_evaluation_transition",
        "_load_phase_evaluation_transition",
    }
)


class LegacyBoundaryError(RuntimeError):
    """旧兼容入口未满足显式历史派发条件。"""


def is_legacy_write_command(command: str) -> bool:
    """判断命令是否属于历史写入入口。"""

    return command in LEGACY_WRITE_COMMANDS


def formal_rejection_reason(
    command: str,
    *,
    campaign_run_context: bool,
    formal_target: bool,
) -> str | None:
    """返回正式流程拒绝旧写入命令的原因；允许历史离线时返回 ``None``。"""

    if not is_legacy_write_command(command):
        return None
    if campaign_run_context:
        return (
            f"正式 campaign-run 禁止旧写入入口：{command}；"
            "请使用 canonical checkpoint 与 campaign-run 队列。"
        )
    if formal_target:
        return (
            f"正式 Campaign 禁止旧写入入口：{command}；"
            "请通过 campaign-run 派发合法动作。"
        )
    return None


def dispatch_historical_write(
    command: str,
    arguments: Any,
    handlers: Mapping[str, Callable[[Any], dict[str, Any]]],
    *,
    allow_compatibility: bool,
) -> dict[str, Any]:
    """显式派发历史离线写入兼容函数。

    ``allow_compatibility`` 必须由上层在完成正式 Campaign 拒绝检查后显式
    传入；缺省或为假时 fail-close，避免旧实现被新的编排路径误调用。
    """

    if not is_legacy_write_command(command):
        raise LegacyBoundaryError(f"不是旧写入命令：{command}")
    if not allow_compatibility:
        raise LegacyBoundaryError(
            f"旧写入入口未获历史离线兼容授权：{command}"
        )
    handler = handlers.get(command)
    if handler is None:
        raise LegacyBoundaryError(f"旧写入命令缺少兼容处理器：{command}")
    return handler(arguments)
