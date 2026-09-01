#!/usr/bin/env python3
"""编排 Codex CLI 版本升级的源码扫描、抓包、出站面比较与覆盖报告。"""

from __future__ import annotations

import argparse
import base64
import fcntl
import glob
import hashlib
import inspect
import json
import math
import os
import re
import secrets
import shutil
import signal
import stat
import string
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.parse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from collections.abc import Mapping
from typing import Any, Iterable

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from tools.official_client_capture.capturelib.model import (
    ConfigurationError,
    track_models_for_version,
)
from tools.official_client_capture.capturelib.security import (
    ensure_private_directory,
    file_sha256,
    normalize_json_shape,
    secure_write_json,
    secure_write_text,
)
from tools.official_client_capture.acceptance_contract import (
    AcceptanceContractError,
    LEGACY_RESULTS_SCHEMAS,
    MODE_DUAL_WIRE,
    RESULTS_SCHEMA_V2,
    build_contract_payload as build_acceptance_contract,
    contract_sha256 as acceptance_contract_sha256,
    expected_check_ids_for_side,
    load_profile as load_acceptance_profile,
    repository_profile_path as acceptance_profile_path,
    verify_frozen_contract,
)
from tools.official_client_capture.assertion_gate import (
    AssertionGateError,
    BUNDLE_DIR_NAME as ASSERTION_BUNDLE_DIR_NAME,
    run_assertion_gate,
    validate_gate_receipt,
)
from tools.official_client_capture.candidate_evidence_guard import (
    scan_files_for_secrets,
)
from tools.official_client_capture.candidate_rule_assertion import (
    ASSERTION_SCHEMA_VERSION as MACHINE_ASSERTION_SCHEMA,
    build_assertion_command as build_machine_assertion_command,
    command_sha256 as machine_command_sha256,
    load_observations as load_assertion_observations,
    source_spec_section_sha256,
)
from tools.official_client_capture.codex_upgrade_environment_probe import (
    EnvironmentProbeError,
    ProbeArguments as EnvironmentProbeArguments,
    STATE_FILES as ENVIRONMENT_STATE_FILES,
    run_probe as run_environment_probe,
)
from tools.official_client_capture import codex_upgrade_arm64_environment_receipt
from tools.official_client_capture import codex_upgrade_evidence_manifest
from tools.official_client_capture import codex_upgrade_job_rehearsal_receipt
from tools.official_client_capture import codex_upgrade_timing_ledger
from tools.official_client_capture import codex_upgrade_gate_receipt as external_gate_receipt
from tools.official_client_capture import incremental_recovery
from tools.official_client_capture.codex_upgrade_receipt_finalizer import (
    CLIENT_BINDING_SCHEMA as FINALIZED_CLIENT_BINDING_SCHEMA,
    OBSERVED_PROFILE_SCHEMA as FINALIZED_OBSERVED_PROFILE_SCHEMA,
    RESTORATION_INPUTS,
    RESTORATION_SCHEMA as FINALIZED_RESTORATION_SCHEMA,
    ReceiptFinalizerError,
    finalize_restoration,
    finalize_scenario,
    replay_receipt,
)
from tools.official_client_capture.scenario_receipts import (
    FACTS_SCHEMA_VERSION as SCENARIO_FACTS_SCHEMA,
    SCHEMA_VERSION as SCENARIO_RECEIPT_SCHEMA,
    SUPPORTED_SCENARIOS as SCENARIO_RECEIPT_SCENARIOS,
    ScenarioReceiptError,
    validate_facts_document as validate_scenario_facts_document,
    validate_receipt as validate_scenario_receipt,
)
from tools.official_client_capture.model_condition_receipts import (
    ModelConditionReceiptError,
    validate_receipt as validate_model_condition_receipt,
)
from tools.official_client_capture.pcap_clienthello import (
    iter_packets,
    parse_client_hello,
    tcp_payload,
)
from tools.official_client_capture.relay_extract import (
    H2_PREFACE,
    parse_h1_stream,
    parse_h2_stream,
    parse_ws_frames,
)


RULE_SCHEMA = "codex-egress-rule-manifest/v1"
REPORT_SCHEMA = "codex-upgrade-report/v1"
SURFACE_SCHEMA = "codex-egress-surface/v1"
SOURCE_SCHEMA = "codex-egress-source-inventory/v1"
EXTRA_JOB_SCHEMA = "codex-upgrade-extra-jobs/v1"
CAMPAIGN_SCHEMA = "codex-upgrade-campaign/v3"
MIGRATION_SCHEMA = "codex-upgrade-rule-migration/v1"
ASSERTION_TEMPLATE_SCHEMA = "codex-egress-rule-assertion-template/v1"
ASSERTION_PROFILE_SCHEMA = "codex-candidate-rule-expectations/v1"
PROFILE_SCHEMA = "codex-egress-profile/v1"
OBSERVED_PROFILE_SCHEMA = FINALIZED_OBSERVED_PROFILE_SCHEMA
CLIENT_BINDING_SCHEMA = FINALIZED_CLIENT_BINDING_SCHEMA
CLIENT_REQUEST_PROOF_SCHEMA = "codex-egress-client-request-evidence/v1"
CLIENT_RESPONSE_PROOF_SCHEMA = "codex-egress-client-response-evidence/v1"
RESTORATION_SCHEMA = FINALIZED_RESTORATION_SCHEMA
CAPTURE_ATTEMPT_SCHEMA = "codex-upgrade-capture-attempt/v2"
CAPTURE_RESERVATION_SCHEMA = "codex-upgrade-capture-reservation/v2"
SEAL_FAILURE_SCHEMA = "codex-upgrade-seal-failure/v2"
LEGACY_SEAL_PREVIEW_SCHEMA = "codex-upgrade-seal-preview/v2"
SEAL_PREVIEW_SCHEMA = "codex-upgrade-seal-preview/v3"
SEAL_DRAFT_SCHEMA = "codex-upgrade-seal-draft/v1"
IMPORTED_STAGE_CHECKPOINT_SCHEMA = "codex-upgrade-imported-stage-checkpoint/v1"
TOOL_EVALUATION_TRANSITION_PREVIEW_SCHEMA = (
    "codex-upgrade-tool-evaluation-transition-preview/v1"
)
TOOL_EVALUATION_TRANSITION_SCHEMA = "codex-upgrade-tool-evaluation-transition/v1"
TOOL_EVALUATION_RECOVERY_CONTROLS_SCHEMA = (
    "codex-upgrade-tool-evaluation-recovery-controls/v1"
)
DEEP_VERIFY_RECEIPT_SCHEMA = "codex-upgrade-deep-verify/v1"
SCENARIO_SCHEMA = "codex-upgrade-scenarios/v1"
STAGE_SCHEMA = "codex-upgrade-stage-result/v2"
PREDECESSOR_IMPORT_SCHEMA_V1 = "codex-upgrade-predecessor-import/v1"
PREDECESSOR_IMPORT_SCHEMA = "codex-upgrade-predecessor-import/v2"
PREDECESSOR_RECLASSIFICATION_IMPORT_SCHEMA = (
    "codex-upgrade-predecessor-import/v3"
)
PREDECESSOR_RUNTIME_IMPORT_SCHEMA = "codex-upgrade-predecessor-import/v4"
PREDECESSOR_REHEARSAL_IMPORT_SCHEMA = "codex-upgrade-predecessor-import/v5"
PREDECESSOR_RECOVERY_IMPORT_SCHEMA = "codex-upgrade-predecessor-import/v6"
COMPARISON_SCHEMA = "codex-upgrade-comparison/v2"
ACCEPTANCE_SCHEMA = "codex-upgrade-acceptance/v2"
CAMPAIGN_MODES = frozenset({"preflight_only", "formal"})
CANDIDATE_PURPOSES = frozenset({"validation_only", "production_replacement"})
MIGRATION_CLASSIFICATIONS = {
    "inherit",
    "change",
    "add",
    "delete",
    "condition_change",
    "blocked",
}
ASSERTION_STATUSES = {"pass", "fail", "blocked", "not_applicable"}
REQUIRED_CLIENT_BINDINGS = frozenset({"kilo-compatible", "kilo-responses"})
SUCCESSOR_REASONS = frozenset(
    {
        "candidate_runtime_identity_correction",
        "classification_fact_correction",
    }
)
RECLASSIFICATION_SUCCESSOR_REASONS = frozenset(
    {"classification_fact_correction"}
)
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
CODEX_USER_AGENT_VERSION_RE = re.compile(
    r"(?:codex_exec|codex-tui|codex_cli_rs)/(\d+\.\d+\.\d+)"
    r"|\((?:codex_exec|codex-tui|codex_cli_rs);\s*(\d+\.\d+\.\d+)\)"
)
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
RUN_NONCE_RE = SHA256_RE
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
RUNTIME_WINDOW_ID_PLACEHOLDER = "20000101T000000Z"
SAFE_ABSOLUTE_PATH_RE = re.compile(r"^/[A-Za-z0-9._/+:-]+$")
IMMUTABLE_IMAGE_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._/:+-]*@sha256:[a-f0-9]{64}$"
)
IMAGE_ID_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
RULE_RE = re.compile(r"^SPEC-[A-Z0-9]+-\d{3}$")
HEADER_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{1,63}$")
QUOTED_STRING_RE = re.compile(r'"((?:\\.|[^"\\])*)"')
NETWORK_SUFFIXES = {".rs", ".toml"}
SKIP_DIRECTORIES = {
    ".git",
    "target",
    "node_modules",
    "vendor",
    "fixtures",
    "snapshots",
}
NETWORK_MARKERS = (
    "reqwest",
    "hyper",
    "tungstenite",
    "websocket",
    "ClientBuilder",
    "Request::builder",
    "RequestBuilder",
    "send_request",
    "connect_async",
    ".request(",
    ".execute(",
    ".send(",
)
ENDPOINT_MARKERS = (
    "backend-api",
    "/responses",
    "/models",
    "/compact",
    "/wham",
    "/search",
    "/images",
    "/realtime",
    "/files",
    "api.openai.com",
    "chatgpt.com",
    "auth.openai.com",
    "oaiusercontent.com",
)
NETWORK_PACKAGES = {
    "h2",
    "http",
    "http-body",
    "http-body-util",
    "hyper",
    "hyper-util",
    "native-tls",
    "openssl",
    "reqwest",
    "rustls",
    "tokio-rustls",
    "tokio-tungstenite",
    "tungstenite",
    "webpki-roots",
}
MAX_JSON_BYTES = 128 * 1024 * 1024
ADMIN_TOKEN_MAX_BYTES = 16 * 1024
ADMIN_TOKEN_RE = re.compile(r"^[A-Za-z0-9._~-]+$")
# 非 attempt 的 Go 生成器也必须有硬上限，避免工具故障把后续阶段永久挂住。
PROFILE_GENERATOR_TIMEOUT_SECONDS = 5 * 60


@dataclass(frozen=True)
class Job:
    """一次可独立恢复的抓包任务。"""

    job_id: str
    phase: str
    suites: tuple[str, ...]
    description: str
    steps: tuple[dict[str, Any], ...]
    evidence_roots: tuple[str, ...]
    covers: tuple[str, ...]
    scenario_ids: tuple[str, ...] = ()
    required: bool = True
    # SCN-REALITY-01：本 job 必须为哪些场景产出真实性收据。不复用 scenario_ids——
    # 后者表达「该 job 覆盖哪些场景」，official-core 一个 job 就覆盖 9 个场景，
    # 不可能逐个产收据；真实性门禁只约束已证实失效的目标场景。
    required_scenario_receipts: tuple[str, ...] = ()
    track: str = "main"
    model_id: str = ""
    expected_use_responses_lite: bool = False
    required_model_receipt: bool = False


def _job_tool_components(job: Job) -> tuple[str, ...]:
    """从 Job 的实际启动命令推导最小 producer 依赖。

    编排器和评估器不会作为抓包字节的依赖；因此修复它们时，已经通过的
    Job 可以继续复用。无法识别的启动器按 shared 处理，保持失败关闭。
    """

    components: set[str] = set()
    for step in job.steps:
        argv = step.get("argv", []) if isinstance(step, Mapping) else []
        for raw in argv if isinstance(argv, list) else []:
            if not isinstance(raw, str):
                continue
            normalized = raw.replace("\\", "/")
            if "tools/official_client_capture/" in normalized:
                relative = normalized.split("tools/official_client_capture/", 1)[1]
                components.add(_tool_component_for_path(relative))
            elif normalized.endswith(".sh") or normalized.endswith(".py"):
                components.add(_tool_component_for_path(normalized.rsplit("/", 1)[-1]))
        # 直接 docker exec 的官方任务依赖 capture 侧 producer，但不依赖
        # 版本编排器本身。
        if argv and isinstance(argv[0], str) and argv[0] == "docker":
            components.add("producer")
    if not components:
        components.add("shared")
    return tuple(sorted(components))


def _job_incremental_metadata(
    job: Job,
    identity: Mapping[str, Any] | None = None,
    tool_identity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """生成 Job 可独立比较的组件依赖和缓存键。"""

    current_tool = tool_identity or _tool_identity(include_git=False)
    components = current_tool.get("components")
    if not isinstance(components, Mapping):
        entries = current_tool.get("entries")
        if not isinstance(entries, list):
            raise ConfigurationError("工具身份缺少组件或文件清单。")
        components = _tool_component_identities(entries)["components"]
    names = _job_tool_components(job)
    dependency_rows = []
    for name in names:
        item = components.get(name)
        if not isinstance(item, Mapping) or not SHA256_RE.fullmatch(
            str(item.get("sha256", ""))
        ):
            raise ConfigurationError(f"Job {job.job_id} 的工具组件摘要缺失：{name}")
        dependency_rows.append(
            {
                "id": f"tool:{name}",
                "status": "passed",
                "result_sha256": str(item["sha256"]),
            }
        )
    # identity 只绑定稳定的官方／候选运行坐标；run_nonce 和证据路径不进入键。
    identity_sha = _fingerprint(dict(identity)) if identity is not None else "0" * 64
    dependency_sha = incremental_recovery.dependency_digest(dependency_rows)
    input_sha = _job_execution_sha256(job)
    environment_sha = _fingerprint(
        {
            "phase": job.phase,
            "track": getattr(job, "track", "main"),
            "model_id": getattr(job, "model_id", ""),
            "identity_sha256": identity_sha,
        }
    )
    return {
        "components": list(names),
        "component_digests": {
            name: str(components[name]["sha256"]) for name in names
        },
        "dependency_sha256": dependency_sha,
        "input_sha256": input_sha,
        "environment_sha256": environment_sha,
        "result_key": incremental_recovery.result_key(
            component="job",
            item_id=job.job_id,
            input_sha256=input_sha,
            environment_sha256=environment_sha,
            dependency_sha256=dependency_sha,
        ),
    }


def _validate_candidate_admin_credential(jobs: Iterable[Job]) -> None:
    """在 reservation 前验证辅助场景所需的短期管理凭据。"""

    if not any(job.job_id == "candidate-frozen-aux" for job in jobs):
        return
    inline = os.environ.get("ADMIN_BEARER_TOKEN", "")
    token_file = os.environ.get("ADMIN_BEARER_TOKEN_FILE", "")
    if inline and token_file:
        raise ConfigurationError(
            "ADMIN_BEARER_TOKEN 与 ADMIN_BEARER_TOKEN_FILE 只能提供一个。"
        )
    if token_file:
        path = Path(token_file)
        if (
            not path.is_absolute()
            or path.is_symlink()
            or not path.is_file()
            or path.stat().st_uid != os.geteuid()
            or stat.S_IMODE(path.stat().st_mode) not in {0o400, 0o600}
            or path.stat().st_size <= 0
            or path.stat().st_size > ADMIN_TOKEN_MAX_BYTES
        ):
            raise ConfigurationError(
                "ADMIN_BEARER_TOKEN_FILE 必须是当前用户持有的 0400/0600 绝对路径普通文件。"
            )
        try:
            token = path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError) as error:
            raise ConfigurationError("无法读取管理 token 文件。") from error
    else:
        token = inline.strip()
    if not token or not ADMIN_TOKEN_RE.fullmatch(token):
        raise ConfigurationError(
            "candidate-frozen-aux 缺少合法管理凭据；请设置 ADMIN_BEARER_TOKEN_FILE。"
        )

    parts = token.split(".")
    if len(parts) != 3:
        raise ConfigurationError("管理 token 不是三段式 JWT。")
    try:
        payload_raw = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_raw))
    except (ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise ConfigurationError("管理 token 载荷无法解码。") from error
    expires_at = payload.get("exp") if isinstance(payload, dict) else None
    if not isinstance(expires_at, int) or isinstance(expires_at, bool):
        raise ConfigurationError("管理 token 缺少整数 exp。")
    minimum_text = os.environ.get("ADMIN_TOKEN_MIN_TTL_SECONDS", "1800")
    if not re.fullmatch(r"[0-9]+", minimum_text):
        raise ConfigurationError("ADMIN_TOKEN_MIN_TTL_SECONDS 必须是非负整数。")
    minimum = int(minimum_text)
    if expires_at - int(time.time()) < minimum:
        expiry = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_at))
        raise ConfigurationError(
            f"管理 token 剩余有效期不足 {minimum} 秒（到期时间 {expiry}）。"
        )


@dataclass(frozen=True)
class HistoricalSourceSpecBinding:
    """历史场景清单允许引用的精确冻结规格身份。"""

    codex_version: str
    source_spec: str
    source_spec_sha256: str


def _fingerprint(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _job_execution_sha256(job: Job) -> str:
    """绑定真实执行定义，同时允许批准场景重新映射规则与场景说明。

    required_scenario_receipts 不属于「场景说明」而属于执行契约：它决定这个 job
    算不算成功。若不入指纹，同一个 execution_sha256 下门禁要求可被悄改，而
    _validate_capture_job_results 与 _prior_complete_results 都检测不到。
    """

    return _fingerprint(
        {
            "id": job.job_id,
            "phase": job.phase,
            "suites": list(job.suites),
            "steps": [dict(step) for step in job.steps],
            "evidence_roots": list(job.evidence_roots),
            "required": job.required,
            "required_scenario_receipts": list(job.required_scenario_receipts),
            "track": getattr(job, "track", "main"),
            "model_id": getattr(job, "model_id", ""),
            "expected_use_responses_lite": getattr(
                job, "expected_use_responses_lite", False
            ),
            "required_model_receipt": getattr(job, "required_model_receipt", False),
        }
    )


def _is_rfc3339_timestamp(value: Any) -> bool:
    """判断时间是否为带时区的 RFC 3339／ISO 8601 字符串。"""

    if not isinstance(value, str) or not value.strip():
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _rfc3339_datetime(value: Any, label: str) -> datetime:
    """解析带时区时间，并统一为可比较的 datetime。"""

    if not _is_rfc3339_timestamp(value):
        raise ConfigurationError(f"{label} 不是带时区 RFC 3339 时间。")
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _utc_now() -> str:
    """返回带微秒精度的 UTC RFC 3339 时间。"""

    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _normalized_line(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _source_entry(kind: str, relative: str, value: str) -> dict[str, str]:
    core = {"kind": kind, "file": relative, "value": value}
    return {**core, "fingerprint": _fingerprint(core)}


def _iter_source_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root)
        if any(part in SKIP_DIRECTORIES for part in relative.parts):
            continue
        if path.name == "Cargo.lock" or path.suffix in NETWORK_SUFFIXES:
            yield path


def _cargo_entries(path: Path, relative: str) -> list[dict[str, str]]:
    try:
        with path.open("rb") as stream:
            data = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ConfigurationError(f"无法解析 {path}：{error}") from error
    entries: list[dict[str, str]] = []
    for package in data.get("package", []):
        name = package.get("name")
        if name not in NETWORK_PACKAGES:
            continue
        value = "|".join(
            str(package.get(key, ""))
            for key in ("name", "version", "source", "checksum")
        )
        entries.append(_source_entry("network_dependency", relative, value))
    return entries


def scan_source_tree(root: Path, version: str) -> dict[str, Any]:
    """生成稳定的出站源码线索清单；新增线索必须人工分类。"""

    if not root.is_dir() or root.is_symlink():
        raise ConfigurationError(f"源码目录不存在或不可信：{root}")
    entries: dict[str, dict[str, str]] = {}
    scanned_files = 0
    network_files = 0
    for path in _iter_source_files(root):
        scanned_files += 1
        relative = path.relative_to(root).as_posix()
        if path.name == "Cargo.lock":
            for entry in _cargo_entries(path, relative):
                entries[entry["fingerprint"]] = entry
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = path.read_text(encoding="utf-8", errors="replace")
        file_matched = False
        for line in text.splitlines():
            normalized = _normalized_line(line)
            if not normalized:
                continue
            if any(marker in normalized for marker in NETWORK_MARKERS):
                entry = _source_entry("network_callsite", relative, normalized[:800])
                entries[entry["fingerprint"]] = entry
                file_matched = True
            for match in QUOTED_STRING_RE.finditer(line):
                literal = match.group(1).replace(r'\"', '"')
                if (
                    literal.startswith(("http://", "https://", "/"))
                    and any(marker in literal for marker in ENDPOINT_MARKERS)
                ):
                    entry = _source_entry("endpoint_literal", relative, literal)
                    entries[entry["fingerprint"]] = entry
                    file_matched = True
                if (
                    HEADER_NAME_RE.fullmatch(literal)
                    and any(
                        token in normalized.lower()
                        for token in ("header", ".insert(", ".append(")
                    )
                ):
                    entry = _source_entry(
                        "header_literal",
                        relative,
                        literal.lower().replace("_", "-"),
                    )
                    entries[entry["fingerprint"]] = entry
                    file_matched = True
        if file_matched:
            network_files += 1
            entry = _source_entry("network_file", relative, file_sha256(path))
            entries[entry["fingerprint"]] = entry
    return {
        "schema_version": SOURCE_SCHEMA,
        "codex_version": version,
        "root": str(root.resolve()),
        "files_scanned": scanned_files,
        "network_files": network_files,
        "entry_count": len(entries),
        "entries": sorted(
            entries.values(),
            key=lambda item: (item["kind"], item["file"], item["value"]),
        ),
    }


def compare_inventory(
    baseline: dict[str, Any], target: dict[str, Any]
) -> dict[str, Any]:
    baseline_by_id = {
        item["fingerprint"]: item for item in baseline.get("entries", [])
    }
    target_by_id = {
        item["fingerprint"]: item for item in target.get("entries", [])
    }
    added = sorted(
        (target_by_id[key] for key in target_by_id.keys() - baseline_by_id.keys()),
        key=lambda item: (item["kind"], item["file"], item["value"]),
    )
    removed = sorted(
        (baseline_by_id[key] for key in baseline_by_id.keys() - target_by_id.keys()),
        key=lambda item: (item["kind"], item["file"], item["value"]),
    )
    return {
        "baseline_version": baseline.get("codex_version"),
        "target_version": target.get("codex_version"),
        "added_count": len(added),
        "removed_count": len(removed),
        "added": added,
        "removed": removed,
    }


def _normalized_path(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    path = parsed.path or "/"
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if not query:
        return path
    return path + "?" + "&".join(name for name, _ in query)


def _header_names(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [str(name) for name in value]
    names: list[str] = []
    if not isinstance(value, list):
        return names
    for item in value:
        if isinstance(item, (list, tuple)) and item:
            names.append(str(item[0]))
        elif isinstance(item, dict) and isinstance(item.get("name"), str):
            names.append(item["name"])
    return names


def _header_value(value: Any, expected_name: str) -> str | None:
    expected = expected_name.lower()
    if isinstance(value, dict):
        for name, item_value in value.items():
            if str(name).lower() == expected:
                return str(item_value)
        return None
    if not isinstance(value, list):
        return None
    for item in value:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            name, item_value = item[0], item[1]
        elif isinstance(item, dict):
            name, item_value = item.get("name"), item.get("value")
        else:
            continue
        if str(name).lower() == expected:
            return str(item_value)
    return None


def _normalized_host(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    try:
        parsed = urllib.parse.urlsplit(
            raw if "://" in raw else f"//{raw}"
        )
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return "<invalid-host>"
    if not hostname or len(hostname) > 253:
        return "<invalid-host>"
    try:
        normalized = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return "<invalid-host>"
    if not re.fullmatch(r"[a-z0-9._:-]+", normalized):
        return "<invalid-host>"
    if port is None:
        return normalized
    rendered = f"[{normalized}]" if ":" in normalized else normalized
    return f"{rendered}:{port}"


def _request_host(request: dict[str, Any], path: str) -> str:
    headers = request.get("headers")
    candidates = (
        request.get("host"),
        request.get("authority"),
        _header_value(headers, ":authority"),
        _header_value(headers, "host"),
        path if "://" in path else None,
    )
    for candidate in candidates:
        normalized = _normalized_host(candidate)
        if normalized:
            return normalized
    return "<unknown>"


def _surface(kind: str, fields: dict[str, Any], source: str) -> dict[str, Any]:
    core = {"kind": kind, **fields}
    return {**core, "fingerprint": _fingerprint(core), "sources": [source]}


def _request_surface(request: dict[str, Any], source: str) -> dict[str, Any] | None:
    request_line = request.get("request_line")
    method = request.get("method")
    path = request.get("path") or request.get("url")
    protocol = request.get("http_version") or request.get("protocol")
    if isinstance(request_line, str):
        parts = request_line.split(" ", 2)
        if len(parts) == 3:
            method, path, protocol = parts
    if not isinstance(method, str) or not isinstance(path, str):
        return None
    headers = request.get("header_names_in_order")
    if not isinstance(headers, list):
        headers = _header_names(request.get("headers"))
    json_shape = request.get("json_shape")
    if json_shape is None:
        json_shape = request.get("shape")
    body = request.get("body")
    if json_shape is None and isinstance(body, dict):
        json_shape = body.get("shape")
        if json_shape is None and isinstance(body.get("text"), str):
            try:
                json_shape = normalize_json_shape(json.loads(body["text"]))
            except json.JSONDecodeError:
                json_shape = None
    body_shape = (
        _fingerprint({"shape": json_shape})
        if isinstance(json_shape, (dict, list))
        else None
    )
    return _surface(
        "http_request",
        {
            "host": _request_host(request, path),
            "method": method.upper(),
            "path": _normalized_path(path),
            "protocol": str(protocol or "unknown"),
            "header_names": [str(item) for item in headers],
            "body_shape_sha256": body_shape,
        },
        source,
    )


def _h2_request_surface(
    frame: dict[str, Any], source: str
) -> dict[str, Any] | None:
    if frame.get("type") != "HEADERS":
        return None
    headers = frame.get("headers")
    method = _header_value(headers, ":method")
    path = _header_value(headers, ":path")
    if method is None or path is None:
        return None
    return _request_surface(
        {
            "method": method,
            "path": path,
            "protocol": "h2",
            "headers": headers,
            "header_names_in_order": frame.get("header_names_in_order", []),
        },
        source,
    )


def _ws_surface(frame: dict[str, Any], source: str) -> dict[str, Any] | None:
    event_type = frame.get("event_type")
    opcode = frame.get("opcode")
    fields = frame.get("top_level_fields_in_order")
    shape = frame.get("shape")
    if not event_type and not opcode and not fields:
        return None
    return _surface(
        "websocket_frame",
        {
            "event_type": event_type,
            "opcode": opcode,
            "compressed": frame.get("compressed"),
            "rsv1_deflate": frame.get("rsv1_deflate"),
            "top_level_fields": list(fields) if isinstance(fields, list) else [],
            "shape_sha256": (
                _fingerprint({"shape": shape})
                if isinstance(shape, (dict, list))
                else None
            ),
        },
        source,
    )


def _extract_json_surfaces(
    value: Any, source: str
) -> list[dict[str, Any]]:
    if not isinstance(value, dict):
        return []
    output: list[dict[str, Any]] = []
    direct_request = value.get("request")
    if isinstance(direct_request, dict):
        item = _request_surface(direct_request, source)
        if item:
            output.append(item)
    if value.get("_websocket") is True and value.get("from_client") is True:
        payload = value.get("json")
        if isinstance(payload, dict):
            item = _ws_surface(
                {
                    "event_type": payload.get("type"),
                    "opcode": "TEXT",
                    "top_level_fields_in_order": list(payload),
                    "shape": normalize_json_shape(payload),
                },
                source,
            )
            if item:
                output.append(item)
    records = value.get("records")
    if isinstance(records, list):
        for record in records:
            if not isinstance(record, dict):
                continue
            request = record.get("request")
            if isinstance(request, dict):
                item = _request_surface(request, source)
                if item:
                    output.append(item)
            frame = record.get("frame")
            if isinstance(frame, dict):
                item = _ws_surface(frame, source)
                if item:
                    output.append(item)
    connections = value.get("connections")
    if isinstance(connections, list):
        for connection in connections:
            if not isinstance(connection, dict):
                continue
            for request in connection.get("requests", []):
                if isinstance(request, dict):
                    item = _request_surface(request, source)
                    if item:
                        output.append(item)
            for frame in connection.get("ws_frames", []):
                if isinstance(frame, dict):
                    item = _ws_surface(frame, source)
                    if item:
                        output.append(item)
            for frame in connection.get("frames", []):
                if isinstance(frame, dict):
                    item = _h2_request_surface(frame, source)
                    if item:
                        output.append(item)
    frames = value.get("frames")
    if isinstance(frames, list):
        for frame in frames:
            if isinstance(frame, dict):
                item = _h2_request_surface(frame, source)
                if item:
                    output.append(item)
    requests = value.get("requests")
    if isinstance(requests, list):
        for request in requests:
            if isinstance(request, dict):
                item = _request_surface(request, source)
                if item:
                    output.append(item)
    if (
        value.get("schema_version") == "codex-wham-consume-safe/v1"
        and isinstance(value.get("request_line"), str)
    ):
        item = _request_surface(
            {
                "request_line": value["request_line"],
                "header_names_in_order": value.get("header_names", []),
                "shape": value.get("body"),
            },
            source,
        )
        if item:
            output.append(item)
    hellos = value.get("client_hellos")
    if isinstance(hellos, list):
        for hello in hellos:
            if not isinstance(hello, dict):
                continue
            output.append(
                _surface(
                    "tls_client_hello",
                    {
                        "sni": hello.get("sni") or "<target-host>",
                        "cipher_suites": hello.get("cipher_suites", []),
                        "extensions": hello.get("extensions", []),
                        "alpn": hello.get("alpn") or hello.get("offered_alpn", []),
                    },
                    source,
                )
            )
    single_hello = value.get("client_hello")
    if isinstance(single_hello, dict):
        output.append(
            _surface(
                "tls_client_hello",
                {
                    "sni": single_hello.get("sni") or "<target-host>",
                    "cipher_suites": single_hello.get("cipher_suites", []),
                    "extensions": single_hello.get("extension_types", []),
                    "alpn": single_hello.get("alpn", []),
                },
                source,
            )
        )
    return output


def _scan_relay_bytes(path: Path, source: str) -> list[dict[str, Any]]:
    """直接解析中继上行字节，避免升级编排依赖人工先运行提取器。"""

    if not path.name.endswith(".client_to_upstream.bin"):
        return []
    data = path.read_bytes()
    if not data:
        return []
    output: list[dict[str, Any]] = []
    if data.startswith(H2_PREFACE):
        parsed = parse_h2_stream(data)
        for frame in parsed.get("frames", []):
            if isinstance(frame, dict):
                item = _h2_request_surface(frame, source)
                if item:
                    output.append(item)
        return output
    requests = parse_h1_stream(data)
    for request in requests:
        item = _request_surface(request, source)
        if item:
            output.append(item)
    if any(
        "upgrade" in str(name).lower()
        for request in requests
        for name in request.get("header_names_in_order", [])
    ):
        header_end = data.find(b"\r\n\r\n")
        if header_end >= 0:
            for frame in parse_ws_frames(data[header_end + 4 :]):
                item = _ws_surface(frame, source)
                if item:
                    output.append(item)
    return output


def _scan_pcap(path: Path, source: str) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for link, packet in iter_packets(path):
        parsed = tcp_payload(link, packet)
        if not parsed:
            continue
        _, _, payload = parsed
        hello = parse_client_hello(payload)
        if not hello:
            continue
        sni, extensions, ciphers, alpn = hello
        output.append(
            _surface(
                "tls_client_hello",
                {
                    "sni": sni or "<unknown>",
                    "cipher_suites": list(ciphers),
                    "extensions": list(extensions),
                    "alpn": list(alpn),
                },
                source,
            )
        )
    return output


def _merge_surfaces(items: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for item in items:
        fingerprint = item["fingerprint"]
        if fingerprint not in merged:
            merged[fingerprint] = dict(item)
            continue
        sources = set(merged[fingerprint].get("sources", []))
        sources.update(item.get("sources", []))
        merged[fingerprint]["sources"] = sorted(sources)
    return sorted(
        merged.values(),
        key=lambda item: (
            item["kind"],
            str(item.get("path", "")),
            item["fingerprint"],
        ),
    )


def _scan_evidence_files(
    files: Iterable[Path],
    label: str,
    *,
    input_paths: Iterable[Path],
) -> dict[str, Any]:
    """只解析显式文件清单，不自行递归发现证据边界。"""

    surfaces: list[dict[str, Any]] = []
    warnings: list[str] = []
    selected_files = sorted(set(files))
    selected_inputs = list(input_paths)
    for path in selected_files:
        source = str(path)
        try:
            if path.suffix.lower() == ".bin":
                surfaces.extend(_scan_relay_bytes(path, source))
                continue
            if path.suffix.lower() == ".pcap":
                surfaces.extend(_scan_pcap(path, source))
                continue
            if path.stat().st_size > MAX_JSON_BYTES:
                warnings.append(f"跳过超大 JSON：{path}")
                continue
            if path.suffix.lower() == ".jsonl":
                with path.open(encoding="utf-8") as stream:
                    for index, line in enumerate(stream, 1):
                        if not line.strip():
                            continue
                        value = json.loads(line)
                        surfaces.extend(
                            _extract_json_surfaces(value, f"{source}:{index}")
                        )
                continue
            value = json.loads(path.read_text(encoding="utf-8"))
            surfaces.extend(_extract_json_surfaces(value, source))
        except (OSError, ValueError, json.JSONDecodeError) as error:
            warnings.append(f"无法解析 {path}：{type(error).__name__}")
    merged = _merge_surfaces(surfaces)
    return {
        "schema_version": SURFACE_SCHEMA,
        "label": label,
        "input_paths": [str(path) for path in selected_inputs],
        "file_count": len(selected_files),
        "surface_count": len(merged),
        "surfaces": merged,
        "warnings": warnings,
    }


def scan_evidence(paths: Iterable[Path], label: str) -> dict[str, Any]:
    """从规范化 JSON、JSONL、relay 摘要和 pcap 建立动态出站面。"""

    input_paths = list(paths)
    files: set[Path] = set()
    for root in input_paths:
        if root.is_file():
            files.add(root)
        elif root.is_dir():
            files.update(
                path
                for path in root.rglob("*")
                if path.is_file()
                and not path.is_symlink()
                and path.suffix.lower() in {".json", ".jsonl", ".pcap", ".bin"}
            )
    return _scan_evidence_files(files, label, input_paths=input_paths)


def compare_surfaces(
    baseline: dict[str, Any], target: dict[str, Any]
) -> dict[str, Any]:
    baseline_by_id = {
        item["fingerprint"]: item for item in baseline.get("surfaces", [])
    }
    target_by_id = {
        item["fingerprint"]: item for item in target.get("surfaces", [])
    }
    added = [
        target_by_id[key] for key in sorted(target_by_id.keys() - baseline_by_id.keys())
    ]
    removed = [
        baseline_by_id[key]
        for key in sorted(baseline_by_id.keys() - target_by_id.keys())
    ]
    return {
        "baseline": baseline.get("label"),
        "target": target.get("label"),
        "equal": not added and not removed,
        "added_count": len(added),
        "removed_count": len(removed),
        "added": added,
        "removed": removed,
    }


def load_rule_manifest(path: Path, baseline_version: str) -> tuple[str, ...]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ConfigurationError(f"无法读取规则清单 {path}：{error}") from error
    if payload.get("schema_version") != RULE_SCHEMA:
        raise ConfigurationError("规则清单 schema_version 不受支持。")
    if payload.get("codex_version") != baseline_version:
        raise ConfigurationError(
            "规则清单版本与 --baseline-version 不一致。"
        )
    rules = payload.get("required_rules")
    if not isinstance(rules, list) or not rules:
        raise ConfigurationError("规则清单 required_rules 不能为空。")
    if len(rules) != len(set(rules)):
        raise ConfigurationError("规则清单存在重复编号。")
    if any(not isinstance(rule, str) or not RULE_RE.fullmatch(rule) for rule in rules):
        raise ConfigurationError("规则清单包含非法编号。")
    return tuple(rules)


def _job(
    job_id: str,
    phase: str,
    description: str,
    argv: list[str],
    environment: dict[str, str],
    evidence_roots: list[str],
    covers: Iterable[str],
    *,
    suites: tuple[str, ...] = ("full",),
    timeout: int = 1200,
) -> Job:
    return Job(
        job_id=job_id,
        phase=phase,
        suites=suites,
        description=description,
        steps=({"argv": argv, "environment": environment, "timeout": timeout},),
        evidence_roots=tuple(evidence_roots),
        covers=tuple(covers),
    )


def _format_template(value: str, context: dict[str, str]) -> str:
    try:
        return value.format_map(context)
    except KeyError as error:
        raise ConfigurationError(f"任务模板引用未知变量：{error.args[0]}") from error


def load_extra_jobs(path: Path | None, context: dict[str, str]) -> list[Job]:
    """加载未来新形态所需的附加任务，不要求修改总编排器。"""

    if path is None:
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ConfigurationError(f"无法读取附加任务：{error}") from error
    if payload.get("schema_version") != EXTRA_JOB_SCHEMA:
        raise ConfigurationError("附加任务 schema_version 不受支持。")
    jobs: list[Job] = []
    for raw in payload.get("jobs", []):
        if not isinstance(raw, dict):
            raise ConfigurationError("附加任务必须是对象。")
        job_id = raw.get("id")
        phase = raw.get("phase")
        if not isinstance(job_id, str) or not SAFE_ID_RE.fullmatch(job_id):
            raise ConfigurationError("附加任务 id 非法。")
        if phase not in {"official", "candidate"}:
            raise ConfigurationError(f"{job_id} 的 phase 非法。")
        steps = []
        for raw_step in raw.get("steps", []):
            argv = raw_step.get("argv")
            environment = raw_step.get("environment", {})
            if not isinstance(argv, list) or not argv or not all(
                isinstance(item, str) and item for item in argv
            ):
                raise ConfigurationError(f"{job_id} 的 argv 非法。")
            if not isinstance(environment, dict) or not all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in environment.items()
            ):
                raise ConfigurationError(f"{job_id} 的 environment 非法。")
            steps.append(
                {
                    "argv": [_format_template(item, context) for item in argv],
                    "environment": {
                        key: _format_template(value, context)
                        for key, value in environment.items()
                    },
                    "timeout": int(raw_step.get("timeout", 1800)),
                }
            )
        roots = raw.get("evidence_roots", [])
        covers = raw.get("covers", [])
        suites = raw.get("suites", ["full"])
        if (
            not steps
            or not isinstance(roots, list)
            or not isinstance(covers, list)
            or not isinstance(suites, list)
        ):
            raise ConfigurationError(f"{job_id} 的任务字段不完整。")
        jobs.append(
            Job(
                job_id=job_id,
                phase=phase,
                suites=tuple(str(item) for item in suites),
                description=str(raw.get("description", job_id)),
                steps=tuple(steps),
                evidence_roots=tuple(
                    _format_template(str(item), context) for item in roots
                ),
                covers=tuple(str(item) for item in covers),
                required=bool(raw.get("required", True)),
            )
        )
    return jobs


def _validate_side_triggers(scenario: dict[str, Any]) -> None:
    """校验分侧触发契约。

    A11／A13／A14 的单一 trigger 原文描述的是候选侧受控形态，官方侧照抄会让
    「受控第二跳」「dummy token」这类手法被当成合法触发——k36 用的正是场景定义里
    根本没写的改 last_refresh 手法。分侧后两侧各自独立声明，不再互相沿用。
    """

    side_triggers = scenario.get("side_triggers")
    if side_triggers is None:
        return
    scenario_id = scenario.get("scenario_id")
    if not isinstance(side_triggers, dict) or set(side_triggers) != {
        "official",
        "candidate",
    }:
        raise ConfigurationError(f"证据场景 {scenario_id} 的分侧触发必须同时声明两侧。")
    for side, contract in side_triggers.items():
        if not isinstance(contract, dict) or set(contract) != {
            "trigger",
            "preconditions",
        }:
            raise ConfigurationError(
                f"证据场景 {scenario_id} 的 {side} 触发契约字段不闭合。"
            )
        if not isinstance(contract["trigger"], str) or not contract["trigger"].strip():
            raise ConfigurationError(
                f"证据场景 {scenario_id} 的 {side} 触发描述不能为空。"
            )
        preconditions = contract["preconditions"]
        if (
            not isinstance(preconditions, list)
            or not preconditions
            or not all(
                isinstance(item, str) and item.strip() for item in preconditions
            )
        ):
            raise ConfigurationError(
                f"证据场景 {scenario_id} 的 {side} 前置条件非法。"
            )


def _validate_scenario_manifest_shape(payload: dict[str, Any]) -> None:
    """在无第三方 JSON Schema 依赖时执行同等失败关闭的场景结构校验。"""

    required_top = {
        "schema_version",
        "codex_version",
        "profile_id",
        "source_spec",
        "rule_manifest",
        "variable_contract",
        "evidence_scenarios",
        "capture_jobs",
        "required_client_bindings",
    }
    if not required_top.issubset(payload) or set(payload) - required_top - {"$schema"}:
        raise ConfigurationError("场景清单顶层字段不闭合。")
    if not VERSION_RE.fullmatch(str(payload.get("codex_version", ""))):
        raise ConfigurationError("场景清单 codex_version 非法。")
    if not SAFE_ID_RE.fullmatch(str(payload.get("profile_id", ""))):
        raise ConfigurationError("场景清单 profile_id 非法。")

    variables = payload.get("variable_contract")
    if not isinstance(variables, list) or not variables:
        raise ConfigurationError("场景清单 variable_contract 不能为空。")
    variable_names: set[str] = set()
    for index, variable in enumerate(variables, 1):
        required = {"name", "type", "required", "sensitive", "description"}
        if (
            not isinstance(variable, dict)
            or not required.issubset(variable)
            or set(variable) - required - {"default"}
        ):
            raise ConfigurationError(f"场景变量 {index} 字段不闭合。")
        name = variable.get("name")
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"^[a-z][a-z0-9_]*$", name)
            or name in variable_names
            or variable.get("type")
            not in {"string", "integer", "absolute_path", "sha256", "image_reference"}
            or not isinstance(variable.get("required"), bool)
            or not isinstance(variable.get("sensitive"), bool)
            or not isinstance(variable.get("description"), str)
            or not variable["description"].strip()
        ):
            raise ConfigurationError(f"场景变量 {index} 定义非法。")
        if "default" in variable and (
            isinstance(variable["default"], bool)
            or not isinstance(variable["default"], (str, int))
        ):
            raise ConfigurationError(f"场景变量 {name} 默认值非法。")
        variable_names.add(name)

    scenarios = payload.get("evidence_scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise ConfigurationError("场景清单 evidence_scenarios 不能为空。")
    scenario_ids: set[str] = set()
    for index, scenario in enumerate(scenarios, 1):
        required = {
            "scenario_id",
            "description",
            "trigger",
            "preconditions",
            "required_artifact_kinds",
            "covers",
        }
        # side_triggers 是唯一登记的可选字段：A11／A13／A14 的官方侧与候选侧触发
        # 形态本就不同，用同一个 trigger 描述会让 official 沿用候选侧受控手法。
        optional = {"side_triggers"}
        if (
            not isinstance(scenario, dict)
            or not required.issubset(scenario)
            or set(scenario) - required - optional
        ):
            raise ConfigurationError(f"证据场景 {index} 字段不闭合。")
        _validate_side_triggers(scenario)
        scenario_id = scenario.get("scenario_id")
        if (
            not isinstance(scenario_id, str)
            or not re.fullmatch(r"^A[0-9]{2}$", scenario_id)
            or scenario_id in scenario_ids
        ):
            raise ConfigurationError(f"证据场景 {index} scenario_id 非法或重复。")
        if any(
            not isinstance(scenario.get(field), str) or not scenario[field].strip()
            for field in ("description", "trigger")
        ):
            raise ConfigurationError(f"证据场景 {scenario_id} 描述或触发条件非法。")
        for field in ("preconditions", "required_artifact_kinds", "covers"):
            values = scenario.get(field)
            if (
                not isinstance(values, list)
                or not values
                or not all(isinstance(value, str) and value for value in values)
                or len(values) != len(set(values))
            ):
                raise ConfigurationError(f"证据场景 {scenario_id} 的 {field} 非法。")
        if not all(RULE_RE.fullmatch(rule) for rule in scenario["covers"]):
            raise ConfigurationError(f"证据场景 {scenario_id} covers 非法。")
        scenario_ids.add(scenario_id)

    jobs = payload.get("capture_jobs")
    if not isinstance(jobs, list) or not jobs:
        raise ConfigurationError("场景清单 capture_jobs 不能为空。")
    for index, job in enumerate(jobs, 1):
        required = {
            "id",
            "phase",
            "suites",
            "scenario_ids",
            "description",
            "required",
            "steps",
            "evidence_roots",
            "covers",
            "required_scenario_receipts",
        }
        model_fields = {
            "track",
            "model_id",
            "expected_use_responses_lite",
            "required_model_receipt",
        }
        if (
            not isinstance(job, dict)
            or not required.issubset(job)
            or set(job) - required - model_fields
            or (set(job) & model_fields and not model_fields.issubset(job))
        ):
            raise ConfigurationError(f"场景任务 {index} 字段不闭合。")
        if model_fields.issubset(job):
            if (
                job["track"] not in {"main", "lite"}
                or not isinstance(job["model_id"], str)
                or not job["model_id"].strip()
                or not isinstance(job["expected_use_responses_lite"], bool)
                or not isinstance(job["required_model_receipt"], bool)
                or (
                    job["track"] == "lite"
                    and job["expected_use_responses_lite"] is not True
                )
            ):
                raise ConfigurationError(f"场景任务 {index} 的模型轨道契约非法。")
        if not isinstance(job.get("required"), bool):
            raise ConfigurationError(f"场景任务 {index} required 必须是布尔值。")
        receipts = job.get("required_scenario_receipts")
        if (
            not isinstance(receipts, list)
            or len(set(map(str, receipts))) != len(receipts)
            or not all(
                isinstance(item, str) and item in SCENARIO_RECEIPT_SCENARIOS
                for item in receipts
            )
        ):
            raise ConfigurationError(
                f"场景任务 {index} required_scenario_receipts 只能声明已登记的目标场景。"
            )
        if not set(receipts).issubset(set(job.get("scenario_ids") or [])):
            raise ConfigurationError(
                f"场景任务 {index} 声明的真实性收据场景必须在自身 scenario_ids 内。"
            )
        steps = job.get("steps")
        if not isinstance(steps, list) or not steps:
            raise ConfigurationError(f"场景任务 {index} steps 不能为空。")
        for step_index, step in enumerate(steps, 1):
            if not isinstance(step, dict) or set(step) != {
                "argv",
                "environment",
                "timeout_seconds",
            }:
                raise ConfigurationError(
                    f"场景任务 {index} 步骤 {step_index} 字段不闭合。"
                )
            if (
                not isinstance(step.get("environment"), dict)
                or not isinstance(step.get("timeout_seconds"), int)
                or isinstance(step.get("timeout_seconds"), bool)
                or step["timeout_seconds"] <= 0
            ):
                raise ConfigurationError(
                    f"场景任务 {index} 步骤 {step_index} 环境或超时非法。"
                )
            if (
                job.get("phase") == "candidate"
                and step["environment"].get("CODEX_VERSION")
                != "{target_version}"
            ):
                raise ConfigurationError(
                    f"候选场景任务 {index} 步骤 {step_index} 必须从 Campaign "
                    "target_version 注入 CODEX_VERSION。"
                )

    clients = payload.get("required_client_bindings")
    if (
        not isinstance(clients, list)
        or not all(isinstance(client, str) and SAFE_ID_RE.fullmatch(client) for client in clients)
        or len(clients) != len(set(clients))
        or not REQUIRED_CLIENT_BINDINGS.issubset(set(clients))
    ):
        raise ConfigurationError("场景清单必须至少绑定 Kilo Compatible 与 Responses。")


def _validate_scenario_variable_contract(
    payload: dict[str, Any], context: dict[str, str]
) -> None:
    """让版本清单声明、模板引用与实际 Campaign 值形成闭环。"""

    variables = {
        item["name"]: item for item in payload["variable_contract"]
    }
    for name, contract in variables.items():
        if contract["sensitive"] is True:
            raise ConfigurationError(
                f"场景变量 {name} 被标为敏感；秘密不得进入版本任务模板。"
            )
        value = context.get(name, "")
        if contract["required"] and not value:
            raise ConfigurationError(f"场景必需变量 {name} 没有 Campaign 值。")
        if not value:
            continue
        variable_type = contract["type"]
        valid = True
        if variable_type == "integer":
            valid = value.isdecimal() and int(value) > 0
        elif variable_type == "absolute_path":
            valid = bool(SAFE_ABSOLUTE_PATH_RE.fullmatch(value))
        elif variable_type == "sha256":
            valid = bool(SHA256_RE.fullmatch(value))
        elif variable_type == "image_reference":
            valid = bool(IMMUTABLE_IMAGE_RE.fullmatch(value))
        elif variable_type == "string":
            valid = bool(value.strip())
        if not valid:
            raise ConfigurationError(f"场景变量 {name} 的实际值不符合 {variable_type}。")

    formatter = string.Formatter()
    template_values: list[str] = []
    for job in payload["capture_jobs"]:
        template_values.extend(str(value) for value in job["evidence_roots"])
        if "model_id" in job:
            template_values.append(job["model_id"])
        for step in job["steps"]:
            template_values.extend(step["argv"])
            template_values.extend(step["environment"].values())
    for value in template_values:
        try:
            parsed = list(formatter.parse(value))
        except ValueError as error:
            raise ConfigurationError(f"场景任务模板语法非法：{value}") from error
        for _, field_name, format_spec, conversion in parsed:
            if field_name is None:
                continue
            if format_spec or conversion is not None:
                raise ConfigurationError(
                    f"场景任务模板禁止格式化与类型转换：{value}"
                )
            if not re.fullmatch(r"^[a-z][a-z0-9_]*$", field_name):
                raise ConfigurationError(f"场景任务模板字段非法：{field_name}")
            if field_name not in variables:
                raise ConfigurationError(
                    f"场景任务模板引用了 variable_contract 外变量：{field_name}"
                )


def _scenario_source_spec_binding(
    payload: dict[str, Any],
    *,
    label: str,
) -> HistoricalSourceSpecBinding:
    """把场景清单中的规格坐标规范化为可精确比较的冻结身份。"""

    codex_version = payload.get("codex_version")
    source_binding = payload.get("source_spec")
    if not isinstance(codex_version, str) or not isinstance(source_binding, dict):
        raise ConfigurationError(f"{label}缺少版本或规格摘要绑定。")
    source_path = source_binding.get("path")
    fragment = source_binding.get("fragment")
    source_sha = source_binding.get("sha256")
    if (
        not isinstance(source_path, str)
        or not source_path
        or Path(source_path).is_absolute()
        or ".." in Path(source_path).parts
        or not isinstance(fragment, str)
        or not fragment
        or not SHA256_RE.fullmatch(str(source_sha))
    ):
        raise ConfigurationError(f"{label}规格摘要绑定非法。")
    return HistoricalSourceSpecBinding(
        codex_version=codex_version,
        source_spec=f"{source_path}#{fragment}",
        source_spec_sha256=str(source_sha),
    )


def _load_frozen_assertion_source_spec_binding(
    path: Path,
    expected_version: str,
) -> HistoricalSourceSpecBinding:
    """从同版本冻结断言画像读取历史规格身份，不触碰可变总手册。"""

    if path.is_symlink() or not path.is_file():
        raise ConfigurationError(f"历史断言画像不存在或不可信：{path}")
    payload = _read_json(path, "历史断言画像")
    if payload.get("schema_version") != ASSERTION_PROFILE_SCHEMA:
        raise ConfigurationError("历史断言画像 schema_version 不受支持。")
    codex_version = payload.get("codex_version")
    source_spec = payload.get("source_spec")
    source_sha = payload.get("source_spec_sha256")
    if (
        codex_version != expected_version
        or not isinstance(source_spec, str)
        or not SHA256_RE.fullmatch(str(source_sha))
    ):
        raise ConfigurationError("历史断言画像的版本或规格摘要绑定不一致。")
    source_path_text, separator, fragment = source_spec.partition("#")
    source_path = Path(source_path_text)
    if (
        not separator
        or not source_path_text
        or source_path.is_absolute()
        or ".." in source_path.parts
        or not fragment
    ):
        raise ConfigurationError("历史断言画像 source_spec 非法。")
    return HistoricalSourceSpecBinding(
        codex_version=codex_version,
        source_spec=source_spec,
        source_spec_sha256=str(source_sha),
    )


def load_scenario_jobs(
    path: Path,
    context: dict[str, str],
    *,
    expected_version: str | None = None,
    expected_rule_sha256: str | None = None,
    require_bindings: bool = False,
    historical_source_spec_binding: HistoricalSourceSpecBinding | None = None,
) -> list[Job]:
    """从版本化场景清单生成任务，并封闭当前或历史规格摘要绑定。"""

    if historical_source_spec_binding is not None and (
        not isinstance(
            historical_source_spec_binding, HistoricalSourceSpecBinding
        )
        or not require_bindings
        or expected_version is None
        or historical_source_spec_binding.codex_version != expected_version
    ):
        raise ConfigurationError(
            "历史场景规格绑定必须是与预期版本一致的受控冻结身份。"
        )

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ConfigurationError(f"无法读取场景清单 {path}：{error}") from error
    if payload.get("schema_version") != SCENARIO_SCHEMA:
        raise ConfigurationError("场景清单 schema_version 不受支持。")
    _validate_scenario_manifest_shape(payload)
    _validate_scenario_variable_contract(payload, context)
    if expected_version is not None and payload.get("codex_version") != expected_version:
        raise ConfigurationError("场景清单 codex_version 与当前阶段不一致。")
    rule_binding = payload.get("rule_manifest")
    source_binding = payload.get("source_spec")
    if require_bindings and not isinstance(rule_binding, dict):
        raise ConfigurationError("场景清单缺少规则清单摘要绑定。")
    if require_bindings and not isinstance(source_binding, dict):
        raise ConfigurationError("场景清单缺少规格第二章摘要绑定。")
    if isinstance(rule_binding, dict):
        rule_sha = rule_binding.get("sha256")
        rule_count = rule_binding.get("rule_count")
        if not SHA256_RE.fullmatch(str(rule_sha)) or not isinstance(rule_count, int):
            raise ConfigurationError("场景清单规则清单绑定非法。")
        if expected_rule_sha256 is not None and rule_sha != expected_rule_sha256:
            raise ConfigurationError("场景清单绑定了其他版本的规则清单。")
    if isinstance(source_binding, dict):
        scenario_source_spec_binding = _scenario_source_spec_binding(
            payload,
            label="场景清单",
        )
        source_path, _, fragment = (
            scenario_source_spec_binding.source_spec.partition("#")
        )
        resolved_source = Path(__file__).resolve().parents[2] / source_path
        if not resolved_source.is_file() or resolved_source.is_symlink():
            raise ConfigurationError("场景清单规格第二章摘要不一致。")
        if historical_source_spec_binding is not None:
            if scenario_source_spec_binding != historical_source_spec_binding:
                raise ConfigurationError(
                    "历史场景规格摘要与受控冻结画像不一致。"
                )
        elif source_spec_section_sha256(
            resolved_source, fragment
        ) != scenario_source_spec_binding.source_spec_sha256:
            raise ConfigurationError("场景清单规格第二章摘要不一致。")
    raw_scenarios = payload.get("evidence_scenarios")
    if require_bindings and (not isinstance(raw_scenarios, list) or not raw_scenarios):
        raise ConfigurationError("场景清单 evidence_scenarios 不能为空。")
    scenario_rules: dict[str, set[str]] = {}
    for raw_scenario in raw_scenarios or []:
        if not isinstance(raw_scenario, dict):
            raise ConfigurationError("证据场景必须是对象。")
        scenario_id = raw_scenario.get("scenario_id")
        covers = raw_scenario.get("covers")
        if (
            not isinstance(scenario_id, str)
            or scenario_id in scenario_rules
            or not isinstance(covers, list)
            or not covers
        ):
            raise ConfigurationError("证据场景身份或 covers 非法。")
        scenario_rules[scenario_id] = set(str(value) for value in covers)
    jobs: list[Job] = []
    for raw in payload.get("capture_jobs", []):
        if not isinstance(raw, dict):
            raise ConfigurationError("场景任务必须是对象。")
        job_id = raw.get("id")
        phase = raw.get("phase")
        if not isinstance(job_id, str) or not SAFE_ID_RE.fullmatch(job_id):
            raise ConfigurationError("场景任务 id 非法。")
        if phase not in {"official", "candidate"}:
            raise ConfigurationError(f"{job_id} 的 phase 非法。")
        raw_suites = raw.get("suites")
        if (
            not isinstance(raw_suites, list)
            or not raw_suites
            or not set(raw_suites).issubset({"core", "full"})
        ):
            raise ConfigurationError(f"{job_id} 的 suites 非法。")
        steps: list[dict[str, Any]] = []
        for raw_step in raw.get("steps", []):
            if not isinstance(raw_step, dict):
                raise ConfigurationError(f"{job_id} 的步骤必须是对象。")
            argv = raw_step.get("argv")
            environment = raw_step.get("environment")
            if not isinstance(argv, list) or not argv or not all(
                isinstance(item, str) and item for item in argv
            ):
                raise ConfigurationError(f"{job_id} 的 argv 非法。")
            if not isinstance(environment, dict) or not all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in environment.items()
            ):
                raise ConfigurationError(f"{job_id} 的 environment 非法。")
            timeout = raw_step.get("timeout_seconds")
            if not isinstance(timeout, int) or timeout <= 0:
                raise ConfigurationError(f"{job_id} 的 timeout_seconds 非法。")
            steps.append(
                {
                    "argv": [_format_template(item, context) for item in argv],
                    "environment": {
                        key: _format_template(value, context)
                        for key, value in environment.items()
                    },
                    "timeout": timeout,
                }
            )
        roots = raw.get("evidence_roots")
        covers = raw.get("covers")
        scenario_ids = raw.get("scenario_ids")
        if not steps:
            raise ConfigurationError(f"{job_id} 没有可执行步骤。")
        if not isinstance(roots, list) or not roots:
            raise ConfigurationError(f"{job_id} 的 evidence_roots 不能为空。")
        if not isinstance(covers, list) or not covers or not all(
            isinstance(rule, str) and RULE_RE.fullmatch(rule) for rule in covers
        ):
            raise ConfigurationError(f"{job_id} 的 covers 非法。")
        if (
            not isinstance(scenario_ids, list)
            or not scenario_ids
            or len(scenario_ids) != len(set(scenario_ids))
            or not set(scenario_ids).issubset(scenario_rules)
        ):
            raise ConfigurationError(f"{job_id} 的 scenario_ids 非法。")
        scenario_coverage = set().union(
            *(scenario_rules[scenario_id] for scenario_id in scenario_ids)
        )
        if not set(covers).issubset(scenario_coverage):
            raise ConfigurationError(f"{job_id} 的 covers 未被绑定场景证明。")
        jobs.append(
            Job(
                job_id=job_id,
                phase=phase,
                suites=tuple(str(item) for item in raw_suites),
                description=str(raw.get("description", job_id)),
                steps=tuple(steps),
                evidence_roots=tuple(
                    _format_template(str(item), context) for item in roots
                ),
                covers=tuple(covers),
                scenario_ids=tuple(str(item) for item in scenario_ids),
                required=raw["required"],
                required_scenario_receipts=tuple(
                    str(item) for item in raw["required_scenario_receipts"]
                ),
                track=str(raw.get("track", "main")),
                model_id=_format_template(
                    str(raw.get("model_id", "{model}")), context
                ),
                expected_use_responses_lite=bool(
                    raw.get("expected_use_responses_lite", False)
                ),
                required_model_receipt=bool(
                    raw.get("required_model_receipt", False)
                ),
            )
        )
    if not jobs:
        raise ConfigurationError("场景清单 capture_jobs 不能为空。")
    return jobs


def _expand_roots(patterns: Iterable[str]) -> list[Path]:
    output: list[Path] = []
    for pattern in patterns:
        matches = sorted(glob.glob(pattern))
        if matches:
            output.extend(Path(match) for match in matches)
        else:
            output.append(Path(pattern))
    return output


def _terminate_process(
    process: subprocess.Popen[Any],
    *,
    deadline: incremental_recovery.WallClockDeadline | None = None,
) -> None:
    """终止整个进程组，并把清理等待限制在 attempt 剩余预算内。"""

    if process.poll() is not None:
        return
    # 普通调用保留原有 15s/5s 宽限；受管 attempt 则不能让清理越过全局
    # deadline。SIGKILL 始终发送，即使 SIGTERM 宽限已经耗尽。
    term_timeout = 15.0
    kill_timeout = 5.0
    if deadline is not None:
        term_timeout = min(term_timeout, max(0.001, deadline.remaining_seconds))
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=term_timeout)
        return
    except (ProcessLookupError, subprocess.TimeoutExpired):
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if deadline is not None:
        kill_timeout = min(kill_timeout, max(0.001, deadline.remaining_seconds))
    try:
        process.wait(timeout=kill_timeout)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        # 进程组已经收到 SIGKILL；上层仍会把未回收状态视为停线错误。
        pass


def _wait_process(
    process: subprocess.Popen[Any],
    requested_seconds: int | float,
    *,
    deadline: incremental_recovery.WallClockDeadline | None = None,
    operation: str = "job step",
    heartbeat: Any | None = None,
) -> int:
    """等待子进程，统一应用单步 timeout 与 attempt 全局 deadline。"""

    if isinstance(requested_seconds, bool) or not isinstance(
        requested_seconds, (int, float)
    ):
        raise ConfigurationError(f"{operation} timeout 非法。")
    requested = float(requested_seconds)
    if requested <= 0 or not math.isfinite(requested):
        raise ConfigurationError(f"{operation} timeout 非法。")
    if deadline is None:
        try:
            return int(process.wait(timeout=requested))
        except subprocess.TimeoutExpired:
            _terminate_process(process)
            return 124

    started = time.monotonic()
    step_deadline = started + requested
    heartbeat_interval = float(
        getattr(deadline, "heartbeat_seconds", DEFAULT_HEARTBEAT_SECONDS)
    )
    while True:
        try:
            remaining_global = deadline.check(operation)
        except incremental_recovery.WallClockTimeoutError:
            _terminate_process(process, deadline=deadline)
            raise
        remaining_step = step_deadline - time.monotonic()
        if remaining_step <= 0:
            _terminate_process(process, deadline=deadline)
            return 124
        wait_for = min(remaining_global, remaining_step, heartbeat_interval)
        try:
            return int(process.wait(timeout=max(0.001, wait_for)))
        except subprocess.TimeoutExpired:
            if heartbeat is not None:
                try:
                    heartbeat(operation)
                except BaseException:
                    # heartbeat 落盘失败也是停线条件；不能让子进程继续占用
                    # 请求、容器或网络资源。
                    _terminate_process(process, deadline=deadline)
                    raise
            # The timeout may have been the global deadline or just a heartbeat
            # slice.  Re-check before another wait; global expiry is terminal.
            if deadline.expired:
                _terminate_process(process, deadline=deadline)
                raise incremental_recovery.WallClockTimeoutError(
                    operation,
                    elapsed_seconds=deadline.elapsed_seconds,
                    budget_seconds=deadline.budget_seconds,
                )
            if time.monotonic() >= step_deadline:
                _terminate_process(process, deadline=deadline)
                return 124


def _evidence_root_has_bytes(
    path: Path,
    *,
    deadline: incremental_recovery.WallClockDeadline | None = None,
    heartbeat: Any | None = None,
    operation: str = "evidence scan",
) -> bool:
    """在可中断边界检查证据根是否含非空普通文件。"""

    if deadline is not None:
        deadline.check(operation)
    if path.is_file() and not path.is_symlink():
        return path.stat().st_size > 0
    if not path.is_dir() or path.is_symlink():
        return False
    for child in path.rglob("*"):
        if deadline is not None:
            deadline.check(operation)
        if child.is_file() and not child.is_symlink() and child.stat().st_size > 0:
            return True
        if heartbeat is not None:
            heartbeat(operation)
    return False


@dataclass(frozen=True)
class ScenarioReceiptContext:
    """场景真实性收据所需的 attempt 身份与落盘位置。

    这三元身份是编排侧的权威事实，采集脚本无从得知也不能自行声明；由 run 阶段
    透传给外层 finalizer 注入，防止跨轮次复用收据。
    """

    campaign_id: str
    attempt_id: str
    run_nonce: str
    evidence_root: Path
    campaign_dir: Path


# 采集脚本把原始事实写在本 job 证据根的这个子目录下，文件名按场景固定。
SCENARIO_FACTS_DIR = "scenario-facts"
# facts 与收据里 evidence_bindings 共用的证据根角色名。
SCENARIO_EVIDENCE_ROOT_ROLE = "job_evidence"


def _job_run_id(job: Job) -> str:
    """取出 job 步骤声明的 RUN_ID，它把收据绑定到具体证据根。"""

    values = {
        str(step.get("environment", {}).get("RUN_ID"))
        for step in job.steps
        if step.get("environment", {}).get("RUN_ID")
    }
    if len(values) != 1:
        raise ConfigurationError(
            f"{job.job_id} 必须恰好声明一个 RUN_ID 才能产出场景真实性收据。"
        )
    return values.pop()


def _finalize_scenario_receipt(
    job: Job,
    scenario_id: str,
    job_root: Path,
    context: ScenarioReceiptContext,
    attempt_index: int,
) -> dict[str, Any]:
    """校验采集侧原始事实并承接为收据；任一环节不成立即抛错，不产出收据。"""

    run_id = _job_run_id(job)
    facts_source = job_root / SCENARIO_FACTS_DIR / f"{scenario_id}-facts.json"
    if facts_source.is_symlink() or not facts_source.is_file():
        raise ConfigurationError(
            f"{job.job_id} 未产出 {scenario_id} 的场景原始事实，目标协议分支未成立。"
        )
    try:
        payload = json.loads(facts_source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ConfigurationError(f"{scenario_id} 场景原始事实不可读：{error}") from error
    # 逐条按本 job 的证据根复核 evidence_bindings 的路径、大小与 SHA-256。
    approved_roots = {SCENARIO_EVIDENCE_ROOT_ROLE: job_root}
    validate_scenario_facts_document(
        payload,
        scenario_id=scenario_id,
        job_id=job.job_id,
        run_id=run_id,
        approved_roots=approved_roots,
    )
    receipt_dir = ensure_private_directory(
        context.evidence_root
        / "receipts"
        / "scenarios"
        / job.job_id
        / f"retry-{attempt_index}",
        context.campaign_dir,
    )
    facts_copy = receipt_dir / f"{scenario_id}-facts.json"
    _secure_write_json_once(facts_copy, payload)
    output = receipt_dir / f"{scenario_id}-scenario-receipt.json"
    receipt = finalize_scenario(
        argparse.Namespace(
            evidence_root=context.evidence_root,
            output=output,
            scenario_id=scenario_id,
            job_id=job.job_id,
            campaign_id=context.campaign_id,
            attempt_id=context.attempt_id,
            run_nonce=context.run_nonce,
            run_id=run_id,
            facts=facts_copy,
        )
    )
    validate_scenario_receipt(
        receipt,
        scenario_id=scenario_id,
        job_id=job.job_id,
        campaign_id=context.campaign_id,
        attempt_id=context.attempt_id,
        run_nonce=context.run_nonce,
        run_id=run_id,
        approved_roots=approved_roots,
    )
    return {
        "scenario_id": scenario_id,
        "path": str(output),
        "sha256": file_sha256(output),
        "final_state": receipt["final_state"],
    }


def _collect_scenario_receipts(
    job: Job,
    existing_roots: list[Path],
    context: ScenarioReceiptContext | None,
    attempt_index: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """按 job 声明逐场景产出真实性收据，失败原因逐条记录。"""

    receipts: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    if not job.required_scenario_receipts:
        return receipts, failures
    for scenario_id in job.required_scenario_receipts:
        try:
            if context is None:
                raise ConfigurationError(
                    "声明了场景真实性收据的任务必须在 attempt 上下文内执行。"
                )
            if len(existing_roots) != 1:
                raise ConfigurationError(
                    f"{job.job_id} 必须恰好命中一个证据根才能绑定场景收据。"
                )
            receipts.append(
                _finalize_scenario_receipt(
                    job, scenario_id, existing_roots[0], context, attempt_index
                )
            )
        except (
            ConfigurationError,
            ReceiptFinalizerError,
            ScenarioReceiptError,
            OSError,
        ) as error:
            failures.append(
                {"scenario_id": scenario_id, "reason": str(error)[:512] or "未知失败"}
            )
    return receipts, failures


def _collect_model_condition_receipt(
    job: Job,
    existing_roots: list[Path],
) -> tuple[dict[str, Any] | None, str | None]:
    """复核 job 证据根内的模型条件成功收据。"""

    if not getattr(job, "required_model_receipt", False):
        return None, None
    try:
        if len(existing_roots) != 1:
            raise ConfigurationError(
                f"{job.job_id} 必须恰好命中一个证据根才能绑定模型条件收据。"
            )
        root = existing_roots[0]
        path = root / "model-condition-receipt.json"
        if path.is_symlink() or not path.is_file():
            raise ConfigurationError(f"{job.job_id} 未产出模型条件成功收据。")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ConfigurationError(f"模型条件收据不可读：{error}") from error
        validated = validate_model_condition_receipt(
            payload,
            root=root,
            job_id=job.job_id,
            track=getattr(job, "track", "main"),
            model_id=getattr(job, "model_id", ""),
            use_responses_lite=getattr(job, "expected_use_responses_lite", False),
        )
        return {
            "path": str(path),
            "sha256": file_sha256(path),
            "track": validated["track"],
            "model_id": validated["model_id"],
            "models_response_sha256": validated["models_response_sha256"],
            "use_responses_lite": validated["use_responses_lite"],
            "model_fallback": validated["model_fallback"],
        }, None
    except (ConfigurationError, ModelConditionReceiptError, OSError) as error:
        return None, str(error)[:512] or "未知失败"


def _revalidate_model_condition_result(job: Job, result: dict[str, Any]) -> None:
    """在 seal／resume 时重放模型收据，拒绝 run 后篡改证据或结果字段。"""

    expected_coordinates = {
        "track": job.track,
        "model_id": job.model_id,
        "expected_use_responses_lite": job.expected_use_responses_lite,
        "required_model_receipt": job.required_model_receipt,
    }
    if any(result.get(key) != value for key, value in expected_coordinates.items()):
        raise ConfigurationError(f"{job.job_id} 的模型轨道结果坐标漂移。")
    receipt_reference = result.get("model_condition_receipt")
    failure = result.get("model_condition_receipt_failure")
    if not job.required_model_receipt:
        if receipt_reference is not None or failure is not None:
            raise ConfigurationError(f"{job.job_id} 未声明模型收据却携带模型结果。")
        return
    roots = result.get("evidence_roots")
    if not isinstance(roots, list) or len(roots) != 1:
        raise ConfigurationError(f"{job.job_id} 的模型收据必须绑定唯一 evidence root。")
    root = Path(roots[0])
    path = root / "model-condition-receipt.json"
    if (
        failure is not None
        or not isinstance(receipt_reference, dict)
        or receipt_reference.get("path") != str(path)
        or not path.is_file()
        or path.is_symlink()
        or receipt_reference.get("sha256") != file_sha256(path)
    ):
        raise ConfigurationError(f"{job.job_id} 的模型条件收据缺失或摘要不一致。")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ConfigurationError(f"{job.job_id} 的模型条件收据不可读：{error}") from error
    validated = validate_model_condition_receipt(
        payload,
        root=root,
        job_id=job.job_id,
        track=job.track,
        model_id=job.model_id,
        use_responses_lite=job.expected_use_responses_lite,
    )
    for key in (
        "track",
        "model_id",
        "models_response_sha256",
        "use_responses_lite",
        "model_fallback",
    ):
        if receipt_reference.get(key) != validated[key]:
            raise ConfigurationError(f"{job.job_id} 的模型条件结果字段 {key} 不一致。")


def run_job(
    job: Job,
    log_root: Path,
    attempt_index: int = 1,
    scenario_context: ScenarioReceiptContext | None = None,
    *,
    identity: Mapping[str, Any] | None = None,
    tool_identity: Mapping[str, Any] | None = None,
    deadline: incremental_recovery.WallClockDeadline | None = None,
    heartbeat: Any | None = None,
) -> dict[str, Any]:
    """顺序执行任务步骤，并保留不含命令环境值的日志。

    attempt_index 只用于在同一 attempt 内区分补跑的第几次，写进任务收据供审计。
    scenario_context 携带 attempt 身份，供声明了真实性收据的任务承接原始事实。
    """

    started = time.time()
    if deadline is not None:
        deadline.check(f"job:{job.job_id}:start")
    incremental = _job_incremental_metadata(
        job,
        identity=identity,
        tool_identity=tool_identity,
    )
    step_results: list[dict[str, Any]] = []
    for index, step in enumerate(job.steps, 1):
        if deadline is not None:
            deadline.check(f"job:{job.job_id}:step-{index}:prepare")
        if heartbeat is not None:
            heartbeat(f"job:{job.job_id}:step-{index}:start")
        log_path = log_root / (
            f"{job.job_id}-{index}.log"
            if attempt_index == 1
            else f"{job.job_id}-retry{attempt_index}-{index}.log"
        )
        environment = os.environ.copy()
        environment.update(step.get("environment", {}))
        argv = list(step["argv"])
        with log_path.open("w", encoding="utf-8") as log:
            os.chmod(log_path, 0o600)
            process = subprocess.Popen(
                argv,
                env=environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
            try:
                return_code = _wait_process(
                    process,
                    step.get("timeout", 1800),
                    deadline=deadline,
                    operation=f"job:{job.job_id}:step-{index}",
                    heartbeat=heartbeat,
                )
            except KeyboardInterrupt:
                _terminate_process(process, deadline=deadline)
                raise
        step_results.append(
            {
                "step": index,
                "argv": [Path(argv[0]).name, *argv[1:]],
                "return_code": return_code,
                "log": str(log_path),
            }
        )
        if heartbeat is not None:
            heartbeat(f"job:{job.job_id}:step-{index}:complete")
        if return_code != 0:
            break
    if deadline is not None:
        deadline.check(f"job:{job.job_id}:evidence-scan")
    roots_by_pattern: dict[str, list[Path]] = {}
    missing_patterns: list[str] = []
    empty_patterns: list[str] = []
    for pattern in job.evidence_roots:
        if deadline is not None:
            deadline.check(f"job:{job.job_id}:evidence:{pattern}")
        matches = [Path(value) for value in sorted(glob.glob(pattern))]
        if not matches and Path(pattern).exists():
            matches = [Path(pattern)]
        existing = [path for path in matches if path.exists() and not path.is_symlink()]
        roots_by_pattern[pattern] = existing
        if not existing:
            missing_patterns.append(pattern)
            continue
        if not any(
            _evidence_root_has_bytes(
                path,
                deadline=deadline,
                heartbeat=heartbeat,
                operation=f"job:{job.job_id}:evidence:{pattern}",
            )
            for path in existing
        ):
            empty_patterns.append(pattern)
        if heartbeat is not None:
            heartbeat(f"job:{job.job_id}:evidence:{pattern}:complete")
    existing_roots = [
        root for values in roots_by_pattern.values() for root in values
    ]
    if deadline is not None:
        deadline.check(f"job:{job.job_id}:finalize")
    steps_ok = len(step_results) == len(job.steps) and all(
        item["return_code"] == 0 for item in step_results
    )
    scenario_receipts_found, scenario_receipt_failures = _collect_scenario_receipts(
        job, existing_roots, scenario_context, attempt_index
    )
    # SCN-REALITY-01 的第四条件：声明的场景收据必须齐备且合法。退出码为 0、证据
    # 目录非空但目标协议分支一跳未发生，正是 k36 的实际形态，必须判失败。
    scenario_receipts_ok = not scenario_receipt_failures and len(
        scenario_receipts_found
    ) == len(job.required_scenario_receipts)
    model_receipt, model_receipt_failure = _collect_model_condition_receipt(
        job, existing_roots
    )
    model_receipt_ok = (
        model_receipt_failure is None
        and (not getattr(job, "required_model_receipt", False) or model_receipt is not None)
    )
    status = (
        "complete"
        if steps_ok
        and not missing_patterns
        and not empty_patterns
        and scenario_receipts_ok
        and model_receipt_ok
        else "failed"
    )
    return {
        "id": job.job_id,
        "phase": job.phase,
        "required": job.required,
        "execution_sha256": _job_execution_sha256(job),
        "status": status,
        "attempt_index": attempt_index,
        "description": job.description,
        "duration_seconds": round(time.time() - started, 3),
        "steps": step_results,
        "evidence_roots": [str(root) for root in existing_roots],
        "missing_evidence_patterns": missing_patterns,
        "empty_evidence_patterns": empty_patterns,
        "covers": list(job.covers),
        "scenario_ids": list(job.scenario_ids),
        "scenario_receipts": scenario_receipts_found,
        "scenario_receipt_failures": scenario_receipt_failures,
        "track": getattr(job, "track", "main"),
        "model_id": getattr(job, "model_id", ""),
        "expected_use_responses_lite": getattr(
            job, "expected_use_responses_lite", False
        ),
        "required_model_receipt": getattr(job, "required_model_receipt", False),
        "model_condition_receipt": model_receipt,
        "model_condition_receipt_failure": model_receipt_failure,
        "disposition": "executed",
        # 组件级身份用于跨 attempt 定向恢复；旧收据缺少这些字段时仍按
        # 原 execution_sha256 规则读取，不会把历史证据改写成新格式。
        "tool_components": incremental["components"],
        "tool_component_digests": incremental["component_digests"],
        "input_sha256": incremental["input_sha256"],
        "environment_sha256": incremental["environment_sha256"],
        "dependency_sha256": incremental["dependency_sha256"],
        "incremental_result_key": incremental["result_key"],
    }


# 上游波动（模型 at capacity、压缩原因未触发、CLI 偶发多一次信任提示）会让个别任务
# 落空。这类失败重跑即消失，但整轮 official 采集要 20 分钟——不在同一 attempt 内补跑，
# 就只能靠 resume 整轮重来，而重来同样要赌全部 17 项一次全过，收敛极慢。
#
# 在同一 attempt 内补跑不等于跨 attempt 拼接证据：run_nonce、环境探针边界、Campaign
# 身份全程不变，产出的仍然是同一次采集的证据。补跑前把上一次的证据目录整体归档，避免
# 与新证据混在一起；补跑次数写进任务收据，供审计还原真实执行过程。
# attempt_index 从 1 起算、判定为 `attempt_index > JOB_RETRY_LIMIT`，故总尝试次数 = 本值 + 1：
# 值 2 即总共 3 次（首次 + retry2 + retry3）。
#
# **这个常量是 official 与 candidate 共用的，不要为了给候选侧提速而下调。**
# k64 实证：改为 1（总共 2 次）后，官方侧 `official-core` 连续两次栽在 codex-ws 的 s4／s2
# 上（双轮对话与工具调用场景，本就最易受上游抖动影响），28/28 退化为 27/28 —— 而这类失败
# 恰恰需要第三次机会；历史正式采集中的 `official-relay-realtime-webrtc` 曾在第 3 次才成功。
# 候选侧的提速改由场景超时承担（`run_sub2api_*_matrix.sh` 的 --timeout 300→70），
# 那两处只作用于候选矩阵，不波及官方链路。
JOB_RETRY_LIMIT = 2
JOB_RETRY_DELAY_SECONDS = 30
DEFAULT_ATTEMPT_WALL_SECONDS = 90 * 60
MAX_ATTEMPT_WALL_SECONDS = 6 * 60 * 60
DEFAULT_HEARTBEAT_SECONDS = 30
MAX_HEARTBEAT_SECONDS = 5 * 60
WATCHDOG_HEARTBEAT_SCHEMA = "codex-upgrade-watchdog-heartbeat/v1"
WATCHDOG_CHECKPOINT_SCHEMA = "codex-upgrade-watchdog-checkpoint/v1"
JOB_CHECKPOINT_SCHEMA = "codex-upgrade-job-checkpoint/v1"
INCREMENTAL_NOOP_SCHEMA = "codex-upgrade-incremental-noop/v1"
WATCHDOG_OPERATION_RE = re.compile(r"^[A-Za-z0-9._:/*?+={}\[\](), -]{1,256}$")
WATCHDOG_SENSITIVE_RE = re.compile(
    r"(authorization|api[-_]?key|cookie|token|secret|password|credential|bearer)",
    re.IGNORECASE,
)
CAPTURE_SUCCESS_STATUSES = frozenset({"complete", "incremental-noop"})


def _normalize_watchdog_operation(value: Any) -> str:
    """只允许可审计的短操作标签，拒绝秘密、环境值和原始响应。"""

    if not isinstance(value, str):
        raise ConfigurationError("watchdog operation 必须是字符串。")
    operation = " ".join(value.strip().split())
    if (
        not operation
        or len(operation) > 256
        or not WATCHDOG_OPERATION_RE.fullmatch(operation)
        or WATCHDOG_SENSITIVE_RE.search(operation)
    ):
        raise ConfigurationError(
            "watchdog operation 含非法字符或敏感字段，拒绝写入 heartbeat。"
        )
    return operation


def _attempt_deadline(
    arguments: argparse.Namespace,
    phase: str,
) -> incremental_recovery.WallClockDeadline:
    """为一次 official／candidate attempt 建立唯一的全阶段 deadline。"""

    raw_budget = getattr(arguments, "max_wall_seconds", None)
    budget = DEFAULT_ATTEMPT_WALL_SECONDS if raw_budget is None else raw_budget
    if isinstance(budget, bool) or not isinstance(budget, int):
        raise ConfigurationError("--max-wall-seconds 必须是整数")
    if budget <= 0 or budget > MAX_ATTEMPT_WALL_SECONDS:
        raise ConfigurationError(
            f"--max-wall-seconds 必须在 1～{MAX_ATTEMPT_WALL_SECONDS} 秒之间"
        )
    raw_heartbeat = getattr(arguments, "heartbeat_seconds", None)
    heartbeat = (
        DEFAULT_HEARTBEAT_SECONDS if raw_heartbeat is None else raw_heartbeat
    )
    if isinstance(heartbeat, bool) or not isinstance(heartbeat, int):
        raise ConfigurationError("--heartbeat-seconds 必须是整数")
    if heartbeat <= 0 or heartbeat > MAX_HEARTBEAT_SECONDS:
        raise ConfigurationError(
            f"--heartbeat-seconds 必须在 1～{MAX_HEARTBEAT_SECONDS} 秒之间"
        )
    try:
        deadline = incremental_recovery.WallClockDeadline(
            budget,
            label=f"{phase}-capture-attempt",
        )
    except incremental_recovery.IncrementalRecoveryError as error:
        raise ConfigurationError(str(error)) from error
    # 这些是编排器元数据，不改变 deadline 的起点；同一对象贯穿预约、探针、
    # Job、清理和收据写入，重试不得重新创建对象。
    deadline.heartbeat_seconds = heartbeat  # type: ignore[attr-defined]
    deadline.phase = phase  # type: ignore[attr-defined]
    deadline.last_completed_job_id = None  # type: ignore[attr-defined]
    return deadline


def _write_attempt_heartbeat(
    path: Path,
    deadline: incremental_recovery.WallClockDeadline,
    *,
    operation: str,
    last_completed_job_id: str | None = None,
    force: bool = False,
    allow_expired: bool = False,
    attempt_root: Path | None = None,
) -> None:
    """原子更新不含秘密的 attempt 心跳。

    ``attempt_root`` 在真实编排路径中始终提供。保留可选参数是为了兼容旧的
    离线单元测试；只要提供该参数，心跳路径就只能是当前 attempt 的固定文件，
    不能借绑定字段指向别的 attempt 或 Campaign。
    """

    now = time.monotonic()
    last = getattr(deadline, "_last_heartbeat_monotonic", None)
    interval = float(
        getattr(deadline, "heartbeat_seconds", DEFAULT_HEARTBEAT_SECONDS)
    )
    if not force and isinstance(last, (int, float)) and now - last < interval:
        return
    if not allow_expired:
        deadline.check(operation)
    operation = _normalize_watchdog_operation(operation)
    if last_completed_job_id is not None and not SAFE_ID_RE.fullmatch(
        str(last_completed_job_id)
    ):
        raise ConfigurationError("watchdog last_completed_job_id 非法。")
    if attempt_root is not None:
        attempt_root = attempt_root.resolve(strict=True)
        if (
            not attempt_root.is_dir()
            or path.is_symlink()
            or path.parent.resolve(strict=False) != attempt_root
            or path.name != "watchdog-heartbeat.json"
        ):
            raise ConfigurationError("watchdog heartbeat 必须位于当前 attempt 根目录。")
    if last_completed_job_id is not None:
        deadline.last_completed_job_id = last_completed_job_id  # type: ignore[attr-defined]
    payload = {
        "schema_version": WATCHDOG_HEARTBEAT_SCHEMA,
        "phase": str(getattr(deadline, "phase", "stage")),
        "operation": str(operation)[:256],
        "elapsed_seconds": round(deadline.elapsed_seconds, 3),
        "remaining_seconds": round(deadline.remaining_seconds, 3),
        "last_completed_job_id": getattr(deadline, "last_completed_job_id", None),
        "updated_at_utc": _utc_now(),
    }
    # secure_write_json 使用临时文件 + replace；心跳允许覆盖，但绝不包含
    # argv、环境变量、token 或原始响应。
    secure_write_json(path, payload)
    deadline._last_heartbeat_monotonic = now  # type: ignore[attr-defined]


def _write_timeout_checkpoint(
    attempt_root: Path,
    deadline: incremental_recovery.WallClockDeadline,
    *,
    operation: str,
    last_completed_job_id: str | None = None,
) -> Path:
    """以不可覆盖方式保存超时终态；写失败由调用方继续停线。"""

    attempt_root = attempt_root.resolve(strict=True)
    if not attempt_root.is_dir() or attempt_root.is_symlink():
        raise ConfigurationError("timeout checkpoint 的 attempt 根不可信。")
    if last_completed_job_id is not None and not SAFE_ID_RE.fullmatch(
        str(last_completed_job_id)
    ):
        raise ConfigurationError("timeout checkpoint 的 Job 身份非法。")
    operation = _normalize_watchdog_operation(operation)

    checkpoint = {
        "schema_version": WATCHDOG_CHECKPOINT_SCHEMA,
        "status": "timeout",
        "phase": str(getattr(deadline, "phase", "stage")),
        "operation": str(operation)[:256],
        "elapsed_seconds": round(deadline.elapsed_seconds, 3),
        "remaining_seconds": round(deadline.remaining_seconds, 3),
        "budget_seconds": deadline.budget_seconds,
        "last_completed_job_id": last_completed_job_id
        or getattr(deadline, "last_completed_job_id", None),
        "recorded_at_utc": _utc_now(),
    }
    path = attempt_root / "timeout-checkpoint.json"
    _secure_write_json_once(path, checkpoint)
    return path


def _job_checkpoint_store(attempt_root: Path) -> incremental_recovery.CheckpointStore:
    """返回 attempt 专属追加式 Job checkpoint 存储器。"""

    attempt_root = attempt_root.resolve(strict=True)
    if not attempt_root.is_dir() or attempt_root.is_symlink():
        raise ConfigurationError("Job checkpoint 的 attempt 根不可信。")
    return incremental_recovery.CheckpointStore(attempt_root / "checkpoints")


def _latest_failed_attempt_identity_hint(
    campaign_dir: Path,
    *,
    phase: str,
    candidate_id: str | None,
) -> dict[str, Any] | None:
    """只读读取最近失败 attempt 的身份，供候选增量计划避免 Docker 探针。"""

    for attempt_root, _ in _ordered_capture_attempts(
        campaign_dir, phase, candidate_id
    ):
        attempt_path = attempt_root / "attempt.json"
        if not attempt_path.is_file() or attempt_path.is_symlink():
            continue
        _, payload = _load_capture_attempt(
            campaign_dir,
            phase,
            candidate_id,
            attempt_root.name,
        )
        if payload.get("status") != "failed":
            continue
        identity = payload.get("identity")
        if isinstance(identity, dict):
            return dict(identity)
    return None


def _cheap_capture_tool_impact(
    manifest: Mapping[str, Any],
    jobs: Iterable[Job],
    tool_identity: Mapping[str, Any],
) -> dict[str, Any]:
    """只用小型工具组件摘要计算影响闭集，不触发 package／容器／环境探针。"""

    expected = manifest.get("tool_identity")
    planned = list(jobs)
    if not isinstance(expected, Mapping):
        # 旧测试／旧 Campaign 没有组件摘要时不能假定未变化；把所有 Job
        # 标为受影响，后续正式校验会再给出更具体的 fail-close 原因。
        return {
            "kind": "unknown",
            "changed_components": ["shared"],
            "changed_paths": {},
            "affected_job_ids": sorted(job.job_id for job in planned),
        }
    try:
        drift = _tool_component_drift(expected, tool_identity)
    except (ConfigurationError, incremental_recovery.IncrementalRecoveryError):
        return {
            "kind": "unknown",
            "changed_components": ["shared"],
            "changed_paths": {},
            "affected_job_ids": sorted(job.job_id for job in planned),
        }
    changed = sorted(str(item) for item in drift.get("changed_components", []))
    return {
        "kind": "component_drift" if changed else "unchanged",
        "changed_components": changed,
        "changed_paths": drift.get("changed_paths", {}),
        "affected_job_ids": _affected_job_ids(planned, changed),
    }


def _write_incremental_noop_receipt(
    campaign_dir: Path,
    manifest: Mapping[str, Any],
    *,
    phase: str,
    candidate_id: str | None,
    identity: Mapping[str, Any],
    planned_job_ids: Iterable[str],
    reused_results: Iterable[Mapping[str, Any]],
    changed_components: Iterable[str] = (),
    affected_job_ids: Iterable[str] = (),
    tool_identity: Mapping[str, Any] | None = None,
    deadline: incremental_recovery.WallClockDeadline | None = None,
) -> dict[str, Any]:
    """写入不可覆盖的 incremental-noop 事实；不创建 reservation 或 attempt。"""

    if deadline is not None:
        deadline.check(f"{phase}:incremental-noop")
    planned = sorted({str(item) for item in planned_job_ids})
    reused = sorted(
        {
            str(item.get("id"))
            for item in reused_results
            if isinstance(item, Mapping) and item.get("id")
        }
    )
    affected = sorted({str(item) for item in affected_job_ids})
    changed = sorted({str(item) for item in changed_components})
    if not planned:
        raise ConfigurationError("incremental-noop 计划 Job 集不能为空。")
    if affected:
        raise ConfigurationError("incremental-noop 不得包含受影响 Job。")
    if reused != planned:
        raise ConfigurationError(
            "incremental-noop 必须完整复用计划内所有 Job，不能遗漏结果。"
        )
    source_receipts = {
        str(item["id"]): dict(item["source_receipt"])
        for item in reused_results
        if isinstance(item, Mapping)
        and item.get("id")
        and isinstance(item.get("source_receipt"), Mapping)
    }
    if set(source_receipts) != set(planned):
        raise ConfigurationError(
            "incremental-noop 缺少一个或多个原有通过 Job 的来源收据。"
        )
    # no-op 是独立的控制事实，不是 attempt；放在专用根下，避免被状态机或
    # 恢复逻辑误识别为可封存的 live attempt。
    relative = _capture_attempt_relative(phase, candidate_id)
    root = ensure_private_directory(
        campaign_dir / "incremental-noop" / relative, campaign_dir
    )
    noop_id = (
        time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        + f"-{secrets.token_hex(8)}"
    )
    plan_core = {
        "schema_version": incremental_recovery.SCHEMA_VERSION,
        "planned_job_ids": planned,
        "changed_components": changed,
        "affected_job_ids": [],
        "reused_job_ids": reused,
        "executed_job_ids": [],
        "failed_job_ids": [],
        "pending_job_ids": [],
    }
    plan_sha256 = incremental_recovery.digest(plan_core)
    source_receipts_sha256 = incremental_recovery.digest(source_receipts)
    payload: dict[str, Any] = {
        "schema_version": INCREMENTAL_NOOP_SCHEMA,
        "status": "incremental-noop",
        "success": True,
        "new_pass_fact": False,
        "campaign_id": str(manifest.get("campaign_id", "")),
        "campaign_manifest_sha256": file_sha256(campaign_dir / "campaign.json"),
        "phase": phase,
        "candidate_id": candidate_id,
        "noop_id": noop_id,
        "identity_sha256": _fingerprint(dict(identity)),
        "tool_component_identity_sha256": (
            _fingerprint(tool_identity.get("components"))
            if isinstance(tool_identity, Mapping)
            else None
        ),
        "planned_job_ids": planned,
        "execute_job_ids": [],
        "reused_job_ids": reused,
        "affected_job_ids": affected,
        "failed_job_ids": [],
        "changed_components": changed,
        "plan_sha256": plan_sha256,
        "incremental_plan": {
            **plan_core,
            "plan_sha256": plan_sha256,
        },
        "source_receipts": source_receipts,
        "source_receipts_sha256": source_receipts_sha256,
        "scanned_bytes": 0,
        "live_request_count": 0,
        "recorded_at_utc": _utc_now(),
        "next_action": "继续引用原有通过收据；无需创建 live attempt。",
    }
    payload["noop_sha256"] = _fingerprint(payload)
    _validate_incremental_noop_receipt(
        campaign_dir,
        payload,
        planned_job_ids=planned,
    )
    path = root / f"{noop_id}.json"
    _secure_write_json_once(path, payload)
    return {
        "status": "incremental-noop",
        "success": True,
        "incremental_noop": True,
        "noop_receipt": {
            "path": str(path),
            "sha256": file_sha256(path),
            "bytes": path.stat().st_size,
        },
        "execute_job_ids": [],
        "reused_job_ids": reused,
        "affected_job_ids": affected,
        "failed_job_ids": [],
        "changed_components": changed,
        "plan_sha256": plan_sha256,
        "source_receipts": source_receipts,
        "scanned_bytes": 0,
        "live_request_count": 0,
        "next_command": "无需重新抓包；继续使用原有通过收据。",
    }


def _validate_incremental_noop_receipt(
    campaign_dir: Path,
    payload: Mapping[str, Any],
    *,
    planned_job_ids: Iterable[str] | None = None,
) -> None:
    """校验主编排器的 no-op 收据；只做小型 stat，不读取证据正文。"""

    required = {
        "schema_version",
        "status",
        "success",
        "new_pass_fact",
        "campaign_id",
        "campaign_manifest_sha256",
        "phase",
        "candidate_id",
        "noop_id",
        "identity_sha256",
        "tool_component_identity_sha256",
        "planned_job_ids",
        "execute_job_ids",
        "reused_job_ids",
        "affected_job_ids",
        "failed_job_ids",
        "changed_components",
        "plan_sha256",
        "incremental_plan",
        "source_receipts",
        "source_receipts_sha256",
        "scanned_bytes",
        "live_request_count",
        "recorded_at_utc",
        "next_action",
        "noop_sha256",
    }
    if not isinstance(payload, Mapping) or set(payload) != required:
        raise ConfigurationError("incremental-noop 收据字段不闭合。")
    if payload.get("schema_version") != INCREMENTAL_NOOP_SCHEMA:
        raise ConfigurationError("incremental-noop schema_version 不匹配。")
    if (
        payload.get("status") != "incremental-noop"
        or payload.get("success") is not True
        or payload.get("new_pass_fact") is not False
        or payload.get("phase") not in {"official", "candidate"}
        or not SAFE_ID_RE.fullmatch(str(payload.get("campaign_id", "")))
        or not SAFE_ID_RE.fullmatch(str(payload.get("noop_id", "")))
        or not SHA256_RE.fullmatch(str(payload.get("campaign_manifest_sha256", "")))
        or not SHA256_RE.fullmatch(str(payload.get("identity_sha256", "")))
        or not SHA256_RE.fullmatch(str(payload.get("plan_sha256", "")))
        or not SHA256_RE.fullmatch(str(payload.get("source_receipts_sha256", "")))
        or not _is_rfc3339_timestamp(payload.get("recorded_at_utc"))
        or not isinstance(payload.get("next_action"), str)
        or not payload.get("next_action")
    ):
        raise ConfigurationError("incremental-noop 收据身份非法。")
    phase = str(payload["phase"])
    candidate_id = payload.get("candidate_id")
    if phase == "official":
        if candidate_id is not None:
            raise ConfigurationError("official incremental-noop 不得绑定 candidate。")
    elif not isinstance(candidate_id, str) or not SAFE_ID_RE.fullmatch(candidate_id):
        raise ConfigurationError("candidate incremental-noop 缺少合法 candidate-id。")
    expected_planned = (
        sorted({str(item) for item in planned_job_ids})
        if planned_job_ids is not None
        else payload.get("planned_job_ids")
    )
    arrays = {
        name: payload.get(name)
        for name in (
            "planned_job_ids",
            "execute_job_ids",
            "reused_job_ids",
            "affected_job_ids",
            "failed_job_ids",
            "changed_components",
        )
    }
    for name, value in arrays.items():
        if (
            not isinstance(value, list)
            or value != sorted(set(value))
            or not all(isinstance(item, str) and item for item in value)
        ):
            raise ConfigurationError(f"incremental-noop {name} 列表非法。")
    if (
        arrays["planned_job_ids"] != expected_planned
        or arrays["execute_job_ids"] != []
        or arrays["affected_job_ids"] != []
        or arrays["failed_job_ids"] != []
        or arrays["reused_job_ids"] != arrays["planned_job_ids"]
        or not arrays["planned_job_ids"]
        or any(item not in _TOOL_COMPONENT_NAMES for item in arrays["changed_components"])
    ):
        raise ConfigurationError("incremental-noop Job 集不闭合。")
    if payload.get("scanned_bytes") != 0 or payload.get("live_request_count") != 0:
        raise ConfigurationError("incremental-noop 不得包含扫描或请求。")
    tool_digest = payload.get("tool_component_identity_sha256")
    if tool_digest is not None and not SHA256_RE.fullmatch(str(tool_digest)):
        raise ConfigurationError("incremental-noop 工具组件摘要非法。")
    source_receipts = payload.get("source_receipts")
    if not isinstance(source_receipts, Mapping) or set(source_receipts) != set(
        arrays["planned_job_ids"]
    ):
        raise ConfigurationError("incremental-noop 来源收据集合不闭合。")
    for job_id, binding in source_receipts.items():
        if not isinstance(job_id, str) or not SAFE_ID_RE.fullmatch(job_id):
            raise ConfigurationError("incremental-noop 来源 Job 身份非法。")
        if not isinstance(binding, Mapping) or set(binding) != {
            "path",
            "sha256",
            "bytes",
        }:
            raise ConfigurationError("incremental-noop 来源绑定字段不闭合。")
        raw_path = binding.get("path")
        if (
            not isinstance(raw_path, str)
            or not raw_path
            or Path(raw_path).is_absolute()
            or "\\" in raw_path
            or str(PurePosixPath(raw_path)) != raw_path
            or any(part in {"", ".", ".."} for part in PurePosixPath(raw_path).parts)
            or not SHA256_RE.fullmatch(str(binding.get("sha256", "")))
            or not isinstance(binding.get("bytes"), int)
            or isinstance(binding.get("bytes"), bool)
            or binding.get("bytes") <= 0
        ):
            raise ConfigurationError("incremental-noop 来源绑定非法。")
        source_path = _campaign_file(campaign_dir, raw_path)
        _reject_symlink_components(source_path, campaign_dir, "incremental-noop 来源")
        if not source_path.is_file() or source_path.is_symlink():
            raise ConfigurationError("incremental-noop 来源收据不存在或不可信。")
        if source_path.stat().st_size != binding["bytes"]:
            raise ConfigurationError("incremental-noop 来源收据大小漂移。")
    if payload.get("source_receipts_sha256") != incremental_recovery.digest(
        dict(source_receipts)
    ):
        raise ConfigurationError("incremental-noop 来源收据摘要不一致。")
    plan = payload.get("incremental_plan")
    if not isinstance(plan, Mapping) or set(plan) != {
        "schema_version",
        "planned_job_ids",
        "changed_components",
        "affected_job_ids",
        "reused_job_ids",
        "executed_job_ids",
        "failed_job_ids",
        "pending_job_ids",
        "plan_sha256",
    }:
        raise ConfigurationError("incremental-noop 内嵌计划字段不闭合。")
    plan_core = dict(plan)
    nested_digest = plan_core.pop("plan_sha256", None)
    if (
        plan.get("schema_version") != incremental_recovery.SCHEMA_VERSION
        or plan.get("plan_sha256") != payload.get("plan_sha256")
        or nested_digest != incremental_recovery.digest(plan_core)
        or dict(plan) != {
            "schema_version": incremental_recovery.SCHEMA_VERSION,
            "planned_job_ids": arrays["planned_job_ids"],
            "changed_components": arrays["changed_components"],
            "affected_job_ids": [],
            "reused_job_ids": arrays["reused_job_ids"],
            "executed_job_ids": [],
            "failed_job_ids": [],
            "pending_job_ids": [],
            "plan_sha256": payload.get("plan_sha256"),
        }
    ):
        raise ConfigurationError("incremental-noop 内嵌计划摘要不一致。")
    unsigned = dict(payload)
    unsigned.pop("noop_sha256", None)
    if payload.get("noop_sha256") != _fingerprint(unsigned):
        raise ConfigurationError("incremental-noop 收据摘要不一致。")


def _archive_failed_job_evidence(result: dict[str, Any], attempt_index: int) -> None:
    """把失败证据整体归档，并同步重定位收据里的路径。

    场景清单为同一个 Campaign 固定证据根。若最后一次内部重试失败后仍把目录留在
    原路径，下一次 ``resume --rerun-failed`` 会在任何请求前触发“拒绝覆盖”，形成
    永远无法恢复的失败环。归档既要清出固定路径，也必须更新失败任务收据；否则
    attempt 会引用一个已经被移动、无法独立重放的旧地址。
    """

    replacements: dict[str, str] = {}

    for value in list(result.get("evidence_roots") or []):
        root = Path(value)
        if not root.exists() or root.is_symlink():
            continue
        archived = root.with_name(f"{root.name}.failed-attempt{attempt_index}")
        suffix = 1
        while archived.exists():
            suffix += 1
            archived = root.with_name(
                f"{root.name}.failed-attempt{attempt_index}-{suffix}"
            )
        try:
            root.rename(archived)
        except OSError:
            # 归档失败不能吞掉：证据残留会让补跑在旧样本上得出结论。
            raise ConfigurationError(f"无法归档失败任务的证据目录：{root}")
        replacements[str(root)] = str(archived)

    if not replacements:
        return

    def rebase(value: Any) -> Any:
        """递归更新证据根及其内部文件引用，不改动其他任务事实。"""

        if isinstance(value, str):
            for before, after in sorted(
                replacements.items(), key=lambda item: len(item[0]), reverse=True
            ):
                if value == before:
                    return after
                prefix = before + os.sep
                if value.startswith(prefix):
                    return after + value[len(before) :]
            return value
        if isinstance(value, list):
            return [rebase(item) for item in value]
        if isinstance(value, dict):
            return {key: rebase(item) for key, item in value.items()}
        return value

    rebased = rebase(result)
    result.clear()
    result.update(rebased)


def _run_job_with_retry(
    job: Job,
    log_root: Path,
    scenario_context: ScenarioReceiptContext | None = None,
    *,
    identity: Mapping[str, Any] | None = None,
    tool_identity: Mapping[str, Any] | None = None,
    deadline: incremental_recovery.WallClockDeadline | None = None,
    heartbeat: Any | None = None,
) -> dict[str, Any]:
    """在同一 attempt 内对失败任务做有限补跑，返回最后一次的收据。"""

    attempt_index = 1
    while True:
        if deadline is not None:
            deadline.check(f"job:{job.job_id}:attempt-{attempt_index}")
        candidate_kwargs: dict[str, Any] = {}
        if identity is not None:
            candidate_kwargs["identity"] = identity
        if tool_identity is not None:
            candidate_kwargs["tool_identity"] = tool_identity
        if deadline is not None:
            candidate_kwargs["deadline"] = deadline
        if heartbeat is not None:
            candidate_kwargs["heartbeat"] = heartbeat
        # 保持第三方／历史测试桩的旧四参数接口可用。真实 ``run_job`` 和
        # 接受 **kwargs 的桩仍会收到组件身份；不通过捕获 TypeError 重试，避免
        # 一个已经发出请求的 Job 被重复启动。
        callable_target: Any = run_job
        side_effect = getattr(run_job, "side_effect", None)
        if callable(side_effect):
            callable_target = side_effect
        try:
            signature = inspect.signature(callable_target)
            accepts_kwargs = any(
                parameter.kind == inspect.Parameter.VAR_KEYWORD
                for parameter in signature.parameters.values()
            )
            run_kwargs = (
                dict(candidate_kwargs)
                if accepts_kwargs
                else {
                    name: value
                    for name, value in candidate_kwargs.items()
                    if name in signature.parameters
                }
            )
        except (TypeError, ValueError):
            run_kwargs = dict(candidate_kwargs)
        result = run_job(
            job,
            log_root,
            attempt_index,
            scenario_context,
            **run_kwargs,
        )
        if result.get("status") == "complete":
            return result
        if not job.required or attempt_index > JOB_RETRY_LIMIT:
            # 最后一份失败证据也必须归档。否则跨 attempt 的显式 resume 会使用
            # 同一固定证据根并被“禁止覆盖”门禁永久卡死。
            _archive_failed_job_evidence(result, attempt_index)
            return result
        _archive_failed_job_evidence(result, attempt_index)
        attempt_index += 1
        if deadline is not None:
            deadline.sleep(
                JOB_RETRY_DELAY_SECONDS,
                operation=f"job:{job.job_id}:retry-backoff",
            )
        else:
            time.sleep(JOB_RETRY_DELAY_SECONDS)


def build_coverage(
    rules: tuple[str, ...],
    jobs: list[Job],
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    status_by_job = {result["id"]: result["status"] for result in results}
    rows = []
    for rule in rules:
        by_phase: dict[str, list[str]] = {"official": [], "candidate": []}
        for job in jobs:
            if rule in job.covers:
                by_phase[job.phase].append(job.job_id)
        official_complete = any(
            status_by_job.get(job_id) == "complete"
            for job_id in by_phase["official"]
        )
        candidate_complete = any(
            status_by_job.get(job_id) == "complete"
            for job_id in by_phase["candidate"]
        )
        rows.append(
            {
                "rule": rule,
                "official_jobs": by_phase["official"],
                "candidate_jobs": by_phase["candidate"],
                "official_evidence_collected": official_complete,
                "candidate_evidence_collected": candidate_complete,
                "evidence_complete": official_complete and candidate_complete,
            }
        )
    complete = [row for row in rows if row["evidence_complete"]]
    return {
        "required_rule_count": len(rules),
        "evidence_complete_count": len(complete),
        "complete": len(complete) == len(rules),
        "rules": rows,
    }


def _validate_capture_job_results(
    jobs: list[Job],
    results: Any,
    *,
    phase: str,
) -> None:
    if not isinstance(results, list):
        raise ConfigurationError(f"{phase} 抓包 results 必须是数组。")
    expected = {job.job_id: job for job in jobs if job.required}
    seen: set[str] = set()
    for result in results:
        if not isinstance(result, dict):
            raise ConfigurationError(f"{phase} 抓包任务收据必须是对象。")
        job_id = result.get("id")
        if not isinstance(job_id, str) or job_id in seen:
            raise ConfigurationError(f"{phase} 抓包任务收据身份非法或重复。")
        seen.add(job_id)
        _validate_incremental_job_result(result, label=f"{phase}:{job_id}")
        if job_id in expected:
            expected_job = expected[job_id]
            if (
                result.get("phase") != phase
                or result.get("status") != "complete"
                or result.get("execution_sha256")
                != _job_execution_sha256(expected_job)
            ):
                raise ConfigurationError(
                    f"{phase} 必需抓包任务 {job_id} 未完成或执行定义漂移。"
                )
            incremental_key = result.get("incremental_result_key")
            if incremental_key is not None and not SHA256_RE.fullmatch(
                str(incremental_key)
            ):
                raise ConfigurationError(
                    f"{phase} 抓包任务 {job_id} 的增量结果键非法。"
                )
            component_names = result.get("tool_components")
            if component_names is not None and (
                not isinstance(component_names, list)
                or not all(isinstance(item, str) and item for item in component_names)
                or component_names != sorted(set(component_names))
            ):
                raise ConfigurationError(
                    f"{phase} 抓包任务 {job_id} 的组件依赖非法。"
                )
            _revalidate_model_condition_result(expected_job, result)
    missing = set(expected) - seen
    if missing:
        raise ConfigurationError(f"{phase} 缺少必需抓包任务收据：{sorted(missing)}")


def _validate_incremental_job_result(
    result: Mapping[str, Any],
    *,
    label: str,
) -> None:
    """校验 Job 级增量字段；旧 attempt 缺字段时保持只读兼容。"""

    components = result.get("tool_components")
    metadata_fields = {
        "tool_components",
        "tool_component_digests",
        "input_sha256",
        "environment_sha256",
        "dependency_sha256",
        "incremental_result_key",
    }
    present = {field for field in metadata_fields if field in result}
    if present and present != metadata_fields:
        raise ConfigurationError(f"{label} 增量字段不完整。")
    if present:
        if (
            not isinstance(components, list)
            or not all(isinstance(item, str) and item for item in components)
            or components != sorted(set(components))
            or not isinstance(result.get("tool_component_digests"), Mapping)
            or set(result["tool_component_digests"]) != set(components)
            or any(
                not isinstance(name, str)
                or not SHA256_RE.fullmatch(str(value))
                for name, value in result["tool_component_digests"].items()
            )
            or any(
                not SHA256_RE.fullmatch(str(result.get(field, "")))
                for field in (
                    "input_sha256",
                    "environment_sha256",
                    "dependency_sha256",
                    "incremental_result_key",
                )
            )
        ):
            raise ConfigurationError(f"{label} 增量身份非法。")
    disposition = result.get("disposition")
    if disposition is not None and disposition not in {"executed", "reused"}:
        raise ConfigurationError(f"{label} disposition 非法。")
    if disposition == "reused":
        source = result.get("source_receipt")
        if (
            not isinstance(source, Mapping)
            or set(source) != {"path", "sha256", "bytes"}
            or not isinstance(source.get("path"), str)
            or not SHA256_RE.fullmatch(str(source.get("sha256", "")))
            or not isinstance(source.get("bytes"), int)
            or isinstance(source.get("bytes"), bool)
            or source.get("bytes") <= 0
        ):
            raise ConfigurationError(f"{label} 复用来源收据非法。")
    if "carried_from_attempt" in result and not SAFE_ID_RE.fullmatch(
        str(result.get("carried_from_attempt", ""))
    ):
        raise ConfigurationError(f"{label} 承接来源 attempt 非法。")


def _validate_attempt_file_binding(
    value: Any,
    *,
    label: str,
    allow_null: bool = True,
) -> PurePosixPath | None:
    """校验 watchdog／checkpoint 的小型相对文件绑定，不读取大证据。"""

    if value is None and allow_null:
        return None
    if not isinstance(value, Mapping) or set(value) != {"path", "sha256", "bytes"}:
        raise ConfigurationError(f"{label} 文件绑定字段不闭合。")
    path = value.get("path")
    parsed = PurePosixPath(path) if isinstance(path, str) else PurePosixPath(".")
    if (
        not isinstance(path, str)
        or not path
        or Path(path).is_absolute()
        or "\\" in path
        or str(parsed) != path
        or any(part in {"", ".", ".."} for part in parsed.parts)
        or not SHA256_RE.fullmatch(str(value.get("sha256", "")))
        or not isinstance(value.get("bytes"), int)
        or isinstance(value.get("bytes"), bool)
        or value.get("bytes") <= 0
    ):
        raise ConfigurationError(f"{label} 文件绑定非法。")
    return parsed


def _resolve_attempt_binding(
    campaign_dir: Path,
    attempt_root: Path,
    value: Any,
    *,
    label: str,
    expected_name: str,
    directory: bool = False,
) -> Path | None:
    """把 Campaign 相对绑定解析到当前 attempt 的固定子路径。"""

    if directory:
        raw_path = value.get("path") if isinstance(value, Mapping) else None
        parsed = _validate_attempt_relative_path(raw_path, label=label)
    else:
        parsed = _validate_attempt_file_binding(value, label=label)
    if parsed is None:
        return None
    campaign = campaign_dir.resolve(strict=True)
    attempt = attempt_root.resolve(strict=True)
    candidate = campaign.joinpath(*parsed.parts)
    _reject_symlink_components(candidate, campaign, label)
    try:
        if candidate.resolve(strict=False) != (attempt / expected_name).resolve(
            strict=False
        ):
            raise ConfigurationError(
                f"{label} 必须绑定当前 attempt 的 {expected_name}。"
            )
    except (OSError, RuntimeError, ValueError) as error:
        raise ConfigurationError(f"{label} 越出当前 attempt。") from error
    if directory:
        if not candidate.is_dir() or candidate.is_symlink():
            raise ConfigurationError(f"{label} 目录不存在或不可信。")
    elif not candidate.is_file() or candidate.is_symlink():
        raise ConfigurationError(f"{label} 文件不存在或不可信。")
    return candidate


def _validate_attempt_relative_path(value: Any, *, label: str) -> PurePosixPath:
    """校验只含路径的 attempt 目录绑定。"""

    if not isinstance(value, str) or not value or Path(value).is_absolute() or "\\" in value:
        raise ConfigurationError(f"{label} 路径非法。")
    parsed = PurePosixPath(value)
    if str(parsed) != value or any(part in {"", ".", ".."} for part in parsed.parts):
        raise ConfigurationError(f"{label} 路径非法。")
    return parsed


def _validate_attempt_watchdog_fields(
    payload: Mapping[str, Any],
    planned_job_ids: set[str] | None = None,
) -> None:
    """校验 attempt 的 heartbeat、超时 checkpoint 和 Job checkpoint 摘要。"""

    watchdog = payload.get("watchdog")
    if watchdog is not None:
        if not isinstance(watchdog, Mapping) or set(watchdog) != {
            "schema_version",
            "budget_seconds",
            "heartbeat_seconds",
            "elapsed_seconds",
            "remaining_seconds",
            "heartbeat",
            "timeout_checkpoint",
            "last_completed_job_id",
        }:
            raise ConfigurationError("attempt watchdog 字段不闭合。")
        if (
            watchdog.get("schema_version") != WATCHDOG_HEARTBEAT_SCHEMA
            or not isinstance(watchdog.get("budget_seconds"), (int, float))
            or isinstance(watchdog.get("budget_seconds"), bool)
            or not math.isfinite(float(watchdog.get("budget_seconds")))
            or float(watchdog.get("budget_seconds")) <= 0
            or not isinstance(watchdog.get("heartbeat_seconds"), (int, float))
            or isinstance(watchdog.get("heartbeat_seconds"), bool)
            or not math.isfinite(float(watchdog.get("heartbeat_seconds")))
            or float(watchdog.get("heartbeat_seconds")) <= 0
            or not isinstance(watchdog.get("elapsed_seconds"), (int, float))
            or isinstance(watchdog.get("elapsed_seconds"), bool)
            or not math.isfinite(float(watchdog.get("elapsed_seconds")))
            or float(watchdog.get("elapsed_seconds")) < 0
            or not isinstance(watchdog.get("remaining_seconds"), (int, float))
            or isinstance(watchdog.get("remaining_seconds"), bool)
            or not math.isfinite(float(watchdog.get("remaining_seconds")))
            or float(watchdog.get("remaining_seconds")) < 0
            or float(watchdog.get("remaining_seconds"))
            > float(watchdog.get("budget_seconds")) + 1
            or (
                (
                    watchdog.get("last_completed_job_id") is not None
                    and not SAFE_ID_RE.fullmatch(
                        str(watchdog.get("last_completed_job_id"))
                    )
                )
                or (
                    planned_job_ids is not None
                    and watchdog.get("last_completed_job_id") is not None
                    and str(watchdog.get("last_completed_job_id"))
                    not in planned_job_ids
                )
            )
        ):
            raise ConfigurationError("attempt watchdog 数值或身份非法。")
        _validate_attempt_file_binding(
            watchdog.get("heartbeat"), label="attempt watchdog heartbeat"
        )
        _validate_attempt_file_binding(
            watchdog.get("timeout_checkpoint"),
            label="attempt watchdog timeout checkpoint",
        )
    checkpoint = payload.get("job_checkpoint")
    if checkpoint is not None:
        base_fields = {"path", "record_count", "last_sequence", "last_sha256"}
        context_fields = {
            "schema_version",
            "campaign_id",
            "phase",
            "attempt_id",
            "run_nonce",
        }
        actual_fields = set(checkpoint) if isinstance(checkpoint, Mapping) else set()
        strict_context = watchdog is not None
        if (
            (strict_context and actual_fields != base_fields | context_fields)
            or (not strict_context and actual_fields != base_fields)
        ):
            raise ConfigurationError("attempt Job checkpoint 字段不闭合。")
        if strict_context and actual_fields == base_fields | context_fields:
            if (
                checkpoint.get("schema_version") != JOB_CHECKPOINT_SCHEMA
                or not isinstance(checkpoint.get("campaign_id"), str)
                or not SAFE_ID_RE.fullmatch(str(checkpoint.get("campaign_id")))
                or checkpoint.get("phase") not in {"official", "candidate"}
                or not isinstance(checkpoint.get("attempt_id"), str)
                or not SAFE_ID_RE.fullmatch(str(checkpoint.get("attempt_id")))
                or not SHA256_RE.fullmatch(str(checkpoint.get("run_nonce", "")))
            ):
                raise ConfigurationError("attempt Job checkpoint 身份非法。")
        if (
            not isinstance(checkpoint.get("path"), str)
            or not checkpoint["path"]
            or Path(checkpoint["path"]).is_absolute()
            or "\\" in checkpoint["path"]
            or str(PurePosixPath(checkpoint["path"])) != checkpoint["path"]
            or any(
                part in {"", ".", ".."}
                for part in PurePosixPath(checkpoint["path"]).parts
            )
            or not isinstance(checkpoint.get("record_count"), int)
            or isinstance(checkpoint.get("record_count"), bool)
            or checkpoint.get("record_count") < 0
            or (
                checkpoint.get("record_count") == 0
                and (
                    checkpoint.get("last_sequence") is not None
                    or checkpoint.get("last_sha256") is not None
                )
            )
            or (
                checkpoint.get("record_count", 0) > 0
                and (
                    not isinstance(checkpoint.get("last_sequence"), int)
                    or isinstance(checkpoint.get("last_sequence"), bool)
                    or checkpoint.get("last_sequence") != checkpoint.get("record_count")
                    or not SHA256_RE.fullmatch(str(checkpoint.get("last_sha256", "")))
                )
            )
        ):
            raise ConfigurationError("attempt Job checkpoint 摘要或序号非法。")


def _validate_attempt_watchdog_bindings(
    campaign_dir: Path,
    attempt_root: Path,
    payload: Mapping[str, Any],
    planned_job_ids: set[str] | None = None,
) -> None:
    """重放 watchdog 的小型文件和 checkpoint 链，拒绝摘要漂移。"""

    watchdog = payload.get("watchdog")
    if isinstance(watchdog, Mapping):
        heartbeat_binding = watchdog.get("heartbeat")
        if heartbeat_binding is None:
            raise ConfigurationError("当前 attempt 缺少 watchdog heartbeat 绑定。")
        heartbeat_path = _resolve_attempt_binding(
            campaign_dir,
            attempt_root,
            heartbeat_binding,
            label="watchdog heartbeat",
            expected_name="watchdog-heartbeat.json",
        )
        assert heartbeat_path is not None
        _validate_attempt_bound_file(heartbeat_path, heartbeat_binding, "watchdog heartbeat")
        try:
            heartbeat_document = _read_json(heartbeat_path, "watchdog heartbeat")
        except ConfigurationError as error:
            raise ConfigurationError("watchdog heartbeat 不是可重放 JSON。") from error
        expected_heartbeat_fields = {
            "schema_version",
            "phase",
            "operation",
            "elapsed_seconds",
            "remaining_seconds",
            "last_completed_job_id",
            "updated_at_utc",
        }
        if set(heartbeat_document) != expected_heartbeat_fields:
            raise ConfigurationError("watchdog heartbeat 内容不闭合。")
        if heartbeat_document.get("schema_version") != WATCHDOG_HEARTBEAT_SCHEMA:
            raise ConfigurationError("watchdog heartbeat schema 不匹配。")
        if heartbeat_document.get("phase") != payload.get("phase"):
            raise ConfigurationError("watchdog heartbeat phase 漂移。")
        _validate_watchdog_document_values(
            heartbeat_document,
            label="watchdog heartbeat",
            planned_job_ids=planned_job_ids,
            budget=float(watchdog["budget_seconds"]),
        )
        if not _is_rfc3339_timestamp(heartbeat_document.get("updated_at_utc")):
            raise ConfigurationError("watchdog heartbeat 时间非法。")
        _validate_watchdog_time_window(
            heartbeat_document["updated_at_utc"], payload, "watchdog heartbeat"
        )
        if (
            heartbeat_document.get("last_completed_job_id")
            != watchdog.get("last_completed_job_id")
        ):
            raise ConfigurationError("watchdog heartbeat 与 attempt 末项身份不一致。")

        timeout_binding = watchdog.get("timeout_checkpoint")
        if timeout_binding is not None:
            timeout_path = _resolve_attempt_binding(
                campaign_dir,
                attempt_root,
                timeout_binding,
                label="watchdog timeout checkpoint",
                expected_name="timeout-checkpoint.json",
            )
            assert timeout_path is not None
            _validate_attempt_bound_file(
                timeout_path, timeout_binding, "watchdog timeout checkpoint"
            )
            try:
                timeout_document = _read_json(
                    timeout_path, "watchdog timeout checkpoint"
                )
            except ConfigurationError as error:
                raise ConfigurationError(
                    "watchdog timeout checkpoint 不是可重放 JSON。"
                ) from error
            expected_timeout_fields = {
                "schema_version",
                "status",
                "phase",
                "operation",
                "elapsed_seconds",
                "remaining_seconds",
                "budget_seconds",
                "last_completed_job_id",
                "recorded_at_utc",
            }
            if set(timeout_document) != expected_timeout_fields:
                raise ConfigurationError("watchdog timeout checkpoint 内容不闭合。")
            if (
                timeout_document.get("schema_version") != WATCHDOG_CHECKPOINT_SCHEMA
                or timeout_document.get("status") != "timeout"
                or timeout_document.get("phase") != payload.get("phase")
                or timeout_document.get("budget_seconds")
                != watchdog.get("budget_seconds")
                or timeout_document.get("last_completed_job_id")
                != watchdog.get("last_completed_job_id")
            ):
                raise ConfigurationError("watchdog timeout checkpoint 身份非法。")
            _validate_watchdog_document_values(
                timeout_document,
                label="watchdog timeout checkpoint",
                planned_job_ids=planned_job_ids,
                budget=float(watchdog["budget_seconds"]),
            )
            if not _is_rfc3339_timestamp(timeout_document.get("recorded_at_utc")):
                raise ConfigurationError("watchdog timeout checkpoint 时间非法。")
            _validate_watchdog_time_window(
                timeout_document["recorded_at_utc"],
                payload,
                "watchdog timeout checkpoint",
            )
        elif float(watchdog.get("remaining_seconds", 0)) <= 0:
            raise ConfigurationError("超时 attempt 缺少 timeout checkpoint。")

    checkpoint = payload.get("job_checkpoint")
    if isinstance(watchdog, Mapping) and checkpoint is None:
        raise ConfigurationError("当前 attempt 缺少 Job checkpoint 绑定。")
    if isinstance(checkpoint, Mapping):
        path = _resolve_attempt_binding(
            campaign_dir,
            attempt_root,
            checkpoint,
            label="Job checkpoint",
            expected_name="checkpoints",
            directory=True,
        )
        assert path is not None
        try:
            store = incremental_recovery.CheckpointStore(path, create=False)
            records = store.records()
        except incremental_recovery.IncrementalRecoveryError as error:
            raise ConfigurationError(f"Job checkpoint 链无法重放：{error}") from error
        if len(records) != checkpoint.get("record_count"):
            raise ConfigurationError("Job checkpoint 记录数量漂移。")
        last = records[-1] if records else None
        if (
            checkpoint.get("last_sequence")
            != (last.get("checkpoint_sequence") if last else None)
            or checkpoint.get("last_sha256")
            != (last.get("checkpoint_sha256") if last else None)
        ):
            raise ConfigurationError("Job checkpoint 末项摘要漂移。")
        if isinstance(watchdog, Mapping):
            if (
                checkpoint.get("campaign_id") != payload.get("campaign_id")
                or checkpoint.get("phase") != payload.get("phase")
                or checkpoint.get("attempt_id") != payload.get("attempt_id")
                or checkpoint.get("run_nonce") != payload.get("run_nonce")
            ):
                raise ConfigurationError("Job checkpoint 汇总身份漂移。")
        _validate_checkpoint_records(
            records,
            payload,
            planned_job_ids=planned_job_ids,
            strict_context=isinstance(watchdog, Mapping),
        )


def _validate_attempt_bound_file(
    path: Path,
    binding: Mapping[str, Any],
    label: str,
) -> None:
    """校验已解析到当前 attempt 的小文件摘要。"""

    if (
        path.stat().st_size != binding.get("bytes")
        or path.stat().st_size > 1024 * 1024
        or file_sha256(path) != binding.get("sha256")
    ):
        raise ConfigurationError(f"{label}摘要漂移。")


def _validate_watchdog_document_values(
    document: Mapping[str, Any],
    *,
    label: str,
    planned_job_ids: set[str] | None,
    budget: float,
) -> None:
    """校验 heartbeat/timeout 中的数值、操作和 Job 身份，不读取原始证据。"""

    for field in ("elapsed_seconds", "remaining_seconds"):
        value = document.get(field)
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(float(value))
            or float(value) < 0
            or float(value) > budget + 1
        ):
            raise ConfigurationError(f"{label} {field} 非法。")
    if document.get("remaining_seconds", 0) > 1 and document.get("status") == "timeout":
        raise ConfigurationError(f"{label} 超时终态仍有过多剩余预算。")
    try:
        _normalize_watchdog_operation(document.get("operation"))
    except ConfigurationError as error:
        raise ConfigurationError(f"{label} operation 含非法或敏感内容。") from error
    completed = document.get("last_completed_job_id")
    if completed is not None and (
        not isinstance(completed, str)
        or not SAFE_ID_RE.fullmatch(completed)
        or (planned_job_ids is not None and completed not in planned_job_ids)
    ):
        raise ConfigurationError(f"{label} last_completed_job_id 非法。")


def _validate_watchdog_time_window(
    recorded_at_utc: str,
    payload: Mapping[str, Any],
    label: str,
) -> None:
    """确保 watchdog 文件属于当前 attempt 的时间窗口。"""

    try:
        recorded = _rfc3339_datetime(recorded_at_utc, f"{label}.time")
        started = _rfc3339_datetime(payload.get("started_at_utc"), "attempt.started_at_utc")
        completed = _rfc3339_datetime(
            payload.get("completed_at_utc"), "attempt.completed_at_utc"
        )
    except ConfigurationError as error:
        raise ConfigurationError(f"{label} 时间窗口非法。") from error
    if recorded < started or recorded > completed:
        raise ConfigurationError(f"{label} 不属于当前 attempt 时间窗口。")


def _validate_checkpoint_records(
    records: list[Mapping[str, Any]],
    payload: Mapping[str, Any],
    *,
    planned_job_ids: set[str] | None,
    strict_context: bool,
) -> None:
    """校验 checkpoint 的记录数量、序号、结果摘要和 attempt 身份。"""

    result_by_id: dict[str, Mapping[str, Any]] = {}
    for item in payload.get("results", []):
        if not isinstance(item, Mapping) or not isinstance(item.get("id"), str):
            raise ConfigurationError("attempt results 身份非法。")
        item_id = str(item["id"])
        if item_id in result_by_id:
            raise ConfigurationError("attempt results 含重复 Job 身份。")
        result_by_id[item_id] = item
    if planned_job_ids is not None and not set(result_by_id).issubset(planned_job_ids):
        raise ConfigurationError("attempt results 含预约外 Job。")
    seen: set[str] = set()
    for record in records:
        item_id = record.get("item_id")
        if (
            not isinstance(item_id, str)
            or not SAFE_ID_RE.fullmatch(item_id)
            or (planned_job_ids is not None and item_id not in planned_job_ids)
            or item_id in seen
        ):
            raise ConfigurationError("Job checkpoint item 身份或数量非法。")
        seen.add(item_id)
        if strict_context:
            if (
                record.get("checkpoint_schema_version") != JOB_CHECKPOINT_SCHEMA
                or record.get("campaign_id") != payload.get("campaign_id")
                or record.get("phase") != payload.get("phase")
                or record.get("attempt_id") != payload.get("attempt_id")
                or record.get("run_nonce") != payload.get("run_nonce")
            ):
                raise ConfigurationError("Job checkpoint 记录的 attempt 身份漂移。")
        result = record.get("result")
        expected = result_by_id.get(item_id)
        if not isinstance(result, Mapping) or expected is None:
            raise ConfigurationError("Job checkpoint 缺少对应结果。")
        if dict(result) != dict(expected):
            raise ConfigurationError("Job checkpoint 结果与 attempt 收据不一致。")
        if record.get("result_sha256") != incremental_recovery.digest(dict(result)):
            raise ConfigurationError("Job checkpoint 结果摘要漂移。")
        if record.get("status") not in {"complete", "failed"}:
            raise ConfigurationError("Job checkpoint 状态非法。")
        expected_status = "complete" if result.get("status") == "complete" else "failed"
        if record.get("status") != expected_status:
            raise ConfigurationError("Job checkpoint 状态与结果不一致。")
        if record.get("result_key") != result.get("incremental_result_key"):
            raise ConfigurationError("Job checkpoint 结果键漂移。")
    if not seen.issubset(set(result_by_id)):
        raise ConfigurationError("Job checkpoint 含未知结果。")
    if strict_context and seen != set(result_by_id):
        raise ConfigurationError("Job checkpoint 未覆盖当前 attempt 的全部结果。")


def _render_report(payload: dict[str, Any]) -> str:
    jobs = payload["jobs"]
    coverage = payload["coverage"]
    source_diff = payload["source_diff"]
    official_diff = payload["baseline_to_target_official"]
    candidate_diff = payload["official_to_candidate"]
    lines = [
        f"# Codex CLI {payload['target_version']} 升级审计报告",
        "",
        f"- 基线版本：{payload['baseline_version']}",
        f"- 目标版本：{payload['target_version']}",
        f"- 任务状态：{payload['status']}",
        (
            f"- 规则证据覆盖：{coverage['evidence_complete_count']}/"
            f"{coverage['required_rule_count']}"
        ),
        f"- 新增源码线索：{source_diff['added_count']}",
        f"- 新增官方动态形态：{official_diff['added_count']}",
        (
            f"- 官方与 Sub2API 动态形态差异："
            f"+{candidate_diff['added_count']}/-{candidate_diff['removed_count']}"
        ),
        "",
        "## 抓包任务",
        "",
        "| 任务 | 边界 | 状态 |",
        "|---|---|---|",
    ]
    for job in jobs:
        lines.append(f"| {job['id']} | {job['phase']} | {job['status']} |")
    incomplete = [
        row["rule"] for row in coverage["rules"] if not row["evidence_complete"]
    ]
    lines.extend(["", "## 尚未闭合的规则", ""])
    lines.append("、".join(incomplete) if incomplete else "无。")
    lines.extend(["", "## 新形态候选", ""])
    if source_diff["added_count"] or official_diff["added_count"]:
        lines.append(
            "存在尚未分类的源码或动态形态变化；必须判定为既有规则变化、"
            "新增规则或不适用后，才能建立目标版本画像。"
        )
    else:
        lines.append("未发现新增源码线索或新增动态出站形态。")
    lines.extend(
        [
            "",
            "## 判定边界",
            "",
            "任务成功只表示证据已收集并完成结构比较，不自动等同于规则通过。",
            "账号权限或场景未触发造成的缺口必须保持失败状态，不能继承旧版本结论。",
            "",
        ]
    )
    return "\n".join(lines)


def _validate_output_path(path: Path) -> None:
    if not path.is_absolute() or path.is_symlink():
        raise ConfigurationError("Campaign 目录必须是非符号链接的绝对路径。")
    resolved = path.resolve(strict=False)
    forbidden = {
        Path("/").resolve(),
        Path.home().resolve(),
        Path("/tmp").resolve(),
    }
    if resolved in forbidden:
        raise ConfigurationError("Campaign 目录不能是根目录、HOME 或 /tmp 本身。")
    if path.exists():
        raise ConfigurationError("Campaign 目录已存在；plan 必须使用新目录。")


def _validate_existing_campaign_path(path: Path) -> None:
    if not path.is_absolute() or path.is_symlink():
        raise ConfigurationError("--campaign-dir 必须是非符号链接的绝对路径。")
    if not path.is_dir():
        raise ConfigurationError(f"Campaign 目录不存在：{path}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_campaign_reference(target: argparse.ArgumentParser) -> None:
        target.add_argument(
            "--campaign-dir",
            "--campaign",
            dest="campaign_dir",
            type=Path,
            required=True,
        )

    def add_candidate_reference(target: argparse.ArgumentParser) -> None:
        add_campaign_reference(target)
        target.add_argument("--candidate-id", required=True)

    def add_capture_receipts(
        target: argparse.ArgumentParser,
        *,
        candidate: bool,
    ) -> None:
        target.add_argument(
            "--attempt-id",
            help="run 阶段返回的不可变 attempt ID；seal 阶段必需。",
        )
        target.add_argument(
            "--capture-manifest",
            type=Path,
            help="finalizer 生成并位于证据根内的统一 capture manifest。",
        )
        target.add_argument(
            "--assertion-evidence-root",
            type=Path,
            help="capture manifest 内 artifact 路径所基于的证据根。",
        )
        target.add_argument(
            "--restoration-report",
            type=Path,
            help="兼容校验：只能指向本次 run 自动生成的环境恢复报告。",
        )
        target.add_argument(
            "--evidence-root",
            action="append",
            default=[],
            type=Path,
            help="seal 时重申 run 已绑定的证据根或其子目录，可重复。",
        )
        target.add_argument(
            "--approve-seal-sha256",
            help="人工复核 seal-preview.json 后回传的联合摘要。",
        )
        if candidate:
            target.add_argument(
                "--observed-profile-receipt",
                type=Path,
                help="由运行中 Sub2API 产生的实际画像观测收据。",
            )

    def add_watchdog_options(target: argparse.ArgumentParser) -> None:
        target.add_argument(
            "--max-wall-seconds",
            type=int,
            default=None,
            help=(
                f"一次 capture attempt 的单调墙钟预算（默认 {DEFAULT_ATTEMPT_WALL_SECONDS} 秒，"
                f"上限 {MAX_ATTEMPT_WALL_SECONDS} 秒）。"
            ),
        )
        target.add_argument(
            "--heartbeat-seconds",
            type=int,
            default=None,
            help=(
                f"watchdog heartbeat 间隔（默认 {DEFAULT_HEARTBEAT_SECONDS} 秒，"
                f"上限 {MAX_HEARTBEAT_SECONDS} 秒）。"
            ),
        )

    plan = subparsers.add_parser("plan", help="预检并创建不可变 Campaign")
    plan.add_argument(
        "--campaign-dir",
        "--output",
        dest="campaign_dir",
        type=Path,
        required=True,
    )
    plan.add_argument("--baseline-version", required=True)
    plan.add_argument("--target-version", required=True)
    plan.add_argument(
        "--campaign-mode",
        choices=sorted(CAMPAIGN_MODES),
        required=True,
        help=(
            "preflight_only 只能生成并检查 P0 计划；formal 才能进入正式升级链。"
        ),
    )
    plan.add_argument(
        "--campaign-purpose",
        choices=sorted(CANDIDATE_PURPOSES),
        required=True,
        help="冻结本 Campaign 的升级用途，后续 candidate 不得改变。",
    )
    plan.add_argument(
        "--timing-ledger-dir",
        type=Path,
        required=True,
        help="已从 DOC-PRE 首项开始计时的 UpgradeTimingLedger 绝对目录。",
    )
    plan.add_argument(
        "--timing-receipt",
        type=Path,
        required=True,
        help="位于 timing ledger 内、可独立重放的 active checkpoint。",
    )
    plan.add_argument(
        "--arm64-environment-root",
        type=Path,
        required=True,
        help="P0 ARM64 网络与磁盘收据所在的 0700 绝对目录。",
    )
    plan.add_argument(
        "--arm64-environment-receipt",
        type=Path,
        required=True,
        help="P0 生成并重放通过的 ARM64 环境收据。",
    )
    plan.add_argument(
        "--job-rehearsal-root",
        type=Path,
        help=(
            "Formal 必需：ARM64 全量 Job 离线演练收据所在的 0700 绝对目录；"
            "preflight_only 不需要。"
        ),
    )
    plan.add_argument(
        "--job-rehearsal-receipt",
        type=Path,
        help=(
            "Formal 必需：从 preflight_only Campaign 生成并独立重放通过的"
            "完整 Job 演练收据。"
        ),
    )
    plan.add_argument("--baseline-source", type=Path, required=True)
    plan.add_argument("--target-source", type=Path, required=True)
    plan.add_argument("--baseline-evidence", type=Path, required=True)
    plan.add_argument("--target-sha256", required=True)
    plan.add_argument(
        "--target-package",
        type=Path,
        required=True,
        help="官方 codex-package 压缩包的持久绝对路径。",
    )
    plan.add_argument("--target-package-sha256", required=True)
    plan.add_argument("--target-code-mode-host-sha256", required=True)
    plan.add_argument(
        "--runtime-image",
        required=True,
        help="官方采集运行时的 repository@sha256 不可变镜像引用。",
    )
    plan.add_argument(
        "--rule-manifest",
        type=Path,
        required=True,
    )
    plan.add_argument(
        "--scenario-manifest",
        type=Path,
        required=True,
        help="当前 baseline 版本的发现场景清单，只用于基线差异分析。",
    )
    plan.add_argument(
        "--target-scenario-manifest",
        type=Path,
        required=True,
        help=(
            "目标版本的正式采集场景清单；Formal official Attempt 必须逐摘要执行"
            "该清单，不得回退到 baseline 命令模板。"
        ),
    )
    plan.add_argument("--extra-jobs", type=Path)
    plan.add_argument("--suite", choices=("core", "full"), default="full")
    plan.add_argument(
        "--campaign-id",
        default="",
        help="留空时按目标版本和 UTC 时间生成。",
    )
    plan.add_argument(
        "--model",
        required=True,
        help=(
            "主升级线模型，必须属于目标版本 main 轨道"
            "（上游 use_responses_lite=false）。"
        ),
    )
    plan.add_argument(
        "--lite-model",
        required=True,
        help="Lite 专项模型，必须属于目标版本 lite 轨道。",
    )
    plan.add_argument("--capture-root", type=Path, default=Path("/root/oauth-capture"))
    plan.add_argument("--capture-container", default="capture-cli")
    plan.add_argument("--service-container", default="sub2apiplus")
    plan.add_argument("--keeper-container", default="sub2apiplus-keeper")
    plan.add_argument("--postgres-container", default="sub2apiplus-postgres")
    plan.add_argument("--redis-container", default="sub2apiplus-redis")
    plan.add_argument(
        "--capture-codex-bin",
        default="",
        help="默认使用 /opt/codex-<target-version>/bin/codex。",
    )
    plan.add_argument(
        "--relay-codex-bin",
        default="",
        help="默认使用 /opt/codex-<target-version>/bin/codex。",
    )
    plan.add_argument(
        "--capture-code-mode-host-bin",
        default="",
        help="默认使用 /opt/codex-<target-version>/bin/codex-code-mode-host。",
    )
    plan.add_argument(
        "--relay-code-mode-host-bin",
        default="",
        help="默认使用 /opt/codex-<target-version>/bin/codex-code-mode-host。",
    )
    plan.add_argument("--codex-account-id", type=int, default=90)
    plan.add_argument("--api-key-id", type=int, default=1)
    plan.add_argument(
        "--live-attestation-compose-dir",
        default="",
        help="候选部署的 compose 工作目录；A11 需据此重建服务启用 candidatecapture provider。",
    )
    plan.add_argument(
        "--live-attestation-compose-files",
        default="",
        help="候选部署的 compose -f 参数串，恢复时按同一串拉回。",
    )

    official = subparsers.add_parser(
        "capture-official", help="运行或封存目标官方 CLI 证据"
    )
    official.add_argument("capture_action", choices=("run", "seal"))
    add_campaign_reference(official)
    add_capture_receipts(official, candidate=False)
    add_watchdog_options(official)
    official.add_argument("--acknowledge-live-requests", action="store_true")

    successor = subparsers.add_parser(
        "successor",
        help="创建同版本后继 Campaign，并按受管原因只读承接官方事实",
    )
    successor.add_argument(
        "--predecessor-campaign-dir",
        type=Path,
        required=True,
        help="已封存官方阶段和批准分类的只读前序 Campaign 目录。",
    )
    add_campaign_reference(successor)
    successor.add_argument("--campaign-id", required=True)
    successor.add_argument(
        "--codex-account-id",
        type=int,
        required=True,
        help="后继 Candidate 运行必须显式冻结的可用 Codex 账号 ID。",
    )
    successor.add_argument(
        "--reason",
        choices=sorted(SUCCESSOR_REASONS),
        required=True,
        help=(
            "触发同版本后继 Campaign 的受管原因；分类事实纠正只承接官方阶段，"
            "不会复制旧批准五件套。"
        ),
    )
    successor.add_argument(
        "--predecessor-candidate-id",
        help="可选：绑定前序 Campaign 中已放弃的 candidate。",
    )
    successor.add_argument(
        "--predecessor-attempt-id",
        help="可选：绑定前序 candidate 中无法继续封存的 attempt。",
    )
    successor.add_argument(
        "--live-attestation-compose-dir",
        type=Path,
        help=(
            "可选：为运行时身份纠正后继冻结新的 compose 工作目录；"
            "必须与 --live-attestation-compose-files 同时提供。"
        ),
    )
    successor.add_argument(
        "--live-attestation-compose-files",
        help=(
            "可选：为运行时身份纠正后继冻结新的 compose -f 参数串；"
            "旧 Campaign 的外部部署文件保持只读。"
        ),
    )
    successor.add_argument(
        "--job-rehearsal-root",
        type=Path,
        help=(
            "可选：产出侧工具变化后，由当前 preflight_only Campaign 生成的"
            "完整 Job 演练证据根；必须与 --job-rehearsal-receipt 同时提供。"
        ),
    )
    successor.add_argument(
        "--job-rehearsal-receipt",
        type=Path,
        help=(
            "可选：按后继当前执行合同生成并重放通过的完整 Job 演练收据；"
            "提供后将替换前序 Formal 的旧演练绑定。"
        ),
    )
    successor.add_argument(
        "--recovery-timing-ledger-dir",
        type=Path,
        help="旧 Ledger 停线后，恢复 P0 使用的新 UpgradeTimingLedger。",
    )
    successor.add_argument(
        "--recovery-timing-receipt",
        type=Path,
        help="新恢复 Ledger 的 active checkpoint。",
    )
    successor.add_argument(
        "--recovery-arm64-environment-root",
        type=Path,
        help="与新恢复 Ledger 同主体的 ARM64 P0 收据根。",
    )
    successor.add_argument(
        "--recovery-arm64-environment-receipt",
        type=Path,
        help="与新恢复 Ledger 同主体的 ARM64 P0 收据。",
    )
    successor.add_argument(
        "--predecessor-stop-ledger-dir",
        type=Path,
        help="前序 Formal 所绑定且已经停线的 Ledger。",
    )
    successor.add_argument(
        "--predecessor-stop-receipt",
        type=Path,
        help="前序 Ledger 的 stop_the_line checkpoint。",
    )

    classify = subparsers.add_parser(
        "classify", help="生成差异草案或封存已审核的目标规则迁移"
    )
    add_campaign_reference(classify)
    classify.add_argument("--target-rule-manifest", type=Path)
    classify.add_argument("--migration-manifest", type=Path)
    classify.add_argument("--scenario-manifest", type=Path)
    classify.add_argument("--profile-manifest", type=Path)
    classify.add_argument("--assertion-profile-manifest", type=Path)
    classify.add_argument("--approve-manifest-sha256")

    prepare_profile = subparsers.add_parser(
        "prepare-profile",
        help="把完整 Snapshot 规范化为待人工审核的目标画像清单",
    )
    add_campaign_reference(prepare_profile)
    prepare_profile.add_argument("--snapshot", type=Path, required=True)
    prepare_profile.add_argument("--profile-id", required=True)
    prepare_profile.add_argument("--output", type=Path, required=True)

    stage_profile = subparsers.add_parser(
        "stage-profile",
        help="把已批准完整画像编译成不切 Active 的候选 RuntimeCatalog",
    )
    add_campaign_reference(stage_profile)
    stage_profile.add_argument(
        "--output",
        type=Path,
        required=True,
        help="不存在的候选目录绝对路径；不会修改仓库或生产 selector。",
    )

    candidate = subparsers.add_parser(
        "capture-candidate", help="运行或封存一个 Sub2API 候选"
    )
    candidate.add_argument("capture_action", choices=("run", "seal"))
    add_candidate_reference(candidate)
    add_watchdog_options(candidate)
    candidate.add_argument("--runtime-image")
    candidate.add_argument("--candidate-image-id")
    candidate.add_argument("--candidate-source", type=Path)
    candidate.add_argument("--build-id")
    candidate.add_argument("--deployed-version")
    candidate.add_argument("--profile-id")
    candidate.add_argument("--profile-digest")
    candidate.add_argument(
        "--candidate-purpose",
        choices=sorted(CANDIDATE_PURPOSES),
        required=True,
        help="run 与 seal 均须重申，且必须等于 Campaign 冻结用途。",
    )
    add_capture_receipts(candidate, candidate=True)
    candidate.add_argument(
        "--client-evidence",
        action="append",
        default=[],
        metavar="CLIENT=PATH",
    )
    candidate.add_argument("--acknowledge-live-requests", action="store_true")

    compare = subparsers.add_parser("compare", help="仅使用封存证据离线比较")
    add_candidate_reference(compare)

    accept = subparsers.add_parser("accept", help="执行逐规则正式验收门禁")
    add_candidate_reference(accept)
    accept.add_argument("--assertions", type=Path)
    accept.add_argument(
        "--external-gate-root",
        type=Path,
        required=True,
        help="candidate 外部门禁收据所在的 0700 evidence root",
    )
    accept.add_argument(
        "--external-gate-receipt",
        type=Path,
        required=True,
        help="由独立 finalizer 生成并可重放的 candidate_external 收据",
    )

    all_command = subparsers.add_parser(
        "all", help="兼容入口：对已批准画像只启动一次候选 run"
    )
    add_candidate_reference(all_command)
    add_watchdog_options(all_command)
    all_command.add_argument("--runtime-image", required=True)
    all_command.add_argument("--candidate-image-id")
    all_command.add_argument("--candidate-source", type=Path)
    all_command.add_argument("--build-id", required=True)
    all_command.add_argument("--deployed-version", required=True)
    all_command.add_argument("--profile-id", required=True)
    all_command.add_argument("--profile-digest", required=True)
    all_command.add_argument(
        "--candidate-purpose",
        choices=sorted(CANDIDATE_PURPOSES),
        required=True,
    )
    all_command.add_argument("--acknowledge-live-requests", action="store_true")

    evaluation_transition = subparsers.add_parser(
        "evaluation-transition",
        help="为已完成请求的 attempt 审批阶段限定的评估工具过渡",
    )
    add_campaign_reference(evaluation_transition)
    evaluation_transition.add_argument(
        "--phase",
        choices=("official", "candidate"),
        required=True,
    )
    evaluation_transition.add_argument("--candidate-id")
    evaluation_transition.add_argument("--attempt-id", required=True)
    evaluation_transition.add_argument("--approve-transition-sha256")
    evaluation_transition.add_argument(
        "--predecessor-stop-ledger-dir",
        type=Path,
        required=True,
        help="原 Campaign 所绑定且已经停线的 Ledger。",
    )
    evaluation_transition.add_argument(
        "--predecessor-stop-receipt",
        type=Path,
        required=True,
        help="原 Ledger 的 stop_the_line checkpoint。",
    )
    evaluation_transition.add_argument(
        "--recovery-timing-ledger-dir",
        type=Path,
        required=True,
        help="恢复流程的新 active UpgradeTimingLedger。",
    )
    evaluation_transition.add_argument(
        "--recovery-timing-receipt",
        type=Path,
        required=True,
        help="恢复 Ledger 的 active checkpoint。",
    )
    evaluation_transition.add_argument(
        "--recovery-arm64-environment-root",
        type=Path,
        required=True,
        help="恢复流程的新 ARM64 P0 证据根。",
    )
    evaluation_transition.add_argument(
        "--recovery-arm64-environment-receipt",
        type=Path,
        required=True,
        help="恢复流程的新 ARM64 P0 收据。",
    )
    evaluation_transition.add_argument(
        "--job-rehearsal-root",
        type=Path,
        required=True,
        help="使用当前工具完成的完整 Job 离线演练证据根。",
    )
    evaluation_transition.add_argument(
        "--job-rehearsal-receipt",
        type=Path,
        required=True,
        help="使用当前工具完成的完整 Job 离线演练收据。",
    )

    deep_verify = subparsers.add_parser(
        "deep-verify",
        help="显式重哈希证据并建立可续作验证 checkpoint",
    )
    add_campaign_reference(deep_verify)
    deep_verify.add_argument("--candidate-id")
    deep_verify.add_argument(
        "--attempt-id",
        help="工具发生阶段限定漂移时，绑定已批准 transition 的 attempt。",
    )

    status = subparsers.add_parser("status", help="显示 Campaign 状态和下一命令")
    add_campaign_reference(status)
    status.add_argument("--candidate-id")

    resume = subparsers.add_parser("resume", help="按最近稳定状态续跑失败阶段")
    add_campaign_reference(resume)
    resume.add_argument("--candidate-id")
    resume.add_argument("--runtime-image")
    resume.add_argument("--candidate-image-id")
    resume.add_argument("--candidate-source", type=Path)
    resume.add_argument("--build-id")
    resume.add_argument("--deployed-version")
    resume.add_argument("--profile-id")
    resume.add_argument("--profile-digest")
    resume.add_argument(
        "--candidate-purpose",
        choices=sorted(CANDIDATE_PURPOSES),
    )
    resume.add_argument("--assertions", type=Path)
    resume.add_argument("--external-gate-root", type=Path)
    resume.add_argument("--external-gate-receipt", type=Path)
    resume.add_argument("--rerun-failed", action="store_true")
    add_watchdog_options(resume)
    resume.add_argument("--acknowledge-live-requests", action="store_true")
    return parser


SUPPORTED_UPGRADE_PAIRS = frozenset(
    {
        ("0.145.0", "0.147.0"),
        ("0.147.0", "0.149.1"),
        ("0.149.1", "0.151.0"),
    }
)


def _validate_upgrade_pair_models(
    *,
    baseline_version: str,
    target_version: str,
    model: str,
    lite_model: str,
) -> None:
    """校验受管升级对及其双轨模型坐标，未知组合一律失败关闭。"""

    upgrade_pair = (baseline_version, target_version)
    if upgrade_pair not in SUPPORTED_UPGRADE_PAIRS:
        raise ConfigurationError(
            f"不支持的 Codex 升级对：{baseline_version}→{target_version}。"
        )
    main_models = track_models_for_version(target_version, "main")
    lite_models = track_models_for_version(target_version, "lite")
    if model not in main_models:
        raise ConfigurationError(
            f"{baseline_version}→{target_version} 主升级线"
            f"只能使用 {'／'.join(main_models)}。"
        )
    if lite_model not in lite_models:
        raise ConfigurationError(
            f"{baseline_version}→{target_version} Lite 专项"
            f"只能使用 {'／'.join(lite_models)}。"
        )


def _validate_arguments(arguments: argparse.Namespace) -> None:
    if getattr(arguments, "campaign_mode", None) not in CAMPAIGN_MODES:
        raise ConfigurationError(
            "--campaign-mode 必须显式为 preflight_only 或 formal。"
        )
    if getattr(arguments, "campaign_purpose", None) not in CANDIDATE_PURPOSES:
        raise ConfigurationError(
            "--campaign-purpose 必须显式为 validation_only 或 "
            "production_replacement。"
        )
    rehearsal_root = getattr(arguments, "job_rehearsal_root", None)
    rehearsal_receipt = getattr(arguments, "job_rehearsal_receipt", None)
    if arguments.campaign_mode == "formal" and not all(
        isinstance(value, Path) for value in (rehearsal_root, rehearsal_receipt)
    ):
        raise ConfigurationError(
            "formal plan 必须显式提供 --job-rehearsal-root 与 "
            "--job-rehearsal-receipt。"
        )
    if arguments.campaign_mode == "preflight_only" and any(
        value is not None for value in (rehearsal_root, rehearsal_receipt)
    ):
        raise ConfigurationError(
            "preflight_only 不得消费完整 Job 演练收据；先创建 preflight，"
            "完成 ARM64 演练后再创建 Formal。"
        )
    if not getattr(arguments, "redis_container", None):
        arguments.redis_container = "sub2apiplus-redis"
    for field, value in (
        ("--baseline-version", arguments.baseline_version),
        ("--target-version", arguments.target_version),
    ):
        if not VERSION_RE.fullmatch(value):
            raise ConfigurationError(f"{field} 必须是三段版本号。")
    _validate_upgrade_pair_models(
        baseline_version=arguments.baseline_version,
        target_version=arguments.target_version,
        model=arguments.model,
        lite_model=arguments.lite_model,
    )
    if not SHA256_RE.fullmatch(arguments.target_sha256):
        raise ConfigurationError("--target-sha256 必须是 64 位小写 SHA-256。")
    if not SHA256_RE.fullmatch(arguments.target_package_sha256):
        raise ConfigurationError(
            "--target-package-sha256 必须是 64 位小写 SHA-256。"
        )
    if not SHA256_RE.fullmatch(arguments.target_code_mode_host_sha256):
        raise ConfigurationError(
            "--target-code-mode-host-sha256 必须是 64 位小写 SHA-256。"
        )
    if not IMMUTABLE_IMAGE_RE.fullmatch(arguments.runtime_image):
        raise ConfigurationError(
            "--runtime-image 必须是 repository@sha256:<manifest-digest>。"
        )
    if not arguments.baseline_evidence.exists():
        raise ConfigurationError("--baseline-evidence 不存在。")
    for field, source in (
        ("--baseline-source", arguments.baseline_source),
        ("--target-source", arguments.target_source),
    ):
        if not source.is_dir() or source.is_symlink():
            raise ConfigurationError(f"{field} 不存在或不是可信目录。")
    if arguments.codex_account_id <= 0 or arguments.api_key_id <= 0:
        raise ConfigurationError("账号和 API Key ID 必须为正整数。")
    if arguments.campaign_id:
        if not SAFE_ID_RE.fullmatch(arguments.campaign_id):
            raise ConfigurationError("--campaign-id 格式非法。")
    else:
        version = arguments.target_version.replace(".", "_")
        arguments.campaign_id = (
            f"codex-{version}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
        )
    if not arguments.capture_root.is_absolute():
        raise ConfigurationError("--capture-root 必须是绝对路径。")
    if not SAFE_ABSOLUTE_PATH_RE.fullmatch(str(arguments.capture_root)):
        raise ConfigurationError("--capture-root 包含不安全字符。")
    for field in (
        "capture_container",
        "service_container",
        "keeper_container",
        "postgres_container",
        "redis_container",
        "model",
        "lite_model",
    ):
        value = str(getattr(arguments, field))
        if not SAFE_ID_RE.fullmatch(value):
            raise ConfigurationError(f"--{field.replace('_', '-')} 格式非法。")
    if (
        not arguments.target_package.is_absolute()
        or not SAFE_ABSOLUTE_PATH_RE.fullmatch(str(arguments.target_package))
        or arguments.target_package.is_symlink()
        or not arguments.target_package.is_file()
    ):
        raise ConfigurationError(
            "--target-package 必须是存在、非符号链接的安全绝对文件。"
        )
    arguments.target_package_identity = _verify_codex_package(
        arguments.target_package,
        expected_version=arguments.target_version,
        expected_package_sha256=arguments.target_package_sha256,
        expected_binary_sha256=arguments.target_sha256,
        expected_code_mode_host_sha256=arguments.target_code_mode_host_sha256,
    )
    runtime_bin = f"/opt/codex-{arguments.target_version}/bin"
    for field, filename in (
        ("capture_codex_bin", "codex"),
        ("relay_codex_bin", "codex"),
        ("capture_code_mode_host_bin", "codex-code-mode-host"),
        ("relay_code_mode_host_bin", "codex-code-mode-host"),
    ):
        if not getattr(arguments, field, ""):
            setattr(arguments, field, f"{runtime_bin}/{filename}")
    for field in (
        "capture_codex_bin",
        "relay_codex_bin",
        "capture_code_mode_host_bin",
        "relay_code_mode_host_bin",
    ):
        value = str(getattr(arguments, field))
        if not SAFE_ABSOLUTE_PATH_RE.fullmatch(value):
            raise ConfigurationError(f"--{field.replace('_', '-')} 路径不安全。")
        path = Path(value)
        if path == Path("/root") or Path("/root") in path.parents:
            raise ConfigurationError(
                f"--{field.replace('_', '-')} 不得位于 /root；"
                "Codex 文件系统 helper 会在 bubblewrap 内重新执行当前二进制，"
                "必须使用可由沙箱子进程穿越的 /opt 受管路径。"
            )
    campaign_dir = getattr(arguments, "campaign_dir", None) or getattr(
        arguments, "output", None
    )
    if campaign_dir is None:
        raise ConfigurationError("缺少 Campaign 目录。")
    arguments.campaign_dir = campaign_dir
    arguments.output = campaign_dir
    _validate_output_path(campaign_dir)


def _safe_plan(
    arguments: argparse.Namespace,
    jobs: list[Job],
    rules: tuple[str, ...],
) -> dict[str, Any]:
    mapped = {
        phase: {rule for job in jobs if job.phase == phase for rule in job.covers}
        for phase in ("official", "candidate")
    }
    return {
        "schema_version": REPORT_SCHEMA,
        "mode": "dry-run",
        "baseline_version": arguments.baseline_version,
        "target_version": arguments.target_version,
        "campaign_id": arguments.campaign_id,
        "campaign_mode": arguments.campaign_mode,
        "campaign_purpose": arguments.campaign_purpose,
        "suite": arguments.suite,
        "baseline_source": str(arguments.baseline_source),
        "target_source": str(arguments.target_source),
        "baseline_evidence": str(arguments.baseline_evidence),
        "output": str(arguments.output),
        "coverage_plan": {
            "required_rule_count": len(rules),
            "official_unmapped": sorted(set(rules) - mapped["official"]),
            "candidate_unmapped": sorted(set(rules) - mapped["candidate"]),
        },
        "jobs": [
            {
                "id": job.job_id,
                "phase": job.phase,
                "description": job.description,
                "steps": [
                    {"argv": step["argv"], "timeout": step.get("timeout")}
                    for step in job.steps
                ],
                "evidence_roots": list(job.evidence_roots),
                "covers": list(job.covers),
                "scenario_ids": list(job.scenario_ids),
                "track": job.track,
                "model_id": job.model_id,
                "expected_use_responses_lite": job.expected_use_responses_lite,
                "required_model_receipt": job.required_model_receipt,
            }
            for job in jobs
        ],
    }


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ConfigurationError(f"无法读取{label} {path}：{error}") from error
    if not isinstance(payload, dict):
        raise ConfigurationError(f"{label}必须是 JSON 对象：{path}")
    return payload


def _reject_symlink_components(path: Path, root: Path, label: str) -> None:
    """拒绝从 Campaign 根到目标文件之间的任一符号链接。"""

    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise ConfigurationError(f"{label}越过 Campaign 根目录。") from error
    current = root
    if current.is_symlink():
        raise ConfigurationError(f"{label} Campaign 根目录是符号链接。")
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ConfigurationError(f"{label}路径包含符号链接：{current}")


def _secure_write_json_once(path: Path, payload: dict[str, Any]) -> None:
    """以硬链接发布临时文件，实现跨进程原子且不可覆盖的 JSON 封存。"""

    ensure_private_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(
                json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
                + "\n"
            )
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise ConfigurationError(f"不可变文件已经存在，禁止覆盖：{path}") from error
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def _secure_copy_file_once(source: Path, destination: Path) -> dict[str, Any]:
    """逐字节复制普通文件，并以不可覆盖方式发布目标。"""

    if source.is_symlink() or not source.is_file():
        raise ConfigurationError(f"后继 Campaign 复制源不是可信普通文件：{source}")
    ensure_private_directory(destination.parent)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with source.open("rb") as source_stream, os.fdopen(
            descriptor, "wb"
        ) as destination_stream:
            shutil.copyfileobj(source_stream, destination_stream)
            destination_stream.flush()
            os.fsync(destination_stream.fileno())
        descriptor = -1
        try:
            os.link(temporary, destination)
        except FileExistsError as error:
            raise ConfigurationError(
                f"不可变文件已经存在，禁止覆盖：{destination}"
            ) from error
        destination.chmod(0o600)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    source_digest = file_sha256(source)
    if file_sha256(destination) != source_digest:
        raise ConfigurationError(f"后继 Campaign 文件复制后摘要不一致：{destination}")
    return {
        "sha256": source_digest,
        "bytes": destination.stat().st_size,
    }


@contextmanager
def _campaign_lock(
    campaign_dir: Path,
    *,
    deadline: incremental_recovery.WallClockDeadline | None = None,
) -> Iterable[None]:
    """以 Campaign 级文件锁串行化 attempt 预约与阶段发布。"""

    _validate_existing_campaign_path(campaign_dir)
    lock_path = campaign_dir / ".campaign.lock"
    _reject_symlink_components(lock_path, campaign_dir, "Campaign 锁")
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        descriptor = os.open(lock_path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        descriptor = os.open(lock_path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or (not created and stat.S_IMODE(metadata.st_mode) != 0o600)
        ):
            raise ConfigurationError("Campaign 锁必须是当前用户拥有的 0600 普通文件。")
        if created:
            os.fchmod(descriptor, 0o600)
        if deadline is None:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        else:
            # 非阻塞轮询让 Campaign 锁等待也受 attempt 全局预算约束；
            # 不能因另一个进程持锁而无限挂起。
            while True:
                deadline.check("campaign-lock")
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    deadline.sleep(
                        min(0.1, deadline.remaining_seconds),
                        operation="campaign-lock-wait",
                    )
                except InterruptedError:
                    continue
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _campaign_file(campaign_dir: Path, relative: str) -> Path:
    path = campaign_dir / relative
    resolved = path.resolve(strict=False)
    if not resolved.is_relative_to(campaign_dir.resolve()):
        raise ConfigurationError(f"Campaign 文件越过根目录：{relative}")
    return path


def _git_commit(root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = result.stdout.strip()
    return value if re.fullmatch(r"[a-f0-9]{40,64}", value) else None


def _source_identity(root: Path, version: str) -> tuple[dict[str, Any], dict[str, Any]]:
    inventory = scan_source_tree(root, version)
    cargo_lock = root / "Cargo.lock"
    identity = {
        "path": str(root.resolve()),
        "source_tree_sha256": _directory_tree_digest(root),
        "egress_inventory_sha256": _fingerprint(inventory),
        "cargo_lock_sha256": file_sha256(cargo_lock) if cargo_lock.is_file() else None,
        "git_commit": _git_commit(root),
    }
    return identity, inventory


def _verify_codex_package(
    package: Path,
    *,
    expected_version: str,
    expected_package_sha256: str,
    expected_binary_sha256: str,
    expected_code_mode_host_sha256: str,
    deadline: incremental_recovery.WallClockDeadline | None = None,
    heartbeat: Any | None = None,
) -> dict[str, Any]:
    """验证官方 package 内的 CLI 与 Code Mode helper 形成同一身份闭包。"""

    if _file_sha256_bounded(
        package,
        deadline=deadline,
        heartbeat=heartbeat,
        operation="official-package:asset-hash",
    ) != expected_package_sha256:
        raise ConfigurationError("官方 codex-package 压缩包摘要不一致。")
    required_members = {
        "codex-package.json",
        "bin/codex",
        "bin/codex-code-mode-host",
    }
    try:
        with tarfile.open(package, mode="r:gz") as archive:
            members_by_name: dict[str, list[tarfile.TarInfo]] = {}
            for member in archive.getmembers():
                members_by_name.setdefault(member.name.removeprefix("./"), []).append(
                    member
                )
            if any(
                len(members_by_name.get(name, [])) != 1
                for name in required_members
            ):
                raise ConfigurationError(
                    "官方 codex-package 缺少必要成员或存在重名成员。"
                )
            selected = {
                name: members_by_name[name][0] for name in required_members
            }
            if any(not member.isfile() for member in selected.values()):
                raise ConfigurationError(
                    "官方 codex-package 必要成员必须是普通文件。"
                )

            def member_bytes(name: str, *, limit: int | None = None) -> bytes:
                member = selected[name]
                if limit is not None and member.size > limit:
                    raise ConfigurationError(
                        f"官方 codex-package 成员过大：{name}"
                    )
                stream = archive.extractfile(member)
                if stream is None:
                    raise ConfigurationError(
                        f"无法读取官方 codex-package 成员：{name}"
                    )
                return stream.read()

            def member_sha256(name: str) -> str:
                stream = archive.extractfile(selected[name])
                if stream is None:
                    raise ConfigurationError(
                        f"无法读取官方 codex-package 成员：{name}"
                    )
                digest = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    if deadline is not None:
                        deadline.check(f"official-package:member-hash:{name}")
                    digest.update(chunk)
                    if heartbeat is not None:
                        heartbeat(f"official-package:member-hash:{name}")
                if deadline is not None:
                    deadline.check(f"official-package:member-hash:{name}")
                return digest.hexdigest()

            metadata = json.loads(
                member_bytes("codex-package.json", limit=1024 * 1024).decode(
                    "utf-8"
                )
            )
            binary_sha256 = member_sha256("bin/codex")
            helper_sha256 = member_sha256("bin/codex-code-mode-host")
    except ConfigurationError:
        raise
    except (
        OSError,
        tarfile.TarError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:
        raise ConfigurationError("无法验证官方 codex-package。") from error
    if not isinstance(metadata, dict):
        raise ConfigurationError("官方 codex-package 元数据必须是对象。")
    package_target = metadata.get("target")
    if (
        metadata.get("layoutVersion") != 1
        or metadata.get("version") != expected_version
        or metadata.get("variant") != "codex"
        or metadata.get("entrypoint") != "bin/codex"
        or not isinstance(package_target, str)
        or not re.fullmatch(r"[A-Za-z0-9._-]+", package_target)
    ):
        raise ConfigurationError("官方 codex-package 元数据与目标坐标不一致。")
    if binary_sha256 != expected_binary_sha256:
        raise ConfigurationError("官方 package 内 Codex CLI 摘要不一致。")
    if helper_sha256 != expected_code_mode_host_sha256:
        raise ConfigurationError(
            "官方 package 内 codex-code-mode-host 摘要不一致。"
        )
    return {
        "asset_sha256": expected_package_sha256,
        "layout_version": 1,
        "target": package_target,
        "variant": "codex",
        "entrypoint": "bin/codex",
        "binary_sha256": binary_sha256,
        "code_mode_host_sha256": helper_sha256,
    }


# 评估侧受管文件：只读既有证据做判定、汇总与编目，不决定任何证据的字节内容。
#
# 这份清单是**白名单**，且必须逐个论证——判定依据是「该文件的改动能否改变已封存证据
# 的字节」。未登记的文件一律按产出侧处理（见 _tool_identity_sides 的 fail-close），
# 新增文件因此默认落到严格侧，不会因为忘记登记而被静默放行。
#
# 之所以要这个划分：Campaign 建立后工具身份一旦漂移就整轮作废，而历史上多数作废源于
# 判据／门禁类修复（k43 的负样本契约、k46 的门禁语义、k56 的四处 seal 门禁修复）。
# 这些修复改的是「怎么判断」，不是「采到什么」，把它们与采集脚本同等对待，代价是
# 每修一次就重采一轮官方证据。
#
# 放宽的边界很窄：评估侧文件改动后，已封存证据逐字节不变，只是重新评估一遍即可；
# 因此承接（resume）成立。产出侧（采集驱动、探针、中继、脱敏、收据生成、环境快照）
# 任何改动都可能改变证据本身，仍然严格拒绝。
_WATCHDOG_ONLY_TOOL_FILES = frozenset(
    {
        "codex_upgrade_arm64_environment_receipt.py",
        "codex_upgrade_environment_probe.py",
        "codex_upgrade_timing_ledger.py",
    }
)
_EVALUATION_SIDE_FILES = frozenset(
    {
        # 从批准断言画像推导验收模型；只读画像与规则，不接触证据字节。
        "acceptance_contract.py",
        # seal 前把 accept 的证据前提失败关闭；只读已收口的 bundle。
        "assertion_gate.py",
        # 按显式规则把已存在的证据根扫描成 manifest；不写证据。
        "build_capture_manifest.py",
        # 按冻结声明把多 job 根编目成三份计划；不写证据。
        "build_evidence_catalog.py",
        # 编排逐规则断言并汇总为 accept 所需结果文档；不写证据。
        "build_rule_assertion_results.py",
        # 对候选抓包执行逐规则断言；只读抓包。
        "candidate_rule_assertion.py",
        # ARM64 完整 Job 预检、环境快照和增量恢复只读取工具树与运行事实，
        # 不产生官方请求字节；watchdog 接线修复应保持在评估侧。
        "codex_upgrade_arm64_environment_receipt.py",
        "codex_upgrade_environment_probe.py",
        "codex_upgrade_job_rehearsal_receipt.py",
        "incremental_recovery.py",
        # 计时台账只记录阶段事实，不改变请求或证据字节。
        "codex_upgrade_timing_ledger.py",
        # 采集后校验中继样本完整性；只读样本。
        "check_sample_integrity.py",
        # 增量计划、attempt 和 Campaign 的 Schema 只收紧事实校验。
        "codex_upgrade_campaign.schema.json",
        "codex_upgrade_capture_attempt.schema.json",
        "codex_upgrade_incremental_noop.schema.json",
        "codex_upgrade_job_rehearsal_receipt.schema.json",
        # capture manifest 的校验 schema；只约束校验严格度，不产生内容。
        "candidate_capture_manifest.schema.json",
        # 对已完成 attempt 做单次 hash／secret scan，并生成只读 manifest；不发送请求。
        "codex_upgrade_evidence_manifest.py",
        # seal 预览与阶段收据 schema 只约束评估结果，不参与采集 Job。
        "codex_upgrade_seal_preview.schema.json",
        "codex_upgrade_stage_result.schema.json",
    }
)


def _tool_identity_sides(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """把受管文件按证据影响面分成两组，并各自计算摘要。

    fail-close：只有显式登记在 _EVALUATION_SIDE_FILES 里的路径才进评估侧，
    其余（含任何新增文件）全部计入产出侧。
    """

    production = [
        e
        for e in entries
        if e["path"] not in _EVALUATION_SIDE_FILES
        and e["path"] not in _WATCHDOG_ONLY_TOOL_FILES
    ]
    evaluation = [
        e
        for e in entries
        if e["path"] in _EVALUATION_SIDE_FILES
        or e["path"] in _WATCHDOG_ONLY_TOOL_FILES
    ]
    return {
        "production_count": len(production),
        "production_sha256": _fingerprint({"entries": production}),
        "evaluation_count": len(evaluation),
        "evaluation_sha256": _fingerprint({"entries": evaluation}),
    }


def _tool_identity_side_digest(identity: Mapping[str, Any], side: str) -> str:
    """按当前边界重算产出／评估侧摘要，兼容旧 Campaign 的误分类。"""

    if side not in {"production", "evaluation"}:
        raise ConfigurationError("工具影响面必须是 production 或 evaluation。")
    entries = identity.get("entries")
    if not isinstance(entries, list):
        # 组件化身份本身没有平铺清单时，从各组件重新展开；这样旧身份和新身份
        # 都能在同一 canonical 视图下比较。
        components = identity.get("components")
        if not isinstance(components, Mapping):
            raise ConfigurationError("工具身份缺少文件清单。")
        entries = [
            entry
            for value in components.values()
            if isinstance(value, Mapping)
            for entry in value.get("entries", [])
            if isinstance(entry, Mapping)
        ]
    normalized = [dict(entry) for entry in entries if isinstance(entry, Mapping)]
    sides = _tool_identity_sides(normalized)
    return str(sides[f"{side}_sha256"])


# 组件边界是恢复选择的唯一输入。路径没有登记到更细的组件时落到 shared，
# 这样新增工具不会因为遗漏登记而被静默复用。这里不把 codex_upgrade.py
# 计入抓包 Job 的 producer 依赖：它负责编排和验收，修复编排缺陷时可以只
# 重跑失败 Job；真正改变字节的脚本、relay 和脱敏器仍会使对应 Job 失效。
_TOOL_COMPONENT_NAMES = frozenset(
    {
        "producer",
        "relay",
        "evaluator",
        "scenario",
        "runtime",
        "orchestrator",
        "shared",
    }
)
_PRODUCER_TOOL_FILES = frozenset(
    {
        "capture.py",
        "pcap_clienthello.py",
        "scrub_raw_bytes.py",
        "extract_capture_records.py",
        "h1_wire_probe.py",
        "relay_extract.py",
        "upstream_byte_relay.py",
    }
)
_RELAY_TOOL_FILES = frozenset(
    {
        "run_official_relay_scenario.sh",
        "run_candidate_core_capture.sh",
        "run_candidate_aux_capture.sh",
        "run_sub2api_direct_matrix.sh",
        "run_sub2api_openai_mitm_matrix.sh",
        "run_h1_wire_probe.sh",
        "run_images_wire_probe.sh",
        "run_official_codex_compact_capture.sh",
        "run_official_http_fallback_baseline.sh",
        "run_claude_relay_scenario.sh",
    }
)
_RUNTIME_TOOL_PREFIXES = ("runtime_", "runtime_scripts/")
_SCENARIO_TOOL_FILES = frozenset(
    {
        "codex_upgrade_scenarios_0_145_0.json",
        "codex_upgrade_scenarios_0_147_0.json",
        "codex_upgrade_scenarios_0_149_1.json",
        "codex_upgrade_scenarios_0_151_0.json",
    }
)


def _tool_component_for_path(path: str) -> str:
    """返回工具路径的最小影响组件。"""

    if (
        path in _EVALUATION_SIDE_FILES
        or path.endswith(".schema.json")
        or path in {"incremental_recovery.py", "codex_upgrade_gate_receipt.py"}
    ):
        return "evaluator"
    basename = path.rsplit("/", 1)[-1]
    if path in _SCENARIO_TOOL_FILES or path.startswith("versions/"):
        return "scenario"
    if basename in _RELAY_TOOL_FILES:
        return "relay"
    if basename in _PRODUCER_TOOL_FILES or basename.startswith("drive_"):
        return "producer"
    if path.startswith(_RUNTIME_TOOL_PREFIXES):
        return "runtime"
    if basename == "codex_upgrade.py":
        return "orchestrator"
    return "shared"


def _tool_component_identities(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """按文件路径生成组件级身份；旧 Campaign 可由 entries 现场补算。"""

    assignments = {
        str(entry["path"]): _tool_component_for_path(str(entry["path"]))
        for entry in entries
    }
    identities = incremental_recovery.build_component_identities(
        entries, assignments, default_component="shared"
    )
    # 组件名固定，空组件也写入摘要，避免删除最后一个文件时无法观察漂移。
    components = dict(identities["components"])
    for name in sorted(_TOOL_COMPONENT_NAMES):
        components.setdefault(
            name,
            {
                "entry_count": 0,
                "entries": [],
                "sha256": incremental_recovery.digest({"entries": []}),
            },
        )
    return {
        "schema_version": identities["schema_version"],
        "component_count": len(components),
        "components": components,
        "all_sha256": identities["all_sha256"],
    }


def _tool_tree_entries(tool_root: Path) -> list[dict[str, Any]]:
    """按受管口径列出一棵工具树的文件摘要。

    抽成独立函数供两处共用：`_tool_identity` 算受管树自身的身份，
    `_verify_execution_tree` 用同一口径比对采集实际执行的那份副本。
    """

    files = sorted(
        path
        for path in tool_root.rglob("*")
        if (
            path.is_file()
            and not path.is_symlink()
            and path.suffix in {".py", ".sh", ".json"}
            and "tests" not in path.relative_to(tool_root).parts
            # 目标版本五件套会在 plan 后由人工审核产生，并由分类阶段独立绑定；
            # 它们不是编排器可执行信任根，不能反向击穿既有 Campaign。
            and "versions" not in path.relative_to(tool_root).parts
            and "__pycache__" not in path.relative_to(tool_root).parts
        )
    )
    return [
        {
            "path": path.relative_to(tool_root).as_posix(),
            "sha256": file_sha256(path),
        }
        for path in files
        if path.is_file() and not path.is_symlink()
    ]


def _verify_execution_tree(capture_root: Path | None) -> None:
    """确认采集实际执行的工具副本与受管树逐字一致。

    `_tool_identity` 只扫描本文件所在的受管树，而采集脚本与 relay 由
    `$CAPTURE_MOUNT/tools/official_client_capture/` 执行——那是**另一份副本**。
    k71 因此出现「工具身份校验通过、跑的却是旧代码」：受管树里
    `upstream_byte_relay.py` 的 `legacy_compact_ordinal`（Cookie 按到达序号下发）
    与 job 定义里写死的 `gpt-5.6-luna`（Lite 轨）都已就位，执行副本却停在更早版本，
    `EP-015`／`EP-022`／`EP-014`／`BODY-006` 四条判据随之必败，且没有任何门禁报警。
    职责边界：本校验只回答「存在的那份执行副本有没有漂移」。执行位置不存在时直接放行
    ——那不是漂移，而是路径配置问题，真实采集会在脚本解析
    `$CAPTURE_MOUNT/tools/...` 时自己失败；把「必须存在」也塞进来，只会让所有用假
    capture_root 的单元测试无法运行。存在但有文件缺失或摘要不符时 fail-close 拒绝。
    """

    if capture_root is None:
        return
    managed_root = Path(__file__).resolve().parent
    execution_root = capture_root / "tools" / "official_client_capture"
    try:
        execution_root_is_dir = execution_root.is_dir()
        execution_root_is_symlink = execution_root.is_symlink()
    except OSError:
        # CI 等普通用户可能连 capture_root 的父目录都无权遍历；这与目录不存在
        # 一样表示当前没有可执行副本可供比较。真实采集仍会在解析脚本时失败。
        return
    if not execution_root_is_dir or execution_root_is_symlink:
        return
    if execution_root.resolve() == managed_root.resolve():
        return
    actual = {
        entry["path"]: entry["sha256"]
        for entry in _tool_tree_entries(execution_root)
    }
    drift = [
        entry["path"]
        for entry in _tool_tree_entries(managed_root)
        if actual.get(entry["path"]) != entry["sha256"]
    ]
    if drift:
        raise ConfigurationError(
            "采集执行位置与受管工具树不一致，实际会跑到未受校验的副本："
            + f"{execution_root}；共 {len(drift)} 个文件漂移，前几个："
            + ", ".join(drift[:5])
        )


def _tool_identity(*, include_git: bool = True) -> dict[str, Any]:
    tool_root = Path(__file__).resolve().parent
    entries = _tool_tree_entries(tool_root)
    components = _tool_component_identities(entries)
    return {
        "git_commit": (
            _git_commit(Path(__file__).resolve().parents[2])
            if include_git
            else None
        ),
        "entry_count": len(entries),
        "files_sha256": _fingerprint({"entries": entries}),
        "entries": entries,
        "components": components["components"],
        "component_identity_sha256": _fingerprint(components),
        **_tool_identity_sides(entries),
    }


def _tool_identity_drift(
    current: Mapping[str, Any],
    expected: Mapping[str, Any],
) -> dict[str, list[str]]:
    """逐文件比对两份工具身份，按证据影响面归类变化路径。"""

    def index(identity: Mapping[str, Any]) -> dict[str, str]:
        raw = identity.get("entries")
        if not isinstance(raw, list):
            return {}
        return {
            str(item.get("path")): str(item.get("sha256"))
            for item in raw
            if isinstance(item, dict)
        }

    now, before = index(current), index(expected)
    changed = sorted(
        path
        for path in set(now) | set(before)
        if now.get(path) != before.get(path)
    )
    return {
        "production": [
            p
            for p in changed
            if p not in _EVALUATION_SIDE_FILES
            and p not in _WATCHDOG_ONLY_TOOL_FILES
        ],
        "evaluation": [
            p
            for p in changed
            if p in _EVALUATION_SIDE_FILES or p in _WATCHDOG_ONLY_TOOL_FILES
        ],
    }


def _tool_component_bundle(identity: Mapping[str, Any]) -> dict[str, Any]:
    """把新旧工具身份都规范化为组件包。"""

    if not isinstance(identity, Mapping):
        raise ConfigurationError("工具身份必须是对象。")
    components = identity.get("components")
    if isinstance(components, Mapping):
        normalized: dict[str, Any] = {}
        for name, value in components.items():
            if not isinstance(name, str) or not isinstance(value, Mapping):
                raise ConfigurationError("工具组件身份字段非法。")
            entries = value.get("entries")
            if not isinstance(entries, list):
                raise ConfigurationError(f"工具组件 {name} 缺少文件清单。")
            entry_count = value.get("entry_count")
            if (
                not isinstance(entry_count, int)
                or isinstance(entry_count, bool)
                or entry_count != len(entries)
            ):
                raise ConfigurationError(f"工具组件 {name} 条目数量非法。")
            if any(not isinstance(item, Mapping) for item in entries):
                raise ConfigurationError(f"工具组件 {name} 文件条目非法。")
            normalized[name] = {
                "entry_count": entry_count,
                "entries": [dict(item) for item in entries],
                "sha256": str(value.get("sha256", "")),
            }
        if normalized:
            bundle = {
                "schema_version": incremental_recovery.SCHEMA_VERSION,
                "component_count": len(normalized),
                "components": normalized,
                "all_sha256": identity.get("files_sha256"),
            }
            try:
                incremental_recovery.component_drift(bundle, bundle)
            except incremental_recovery.IncrementalRecoveryError as error:
                raise ConfigurationError(f"工具组件身份非法：{error}") from error
            recorded_identity = identity.get("component_identity_sha256")
            if recorded_identity is not None and recorded_identity != _fingerprint(bundle):
                raise ConfigurationError("工具组件总摘要不一致。")
            return bundle
    entries = identity.get("entries")
    if not isinstance(entries, list):
        raise ConfigurationError("工具身份缺少组件和文件清单。")
    if any(not isinstance(item, Mapping) for item in entries):
        raise ConfigurationError("工具身份文件条目非法。")
    return _tool_component_identities([dict(item) for item in entries])


def _canonicalize_watchdog_component_bundle(
    bundle: Mapping[str, Any],
) -> dict[str, Any]:
    """把历史上误归入 shared 的 watchdog 文件迁移到 evaluator 再比较。

    0.149.1 及更早 Campaign 没有这个边界，直接比较原始组件摘要会把“组件
    归类修正”误判成 shared 产出侧变化，进而使全部 Job 失效。这里仅规范化
    比较视图，保留原始身份和漂移台账，不静默吞掉 watchdog 文件的真实改动。
    """

    components = bundle.get("components")
    if not isinstance(components, Mapping):
        raise ConfigurationError("工具组件身份缺少 components。")
    entries: list[dict[str, Any]] = []
    assignments: dict[str, str] = {}
    for component, value in components.items():
        if not isinstance(component, str) or not isinstance(value, Mapping):
            raise ConfigurationError("工具组件身份结构非法。")
        raw_entries = value.get("entries")
        if not isinstance(raw_entries, list):
            raise ConfigurationError(f"工具组件 {component} 文件清单非法。")
        for raw_entry in raw_entries:
            if not isinstance(raw_entry, Mapping):
                raise ConfigurationError("工具组件文件条目非法。")
            entry = {
                "path": str(raw_entry.get("path", "")),
                "sha256": str(raw_entry.get("sha256", "")),
            }
            path = entry["path"]
            if path in assignments:
                raise ConfigurationError(f"工具组件文件重复：{path}")
            assignments[path] = (
                "evaluator"
                if path in _WATCHDOG_ONLY_TOOL_FILES
                else component
            )
            entries.append(entry)
    try:
        canonical = incremental_recovery.build_component_identities(
            entries,
            assignments,
            default_component="shared",
        )
    except incremental_recovery.IncrementalRecoveryError as error:
        raise ConfigurationError(f"工具组件身份规范化失败：{error}") from error
    # 保持旧摘要中存在的空组件，避免“删除最后一个文件”被误报为组件新增；
    # 当前身份通常已经包含固定组件集合，历史身份则按其原有集合保留。
    for component in components:
        canonical.setdefault(
            "components", {}
        ).setdefault(
            component,
            {
                "entry_count": 0,
                "entries": [],
                "sha256": incremental_recovery.digest({"entries": []}),
            },
        )
    canonical["component_count"] = len(canonical["components"])
    return canonical


def _tool_component_drift(
    expected: Mapping[str, Any], current: Mapping[str, Any]
) -> dict[str, Any]:
    """计算组件摘要变化；兼容没有 components 字段的旧 Campaign。"""
    expected_bundle = _canonicalize_watchdog_component_bundle(
        _tool_component_bundle(expected)
    )
    current_bundle = _canonicalize_watchdog_component_bundle(
        _tool_component_bundle(current)
    )
    return incremental_recovery.component_drift(
        expected_bundle,
        current_bundle,
    )


def _affected_job_ids(
    jobs: Iterable[Job],
    changed_components: Iterable[str],
) -> list[str]:
    """按 Job 直接依赖选择最小失效闭集。

    编排器和纯评估器只影响失败项的判定，不会改变已经生成的抓包字节；
    其余高风险组件会使声明依赖该组件的 Job 失效。
    """

    changed = set(changed_components)
    high_risk = changed.intersection({"producer", "relay", "runtime", "shared", "scenario"})
    affected: list[str] = []
    for job in jobs:
        dependencies = set(_job_tool_components(job))
        if high_risk.intersection(dependencies):
            affected.append(job.job_id)
    return sorted(affected)


def _build_incremental_tool_transition(
    expected_tool: Mapping[str, Any],
    current_tool: Mapping[str, Any],
    impact: Mapping[str, Any],
    *,
    phase: str,
    planned_job_ids: Iterable[str],
) -> dict[str, Any]:
    """为低风险工具修复生成 attempt 绑定的组件过渡事实。"""

    changed = sorted(str(item) for item in impact.get("changed_components", []))
    if not changed or not set(changed).issubset({"orchestrator", "evaluator"}):
        raise ConfigurationError("只有编排／评估组件可以原地建立增量过渡。")
    core = {
        "schema_version": INCREMENTAL_TOOL_TRANSITION_SCHEMA,
        "phase": phase,
        "from_component_identity_sha256": _fingerprint(
            _tool_component_bundle(expected_tool)
        ),
        "to_component_identity_sha256": _fingerprint(
            _tool_component_bundle(current_tool)
        ),
        "changed_components": changed,
        "changed_paths": impact.get("changed_paths", {}),
        "planned_job_ids": sorted(str(item) for item in planned_job_ids),
        "affected_job_ids": sorted(
            str(item) for item in impact.get("affected_job_ids", [])
        ),
        "raw_evidence_scanned_bytes": 0,
    }
    return {**core, "transition_sha256": _fingerprint(core)}


def _validate_incremental_tool_transition(
    transition: Mapping[str, Any],
    expected_tool: Mapping[str, Any],
    current_tool: Mapping[str, Any],
) -> dict[str, Any]:
    """校验 attempt 中的低风险组件过渡，避免工具漂移被静默放行。"""

    if not isinstance(transition, Mapping):
        raise ConfigurationError("增量工具过渡结构非法。")
    required = {
        "schema_version",
        "phase",
        "from_component_identity_sha256",
        "to_component_identity_sha256",
        "changed_components",
        "changed_paths",
        "planned_job_ids",
        "affected_job_ids",
        "raw_evidence_scanned_bytes",
        "transition_sha256",
    }
    if set(transition) != required:
        raise ConfigurationError("增量工具过渡字段不闭合。")
    unsigned = dict(transition)
    recorded = unsigned.pop("transition_sha256")
    if recorded != _fingerprint(unsigned):
        raise ConfigurationError("增量工具过渡自摘要不一致。")
    changed = transition.get("changed_components")
    if (
        transition.get("schema_version") != INCREMENTAL_TOOL_TRANSITION_SCHEMA
        or not isinstance(changed, list)
        or not all(isinstance(item, str) and item for item in changed)
        or changed != sorted(set(changed))
        or not set(changed).issubset({"orchestrator", "evaluator"})
        or transition.get("raw_evidence_scanned_bytes") != 0
        or transition.get("from_component_identity_sha256")
        != _fingerprint(_tool_component_bundle(expected_tool))
        or transition.get("to_component_identity_sha256")
        != _fingerprint(_tool_component_bundle(current_tool))
    ):
        raise ConfigurationError("增量工具过渡身份或风险范围非法。")
    return dict(transition)


def _job_context(arguments: argparse.Namespace) -> dict[str, str]:
    return {
        "baseline_version": arguments.baseline_version,
        "target_version": arguments.target_version,
        "campaign_id": arguments.campaign_id,
        "candidate_id": str(getattr(arguments, "candidate_id", "") or ""),
        "capture_root": str(arguments.capture_root),
        "output": str(arguments.output),
        "campaign_dir": str(arguments.output),
        "repo_root": str(Path(__file__).resolve().parents[2]),
        "model": arguments.model,
        "lite_model": str(getattr(arguments, "lite_model", "") or ""),
        "runtime_image": str(arguments.runtime_image),
        "target_sha256": arguments.target_sha256,
        "profile_id": str(getattr(arguments, "profile_id", "") or ""),
        "profile_digest": str(getattr(arguments, "profile_digest", "") or ""),
        "build_id": str(getattr(arguments, "build_id", "") or ""),
        "deployed_version": str(
            getattr(arguments, "deployed_version", "") or ""
        ),
        "candidate_image_id": str(
            getattr(arguments, "candidate_image_id", "") or ""
        ),
        "source_tree_sha256": str(
            getattr(arguments, "source_tree_sha256", "") or ""
        ),
        "capture_container": arguments.capture_container,
        "service_container": arguments.service_container,
        "keeper_container": arguments.keeper_container,
        "postgres_container": arguments.postgres_container,
        "redis_container": arguments.redis_container,
        "capture_codex_bin": arguments.capture_codex_bin,
        "relay_codex_bin": arguments.relay_codex_bin,
        "codex_account_id": str(arguments.codex_account_id),
        "api_key_id": str(arguments.api_key_id),
        # A11 的 Live attestation 只读进程环境，采集侧需按本轮四元组重建候选服务；
        # 缺省为空表示不注入，届时 A11 会以断言失败暴露而不是静默跳过。
        "live_attestation_compose_dir": str(
            getattr(arguments, "live_attestation_compose_dir", "") or ""
        ),
        "live_attestation_compose_files": str(
            getattr(arguments, "live_attestation_compose_files", "") or ""
        ),
    }


def _validate_jobs(jobs: list[Job], rules: tuple[str, ...]) -> None:
    duplicate_jobs = sorted(
        {
            job.job_id
            for job in jobs
            if sum(item.job_id == job.job_id for item in jobs) > 1
        }
    )
    if duplicate_jobs:
        raise ConfigurationError(f"任务 ID 重复：{duplicate_jobs}")
    evidence_owners: dict[tuple[str, str], list[str]] = {}
    for job in jobs:
        for root in job.evidence_roots:
            evidence_owners.setdefault((job.phase, root), []).append(job.job_id)
    duplicate_roots = {
        f"{phase}:{root}": sorted(set(job_ids))
        for (phase, root), job_ids in evidence_owners.items()
        if len(set(job_ids)) > 1
    }
    if duplicate_roots:
        raise ConfigurationError(
            "同一阶段的证据根必须由单一任务独占："
            f"{duplicate_roots}"
        )
    unknown_rules = sorted({rule for job in jobs for rule in job.covers} - set(rules))
    if unknown_rules:
        raise ConfigurationError(f"任务引用规则清单外编号：{unknown_rules}")
    unbound_jobs = sorted(
        job.job_id for job in jobs if job.covers and not job.scenario_ids
    )
    if unbound_jobs:
        raise ConfigurationError(
            "只有版本化场景清单中的任务可以声明规则覆盖；"
            f"未绑定场景的任务={unbound_jobs}"
        )
    _validate_capture_runtime_ids(jobs)


def _validate_capture_runtime_ids(jobs: Iterable[Job]) -> None:
    """在创建 attempt 前复算 direct／mitm 最终运行 ID 的长度边界。

    场景清单中的 ``RUN_ID_PREFIX`` 不是最终值；mitm 矩阵还会追加主体和
    16 字符 UTC 窗口。只检查 Campaign 或 candidate ID 会把超长坐标拖到
    真实任务启动后才暴露，既浪费时间又留下必败 attempt，因此这里按脚本
    的确定性拼接规则提前失败关闭。
    """

    invalid: list[str] = []
    for job in jobs:
        for step_index, step in enumerate(job.steps, start=1):
            environment = step.get("environment", {})
            if not isinstance(environment, dict):
                raise ConfigurationError(
                    f"{job.job_id} 第 {step_index} 步的环境变量结构非法。"
                )

            projected: list[tuple[str, str]] = []
            run_id = environment.get("RUN_ID")
            if run_id:
                projected.append(("RUN_ID", str(run_id)))

            run_id_prefix = environment.get("RUN_ID_PREFIX")
            if run_id_prefix:
                subjects = str(environment.get("SUBJECTS", "")).split()
                if not subjects:
                    raise ConfigurationError(
                        f"{job.job_id} 使用 RUN_ID_PREFIX 时必须冻结 SUBJECTS。"
                    )
                window_id = str(
                    environment.get("WINDOW_ID", "")
                    or RUNTIME_WINDOW_ID_PLACEHOLDER
                )
                prefix = str(run_id_prefix)
                projected.append(
                    ("RUN_ID_PREFIX/setup", f"{prefix}-setup-{window_id}")
                )
                projected.extend(
                    (
                        f"RUN_ID_PREFIX/{subject}",
                        f"{prefix}-{subject}-{window_id}",
                    )
                    for subject in subjects
                )

            for coordinate, value in projected:
                if not SAFE_ID_RE.fullmatch(value):
                    invalid.append(
                        f"{job.job_id}:step-{step_index}:{coordinate}="
                        f"{len(value)}字符"
                    )

    if invalid:
        raise ConfigurationError(
            "抓包运行坐标超过 direct／mitm 的 128 字符安全边界；必须缩短 "
            "Campaign／candidate ID 后重新生成坐标，禁止先创建必败 attempt："
            + "、".join(invalid)
        )


def _validate_phase_coverage(jobs: list[Job], rules: tuple[str, ...]) -> None:
    required = set(rules)
    missing = {
        phase: sorted(
            required
            - {
                rule
                for job in jobs
                if job.phase == phase and job.required
                for rule in job.covers
            }
        )
        for phase in ("official", "candidate")
    }
    incomplete = {phase: values for phase, values in missing.items() if values}
    if incomplete:
        raise ConfigurationError(f"full 场景清单存在未映射规则：{incomplete}")


def _load_plan_jobs(
    arguments: argparse.Namespace,
    rules: tuple[str, ...],
) -> tuple[list[Job], Path, Path]:
    """同时冻结 baseline 分析场景与 target 正式执行场景。

    baseline 清单只描述升级前已经成立的发现与规则坐标；真正运行目标 CLI 的 official
    Attempt 必须使用 target 清单。两份清单分别校验且都不可缺省，避免目标版本需要的
    entrypoint、分支触发或恢复契约被旧命令模板静默吞掉。
    """

    scenario_manifest = arguments.scenario_manifest
    target_scenario_manifest = arguments.target_scenario_manifest
    for label, path in (
        ("baseline 场景清单", scenario_manifest),
        ("target 场景清单", target_scenario_manifest),
    ):
        if not path.is_file() or path.is_symlink():
            raise ConfigurationError(f"{label}不存在或不可信：{path}")
    context = _job_context(arguments)
    baseline_assertion_profile = Path(__file__).with_name(
        "candidate_rule_expectations_"
        f"{arguments.baseline_version.replace('.', '_')}.json"
    )
    baseline_source_spec_binding = (
        _load_frozen_assertion_source_spec_binding(
            baseline_assertion_profile,
            arguments.baseline_version,
        )
    )
    baseline_jobs = load_scenario_jobs(
        scenario_manifest,
        context,
        expected_version=arguments.baseline_version,
        expected_rule_sha256=file_sha256(arguments.rule_manifest),
        require_bindings=True,
        historical_source_spec_binding=baseline_source_spec_binding,
    )
    target_payload = _read_json(target_scenario_manifest, "target 场景清单")
    target_rule_binding = target_payload.get("rule_manifest")
    if (
        not isinstance(target_rule_binding, dict)
        or target_rule_binding.get("rule_count") != len(rules)
    ):
        raise ConfigurationError(
            "target 场景清单的规则数量与当前升级规则全集不一致。"
        )
    target_jobs = load_scenario_jobs(
        target_scenario_manifest,
        context,
        expected_version=arguments.target_version,
        require_bindings=True,
    )
    extra_jobs = load_extra_jobs(arguments.extra_jobs, context)
    baseline_jobs = [
        job for job in [*baseline_jobs, *extra_jobs] if arguments.suite in job.suites
    ]
    target_jobs = [
        job for job in [*target_jobs, *extra_jobs] if arguments.suite in job.suites
    ]
    _validate_jobs(baseline_jobs, rules)
    _validate_jobs(target_jobs, rules)
    if arguments.suite == "full":
        _validate_phase_coverage(baseline_jobs, rules)
        _validate_phase_coverage(target_jobs, rules)
    return target_jobs, scenario_manifest, target_scenario_manifest


def _control_receipt_relative(root: Path, value: Path, label: str) -> str:
    """把控制收据规范化为其受管根内的 POSIX 相对路径。"""

    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise ConfigurationError(f"{label} 的 evidence root 必须是现有非符号链接绝对目录。")
    resolved_root = root.resolve(strict=True)
    candidate = value if value.is_absolute() else resolved_root / value
    try:
        resolved = candidate.resolve(strict=True)
        relative = resolved.relative_to(resolved_root).as_posix()
    except (OSError, RuntimeError, ValueError) as error:
        raise ConfigurationError(f"{label} 必须位于其受管根内。") from error
    if candidate.is_symlink() or not resolved.is_file():
        raise ConfigurationError(f"{label} 必须是非符号链接普通文件。")
    return relative


def _job_rehearsal_configuration(
    source: Mapping[str, Any] | argparse.Namespace,
) -> dict[str, Any]:
    """提取会改变 Job 实际执行的固定配置。"""

    def value(field: str) -> Any:
        if isinstance(source, Mapping):
            current = source.get(field)
        else:
            current = getattr(source, field, None)
        return str(current) if isinstance(current, Path) else current

    return {
        field: value(field)
        for field in codex_upgrade_job_rehearsal_receipt.EXECUTION_CONFIGURATION_FIELDS
    }


def _job_rehearsal_contract_from_arguments(
    arguments: argparse.Namespace,
) -> dict[str, Any]:
    """按 Formal plan 输入复算应与 preflight 完全一致的执行合同。"""

    target_scenario = _read_json(
        arguments.target_scenario_manifest, "target 正式采集场景清单"
    )
    extra_jobs = (
        _read_json(arguments.extra_jobs, "附加任务清单")
        if arguments.extra_jobs is not None
        else None
    )
    try:
        return codex_upgrade_job_rehearsal_receipt.build_execution_contract(
            target_version=arguments.target_version,
            target_sha256=arguments.target_sha256,
            target_package_sha256=arguments.target_package_sha256,
            target_code_mode_host_sha256=arguments.target_code_mode_host_sha256,
            suite=arguments.suite,
            tool_files_sha256=_tool_identity()["files_sha256"],
            configuration=_job_rehearsal_configuration(arguments),
            target_scenario=target_scenario,
            extra_jobs=extra_jobs,
        )
    except codex_upgrade_job_rehearsal_receipt.JobRehearsalReceiptError as error:
        raise ConfigurationError(f"Formal Job 执行合同非法：{error}") from error


def _job_rehearsal_contract_from_manifest(
    campaign_dir: Path,
    manifest: Mapping[str, Any],
    *,
    target_scenario_override: Mapping[str, Any] | None = None,
    tool_files_sha256_override: str | None = None,
) -> dict[str, Any]:
    """从已封存 Formal Campaign 复算完整 Job 演练合同。"""

    inputs = manifest.get("inputs")
    if not isinstance(inputs, Mapping):
        raise ConfigurationError("Campaign 缺少输入绑定。")
    scenario_reference = inputs.get("target_discovery_scenarios")
    if not isinstance(scenario_reference, Mapping):
        raise ConfigurationError("Campaign 缺少 target 场景清单绑定。")
    frozen_target_scenario = _read_json(
        _campaign_file(campaign_dir, str(scenario_reference.get("path", ""))),
        "Campaign target 场景清单",
    )
    extra_reference = inputs.get("extra_jobs")
    extra_jobs = (
        _read_json(
            _campaign_file(campaign_dir, str(extra_reference.get("path", ""))),
            "Campaign 附加任务清单",
        )
        if isinstance(extra_reference, Mapping)
        else None
    )
    package = manifest.get("official_identity", {}).get("package")
    configuration = manifest.get("configuration")
    tool_identity = manifest.get("tool_identity")
    if (
        not isinstance(package, Mapping)
        or not isinstance(configuration, Mapping)
        or not isinstance(tool_identity, Mapping)
    ):
        raise ConfigurationError("Campaign 缺少 Job 演练所需身份。")
    def build(target_scenario: Mapping[str, Any]) -> dict[str, Any]:
        return codex_upgrade_job_rehearsal_receipt.build_execution_contract(
            target_version=str(manifest.get("target_version", "")),
            target_sha256=str(manifest.get("target_sha256", "")),
            target_package_sha256=str(package.get("asset_sha256", "")),
            target_code_mode_host_sha256=str(
                package.get("code_mode_host_sha256", "")
            ),
            suite=str(manifest.get("suite", "")),
            tool_files_sha256=(
                tool_files_sha256_override
                if tool_files_sha256_override is not None
                else str(tool_identity.get("files_sha256", ""))
            ),
            configuration=_job_rehearsal_configuration(configuration),
            target_scenario=target_scenario,
            extra_jobs=extra_jobs,
        )

    try:
        if target_scenario_override is not None:
            return build(target_scenario_override)
        frozen_contract = build(frozen_target_scenario)
        controls = manifest.get("control_receipts")
        rehearsal = (
            controls.get("job_rehearsal")
            if isinstance(controls, Mapping)
            else None
        )
        bound_contract_sha256 = (
            rehearsal.get("execution_contract_sha256")
            if isinstance(rehearsal, Mapping)
            else None
        )
        if (
            bound_contract_sha256
            == codex_upgrade_job_rehearsal_receipt.execution_contract_sha256(
                frozen_contract
            )
            or not isinstance(manifest.get("predecessor"), Mapping)
        ):
            return frozen_contract

        # 同版本后继可保留历史 Formal 场景字节，同时由已批准的当前场景
        # 证明执行合同等价。新演练绑定若指向当前批准场景，就按该场景复算。
        classification_path = campaign_dir / "classification" / "result.json"
        if classification_path.is_file() and not classification_path.is_symlink():
            classification = _read_json(
                classification_path,
                "后继 Campaign 分类结果",
            )
            approved_reference = classification.get("scenario_manifest")
            if isinstance(approved_reference, dict):
                historical_binding = (
                    _successor_uses_reclassified_historical_plan_binding(
                        campaign_dir,
                        dict(manifest),
                        {"scenario_manifest": approved_reference},
                    )
                )
                if historical_binding is not None:
                    approved_scenario = _read_json(
                        _campaign_file(
                            campaign_dir,
                            str(approved_reference.get("path", "")),
                        ),
                        "后继 Campaign 当前批准场景",
                    )
                    approved_contract = build(approved_scenario)
                    if bound_contract_sha256 == (
                        codex_upgrade_job_rehearsal_receipt.execution_contract_sha256(
                            approved_contract
                        )
                    ):
                        return approved_contract
        return frozen_contract
    except codex_upgrade_job_rehearsal_receipt.JobRehearsalReceiptError as error:
        raise ConfigurationError(f"Campaign Job 执行合同非法：{error}") from error


def _job_rehearsal_control_from_receipt(
    rehearsal_root: Path,
    rehearsal_path: Path,
    expected_contract: Mapping[str, Any],
) -> dict[str, Any]:
    """重放完整 Job 演练并生成可写入 Campaign 的不可变绑定。"""

    rehearsal_relative = _control_receipt_relative(
        rehearsal_root,
        rehearsal_path,
        "ARM64 完整 Job 离线演练收据",
    )
    try:
        rehearsal = codex_upgrade_job_rehearsal_receipt.replay(
            rehearsal_root, rehearsal_relative
        )
        codex_upgrade_job_rehearsal_receipt.assert_formal_compatible(
            rehearsal, dict(expected_contract)
        )
    except (
        OSError,
        codex_upgrade_job_rehearsal_receipt.JobRehearsalReceiptError,
    ) as error:
        raise ConfigurationError(
            f"ARM64 完整 Job 离线演练收据未通过：{error}"
        ) from error
    resolved_rehearsal = rehearsal_root.resolve(strict=True)
    rehearsal_file = resolved_rehearsal / rehearsal_relative
    preflight = rehearsal["preflight_campaign"]
    return {
        "evidence_root": str(resolved_rehearsal),
        "receipt": {
            "path": rehearsal_relative,
            "sha256": file_sha256(rehearsal_file),
            "bytes": rehearsal_file.stat().st_size,
        },
        "preflight_campaign_id": preflight["campaign_id"],
        "preflight_campaign_manifest_sha256": preflight["manifest_sha256"],
        "execution_contract_sha256": rehearsal["execution_contract_sha256"],
        "runtime_identity_sha256": rehearsal["runtime_identity_sha256"],
        "job_count": rehearsal["job_count"],
        "job_set_sha256": rehearsal["job_set_sha256"],
    }


def _plan_control_receipts(arguments: argparse.Namespace) -> dict[str, Any]:
    """在创建 Campaign 前重放并绑定时间、ARM64 与完整 Job 硬门禁。"""

    timing_root = getattr(arguments, "timing_ledger_dir", None)
    timing_receipt_path = getattr(arguments, "timing_receipt", None)
    arm_root = getattr(arguments, "arm64_environment_root", None)
    arm_receipt_path = getattr(arguments, "arm64_environment_receipt", None)
    if not all(
        isinstance(value, Path)
        for value in (timing_root, timing_receipt_path, arm_root, arm_receipt_path)
    ):
        raise ConfigurationError(
            "plan 必须显式提供 UpgradeTimingLedger 与 ARM64 P0 环境收据。"
        )
    assert isinstance(timing_root, Path)
    assert isinstance(timing_receipt_path, Path)
    assert isinstance(arm_root, Path)
    assert isinstance(arm_receipt_path, Path)
    timing_relative = _control_receipt_relative(
        timing_root, timing_receipt_path, "UpgradeTimingLedger checkpoint"
    )
    arm_relative = _control_receipt_relative(
        arm_root, arm_receipt_path, "ARM64 P0 环境收据"
    )
    try:
        timing_checkpoint = codex_upgrade_timing_ledger.replay(
            timing_root, timing_relative
        )
        timing_summary = codex_upgrade_timing_ledger.assert_usable(
            timing_root,
            timing_relative,
            baseline_version=arguments.baseline_version,
            target_version=arguments.target_version,
            campaign_purpose=arguments.campaign_purpose,
            # Formal 只能在 VC-0 新建。preflight_only 不会发送请求或推进
            # Campaign 阶段，允许在后续 active 阶段为工具修复重跑离线 P0。
            required_phase=(
                "VC-0" if arguments.campaign_mode == "formal" else None
            ),
        )
    except (OSError, codex_upgrade_timing_ledger.TimingLedgerError) as error:
        raise ConfigurationError(f"UpgradeTimingLedger 未通过：{error}") from error
    try:
        arm_receipt = codex_upgrade_arm64_environment_receipt.replay(
            arm_root, arm_relative
        )
    except (
        OSError,
        codex_upgrade_arm64_environment_receipt.Arm64EnvironmentReceiptError,
    ) as error:
        raise ConfigurationError(f"ARM64 P0 环境收据未通过：{error}") from error
    if (
        arm_receipt.get("status") != "passed"
        or arm_receipt.get("phase") != "p0"
        or arm_receipt.get("subject_id") != timing_summary["upgrade_id"]
    ):
        raise ConfigurationError("ARM64 P0 环境收据与 UpgradeTimingLedger 身份不一致。")
    resolved_timing = timing_root.resolve(strict=True)
    resolved_arm = arm_root.resolve(strict=True)
    timing_file = resolved_timing / timing_relative
    arm_file = resolved_arm / arm_relative
    controls: dict[str, Any] = {
        "upgrade_timing": {
            "ledger_dir": str(resolved_timing),
            "ledger_plan_sha256": file_sha256(resolved_timing / "ledger.json"),
            "receipt": {
                "path": timing_relative,
                "sha256": file_sha256(timing_file),
                "bytes": timing_file.stat().st_size,
            },
            "upgrade_id": timing_summary["upgrade_id"],
            "evidence_decision": timing_summary["evidence_decision"],
            "checkpoint_head_sha256": timing_checkpoint["summary"]["head_sha256"],
        },
        "arm64_environment": {
            "evidence_root": str(resolved_arm),
            "receipt": {
                "path": arm_relative,
                "sha256": file_sha256(arm_file),
                "bytes": arm_file.stat().st_size,
            },
            "subject_id": arm_receipt["subject_id"],
            "contract_sha256": arm_receipt["contract_sha256"],
            "continuity_identity_sha256": arm_receipt[
                "continuity_identity_sha256"
            ],
        },
    }
    if arguments.campaign_mode == "formal":
        rehearsal_root = getattr(arguments, "job_rehearsal_root", None)
        rehearsal_path = getattr(arguments, "job_rehearsal_receipt", None)
        assert isinstance(rehearsal_root, Path)
        assert isinstance(rehearsal_path, Path)
        controls["job_rehearsal"] = _job_rehearsal_control_from_receipt(
            rehearsal_root,
            rehearsal_path,
            _job_rehearsal_contract_from_arguments(arguments),
        )
    return controls


def _verify_control_receipts(
    campaign_dir: Path,
    manifest: Mapping[str, Any],
    *,
    require_active: bool,
) -> None:
    """重放 Campaign 冻结控制收据；执行前额外检查实时墙钟。"""

    controls = manifest.get("control_receipts")
    expected_controls = {
        "upgrade_timing",
        "arm64_environment",
    }
    if manifest.get("campaign_mode") == "formal":
        expected_controls.add("job_rehearsal")
    if not isinstance(controls, dict) or set(controls) != expected_controls:
        raise ConfigurationError("Campaign 缺少完整控制收据绑定。")
    timing = controls.get("upgrade_timing")
    arm = controls.get("arm64_environment")
    if not isinstance(timing, dict) or not isinstance(arm, dict):
        raise ConfigurationError("Campaign 控制收据结构非法。")

    def validate_binding(value: Any, label: str) -> tuple[str, str, int]:
        if not isinstance(value, dict) or set(value) != {"path", "sha256", "bytes"}:
            raise ConfigurationError(f"{label}绑定字段不闭合。")
        relative = value.get("path")
        digest = value.get("sha256")
        size = value.get("bytes")
        if (
            not isinstance(relative, str)
            or not SHA256_RE.fullmatch(str(digest))
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
        ):
            raise ConfigurationError(f"{label}绑定非法。")
        return relative, str(digest), size

    try:
        timing_root = Path(str(timing["ledger_dir"]))
        timing_relative, timing_sha, timing_bytes = validate_binding(
            timing.get("receipt"), "UpgradeTimingLedger checkpoint"
        )
        timing_path = timing_root / timing_relative
        if (
            file_sha256(timing_root / "ledger.json")
            != timing.get("ledger_plan_sha256")
            or file_sha256(timing_path) != timing_sha
            or timing_path.stat().st_size != timing_bytes
        ):
            raise ConfigurationError("UpgradeTimingLedger 绑定摘要漂移。")
        timing_checkpoint = codex_upgrade_timing_ledger.replay(
            timing_root, timing_relative
        )
        if (
            timing_checkpoint["summary"].get("upgrade_id")
            != timing.get("upgrade_id")
            or timing_checkpoint["summary"].get("evidence_decision")
            != timing.get("evidence_decision")
            or timing_checkpoint["summary"].get("head_sha256")
            != timing.get("checkpoint_head_sha256")
        ):
            raise ConfigurationError("UpgradeTimingLedger checkpoint 身份漂移。")
        if require_active:
            codex_upgrade_timing_ledger.assert_usable(
                timing_root,
                timing_relative,
                baseline_version=str(manifest["baseline_version"]),
                target_version=str(manifest["target_version"]),
                campaign_purpose=str(manifest["campaign_purpose"]),
            )
    except (
        KeyError,
        OSError,
        ValueError,
        codex_upgrade_timing_ledger.TimingLedgerError,
    ) as error:
        if isinstance(error, ConfigurationError):
            raise
        raise ConfigurationError(f"UpgradeTimingLedger 无法重放：{error}") from error

    try:
        arm_root = Path(str(arm["evidence_root"]))
        arm_relative, arm_sha, arm_bytes = validate_binding(
            arm.get("receipt"), "ARM64 P0 环境收据"
        )
        arm_path = arm_root / arm_relative
        if file_sha256(arm_path) != arm_sha or arm_path.stat().st_size != arm_bytes:
            raise ConfigurationError("ARM64 P0 环境收据绑定摘要漂移。")
        arm_receipt = codex_upgrade_arm64_environment_receipt.replay(
            arm_root, arm_relative
        )
        if (
            arm_receipt.get("status") != "passed"
            or arm_receipt.get("phase") != "p0"
            or arm_receipt.get("subject_id") != arm.get("subject_id")
            or arm_receipt.get("contract_sha256") != arm.get("contract_sha256")
            or arm_receipt.get("continuity_identity_sha256")
            != arm.get("continuity_identity_sha256")
            or arm.get("subject_id") != timing.get("upgrade_id")
        ):
            raise ConfigurationError("ARM64 P0 环境收据身份漂移。")
    except (
        KeyError,
        OSError,
        ValueError,
        codex_upgrade_arm64_environment_receipt.Arm64EnvironmentReceiptError,
    ) as error:
        if isinstance(error, ConfigurationError):
            raise
        raise ConfigurationError(f"ARM64 P0 环境收据无法重放：{error}") from error

    if manifest.get("campaign_mode") == "formal":
        rehearsal = controls.get("job_rehearsal")
        if not isinstance(rehearsal, dict) or set(rehearsal) != {
            "evidence_root",
            "receipt",
            "preflight_campaign_id",
            "preflight_campaign_manifest_sha256",
            "execution_contract_sha256",
            "runtime_identity_sha256",
            "job_count",
            "job_set_sha256",
        }:
            raise ConfigurationError("Campaign 完整 Job 演练绑定字段不闭合。")
        try:
            rehearsal_root = Path(str(rehearsal["evidence_root"]))
            rehearsal_relative, rehearsal_sha, rehearsal_bytes = validate_binding(
                rehearsal.get("receipt"), "ARM64 完整 Job 离线演练收据"
            )
            rehearsal_path = rehearsal_root / rehearsal_relative
            if (
                file_sha256(rehearsal_path) != rehearsal_sha
                or rehearsal_path.stat().st_size != rehearsal_bytes
            ):
                raise ConfigurationError("完整 Job 演练收据绑定摘要漂移。")
            receipt = codex_upgrade_job_rehearsal_receipt.replay(
                rehearsal_root, rehearsal_relative
            )
            expected_contract = _job_rehearsal_contract_from_manifest(
                campaign_dir, manifest
            )
            codex_upgrade_job_rehearsal_receipt.assert_formal_compatible(
                receipt, expected_contract
            )
            preflight = receipt["preflight_campaign"]
            if (
                preflight.get("campaign_id")
                != rehearsal.get("preflight_campaign_id")
                or preflight.get("manifest_sha256")
                != rehearsal.get("preflight_campaign_manifest_sha256")
                or receipt.get("execution_contract_sha256")
                != rehearsal.get("execution_contract_sha256")
                or receipt.get("runtime_identity_sha256")
                != rehearsal.get("runtime_identity_sha256")
                or receipt.get("job_count") != rehearsal.get("job_count")
                or receipt.get("job_set_sha256")
                != rehearsal.get("job_set_sha256")
            ):
                raise ConfigurationError("Campaign 完整 Job 演练身份漂移。")
        except (
            KeyError,
            OSError,
            ValueError,
            codex_upgrade_job_rehearsal_receipt.JobRehearsalReceiptError,
        ) as error:
            if isinstance(error, ConfigurationError):
                raise
            raise ConfigurationError(
                f"ARM64 完整 Job 离线演练收据无法重放：{error}"
            ) from error


def create_campaign(arguments: argparse.Namespace) -> dict[str, Any]:
    """创建只写一次的 Campaign 核心清单和计划期分析产物。"""

    _validate_arguments(arguments)
    control_receipts = _plan_control_receipts(arguments)
    rules = load_rule_manifest(arguments.rule_manifest, arguments.baseline_version)
    jobs, scenario_manifest, target_scenario_manifest = _load_plan_jobs(
        arguments, rules
    )
    baseline_identity, baseline_source = _source_identity(
        arguments.baseline_source, arguments.baseline_version
    )
    target_identity, target_source = _source_identity(
        arguments.target_source, arguments.target_version
    )
    source_diff = compare_inventory(baseline_source, target_source)
    baseline_surface = scan_evidence(
        [arguments.baseline_evidence], "baseline-official"
    )

    campaign_dir = arguments.campaign_dir
    ensure_private_directory(campaign_dir)
    inputs_root = ensure_private_directory(campaign_dir / "inputs", campaign_dir)
    analysis_root = ensure_private_directory(campaign_dir / "analysis", campaign_dir)
    baseline_rules_payload = _read_json(arguments.rule_manifest, "基线规则清单")
    scenario_payload = _read_json(scenario_manifest, "baseline 发现场景清单")
    target_scenario_payload = _read_json(
        target_scenario_manifest, "target 正式采集场景清单"
    )
    secure_write_json(inputs_root / "baseline-rules.json", baseline_rules_payload)
    secure_write_json(inputs_root / "discovery-scenarios.json", scenario_payload)
    secure_write_json(
        inputs_root / "target-discovery-scenarios.json", target_scenario_payload
    )
    extra_jobs_reference: dict[str, Any] | None = None
    if arguments.extra_jobs is not None:
        extra_payload = _read_json(arguments.extra_jobs, "附加任务清单")
        secure_write_json(inputs_root / "extra-jobs.json", extra_payload)
        extra_jobs_reference = {
            "path": "inputs/extra-jobs.json",
            "sha256": file_sha256(inputs_root / "extra-jobs.json"),
        }
    for name, payload in (
        ("baseline-source.json", baseline_source),
        ("target-source.json", target_source),
        ("source-diff.json", source_diff),
        ("baseline-surface.json", baseline_surface),
    ):
        secure_write_json(analysis_root / name, payload)

    official_identity = {
        "cli_version": arguments.target_version,
        "binary_sha256": arguments.target_sha256,
        "package": arguments.target_package_identity,
        "source_tree_sha256": target_identity["source_tree_sha256"],
        "cargo_lock_sha256": target_identity["cargo_lock_sha256"],
        "git_commit": target_identity["git_commit"],
        "runtime_image": arguments.runtime_image,
        "operating_system": sys.platform,
        "architecture": os.uname().machine,
        "tls_dependencies_sha256": _fingerprint(
            {
                "entries": [
                    item
                    for item in target_source.get("entries", [])
                    if item.get("kind") == "network_dependency"
                ]
            }
        ),
    }
    # 冻结工具身份之前先确认执行副本与受管树一致：这里记进 manifest 的是受管树的
    # 摘要，若执行位置此刻已经漂移，整轮采集都会跑在未受校验的代码上（k71 即此）。
    _verify_execution_tree(getattr(arguments, "capture_root", None))
    plan = _safe_plan(arguments, jobs, rules)
    manifest = {
        "schema_version": CAMPAIGN_SCHEMA,
        "campaign_id": arguments.campaign_id,
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "campaign_mode": arguments.campaign_mode,
        "campaign_purpose": arguments.campaign_purpose,
        "baseline_version": arguments.baseline_version,
        "target_version": arguments.target_version,
        "target_sha256": arguments.target_sha256,
        "suite": arguments.suite,
        "official_identity": official_identity,
        "baseline_identity": baseline_identity,
        "tool_identity": _tool_identity(),
        "control_receipts": control_receipts,
        "inputs": {
            "baseline_rules": {
                "path": "inputs/baseline-rules.json",
                "sha256": file_sha256(inputs_root / "baseline-rules.json"),
            },
            "discovery_scenarios": {
                "path": "inputs/discovery-scenarios.json",
                "sha256": file_sha256(inputs_root / "discovery-scenarios.json"),
            },
            "target_discovery_scenarios": {
                "path": "inputs/target-discovery-scenarios.json",
                "sha256": file_sha256(
                    inputs_root / "target-discovery-scenarios.json"
                ),
            },
            "extra_jobs": extra_jobs_reference,
        },
        "analysis": {
            name: {
                "path": f"analysis/{name}.json",
                "sha256": file_sha256(analysis_root / f"{name}.json"),
            }
            for name in (
                "baseline-source",
                "target-source",
                "source-diff",
                "baseline-surface",
            )
        },
        "configuration": {
            "baseline_source": str(arguments.baseline_source.resolve()),
            "target_source": str(arguments.target_source.resolve()),
            "target_package": str(arguments.target_package.resolve()),
            "baseline_evidence": str(arguments.baseline_evidence.resolve()),
            "runtime_image": arguments.runtime_image,
            "model": arguments.model,
            "lite_model": arguments.lite_model,
            "capture_root": str(arguments.capture_root),
            "capture_container": arguments.capture_container,
            "service_container": arguments.service_container,
            "keeper_container": arguments.keeper_container,
            "postgres_container": arguments.postgres_container,
            "redis_container": arguments.redis_container,
            "capture_codex_bin": arguments.capture_codex_bin,
            "relay_codex_bin": arguments.relay_codex_bin,
            "capture_code_mode_host_bin": arguments.capture_code_mode_host_bin,
            "relay_code_mode_host_bin": arguments.relay_code_mode_host_bin,
            "codex_account_id": arguments.codex_account_id,
            "api_key_id": arguments.api_key_id,
            "live_attestation_compose_dir": str(
                getattr(arguments, "live_attestation_compose_dir", "") or ""
            ),
            "live_attestation_compose_files": str(
                getattr(arguments, "live_attestation_compose_files", "") or ""
            ),
        },
        "required_rules": list(rules),
        "coverage_plan": plan["coverage_plan"],
        "jobs": plan["jobs"],
    }
    manifest_path = campaign_dir / "campaign.json"
    _secure_write_json_once(manifest_path, manifest)
    secure_write_text(
        campaign_dir / "campaign.sha256", file_sha256(manifest_path) + "\n"
    )
    return manifest


_CLASSIFICATION_APPROVAL_FIELDS = (
    "target_rule_manifest",
    "migration_manifest",
    "scenario_manifest",
    "profile_manifest",
    "assertion_profile_manifest",
)

_SUCCESSOR_OFFICIAL_SURFACE_PATH = "imports/official/surface.json"


def _copy_successor_binding(
    predecessor_dir: Path,
    staging_dir: Path,
    reference: Any,
    *,
    kind: str,
    copied_files: dict[str, dict[str, Any]],
    target_relative: str | None = None,
) -> dict[str, str]:
    """把一个前序 Campaign 文件逐字节复制到后继受管路径。"""

    _require_file_binding(reference, f"后继 Campaign {kind}")
    source_relative = str(reference["path"])
    destination_relative = target_relative or source_relative
    source = _campaign_file(predecessor_dir, source_relative)
    if source.is_symlink() or not source.is_file():
        raise ConfigurationError(
            f"前序 Campaign 文件不存在或不可信：{source_relative}"
        )
    expected_sha256 = str(reference["sha256"])
    if file_sha256(source) != expected_sha256:
        raise ConfigurationError(
            f"前序 Campaign 文件摘要漂移：{source_relative}"
        )
    existing = copied_files.get(destination_relative)
    if existing is not None:
        if (
            existing["source_path"] != source_relative
            or existing["sha256"] != expected_sha256
        ):
            raise ConfigurationError(
                "后继 Campaign 复制目标发生摘要冲突："
                + destination_relative
            )
        return {"path": destination_relative, "sha256": expected_sha256}
    destination = _campaign_file(staging_dir, destination_relative)
    copied = _secure_copy_file_once(source, destination)
    if copied["sha256"] != expected_sha256:
        raise ConfigurationError(
            f"后继 Campaign 复制摘要与绑定不一致：{source_relative}"
        )
    copied_files[destination_relative] = {
        "kind": kind,
        "source_path": source_relative,
        "target_path": destination_relative,
        "sha256": expected_sha256,
        "bytes": copied["bytes"],
    }
    return {"path": destination_relative, "sha256": expected_sha256}


def _successor_uses_reclassified_historical_plan_binding(
    staging_dir: Path,
    manifest: dict[str, Any],
    classification_bindings: dict[str, dict[str, str]],
) -> HistoricalSourceSpecBinding | None:
    """判定已完成分类纠正的后继是否仍需重放历史 Formal 摘要。

    分类事实纠正只会追加批准五件套，不会改写 Formal 时冻结的 target 场景
    清单。因此后续运行时坐标后继可能同时看到：历史 Formal 清单仍绑定旧章节
    摘要，而批准场景已经绑定当前章节摘要。只有批准场景可按当前源码重验、
    且两份清单的官方执行合同完全一致时，才允许计划重建读取历史摘要。
    """

    scenario_reference = manifest.get("inputs", {}).get(
        "target_discovery_scenarios"
    )
    if not isinstance(scenario_reference, dict):
        raise ConfigurationError(
            "同版本后继 Campaign 要求前序已冻结 target 场景清单。"
        )
    _require_file_binding(scenario_reference, "后继 Formal target 场景清单")
    frozen_path = _campaign_file(staging_dir, scenario_reference["path"])
    if (
        frozen_path.is_symlink()
        or not frozen_path.is_file()
        or file_sha256(frozen_path) != scenario_reference["sha256"]
    ):
        raise ConfigurationError("后继 Formal target 场景清单摘要不一致。")
    frozen = _read_json(frozen_path, "后继 Formal target 场景清单")
    _validate_scenario_manifest_shape(frozen)
    if frozen.get("codex_version") != manifest.get("target_version"):
        raise ConfigurationError("后继 Formal target 场景版本不一致。")
    frozen_binding = _scenario_source_spec_binding(
        frozen,
        label="后继 Formal target 场景",
    )
    source_path_text, _, fragment = frozen_binding.source_spec.partition("#")
    frozen_sha256 = frozen_binding.source_spec_sha256
    current_source = Path(__file__).resolve().parents[2] / source_path_text
    if not current_source.is_file() or current_source.is_symlink():
        raise ConfigurationError("后继 Formal target 场景规格文件不可信。")
    current_sha256 = source_spec_section_sha256(current_source, fragment)
    if frozen_sha256 == current_sha256:
        return None

    approved_reference = classification_bindings.get("scenario_manifest")
    if not isinstance(approved_reference, dict):
        raise ConfigurationError(
            "历史 Formal 摘要只能由已导入的当前批准场景承接。"
        )
    _require_file_binding(approved_reference, "后继批准场景清单")
    approved_path = _campaign_file(staging_dir, approved_reference["path"])
    if (
        approved_path.is_symlink()
        or not approved_path.is_file()
        or file_sha256(approved_path) != approved_reference["sha256"]
    ):
        raise ConfigurationError("后继批准场景清单摘要不一致。")
    approved = _read_json(approved_path, "后继批准场景清单")
    _validate_scenario_manifest_shape(approved)
    approved_source = approved.get("source_spec")
    if (
        approved.get("codex_version") != manifest.get("target_version")
        or not isinstance(approved_source, dict)
        or approved_source.get("path") != source_path_text
        or approved_source.get("fragment") != fragment
        or approved_source.get("sha256") != current_sha256
    ):
        raise ConfigurationError(
            "历史 Formal 摘要对应的批准场景未绑定当前规格摘要。"
        )
    if _fingerprint(_official_scenario_execution_contract(frozen)) != _fingerprint(
        _official_scenario_execution_contract(approved)
    ):
        raise ConfigurationError(
            "历史 Formal 场景与当前批准场景的官方执行合同不一致。"
        )
    return frozen_binding


def _rebuild_successor_plan(
    staging_dir: Path,
    final_dir: Path,
    manifest: dict[str, Any],
    *,
    historical_source_spec_binding: HistoricalSourceSpecBinding | None = None,
) -> None:
    """用新 Campaign ID 重算计划坐标，证据与批准输入保持逐字不变。"""

    arguments = _campaign_arguments(staging_dir, manifest)
    arguments.output = final_dir
    arguments.campaign_dir = final_dir
    context = _job_context(arguments)
    scenario_reference = manifest["inputs"].get("target_discovery_scenarios")
    if not isinstance(scenario_reference, dict):
        raise ConfigurationError(
            "同版本后继 Campaign 要求前序已冻结 target 场景清单。"
        )
    scenario_path = _campaign_file(staging_dir, scenario_reference["path"])
    jobs = load_scenario_jobs(
        scenario_path,
        context,
        expected_version=manifest["target_version"],
        require_bindings=True,
        historical_source_spec_binding=historical_source_spec_binding,
    )
    extra_reference = manifest["inputs"].get("extra_jobs")
    if extra_reference is not None:
        jobs.extend(
            load_extra_jobs(
                _campaign_file(staging_dir, extra_reference["path"]),
                context,
            )
        )
    jobs = [job for job in jobs if manifest["suite"] in job.suites]
    rules = load_rule_manifest(
        _campaign_file(staging_dir, manifest["inputs"]["baseline_rules"]["path"]),
        manifest["baseline_version"],
    )
    _validate_jobs(jobs, rules)
    if manifest["suite"] == "full":
        _validate_phase_coverage(jobs, rules)
    plan = _safe_plan(arguments, jobs, rules)
    manifest["coverage_plan"] = plan["coverage_plan"]
    manifest["jobs"] = plan["jobs"]


def _successor_abandoned_attempt(
    predecessor_dir: Path,
    candidate_id: str | None,
    attempt_id: str | None,
) -> dict[str, Any] | None:
    """可选绑定前序中因不可变时间窗口而放弃的 candidate attempt。"""

    if bool(candidate_id) != bool(attempt_id):
        raise ConfigurationError(
            "--predecessor-candidate-id 与 --predecessor-attempt-id 必须同时提供。"
        )
    if candidate_id is None or attempt_id is None:
        return None
    if not SAFE_ID_RE.fullmatch(candidate_id) or not SAFE_ID_RE.fullmatch(attempt_id):
        raise ConfigurationError("前序 candidate-id 或 attempt-id 格式非法。")
    attempt_root, attempt = _load_capture_attempt(
        predecessor_dir,
        "candidate",
        candidate_id,
        attempt_id,
    )
    attempt_path = attempt_root / "attempt.json"
    return {
        "candidate_id": candidate_id,
        "attempt_id": attempt_id,
        "path": attempt_path.relative_to(predecessor_dir).as_posix(),
        "sha256": file_sha256(attempt_path),
        "attempt_digest": attempt["attempt_digest"],
        "identity_sha256": _fingerprint(attempt["identity"]),
        "status": attempt["status"],
    }


def _successor_runtime_configuration(
    arguments: argparse.Namespace,
    predecessor_configuration: dict[str, Any],
) -> dict[str, str] | None:
    """校验并返回后继 Campaign 的新 Live attestation compose 坐标。

    compose 文件属于 Candidate 运行身份。历史路径已经被前序 Campaign 和
    attempt 引用，不能原位覆盖；只有运行时身份纠正后继可以通过 v4 收据
    冻结一组全新的可信绝对路径。其余配置仍由前序 Campaign 逐字承接。
    """

    compose_dir = getattr(arguments, "live_attestation_compose_dir", None)
    compose_files = str(
        getattr(arguments, "live_attestation_compose_files", "") or ""
    ).strip()
    if (compose_dir is None) != (not compose_files):
        raise ConfigurationError(
            "后继 compose 工作目录与 -f 参数串必须同时提供。"
        )
    if compose_dir is None:
        return None
    if arguments.reason != "candidate_runtime_identity_correction":
        raise ConfigurationError(
            "只有 candidate_runtime_identity_correction 后继可以改变 compose 坐标。"
        )

    resolved_dir = compose_dir.resolve(strict=False)
    if (
        not compose_dir.is_absolute()
        or str(resolved_dir) != str(compose_dir)
        or not SAFE_ABSOLUTE_PATH_RE.fullmatch(str(compose_dir))
        or compose_dir.is_symlink()
        or not compose_dir.is_dir()
    ):
        raise ConfigurationError(
            "--live-attestation-compose-dir 必须是可信的规范绝对目录。"
        )

    tokens = compose_files.split()
    compose_paths: list[str] = []
    expect_file = False
    for token in tokens:
        if expect_file:
            compose_paths.append(token)
            expect_file = False
            continue
        if token in {"-f", "--file"}:
            expect_file = True
            continue
        if token.startswith("-"):
            raise ConfigurationError(
                "--live-attestation-compose-files 只允许 -f/--file 参数。"
            )
        compose_paths.append(token)
    if expect_file or not compose_paths:
        raise ConfigurationError(
            "--live-attestation-compose-files 的 -f 参数串不完整。"
        )
    for raw_path in compose_paths:
        path = Path(raw_path)
        if (
            not path.is_absolute()
            or str(path.resolve(strict=False)) != raw_path
            or not SAFE_ABSOLUTE_PATH_RE.fullmatch(raw_path)
            or path.is_symlink()
            or not path.is_file()
        ):
            raise ConfigurationError(
                "后继 compose 参数必须引用存在、非符号链接的规范绝对文件："
                + raw_path
            )

    successor = {
        "live_attestation_compose_dir": str(compose_dir),
        "live_attestation_compose_files": compose_files,
    }
    if all(
        str(predecessor_configuration.get(field, "") or "") == value
        for field, value in successor.items()
    ):
        raise ConfigurationError("后继 compose 坐标没有发生变化。")
    return successor


def _successor_job_rehearsal_transition(
    arguments: argparse.Namespace,
    staging_dir: Path,
    successor_manifest: dict[str, Any],
    *,
    target_scenario_override: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """校验后继当前执行合同，并按需替换前序完整 Job 演练绑定。"""

    rehearsal_root = getattr(arguments, "job_rehearsal_root", None)
    rehearsal_receipt = getattr(arguments, "job_rehearsal_receipt", None)
    if (rehearsal_root is None) != (rehearsal_receipt is None):
        raise ConfigurationError(
            "后继 --job-rehearsal-root 与 --job-rehearsal-receipt 必须同时提供。"
        )
    controls = successor_manifest.get("control_receipts")
    predecessor_control = (
        controls.get("job_rehearsal") if isinstance(controls, dict) else None
    )
    if not isinstance(predecessor_control, dict):
        raise ConfigurationError("前序 Formal Campaign 缺少完整 Job 演练绑定。")
    expected_contract = _job_rehearsal_contract_from_manifest(
        staging_dir,
        successor_manifest,
        target_scenario_override=target_scenario_override,
    )
    if rehearsal_root is None or rehearsal_receipt is None:
        try:
            replayed_control = _job_rehearsal_control_from_receipt(
                Path(str(predecessor_control.get("evidence_root", ""))),
                Path(
                    str(
                        predecessor_control.get("receipt", {}).get("path", "")
                        if isinstance(predecessor_control.get("receipt"), dict)
                        else ""
                    )
                ),
                expected_contract,
            )
        except ConfigurationError as error:
            raise ConfigurationError(
                "后继当前执行合同与前序完整 Job 演练不一致；先用当前工具"
                "创建 preflight_only Campaign 并完成离线演练，再向 successor "
                "同时提供 --job-rehearsal-root 与 --job-rehearsal-receipt。"
            ) from error
        if replayed_control != predecessor_control:
            raise ConfigurationError("前序完整 Job 演练绑定无法逐字重建。")
        return None

    assert isinstance(rehearsal_root, Path)
    assert isinstance(rehearsal_receipt, Path)
    successor_control = _job_rehearsal_control_from_receipt(
        rehearsal_root,
        rehearsal_receipt,
        expected_contract,
    )
    if successor_control == predecessor_control:
        raise ConfigurationError("后继完整 Job 演练绑定没有发生变化。")
    controls["job_rehearsal"] = successor_control
    return {
        "reason": "current_execution_contract_rehearsal",
        "predecessor": predecessor_control,
        "successor": successor_control,
    }


def _successor_recovery_control_transition(
    arguments: argparse.Namespace,
    successor_manifest: dict[str, Any],
) -> dict[str, Any] | None:
    """把已停线 Ledger 精确连接到新的离线恢复 P0 控制收据。"""

    names = (
        "recovery_timing_ledger_dir",
        "recovery_timing_receipt",
        "recovery_arm64_environment_root",
        "recovery_arm64_environment_receipt",
        "predecessor_stop_ledger_dir",
        "predecessor_stop_receipt",
    )
    values = {name: getattr(arguments, name, None) for name in names}
    provided = [value is not None for value in values.values()]
    if not any(provided):
        return None
    if not all(provided):
        raise ConfigurationError("后继恢复控制坐标必须六项同时提供。")
    if (
        getattr(arguments, "job_rehearsal_root", None) is None
        or getattr(arguments, "job_rehearsal_receipt", None) is None
    ):
        raise ConfigurationError("恢复控制重绑必须同时提供新的完整 Job 演练收据。")

    controls = successor_manifest.get("control_receipts")
    if not isinstance(controls, dict):
        raise ConfigurationError("前序 Formal Campaign 缺少控制收据。")
    predecessor_timing = controls.get("upgrade_timing")
    predecessor_arm = controls.get("arm64_environment")
    if not isinstance(predecessor_timing, dict) or not isinstance(
        predecessor_arm, dict
    ):
        raise ConfigurationError("前序 Formal Campaign 控制收据不完整。")

    stop_root = values["predecessor_stop_ledger_dir"]
    stop_path = values["predecessor_stop_receipt"]
    assert isinstance(stop_root, Path) and isinstance(stop_path, Path)
    stop_relative = _control_receipt_relative(
        stop_root,
        stop_path,
        "前序 stop_the_line checkpoint",
    )
    try:
        stop_checkpoint = codex_upgrade_timing_ledger.replay(
            stop_root,
            stop_relative,
        )
    except (OSError, codex_upgrade_timing_ledger.TimingLedgerError) as error:
        raise ConfigurationError(f"前序停线 checkpoint 未通过：{error}") from error
    stop_summary = stop_checkpoint.get("summary")
    expected_summary = {
        "baseline_version": successor_manifest.get("baseline_version"),
        "target_version": successor_manifest.get("target_version"),
        "campaign_purpose": successor_manifest.get("campaign_purpose"),
    }
    if (
        not isinstance(stop_summary, dict)
        or stop_summary.get("status") != "stopped"
        or stop_summary.get("active_phase")
        not in codex_upgrade_timing_ledger.PHASE_ORDER[1:]
        or any(stop_summary.get(key) != value for key, value in expected_summary.items())
    ):
        raise ConfigurationError("前序 checkpoint 不是当前升级在 VC-1～VC-6 的停线事实。")
    resolved_stop_root = stop_root.resolve(strict=True)
    if (
        Path(str(predecessor_timing.get("ledger_dir", ""))).resolve(strict=True)
        != resolved_stop_root
        or predecessor_timing.get("upgrade_id") != stop_summary.get("upgrade_id")
    ):
        raise ConfigurationError("前序停线 checkpoint 与 Formal Campaign 的 Ledger 不一致。")

    recovery_arguments = argparse.Namespace(
        campaign_mode="preflight_only",
        campaign_purpose=successor_manifest["campaign_purpose"],
        baseline_version=successor_manifest["baseline_version"],
        target_version=successor_manifest["target_version"],
        timing_ledger_dir=values["recovery_timing_ledger_dir"],
        timing_receipt=values["recovery_timing_receipt"],
        arm64_environment_root=values["recovery_arm64_environment_root"],
        arm64_environment_receipt=values[
            "recovery_arm64_environment_receipt"
        ],
    )
    successor_controls = _plan_control_receipts(recovery_arguments)
    successor_timing = successor_controls["upgrade_timing"]
    if (
        successor_timing["ledger_dir"] == predecessor_timing.get("ledger_dir")
        or successor_timing["upgrade_id"] == predecessor_timing.get("upgrade_id")
    ):
        raise ConfigurationError("恢复 Ledger 必须使用新的目录和 upgrade-id。")

    controls.update(successor_controls)
    stop_file = resolved_stop_root / stop_relative
    return {
        "reason": "stopped_ledger_recovery",
        "predecessor": {
            "upgrade_timing": predecessor_timing,
            "arm64_environment": predecessor_arm,
        },
        "stop_checkpoint": {
            "ledger_dir": str(resolved_stop_root),
            "receipt": {
                "path": stop_relative,
                "sha256": file_sha256(stop_file),
                "bytes": stop_file.stat().st_size,
            },
            "upgrade_id": stop_summary["upgrade_id"],
            "active_phase": stop_summary["active_phase"],
            "head_sequence": stop_summary["head_sequence"],
            "head_sha256": stop_summary["head_sha256"],
            "total_elapsed_seconds": stop_summary["total_elapsed_seconds"],
            "total_live_request_count": stop_summary["total_live_request_count"],
        },
        "successor": successor_controls,
    }


def _assert_recovery_rehearsal_uses_successor_controls(
    arguments: argparse.Namespace,
    successor_manifest: Mapping[str, Any],
) -> tuple[Path, dict[str, Any]]:
    """确认新演练来自绑定同一恢复 Ledger 和 ARM64 收据的 preflight。"""

    rehearsal_root = arguments.job_rehearsal_root
    rehearsal_path = arguments.job_rehearsal_receipt
    assert isinstance(rehearsal_root, Path) and isinstance(rehearsal_path, Path)
    rehearsal_relative = _control_receipt_relative(
        rehearsal_root,
        rehearsal_path,
        "恢复完整 Job 离线演练收据",
    )
    try:
        rehearsal = codex_upgrade_job_rehearsal_receipt.replay(
            rehearsal_root,
            rehearsal_relative,
        )
    except (OSError, codex_upgrade_job_rehearsal_receipt.JobRehearsalReceiptError) as error:
        raise ConfigurationError(f"恢复完整 Job 演练无法重放：{error}") from error
    preflight = rehearsal.get("preflight_campaign")
    if not isinstance(preflight, dict):
        raise ConfigurationError("恢复完整 Job 演练缺少 preflight Campaign。")
    preflight_dir = Path(str(preflight.get("path", "")))
    preflight_manifest_path = preflight_dir / "campaign.json"
    if (
        not preflight_dir.is_absolute()
        or not preflight_manifest_path.is_file()
        or preflight_manifest_path.is_symlink()
        or file_sha256(preflight_manifest_path) != preflight.get("manifest_sha256")
    ):
        raise ConfigurationError("恢复完整 Job 演练的 preflight Campaign 绑定非法。")
    preflight_manifest = load_campaign_manifest(preflight_dir)
    expected_controls = successor_manifest.get("control_receipts")
    actual_controls = preflight_manifest.get("control_receipts")
    if (
        preflight_manifest.get("campaign_mode") != "preflight_only"
        or preflight_manifest.get("campaign_id") != preflight.get("campaign_id")
        or any(
            preflight_manifest.get(field) != successor_manifest.get(field)
            for field in ("baseline_version", "target_version", "campaign_purpose")
        )
        or preflight_manifest.get("tool_identity")
        != successor_manifest.get("tool_identity")
        or not isinstance(expected_controls, dict)
        or not isinstance(actual_controls, dict)
        or actual_controls.get("upgrade_timing")
        != expected_controls.get("upgrade_timing")
        or actual_controls.get("arm64_environment")
        != expected_controls.get("arm64_environment")
    ):
        raise ConfigurationError("恢复 preflight 与后继当前控制合同不一致。")
    _verify_control_receipts(
        preflight_dir,
        preflight_manifest,
        require_active=True,
    )
    return preflight_dir, preflight_manifest


def _recovery_rehearsal_target_scenario_override(
    campaign_dir: Path,
    manifest: Mapping[str, Any],
    preflight_dir: Path,
    preflight_manifest: Mapping[str, Any],
) -> dict[str, Any] | None:
    """只允许当前受管场景承接 Formal 的历史规格章节摘要。"""

    target_version = str(manifest.get("target_version", ""))
    if not VERSION_RE.fullmatch(target_version):
        raise ConfigurationError("Formal target_version 非法。")

    def bound_scenario(
        root: Path,
        source_manifest: Mapping[str, Any],
        label: str,
    ) -> dict[str, Any]:
        inputs = source_manifest.get("inputs")
        reference = (
            inputs.get("target_discovery_scenarios")
            if isinstance(inputs, Mapping)
            else None
        )
        if not isinstance(reference, dict):
            raise ConfigurationError(f"{label}缺少 target 场景绑定。")
        _require_file_binding(reference, f"{label} target 场景")
        path = _campaign_file(root, reference["path"])
        if (
            path.is_symlink()
            or not path.is_file()
            or file_sha256(path) != reference["sha256"]
        ):
            raise ConfigurationError(f"{label} target 场景摘要不一致。")
        payload = _read_json(path, f"{label} target 场景")
        _validate_scenario_manifest_shape(payload)
        if payload.get("codex_version") != target_version:
            raise ConfigurationError(f"{label} target 场景版本不一致。")
        return payload

    frozen = bound_scenario(campaign_dir, manifest, "Formal")
    preflight = bound_scenario(
        preflight_dir,
        preflight_manifest,
        "恢复 preflight",
    )
    managed_path = (
        Path(__file__).resolve().parent
        / f"codex_upgrade_scenarios_{target_version.replace('.', '_')}.json"
    )
    if managed_path.is_symlink() or not managed_path.is_file():
        raise ConfigurationError("当前受管版本化 target 场景不存在或不可信。")
    managed = _read_json(managed_path, "当前受管版本化 target 场景")
    _validate_scenario_manifest_shape(managed)
    if managed.get("codex_version") != target_version or preflight != managed:
        raise ConfigurationError(
            "恢复 preflight 必须使用当前受管版本化 target 场景原文件。"
        )
    if frozen == managed:
        return None

    frozen_binding = _scenario_source_spec_binding(
        frozen,
        label="Formal 历史 target 场景",
    )
    managed_binding = _scenario_source_spec_binding(
        managed,
        label="当前受管版本化 target 场景",
    )
    source_path_text, _, fragment = managed_binding.source_spec.partition("#")
    current_source = Path(__file__).resolve().parents[2] / source_path_text
    if (
        frozen_binding.codex_version != managed_binding.codex_version
        or frozen_binding.source_spec != managed_binding.source_spec
        or current_source.is_symlink()
        or not current_source.is_file()
        or source_spec_section_sha256(current_source, fragment)
        != managed_binding.source_spec_sha256
    ):
        raise ConfigurationError("Formal 与当前场景的规格来源身份不一致。")

    normalized_frozen = json.loads(json.dumps(frozen, ensure_ascii=False))
    normalized_source = normalized_frozen.get("source_spec")
    if not isinstance(normalized_source, dict):
        raise ConfigurationError("Formal 历史 target 场景缺少 source_spec。")
    normalized_source["sha256"] = managed_binding.source_spec_sha256
    if normalized_frozen != managed:
        raise ConfigurationError(
            "Formal 历史 target 场景除 source_spec.sha256 外发生变化。"
        )
    return managed


def _reject_repeated_successor_reason(
    predecessor_dir: Path,
    predecessor_manifest: Mapping[str, Any],
    reason: str,
) -> None:
    """只读小型 Campaign 清单，拒绝同一根因形成第二层后继链。"""

    current_dir = predecessor_dir.resolve()
    current: Mapping[str, Any] = predecessor_manifest
    visited = {current_dir}
    for _depth in range(64):
        binding = current.get("predecessor")
        if binding is None:
            return
        if not isinstance(binding, dict):
            raise ConfigurationError("前序 Campaign 链绑定非法。")
        if binding.get("reason") == reason:
            raise ConfigurationError(
                "同一根因已经使用过一次 successor，第二层必须停线："
                f"{reason}"
            )
        next_dir = Path(str(binding.get("campaign_dir", "")))
        if (
            not next_dir.is_absolute()
            or str(next_dir.resolve()) != str(next_dir)
            or next_dir.resolve() in visited
        ):
            raise ConfigurationError("前序 Campaign 链路径不可信或形成循环。")
        manifest_path = next_dir / "campaign.json"
        if (
            manifest_path.is_symlink()
            or not manifest_path.is_file()
            or file_sha256(manifest_path)
            != binding.get("campaign_manifest_sha256")
        ):
            raise ConfigurationError("前序 Campaign 链清单摘要漂移。")
        current = load_campaign_manifest(next_dir)
        if current.get("campaign_id") != binding.get("campaign_id"):
            raise ConfigurationError("前序 Campaign 链 ID 漂移。")
        current_dir = next_dir.resolve()
        visited.add(current_dir)
    raise ConfigurationError("前序 Campaign 链超过 64 层，拒绝继续 successor。")


def create_successor_campaign(arguments: argparse.Namespace) -> dict[str, Any]:
    """创建同版本后继 Campaign，并按原因选择承接边界。

    普通运行时纠正会承接官方阶段和批准分类；若现有批准事实与原始官方
    证据冲突，分类纠正后继只承接官方阶段，并要求在新 Campaign 内重新
    生成、审核和批准五件套。两种模式都不会复制或改写历史 attempt。
    """

    predecessor_dir = arguments.predecessor_campaign_dir
    successor_dir = arguments.campaign_dir
    _validate_existing_campaign_path(predecessor_dir)
    _validate_output_path(successor_dir)
    if predecessor_dir.resolve() == successor_dir.resolve(strict=False):
        raise ConfigurationError("后继 Campaign 目录不得等于前序 Campaign。")
    if not SAFE_ID_RE.fullmatch(str(arguments.campaign_id)):
        raise ConfigurationError("--campaign-id 格式非法。")
    if arguments.codex_account_id <= 0:
        raise ConfigurationError("--codex-account-id 必须为正整数。")
    if arguments.reason not in SUCCESSOR_REASONS:
        raise ConfigurationError("--reason 不是受管的同版本后继原因。")
    reclassification_successor = (
        arguments.reason in RECLASSIFICATION_SUCCESSOR_REASONS
    )

    predecessor_manifest = _require_formal_campaign(predecessor_dir)
    _reject_repeated_successor_reason(
        predecessor_dir,
        predecessor_manifest,
        arguments.reason,
    )
    predecessor_configuration = predecessor_manifest.get("configuration")
    if not isinstance(predecessor_configuration, dict):
        raise ConfigurationError("前序 Campaign 的运行配置不是对象。")
    predecessor_account_id = predecessor_configuration.get("codex_account_id")
    if (
        isinstance(predecessor_account_id, bool)
        or not isinstance(predecessor_account_id, int)
        or predecessor_account_id <= 0
    ):
        raise ConfigurationError("前序 Campaign 的 Codex 账号坐标非法。")
    if arguments.campaign_id == predecessor_manifest["campaign_id"]:
        raise ConfigurationError("后继 Campaign 必须使用新的 campaign-id。")
    runtime_configuration = _successor_runtime_configuration(
        arguments,
        predecessor_configuration,
    )
    # 后继承接只重放前序阶段封印、证据 inventory/security 与批准清单。
    # 历史机器收据绑定的是当时 finalizer 的绝对路径和摘要；用当前 finalizer
    # 强行重放会把合法的只读历史路径迁移误判为篡改。当前后继不会借用这些
    # 收据生成新事实，因此保留阶段级逐字节校验，但不重新绑定历史 finalizer。
    official = _load_stage_result(
        predecessor_dir,
        "capture-official",
        _replay_machine_receipts=False,
    )
    classification = _load_stage_result(predecessor_dir, "classify")
    if official.get("status") != "complete":
        raise ConfigurationError("前序 Campaign 官方阶段尚未完整封存。")
    if (
        classification.get("status") != "complete"
        or classification.get("migration", {}).get("unclassified_count") != 0
    ):
        raise ConfigurationError("前序 Campaign 分类未完整批准或仍有阻断。")
    abandoned_attempt = _successor_abandoned_attempt(
        predecessor_dir,
        arguments.predecessor_candidate_id,
        arguments.predecessor_attempt_id,
    )

    if successor_dir.parent.exists():
        if successor_dir.parent.is_symlink() or not successor_dir.parent.is_dir():
            raise ConfigurationError("后继 Campaign 的父目录不可信。")
    else:
        ensure_private_directory(successor_dir.parent)
    staging_dir = Path(
        tempfile.mkdtemp(
            prefix=f".{successor_dir.name}.successor-",
            dir=successor_dir.parent,
        )
    )
    staging_dir.chmod(0o700)
    published = False
    try:
        copied_files: dict[str, dict[str, Any]] = {}
        for group_name in ("inputs", "analysis"):
            for reference in predecessor_manifest[group_name].values():
                if reference is None:
                    continue
                _copy_successor_binding(
                    predecessor_dir,
                    staging_dir,
                    reference,
                    kind=f"plan_{group_name}",
                    copied_files=copied_files,
                )

        classification_bindings: dict[str, dict[str, str]] = {}
        if not reclassification_successor:
            for field in _CLASSIFICATION_APPROVAL_FIELDS:
                classification_bindings[field] = _copy_successor_binding(
                    predecessor_dir,
                    staging_dir,
                    classification.get(field),
                    kind="approved_classification",
                    copied_files=copied_files,
                )
        surface_binding = _copy_successor_binding(
            predecessor_dir,
            staging_dir,
            official.get("surface"),
            kind="official_surface",
            copied_files=copied_files,
            target_relative=_SUCCESSOR_OFFICIAL_SURFACE_PATH,
        )

        predecessor_manifest_sha256 = file_sha256(
            predecessor_dir / "campaign.json"
        )
        successor_manifest = json.loads(
            json.dumps(predecessor_manifest, ensure_ascii=False)
        )
        successor_manifest["configuration"]["codex_account_id"] = (
            arguments.codex_account_id
        )
        if runtime_configuration is not None:
            successor_manifest["configuration"].update(runtime_configuration)
        successor_manifest.update(
            {
                "campaign_id": arguments.campaign_id,
                "created_at_utc": _utc_now(),
                "tool_identity": _tool_identity(),
                "predecessor": {
                    "campaign_dir": str(predecessor_dir.resolve()),
                    "campaign_id": predecessor_manifest["campaign_id"],
                    "campaign_manifest_sha256": predecessor_manifest_sha256,
                    "reason": arguments.reason,
                },
            }
        )
        if reclassification_successor:
            scenario_reference = successor_manifest["inputs"].get(
                "target_discovery_scenarios"
            )
            if not isinstance(scenario_reference, dict):
                raise ConfigurationError(
                    "分类纠正后继缺少冻结 target 场景清单。"
                )
            _require_file_binding(
                scenario_reference,
                "分类纠正后继 target 场景清单",
            )
            scenario_path = _campaign_file(
                staging_dir,
                scenario_reference["path"],
            )
            if (
                scenario_path.is_symlink()
                or not scenario_path.is_file()
                or file_sha256(scenario_path) != scenario_reference["sha256"]
            ):
                raise ConfigurationError(
                    "分类纠正后继 target 场景清单摘要不一致。"
                )
            frozen_scenario = _read_json(
                scenario_path,
                "分类纠正后继 target 场景清单",
            )
            _validate_scenario_manifest_shape(frozen_scenario)
            if frozen_scenario.get("codex_version") != successor_manifest.get(
                "target_version"
            ):
                raise ConfigurationError(
                    "分类纠正后继 target 场景版本不一致。"
                )
            historical_source_spec_binding = _scenario_source_spec_binding(
                frozen_scenario,
                label="分类纠正后继 target 场景清单",
            )
        else:
            historical_source_spec_binding = (
                _successor_uses_reclassified_historical_plan_binding(
                    staging_dir,
                    successor_manifest,
                    classification_bindings,
                )
            )
        rehearsal_scenario_override: Mapping[str, Any] | None = None
        if historical_source_spec_binding is not None and not reclassification_successor:
            approved_scenario_reference = classification_bindings[
                "scenario_manifest"
            ]
            rehearsal_scenario_override = _read_json(
                _campaign_file(
                    staging_dir,
                    approved_scenario_reference["path"],
                ),
                "后继 Campaign 当前批准场景",
            )
        recovery_control_transition = _successor_recovery_control_transition(
            arguments,
            successor_manifest,
        )
        # 分类事实纠正后继可能继续承接历史 Formal 的 target 场景字节，
        # 但恢复 preflight 必须使用当前受管场景。两者只要存在合法的
        # source_spec 摘要差异，完整 Job 演练合同就应以恢复 preflight
        # 的当前场景重算；否则会把同一组 Job 错误判成工具／合同漂移。
        if recovery_control_transition is not None and reclassification_successor:
            recovery_preflight_dir, recovery_preflight_manifest = (
                _assert_recovery_rehearsal_uses_successor_controls(
                    arguments,
                    successor_manifest,
                )
            )
            recovery_scenario_override = _recovery_rehearsal_target_scenario_override(
                staging_dir,
                successor_manifest,
                recovery_preflight_dir,
                recovery_preflight_manifest,
            )
            if recovery_scenario_override is not None:
                rehearsal_scenario_override = recovery_scenario_override
        job_rehearsal_transition = _successor_job_rehearsal_transition(
            arguments,
            staging_dir,
            successor_manifest,
            target_scenario_override=rehearsal_scenario_override,
        )
        _rebuild_successor_plan(
            staging_dir,
            successor_dir,
            successor_manifest,
            historical_source_spec_binding=historical_source_spec_binding,
        )
        manifest_path = staging_dir / "campaign.json"
        _secure_write_json_once(manifest_path, successor_manifest)
        secure_write_text(
            staging_dir / "campaign.sha256", file_sha256(manifest_path) + "\n"
        )

        official_path = _stage_path(
            predecessor_dir, "capture-official"
        )[1]
        classification_path = _stage_path(predecessor_dir, "classify")[1]
        import_receipt: dict[str, Any] = {
            "schema_version": (
                PREDECESSOR_RECOVERY_IMPORT_SCHEMA
                if recovery_control_transition is not None
                else (
                    PREDECESSOR_REHEARSAL_IMPORT_SCHEMA
                    if job_rehearsal_transition is not None
                    else (
                        PREDECESSOR_RECLASSIFICATION_IMPORT_SCHEMA
                        if reclassification_successor
                        else (
                            PREDECESSOR_RUNTIME_IMPORT_SCHEMA
                            if runtime_configuration is not None
                            else PREDECESSOR_IMPORT_SCHEMA
                        )
                    )
                )
            ),
            "created_at_utc": _utc_now(),
            "reason": arguments.reason,
            "successor_campaign_id": arguments.campaign_id,
            "successor_campaign_manifest_sha256": file_sha256(manifest_path),
            "predecessor_campaign": {
                "campaign_dir": str(predecessor_dir.resolve()),
                "campaign_id": predecessor_manifest["campaign_id"],
                "campaign_manifest_sha256": predecessor_manifest_sha256,
            },
            "stages": {
                "capture-official": {
                    "path": official_path.relative_to(predecessor_dir).as_posix(),
                    "sha256": file_sha256(official_path),
                    "package_digest": official["package_digest"],
                    "evidence_inventory_digest": official[
                        "evidence_inventory"
                    ]["digest"],
                    "security_sha256": _fingerprint(official["security"]),
                },
                "classify": {
                    "path": classification_path.relative_to(
                        predecessor_dir
                    ).as_posix(),
                    "sha256": file_sha256(classification_path),
                    "package_digest": classification["package_digest"],
                    "joint_manifest_sha256": classification[
                        "joint_manifest_sha256"
                    ],
                },
            },
            "copied_files": sorted(
                copied_files.values(), key=lambda item: item["target_path"]
            ),
            "configuration_transition": {
                "codex_account_id": {
                    "predecessor": predecessor_account_id,
                    "successor": arguments.codex_account_id,
                    "reason": "operator_selected_active_account",
                }
            },
            "abandoned_candidate_attempt": abandoned_attempt,
        }
        if job_rehearsal_transition is not None:
            import_receipt["job_rehearsal_transition"] = (
                job_rehearsal_transition
            )
        if recovery_control_transition is not None:
            import_receipt["recovery_control_transition"] = (
                recovery_control_transition
            )
        if runtime_configuration is not None:
            import_receipt["configuration_transition"].update(
                {
                    field: {
                        "predecessor": str(
                            predecessor_configuration.get(field, "") or ""
                        ),
                        "successor": value,
                        "reason": "candidate_runtime_identity_correction",
                    }
                    for field, value in runtime_configuration.items()
                }
            )
        if reclassification_successor:
            import_receipt["import_mode"] = "official_only_reclassification"
        import_receipt["receipt_digest"] = _fingerprint(import_receipt)
        import_path = staging_dir / "predecessor-import.json"
        _secure_write_json_once(import_path, import_receipt)
        import_binding = {
            "path": import_path.relative_to(staging_dir).as_posix(),
            "sha256": file_sha256(import_path),
        }

        save_stage_result(
            staging_dir,
            "capture-official",
            {
                "status": "complete",
                "predecessor_import": import_binding,
                "predecessor_package_digest": official["package_digest"],
                "surface": surface_binding,
            },
            _successor_manifest=successor_manifest,
        )
        if not reclassification_successor:
            imported_classification = {
                "status": "complete",
                "predecessor_import": import_binding,
                "predecessor_package_digest": classification["package_digest"],
                **classification_bindings,
            }
            for field in (
                "joint_manifest_sha256",
                "baseline_rule_count",
                "target_rule_count",
                "migration",
                "source_diff_sha256",
                "official_diff_sha256",
            ):
                imported_classification[field] = classification[field]
            save_stage_result(
                staging_dir,
                "classify",
                imported_classification,
                _successor_manifest=successor_manifest,
            )

        if successor_dir.exists():
            raise ConfigurationError("后继 Campaign 目录在发布前已被占用。")
        os.rename(staging_dir, successor_dir)
        published = True
    finally:
        if not published:
            shutil.rmtree(staging_dir, ignore_errors=True)

    status = campaign_status(successor_dir)
    return {
        "status": status["status"],
        "campaign_id": arguments.campaign_id,
        "campaign_dir": str(successor_dir),
        "predecessor_campaign_id": predecessor_manifest["campaign_id"],
        "predecessor_campaign_dir": str(predecessor_dir.resolve()),
        "reason": arguments.reason,
        "official_imported": True,
        "classification_imported": not reclassification_successor,
        "classification_reapproval_required": reclassification_successor,
        "official_recapture_required": False,
        "codex_account_id": arguments.codex_account_id,
        "runtime_configuration_rebound": runtime_configuration is not None,
        "job_rehearsal_rebound": job_rehearsal_transition is not None,
        "recovery_controls_rebound": recovery_control_transition is not None,
        "next_command": status["next_command"],
    }


def load_campaign_manifest(path: Path) -> dict[str, Any]:
    """加载 Campaign，并验证核心清单及其计划期输入未被改写。"""

    campaign_dir = path.parent if path.name == "campaign.json" else path
    _validate_existing_campaign_path(campaign_dir)
    manifest_path = campaign_dir / "campaign.json"
    digest_path = campaign_dir / "campaign.sha256"
    if not manifest_path.is_file() or not digest_path.is_file():
        raise ConfigurationError("Campaign 缺少 campaign.json 或 campaign.sha256。")
    expected = digest_path.read_text(encoding="utf-8").strip()
    if not SHA256_RE.fullmatch(expected) or file_sha256(manifest_path) != expected:
        raise ConfigurationError("Campaign 核心清单摘要不一致，拒绝继续。")
    manifest = _read_json(manifest_path, "Campaign 核心清单")
    if manifest.get("schema_version") != CAMPAIGN_SCHEMA:
        raise ConfigurationError("Campaign schema_version 不受支持。")
    _campaign_coordinates(manifest)
    predecessor = manifest.get("predecessor")
    if predecessor is not None:
        if (
            not isinstance(predecessor, dict)
            or set(predecessor)
            != {
                "campaign_dir",
                "campaign_id",
                "campaign_manifest_sha256",
                "reason",
            }
            or not isinstance(predecessor.get("campaign_dir"), str)
            or not Path(predecessor["campaign_dir"]).is_absolute()
            or not SAFE_ID_RE.fullmatch(str(predecessor.get("campaign_id", "")))
            or not SHA256_RE.fullmatch(
                str(predecessor.get("campaign_manifest_sha256", ""))
            )
            or predecessor.get("reason") not in SUCCESSOR_REASONS
        ):
            raise ConfigurationError("Campaign 前序绑定非法。")
    for group_name in ("inputs", "analysis"):
        for reference in manifest.get(group_name, {}).values():
            if reference is None:
                continue
            relative = reference.get("path")
            expected_sha = reference.get("sha256")
            if not isinstance(relative, str) or not SHA256_RE.fullmatch(
                str(expected_sha)
            ):
                raise ConfigurationError(f"Campaign {group_name} 引用非法。")
            target = _campaign_file(campaign_dir, relative)
            if not target.is_file() or file_sha256(target) != expected_sha:
                raise ConfigurationError(f"Campaign 输入摘要漂移：{relative}")
    _verify_control_receipts(
        campaign_dir,
        manifest,
        require_active=False,
    )
    return manifest


def _campaign_coordinates(manifest: Mapping[str, Any]) -> tuple[str, str]:
    """读取并严格校验 Campaign 创建时冻结的模式与用途。"""

    mode = manifest.get("campaign_mode")
    purpose = manifest.get("campaign_purpose")
    if mode not in CAMPAIGN_MODES:
        raise ConfigurationError("Campaign 缺少或携带非法 campaign_mode。")
    if purpose not in CANDIDATE_PURPOSES:
        raise ConfigurationError("Campaign 缺少或携带非法 campaign_purpose。")
    return str(mode), str(purpose)


def _require_formal_campaign(
    campaign_dir: Path,
    manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """阻止 P0 计划通过任何直接或 continuation 入口进入正式阶段。"""

    current = manifest or load_campaign_manifest(campaign_dir)
    mode, _ = _campaign_coordinates(current)
    if mode != "formal":
        raise ConfigurationError(
            "preflight_only Campaign 只允许 plan/status；不得进入正式或 live 阶段，"
            "请以 formal 模式创建全新 Campaign。"
        )
    return current


def _stage_path(
    campaign_dir: Path,
    stage: str,
    candidate_id: str | None = None,
) -> tuple[str, Path]:
    aliases = {
        "official": "capture-official",
        "candidate": "capture-candidate",
        "classification": "classify",
        "comparison": "compare",
        "acceptance": "accept",
    }
    canonical = aliases.get(stage, stage)
    if canonical == "capture-official":
        return canonical, campaign_dir / "official" / "result.json"
    if canonical == "classify":
        return canonical, campaign_dir / "classification" / "result.json"
    if canonical in {"capture-candidate", "compare", "accept"}:
        if not candidate_id or not SAFE_ID_RE.fullmatch(candidate_id):
            raise ConfigurationError(f"{canonical} 必须提供合法 candidate-id。")
        roots = {
            "capture-candidate": "candidates",
            "compare": "comparisons",
            "accept": "acceptance",
        }
        return canonical, campaign_dir / roots[canonical] / candidate_id / "result.json"
    raise ConfigurationError(f"未知 Campaign 阶段：{stage}")


def _require_file_binding(value: Any, label: str) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"path", "sha256"}
        or not isinstance(value.get("path"), str)
        or not value["path"]
        or not SHA256_RE.fullmatch(str(value.get("sha256")))
    ):
        raise ConfigurationError(f"{label}文件绑定非法。")


def _validate_stage_contract(document: dict[str, Any]) -> None:
    """对运行期阶段收据执行失败关闭的核心契约校验。"""

    if document.get("schema_version") != STAGE_SCHEMA:
        raise ConfigurationError("阶段收据 schema_version 不受支持。")
    if document.get("campaign_mode") != "formal":
        raise ConfigurationError("阶段收据只能属于 formal Campaign。")
    if document.get("campaign_purpose") not in CANDIDATE_PURPOSES:
        raise ConfigurationError("阶段收据缺少或携带非法 Campaign 用途。")
    stage = document.get("stage")
    status = document.get("status")
    if stage not in {"capture-official", "classify", "capture-candidate", "compare", "accept"}:
        raise ConfigurationError("阶段收据 stage 非法。")
    if status not in {"complete", "blocked", "failed"}:
        raise ConfigurationError("阶段收据 status 非法。")
    candidate_stage = stage in {"capture-candidate", "compare", "accept"}
    expected_candidate_purpose = (
        document.get("campaign_purpose") if candidate_stage else None
    )
    if document.get("candidate_purpose") != expected_candidate_purpose:
        raise ConfigurationError("阶段收据 candidate purpose 与阶段／Campaign 不一致。")
    predecessor_import = document.get("predecessor_import")
    if predecessor_import is not None:
        if stage not in {"capture-official", "classify"} or status != "complete":
            raise ConfigurationError("前序导入只允许完整的官方或分类阶段。")
        _require_file_binding(predecessor_import, "前序导入收据")
        if not SHA256_RE.fullmatch(
            str(document.get("predecessor_package_digest", ""))
        ):
            raise ConfigurationError("前序导入缺少原阶段 package digest。")
        if stage == "capture-official":
            _require_file_binding(document.get("surface"), "导入的官方表面")
            return
    elif "predecessor_package_digest" in document:
        raise ConfigurationError("阶段收据不得携带未绑定收据的前序摘要。")
    if stage in {"capture-official", "capture-candidate"} and status == "complete":
        required = {
            "identity",
            "attempt",
            "seal_preview",
            "results",
            "evidence_roots",
            "evidence_inventory",
            "surface",
            "client_bindings",
            "assertion_context",
            "assertion_gate",
            "restoration",
            "security",
        }
        missing = sorted(required - set(document))
        if missing:
            raise ConfigurationError(f"抓包阶段收据缺少字段：{missing}")
        try:
            validate_gate_receipt(
                document.get("assertion_gate"),
                side="official" if stage == "capture-official" else "candidate",
            )
        except AssertionGateError as error:
            raise ConfigurationError(
                f"抓包阶段断言门禁收据非法：{error}"
            ) from error
        if not isinstance(document["results"], list) or not document["results"]:
            raise ConfigurationError("抓包阶段 results 不能为空。")
        _require_file_binding(document.get("attempt"), "抓包 attempt")
        _require_file_binding(document.get("seal_preview"), "seal 预览")
        evaluation_transition = document.get("evaluation_transition")
        if evaluation_transition is not None:
            _require_file_binding(evaluation_transition, "评估工具 transition")
        evidence_manifest = document.get("evidence_manifest")
        if evidence_manifest is not None:
            _require_file_binding(evidence_manifest, "EvidenceManifest")
            scan_summary = document.get("scan_summary")
            if (
                not isinstance(scan_summary, dict)
                or set(scan_summary)
                != {
                    "full_scan_count",
                    "scanned_bytes",
                    "reused_bytes",
                    "total_bytes",
                    "elapsed_seconds",
                }
                or scan_summary.get("full_scan_count") != 1
                or not all(
                    isinstance(scan_summary.get(field), int)
                    and scan_summary[field] >= 0
                    for field in ("scanned_bytes", "reused_bytes", "total_bytes")
                )
                or scan_summary["scanned_bytes"] + scan_summary["reused_bytes"]
                != scan_summary["total_bytes"]
                or not isinstance(scan_summary.get("elapsed_seconds"), (int, float))
                or scan_summary["elapsed_seconds"] < 0
            ):
                raise ConfigurationError("抓包阶段 scan_summary 非法。")
        elif "scan_summary" in document:
            raise ConfigurationError("抓包阶段不得携带无 manifest 的 scan_summary。")
        if not isinstance(document["evidence_roots"], list) or not document["evidence_roots"]:
            raise ConfigurationError("抓包阶段 evidence_roots 不能为空。")
        inventory = document["evidence_inventory"]
        if (
            not isinstance(inventory, dict)
            or not isinstance(inventory.get("entries"), list)
            or not inventory["entries"]
            or inventory.get("entry_count") != len(inventory["entries"])
            or inventory.get("digest") != _fingerprint({"entries": inventory["entries"]})
        ):
            raise ConfigurationError("抓包阶段 evidence_inventory 非法。")
        inventory_index = {
            entry.get("path"): entry.get("sha256")
            for entry in inventory["entries"]
            if isinstance(entry, dict)
        }
        _require_file_binding(document["surface"], "抓包表面")
        restoration = document["restoration"]
        if (
            not isinstance(restoration, dict)
            or restoration.get("passed") is not True
            or not isinstance(restoration.get("checks"), list)
            or not restoration["checks"]
        ):
            raise ConfigurationError("抓包阶段恢复门禁未通过。")
        _require_file_binding(restoration.get("report"), "环境恢复报告")
        if inventory_index.get(restoration["report"]["path"]) != restoration["report"]["sha256"]:
            raise ConfigurationError("环境恢复报告未绑定封存证据清单。")
        security = document["security"]
        if (
            not isinstance(security, dict)
            or security.get("raw_evidence_private") is not True
            or security.get("known_secret_scan_passed") is not True
        ):
            raise ConfigurationError("抓包阶段秘密扫描门禁未通过。")
        context = document["assertion_context"]
        if (
            not isinstance(context, dict)
            or not isinstance(context.get("capture_manifest_path"), str)
            or not isinstance(context.get("evidence_root"), str)
            or not isinstance(context.get("evidence_prefix"), str)
        ):
            raise ConfigurationError("抓包阶段 assertion_context 非法。")
        _require_file_binding(context.get("capture_manifest"), "capture manifest")
        if inventory_index.get(context["capture_manifest"]["path"]) != context["capture_manifest"]["sha256"]:
            raise ConfigurationError("capture manifest 未绑定封存证据清单。")
        if stage == "capture-candidate":
            capture_identity = document.get("identity")
            if (
                not isinstance(capture_identity, dict)
                or capture_identity.get("candidate_purpose")
                != document.get("candidate_purpose")
            ):
                raise ConfigurationError("候选阶段身份用途与阶段用途不一致。")
            post_client = restoration.get("post_client")
            if (
                not isinstance(post_client, dict)
                or post_client.get("passed") is not True
                or not isinstance(post_client.get("checks"), list)
                or not post_client["checks"]
            ):
                raise ConfigurationError("候选阶段缺少 Kilo 后环境恢复门禁。")
            _require_file_binding(
                post_client.get("report"), "Kilo 后环境恢复报告"
            )
            if (
                inventory_index.get(post_client["report"]["path"])
                != post_client["report"]["sha256"]
            ):
                raise ConfigurationError("Kilo 后恢复报告未绑定封存证据清单。")
            _require_file_binding(document.get("observed_profile"), "运行画像观测")
            if inventory_index.get(document["observed_profile"]["path"]) != document["observed_profile"]["sha256"]:
                raise ConfigurationError("运行画像观测未绑定封存证据清单。")
            client_bindings = document.get("client_bindings")
            client_ids = {
                item.get("client_id")
                for item in client_bindings
                if isinstance(item, dict)
            } if isinstance(client_bindings, list) else set()
            if not REQUIRED_CLIENT_BINDINGS.issubset(client_ids):
                raise ConfigurationError("候选阶段缺少两种必需 Kilo 客户端绑定。")
        else:
            binary_verification = document.get("binary_verification")
            if (
                not isinstance(binary_verification, dict)
                or binary_verification.get("passed") is not True
                or not SHA256_RE.fullmatch(
                    str(binary_verification.get("expected_sha256", ""))
                )
                or not VERSION_RE.fullmatch(
                    str(binary_verification.get("expected_version", ""))
                )
                or not IMMUTABLE_IMAGE_RE.fullmatch(
                    str(binary_verification.get("runtime_image_reference", ""))
                )
                or not IMAGE_ID_RE.fullmatch(
                    str(binary_verification.get("runtime_image_id", ""))
                )
                or not isinstance(binary_verification.get("identities"), list)
                or len(binary_verification["identities"]) < 3
            ):
                raise ConfigurationError("官方阶段缺少完整二进制身份验证。")
    if stage == "classify" and status in {"complete", "blocked"}:
        for field in (
            "target_rule_manifest",
            "migration_manifest",
            "scenario_manifest",
            "profile_manifest",
            "assertion_profile_manifest",
        ):
            _require_file_binding(document.get(field), field)
    if stage == "compare" and status == "complete":
        for field in (
            "official_package_digest",
            "candidate_package_digest",
            "classification_package_digest",
        ):
            if not SHA256_RE.fullmatch(str(document.get(field))):
                raise ConfigurationError(f"比较阶段 {field} 非法。")
        if document.get("offline_only") is not True:
            raise ConfigurationError("比较阶段必须是纯离线。")
    if stage == "accept" and status == "complete":
        _require_file_binding(document.get("assertion_result"), "逐规则断言结果")
        _require_file_binding(document.get("evidence_seal"), "验收证据封印")
        external_gate = document.get("candidate_external_gate")
        if (
            not isinstance(external_gate, dict)
            or set(external_gate) != {"evidence_root", "receipt"}
            or not isinstance(external_gate.get("evidence_root"), str)
            or not isinstance(external_gate.get("receipt"), dict)
            or set(external_gate["receipt"]) != {"path", "sha256", "bytes"}
        ):
            raise ConfigurationError("验收阶段缺少 candidate 外部门禁绑定。")
        identity = document.get("candidate_identity")
        if (
            not isinstance(identity, dict)
            or set(identity)
            != {
                "source_tree_sha256",
                "image_id",
                "image_reference",
                "build_id",
                "deployed_version",
                "candidate_purpose",
            }
            or not SHA256_RE.fullmatch(str(identity.get("source_tree_sha256", "")))
            or not IMAGE_ID_RE.fullmatch(str(identity.get("image_id", "")))
            or not IMMUTABLE_IMAGE_RE.fullmatch(str(identity.get("image_reference", "")))
            or identity.get("candidate_purpose") != document.get("candidate_purpose")
        ):
            raise ConfigurationError("验收阶段 candidate 身份投影非法。")
        if document.get("production_state") != "accepted_not_activated":
            raise ConfigurationError("验收阶段必须显式记录 accepted_not_activated。")


def save_stage_result(
    campaign_dir: Path,
    stage: str,
    payload: dict[str, Any],
    candidate_id: str | None = None,
    *,
    _successor_manifest: dict[str, Any] | None = None,
) -> Path:
    """封存阶段结果；同一阶段和候选编号永不覆盖。"""

    if _successor_manifest is None:
        manifest = _require_formal_campaign(campaign_dir)
    else:
        # successor 在未发布暂存区内需要先同时写入 official/classify 导入结果；
        # 此时历史场景的当前批准绑定尚未形成完整阶段闭环，不能提前走普通重放。
        stored_manifest = _read_json(
            campaign_dir / "campaign.json",
            "后继暂存 Campaign manifest",
        )
        if (
            stored_manifest != _successor_manifest
            or not isinstance(_successor_manifest.get("predecessor"), dict)
            or ".successor-" not in campaign_dir.name
        ):
            raise ConfigurationError("后继暂存 Campaign manifest 非法。")
        manifest = _require_formal_campaign(
            campaign_dir,
            _successor_manifest,
        )
    canonical, path = _stage_path(campaign_dir, stage, candidate_id)
    _reject_symlink_components(path.parent, campaign_dir, f"{canonical} 阶段目录")
    if path.exists():
        raise ConfigurationError(f"阶段结果已存在，禁止覆盖：{path}")
    if path.parent.exists() and path.parent.is_symlink():
        raise ConfigurationError(f"阶段目录不可信：{path.parent}")
    ensure_private_directory(path.parent, campaign_dir)
    document = dict(payload)
    for field in ("campaign_mode", "campaign_purpose"):
        provided = document.get(field)
        if provided is not None and provided != manifest[field]:
            raise ConfigurationError(f"阶段收据 {field} 与 Campaign 不一致。")
        document[field] = manifest[field]
    expected_candidate_purpose = (
        manifest["campaign_purpose"]
        if canonical in {"capture-candidate", "compare", "accept"}
        else None
    )
    if document.get("candidate_purpose") not in {
        None,
        expected_candidate_purpose,
    }:
        raise ConfigurationError("阶段收据 candidate purpose 与 Campaign 不一致。")
    document["candidate_purpose"] = expected_candidate_purpose
    evidence_roots = [Path(value) for value in document.get("evidence_roots", [])]
    has_evidence_manifest = isinstance(document.get("evidence_manifest"), dict)
    if canonical in {"capture-official", "capture-candidate"} and evidence_roots:
        if has_evidence_manifest:
            _stage_evidence_manifest(
                campaign_dir,
                document,
                verify_boundary=True,
            )
        else:
            document.setdefault("evidence_inventory", _evidence_inventory(evidence_roots))
            security = document.setdefault("security", _evidence_security(evidence_roots))
            if not security.get("known_secret_scan_passed"):
                raise ConfigurationError(f"{canonical} 证据秘密扫描未通过。")
    result_schema = document.pop("schema_version", None)
    document["schema_version"] = STAGE_SCHEMA
    if result_schema and result_schema != STAGE_SCHEMA:
        document["result_schema_version"] = result_schema
    document["stage"] = canonical
    document["campaign_id"] = manifest["campaign_id"]
    if candidate_id is not None:
        document["candidate_id"] = candidate_id
    document["campaign_manifest_sha256"] = file_sha256(
        campaign_dir / "campaign.json"
    )
    with _campaign_lock(campaign_dir):
        _reject_contaminated_campaign(campaign_dir)
        _reject_symlink_components(path.parent, campaign_dir, f"{canonical} 阶段目录")
        if path.exists() or path.is_symlink():
            raise ConfigurationError(f"阶段结果已存在，禁止覆盖：{path}")
        if canonical in {"capture-official", "capture-candidate"} and evidence_roots:
            if has_evidence_manifest:
                _stage_evidence_manifest(
                    campaign_dir,
                    document,
                    verify_boundary=True,
                )
            else:
                current_inventory = _evidence_inventory(evidence_roots)
                if current_inventory != document.get("evidence_inventory"):
                    raise ConfigurationError(
                        f"{canonical} 证据在封存审批后发生变化，禁止写入。"
                    )
                current_security = _evidence_security(evidence_roots)
                expected_security = document.get("security")
                if not isinstance(expected_security, dict) or any(
                    expected_security.get(key) != value
                    for key, value in current_security.items()
                ):
                    raise ConfigurationError(
                        f"{canonical} 证据秘密扫描结果在封存审批后发生变化。"
                    )
                if (
                    expected_security.get("raw_evidence_private") is not True
                    or not _evidence_permissions_private(evidence_roots)
                ):
                    raise ConfigurationError(
                        f"{canonical} 原始证据权限在封存审批后发生变化。"
                    )
        document["sealed_at_utc"] = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
        )
        _validate_stage_contract(document)
        document["package_digest"] = _fingerprint(document)
        _secure_write_json_once(path, document)
    return path


def _successor_copy_expectations(
    predecessor_dir: Path,
    predecessor_manifest: dict[str, Any],
    official: dict[str, Any],
    classification: dict[str, Any],
    *,
    include_classification: bool = True,
) -> dict[str, dict[str, Any]]:
    """重建后继 Campaign 必须逐字复制的完整文件闭集。"""

    expected: dict[str, dict[str, Any]] = {}

    def add(
        reference: Any,
        kind: str,
        *,
        target_relative: str | None = None,
    ) -> None:
        _require_file_binding(reference, f"前序 {kind}")
        source_relative = str(reference["path"])
        destination_relative = target_relative or source_relative
        source = _campaign_file(predecessor_dir, source_relative)
        if source.is_symlink() or not source.is_file():
            raise ConfigurationError(
                f"前序复制源不存在或不可信：{source_relative}"
            )
        digest = file_sha256(source)
        if digest != reference["sha256"]:
            raise ConfigurationError(
                f"前序复制源摘要漂移：{source_relative}"
            )
        row = {
            "kind": kind,
            "source_path": source_relative,
            "target_path": destination_relative,
            "sha256": digest,
            "bytes": source.stat().st_size,
        }
        previous = expected.get(destination_relative)
        if previous is not None and previous != row:
            raise ConfigurationError(
                "前序复制闭集出现路径摘要冲突：" + destination_relative
            )
        expected.setdefault(destination_relative, row)

    for group_name in ("inputs", "analysis"):
        for reference in predecessor_manifest[group_name].values():
            if reference is not None:
                add(reference, f"plan_{group_name}")
    if include_classification:
        for field in _CLASSIFICATION_APPROVAL_FIELDS:
            add(classification.get(field), "approved_classification")
    add(
        official.get("surface"),
        "official_surface",
        target_relative=_SUCCESSOR_OFFICIAL_SURFACE_PATH,
    )
    return expected


def _validate_direct_predecessor_official_attempt(
    predecessor_dir: Path,
    predecessor_official: dict[str, Any],
) -> None:
    """重放直接前序的官方 attempt 与原子预约。

    若前序 official 自身来自更早 Campaign，调用方已通过递归
    ``_load_stage_result`` 在其原始绝对目录完成相同校验；不得把投影结果中保留的
    上游相对 attempt 路径再次拼到当前前序目录。
    """

    attempt_reference = predecessor_official.get("attempt")
    _require_file_binding(attempt_reference, "前序官方 attempt")
    attempt_path = _campaign_file(predecessor_dir, attempt_reference["path"])
    attempt_root, attempt = _load_capture_attempt(
        predecessor_dir,
        "official",
        None,
        attempt_path.parent.name,
    )
    reservation = _load_capture_reservation(
        predecessor_dir,
        attempt_root,
        phase="official",
        candidate_id=None,
    )
    planned = {
        item["id"]: item
        for item in reservation["planned_jobs"]
        if item["required"]
    }
    completed = {
        item.get("id"): item
        for item in predecessor_official.get("results", [])
        if isinstance(item, dict)
    }
    if any(
        job_id not in completed
        or completed[job_id].get("status") != "complete"
        or completed[job_id].get("execution_sha256")
        != planned_job["execution_sha256"]
        for job_id, planned_job in planned.items()
    ) or attempt.get("results") != predecessor_official.get("results"):
        raise ConfigurationError("前序官方任务未按原子预约完整执行或结果漂移。")


def _validate_predecessor_import_receipt(
    campaign_dir: Path,
    manifest: dict[str, Any],
    stage_payload: dict[str, Any],
    canonical: str,
    import_chain: frozenset[Path],
    *,
    import_cache: dict[tuple[str, str, str | None], dict[str, Any]] | None = None,
    skip_evidence_scan: bool = False,
) -> dict[str, Any]:
    """重放前序 Campaign、官方证据、安全门禁和批准五件套。"""

    import_binding = stage_payload.get("predecessor_import")
    _verify_campaign_binding(campaign_dir, import_binding, "前序导入收据")
    import_path = _campaign_file(campaign_dir, import_binding["path"])
    receipt = _read_json(import_path, "前序导入收据")
    receipt_schema = receipt.get("schema_version")
    expected_receipt_fields = {
        "schema_version",
        "created_at_utc",
        "reason",
        "successor_campaign_id",
        "successor_campaign_manifest_sha256",
        "predecessor_campaign",
        "stages",
        "copied_files",
        "abandoned_candidate_attempt",
        "receipt_digest",
    }
    if receipt_schema in {
        PREDECESSOR_IMPORT_SCHEMA,
        PREDECESSOR_RECLASSIFICATION_IMPORT_SCHEMA,
        PREDECESSOR_RUNTIME_IMPORT_SCHEMA,
        PREDECESSOR_REHEARSAL_IMPORT_SCHEMA,
        PREDECESSOR_RECOVERY_IMPORT_SCHEMA,
    }:
        expected_receipt_fields.add("configuration_transition")
    if receipt_schema in {
        PREDECESSOR_REHEARSAL_IMPORT_SCHEMA,
        PREDECESSOR_RECOVERY_IMPORT_SCHEMA,
    }:
        expected_receipt_fields.add("job_rehearsal_transition")
    if receipt_schema == PREDECESSOR_RECOVERY_IMPORT_SCHEMA:
        expected_receipt_fields.add("recovery_control_transition")
    if receipt_schema == PREDECESSOR_RECLASSIFICATION_IMPORT_SCHEMA or (
        receipt_schema in {
            PREDECESSOR_REHEARSAL_IMPORT_SCHEMA,
            PREDECESSOR_RECOVERY_IMPORT_SCHEMA,
        }
        and receipt.get("reason") in RECLASSIFICATION_SUCCESSOR_REASONS
    ):
        expected_receipt_fields.add("import_mode")
    unsigned_receipt = dict(receipt)
    receipt_digest = unsigned_receipt.pop("receipt_digest", None)
    if (
        set(receipt) != expected_receipt_fields
        or receipt_schema
        not in {
            PREDECESSOR_IMPORT_SCHEMA_V1,
            PREDECESSOR_IMPORT_SCHEMA,
            PREDECESSOR_RECLASSIFICATION_IMPORT_SCHEMA,
            PREDECESSOR_RUNTIME_IMPORT_SCHEMA,
            PREDECESSOR_REHEARSAL_IMPORT_SCHEMA,
            PREDECESSOR_RECOVERY_IMPORT_SCHEMA,
        }
        or not _is_rfc3339_timestamp(receipt.get("created_at_utc"))
        or receipt.get("reason") not in SUCCESSOR_REASONS
        or receipt.get("successor_campaign_id") != manifest["campaign_id"]
        or receipt.get("successor_campaign_manifest_sha256")
        != file_sha256(campaign_dir / "campaign.json")
        or not SHA256_RE.fullmatch(str(receipt_digest))
        or _fingerprint(unsigned_receipt) != receipt_digest
    ):
        raise ConfigurationError("前序导入收据身份、时间或摘要非法。")
    reclassification_import = receipt_schema in {
        PREDECESSOR_RECLASSIFICATION_IMPORT_SCHEMA,
        PREDECESSOR_REHEARSAL_IMPORT_SCHEMA,
        PREDECESSOR_RECOVERY_IMPORT_SCHEMA,
    } and receipt.get("reason") in RECLASSIFICATION_SUCCESSOR_REASONS
    if reclassification_import:
        if (
            receipt.get("reason") not in RECLASSIFICATION_SUCCESSOR_REASONS
            or receipt.get("import_mode")
            != "official_only_reclassification"
            or canonical != "capture-official"
        ):
            raise ConfigurationError("分类纠正后继的导入模式或阶段边界非法。")
    elif receipt.get("reason") in RECLASSIFICATION_SUCCESSOR_REASONS:
        raise ConfigurationError("分类纠正后继必须使用 official-only 受管收据。")

    manifest_predecessor = manifest.get("predecessor")
    predecessor_binding = receipt.get("predecessor_campaign")
    if (
        not isinstance(manifest_predecessor, dict)
        or not isinstance(predecessor_binding, dict)
        or set(predecessor_binding)
        != {"campaign_dir", "campaign_id", "campaign_manifest_sha256"}
        or manifest_predecessor
        != {
            **predecessor_binding,
            "reason": receipt["reason"],
        }
    ):
        raise ConfigurationError("前序导入收据与 Campaign 前序绑定不一致。")
    predecessor_dir = Path(str(predecessor_binding["campaign_dir"]))
    if (
        not predecessor_dir.is_absolute()
        or str(predecessor_dir.resolve()) != str(predecessor_dir)
        or predecessor_dir.resolve() in import_chain
        or predecessor_dir.resolve() == campaign_dir.resolve()
    ):
        raise ConfigurationError("前序 Campaign 路径不可信或导入链形成循环。")
    _validate_existing_campaign_path(predecessor_dir)
    predecessor_manifest = _require_formal_campaign(predecessor_dir)
    if (
        predecessor_binding.get("campaign_id")
        != predecessor_manifest.get("campaign_id")
        or predecessor_binding.get("campaign_manifest_sha256")
        != file_sha256(predecessor_dir / "campaign.json")
    ):
        raise ConfigurationError("前序 Campaign 清单身份或摘要漂移。")

    predecessor_controls = predecessor_manifest.get("control_receipts")
    successor_controls = manifest.get("control_receipts")
    predecessor_rehearsal = (
        predecessor_controls.get("job_rehearsal")
        if isinstance(predecessor_controls, dict)
        else None
    )
    successor_rehearsal = (
        successor_controls.get("job_rehearsal")
        if isinstance(successor_controls, dict)
        else None
    )
    if not isinstance(predecessor_rehearsal, dict) or not isinstance(
        successor_rehearsal, dict
    ):
        raise ConfigurationError("前序或后继 Campaign 缺少完整 Job 演练绑定。")
    if receipt_schema in {
        PREDECESSOR_REHEARSAL_IMPORT_SCHEMA,
        PREDECESSOR_RECOVERY_IMPORT_SCHEMA,
    }:
        expected_rehearsal_transition = {
            "reason": "current_execution_contract_rehearsal",
            "predecessor": predecessor_rehearsal,
            "successor": successor_rehearsal,
        }
        if (
            receipt.get("job_rehearsal_transition")
            != expected_rehearsal_transition
            or predecessor_rehearsal == successor_rehearsal
        ):
            raise ConfigurationError("后继完整 Job 演练过渡收据非法。")
    elif successor_rehearsal != predecessor_rehearsal:
        raise ConfigurationError("后继未登记完整 Job 演练绑定变化。")

    predecessor_timing = (
        predecessor_controls.get("upgrade_timing")
        if isinstance(predecessor_controls, dict)
        else None
    )
    predecessor_arm = (
        predecessor_controls.get("arm64_environment")
        if isinstance(predecessor_controls, dict)
        else None
    )
    successor_timing = (
        successor_controls.get("upgrade_timing")
        if isinstance(successor_controls, dict)
        else None
    )
    successor_arm = (
        successor_controls.get("arm64_environment")
        if isinstance(successor_controls, dict)
        else None
    )
    if not all(
        isinstance(value, dict)
        for value in (
            predecessor_timing,
            predecessor_arm,
            successor_timing,
            successor_arm,
        )
    ):
        raise ConfigurationError("前序或后继 Campaign 的计时／ARM64 控制绑定非法。")
    if receipt_schema == PREDECESSOR_RECOVERY_IMPORT_SCHEMA:
        control_transition = receipt.get("recovery_control_transition")
        if (
            not isinstance(control_transition, dict)
            or set(control_transition)
            != {"reason", "predecessor", "stop_checkpoint", "successor"}
            or control_transition.get("reason") != "stopped_ledger_recovery"
            or control_transition.get("predecessor")
            != {
                "upgrade_timing": predecessor_timing,
                "arm64_environment": predecessor_arm,
            }
            or control_transition.get("successor")
            != {
                "upgrade_timing": successor_timing,
                "arm64_environment": successor_arm,
            }
            or predecessor_timing == successor_timing
            or predecessor_arm == successor_arm
        ):
            raise ConfigurationError("后继恢复控制过渡收据非法。")
        stop_binding = control_transition.get("stop_checkpoint")
        if not isinstance(stop_binding, dict) or set(stop_binding) != {
            "ledger_dir",
            "receipt",
            "upgrade_id",
            "active_phase",
            "head_sequence",
            "head_sha256",
            "total_elapsed_seconds",
            "total_live_request_count",
        }:
            raise ConfigurationError("后继恢复停线绑定字段不闭合。")
        stop_root = Path(str(stop_binding.get("ledger_dir", "")))
        stop_receipt = stop_binding.get("receipt")
        if (
            not isinstance(stop_receipt, dict)
            or set(stop_receipt) != {"path", "sha256", "bytes"}
            or not stop_root.is_absolute()
            or str(stop_root.resolve()) != str(stop_root)
            or str(predecessor_timing.get("ledger_dir", "")) != str(stop_root)
        ):
            raise ConfigurationError("后继恢复停线坐标非法。")
        try:
            stop_relative = _control_receipt_relative(
                stop_root,
                Path(str(stop_receipt.get("path", ""))),
                "后继恢复停线 checkpoint",
            )
            stop_path = stop_root / stop_relative
            stop_checkpoint = codex_upgrade_timing_ledger.replay(
                stop_root,
                stop_relative,
            )
        except (OSError, codex_upgrade_timing_ledger.TimingLedgerError) as error:
            raise ConfigurationError(f"后继恢复停线 checkpoint 未通过：{error}") from error
        stop_summary = stop_checkpoint.get("summary")
        expected_stop = {
            "ledger_dir": str(stop_root),
            "receipt": {
                "path": stop_relative,
                "sha256": file_sha256(stop_path),
                "bytes": stop_path.stat().st_size,
            },
            "upgrade_id": stop_summary.get("upgrade_id"),
            "active_phase": stop_summary.get("active_phase"),
            "head_sequence": stop_summary.get("head_sequence"),
            "head_sha256": stop_summary.get("head_sha256"),
            "total_elapsed_seconds": stop_summary.get("total_elapsed_seconds"),
            "total_live_request_count": stop_summary.get(
                "total_live_request_count"
            ),
        }
        if (
            not isinstance(stop_summary, dict)
            or stop_summary.get("status") != "stopped"
            or stop_binding != expected_stop
            or stop_summary.get("upgrade_id")
            != predecessor_timing.get("upgrade_id")
            or stop_summary.get("active_phase")
            not in codex_upgrade_timing_ledger.PHASE_ORDER[1:]
        ):
            raise ConfigurationError("后继恢复停线 checkpoint 事实非法。")
    elif (
        successor_timing != predecessor_timing
        or successor_arm != predecessor_arm
    ):
        raise ConfigurationError("后继未登记计时／ARM64 控制绑定变化。")

    invariant_fields = (
        "campaign_mode",
        "campaign_purpose",
        "baseline_version",
        "target_version",
        "target_sha256",
        "suite",
        "official_identity",
        "baseline_identity",
        "inputs",
        "analysis",
        "required_rules",
    )
    mismatches = [
        field
        for field in invariant_fields
        if manifest.get(field) != predecessor_manifest.get(field)
    ]
    if mismatches:
        raise ConfigurationError(
            "同版本后继 Campaign 改变了禁止承接的前序坐标："
            + "、".join(mismatches)
        )

    predecessor_configuration = predecessor_manifest.get("configuration")
    successor_configuration = manifest.get("configuration")
    if not isinstance(predecessor_configuration, dict) or not isinstance(
        successor_configuration, dict
    ):
        raise ConfigurationError("同版本后继 Campaign 配置不是对象。")
    predecessor_account_id = predecessor_configuration.get("codex_account_id")
    successor_account_id = successor_configuration.get("codex_account_id")
    runtime_fields = (
        "live_attestation_compose_dir",
        "live_attestation_compose_files",
    )
    runtime_configuration_changed = any(
        str(predecessor_configuration.get(field, "") or "")
        != str(successor_configuration.get(field, "") or "")
        for field in runtime_fields
    )
    allowed_configuration_fields = {"codex_account_id"}
    if receipt_schema == PREDECESSOR_RUNTIME_IMPORT_SCHEMA or (
        receipt_schema
        in {
            PREDECESSOR_REHEARSAL_IMPORT_SCHEMA,
            PREDECESSOR_RECOVERY_IMPORT_SCHEMA,
        }
        and runtime_configuration_changed
    ):
        allowed_configuration_fields.update(runtime_fields)
    predecessor_fixed_configuration = dict(predecessor_configuration)
    successor_fixed_configuration = dict(successor_configuration)
    for field in allowed_configuration_fields:
        predecessor_fixed_configuration.pop(field, None)
        successor_fixed_configuration.pop(field, None)
    if predecessor_fixed_configuration != successor_fixed_configuration:
        raise ConfigurationError("同版本后继 Campaign 改变了未授权的运行配置。")
    if receipt_schema == PREDECESSOR_IMPORT_SCHEMA_V1:
        if successor_account_id != predecessor_account_id:
            raise ConfigurationError("历史 v1 后继收据不允许改变 Codex 账号。")
    else:
        configuration_transition = receipt.get("configuration_transition")
        expected_transition: dict[str, Any] = {
            "codex_account_id": {
                "predecessor": predecessor_account_id,
                "successor": successor_account_id,
                "reason": "operator_selected_active_account",
            }
        }
        if receipt_schema == PREDECESSOR_RUNTIME_IMPORT_SCHEMA or (
            receipt_schema
            in {
                PREDECESSOR_REHEARSAL_IMPORT_SCHEMA,
                PREDECESSOR_RECOVERY_IMPORT_SCHEMA,
            }
            and runtime_configuration_changed
        ):
            if receipt.get("reason") != "candidate_runtime_identity_correction":
                raise ConfigurationError("后继收据原因不是运行时身份纠正。")
            successor_runtime_configuration = {
                field: str(successor_configuration.get(field, "") or "")
                for field in runtime_fields
            }
            try:
                validated_runtime_configuration = _successor_runtime_configuration(
                    argparse.Namespace(
                        live_attestation_compose_dir=Path(
                            successor_runtime_configuration[
                                "live_attestation_compose_dir"
                            ]
                        ),
                        live_attestation_compose_files=(
                            successor_runtime_configuration[
                                "live_attestation_compose_files"
                            ]
                        ),
                        reason="candidate_runtime_identity_correction",
                    ),
                    predecessor_configuration,
                )
            except ConfigurationError as error:
                raise ConfigurationError(
                    "后继 Campaign 的 compose 坐标非法。"
                ) from error
            if validated_runtime_configuration != successor_runtime_configuration:
                raise ConfigurationError("后继 Campaign 的 compose 坐标漂移。")
            expected_transition.update(
                {
                    field: {
                        "predecessor": str(
                            predecessor_configuration.get(field, "") or ""
                        ),
                        "successor": value,
                        "reason": "candidate_runtime_identity_correction",
                    }
                    for field, value in successor_runtime_configuration.items()
                }
            )
        if (
            isinstance(predecessor_account_id, bool)
            or not isinstance(predecessor_account_id, int)
            or predecessor_account_id <= 0
            or isinstance(successor_account_id, bool)
            or not isinstance(successor_account_id, int)
            or successor_account_id <= 0
            or configuration_transition != expected_transition
        ):
            raise ConfigurationError("后继 Campaign 的运行配置过渡收据非法。")

    next_chain = frozenset({*import_chain, campaign_dir.resolve()})
    cache = import_cache if import_cache is not None else {}

    def load_predecessor_stage(stage: str) -> dict[str, Any]:
        key = (str(predecessor_dir.resolve()), stage, None)
        cached = cache.get(key)
        if cached is not None:
            return dict(cached)
        loaded = _load_stage_result(
            predecessor_dir,
            stage,
            _import_chain=next_chain,
            _replay_machine_receipts=(stage != "capture-official"),
            _import_cache=cache,
            _skip_evidence_scan=skip_evidence_scan,
        )
        cache[key] = dict(loaded)
        return loaded

    predecessor_official = load_predecessor_stage("capture-official")
    predecessor_classification = load_predecessor_stage("classify")
    if (
        predecessor_official.get("status") != "complete"
        or predecessor_classification.get("status") != "complete"
        or predecessor_classification.get("migration", {}).get(
            "unclassified_count"
        )
        != 0
    ):
        raise ConfigurationError("前序官方阶段或批准分类已不满足完整承接条件。")

    stage_receipts = receipt.get("stages")
    if not isinstance(stage_receipts, dict) or set(stage_receipts) != {
        "capture-official",
        "classify",
    }:
        raise ConfigurationError("前序导入收据阶段闭集非法。")
    stage_expectations = {
        "capture-official": {
            "path": "official/result.json",
            "sha256": file_sha256(predecessor_dir / "official" / "result.json"),
            "package_digest": predecessor_official["package_digest"],
            "evidence_inventory_digest": predecessor_official[
                "evidence_inventory"
            ]["digest"],
            "security_sha256": _fingerprint(predecessor_official["security"]),
        },
        "classify": {
            "path": "classification/result.json",
            "sha256": file_sha256(
                predecessor_dir / "classification" / "result.json"
            ),
            "package_digest": predecessor_classification["package_digest"],
            "joint_manifest_sha256": predecessor_classification[
                "joint_manifest_sha256"
            ],
        },
    }
    if stage_receipts != stage_expectations:
        raise ConfigurationError("前序导入收据的阶段摘要或证据门禁发生漂移。")

    copied = receipt.get("copied_files")
    if not isinstance(copied, list):
        raise ConfigurationError("前序导入收据缺少复制文件闭集。")
    expected_copies = _successor_copy_expectations(
        predecessor_dir,
        predecessor_manifest,
        predecessor_official,
        predecessor_classification,
        include_classification=not reclassification_import,
    )
    copied_index: dict[str, dict[str, Any]] = {}
    for row in copied:
        if (
            not isinstance(row, dict)
            or set(row)
            != {
                "kind",
                "source_path",
                "target_path",
                "sha256",
                "bytes",
            }
            or not isinstance(row.get("source_path"), str)
            or not isinstance(row.get("target_path"), str)
            or row["target_path"] in copied_index
        ):
            raise ConfigurationError("前序导入复制文件条目非法或重复。")
        copied_index[row["target_path"]] = row
    if copied_index != expected_copies:
        raise ConfigurationError("前序导入复制文件闭集不完整或摘要漂移。")
    for relative, row in copied_index.items():
        target = _campaign_file(campaign_dir, relative)
        if (
            target.is_symlink()
            or not target.is_file()
            or file_sha256(target) != row["sha256"]
            or target.stat().st_size != row["bytes"]
        ):
            raise ConfigurationError(f"后继 Campaign 复制文件漂移：{relative}")

    abandoned = receipt.get("abandoned_candidate_attempt")
    if abandoned is not None:
        if (
            not isinstance(abandoned, dict)
            or set(abandoned)
            != {
                "candidate_id",
                "attempt_id",
                "path",
                "sha256",
                "attempt_digest",
                "identity_sha256",
                "status",
            }
        ):
            raise ConfigurationError("前序放弃 attempt 绑定结构非法。")
        attempt_root, attempt = _load_capture_attempt(
            predecessor_dir,
            "candidate",
            str(abandoned.get("candidate_id", "")),
            str(abandoned.get("attempt_id", "")),
        )
        expected_abandoned = {
            "candidate_id": attempt["candidate_id"],
            "attempt_id": attempt["attempt_id"],
            "path": (attempt_root / "attempt.json")
            .relative_to(predecessor_dir)
            .as_posix(),
            "sha256": file_sha256(attempt_root / "attempt.json"),
            "attempt_digest": attempt["attempt_digest"],
            "identity_sha256": _fingerprint(attempt["identity"]),
            "status": attempt["status"],
        }
        if abandoned != expected_abandoned:
            raise ConfigurationError("前序放弃 attempt 身份或摘要漂移。")

    # 直接前序必须按其原始预约坐标重放；import 前序已经在递归加载时于自身
    # 原始绝对目录完成相同校验，不能把上游相对路径重新解释到当前目录。
    if predecessor_official.get("predecessor_import") is None:
        _validate_direct_predecessor_official_attempt(
            predecessor_dir,
            predecessor_official,
        )

    predecessor_stage = (
        predecessor_official
        if canonical == "capture-official"
        else predecessor_classification
    )
    if stage_payload.get("predecessor_package_digest") != predecessor_stage.get(
        "package_digest"
    ):
        raise ConfigurationError("导入阶段未绑定前序阶段 package digest。")
    projected = dict(predecessor_stage)
    for field in (
        "schema_version",
        "stage",
        "campaign_id",
        "campaign_mode",
        "campaign_purpose",
        "candidate_purpose",
        "campaign_manifest_sha256",
        "sealed_at_utc",
        "package_digest",
        "status",
        "predecessor_import",
        "predecessor_package_digest",
    ):
        projected[field] = stage_payload[field]
    if canonical == "capture-official":
        projected["surface"] = stage_payload["surface"]
    else:
        for field in (
            *_CLASSIFICATION_APPROVAL_FIELDS,
            "joint_manifest_sha256",
            "baseline_rule_count",
            "target_rule_count",
            "migration",
            "source_diff_sha256",
            "official_diff_sha256",
        ):
            projected[field] = stage_payload[field]
    _validate_stage_contract(projected)
    return projected


def _verify_predecessor_import_shallow(
    campaign_dir: Path,
    manifest: Mapping[str, Any],
    payload: Mapping[str, Any],
) -> None:
    """只验证本 Campaign 的导入摘要，不打开前序目录。"""

    binding = payload.get("predecessor_import")
    _verify_campaign_binding(campaign_dir, binding, "前序导入收据")
    receipt_path = _campaign_file(campaign_dir, str(binding["path"]))
    receipt = _read_json(receipt_path, "前序导入收据")
    unsigned = dict(receipt)
    digest = unsigned.pop("receipt_digest", None)
    predecessor = manifest.get("predecessor")
    predecessor_binding = receipt.get("predecessor_campaign")
    if (
        not isinstance(predecessor, dict)
        or not isinstance(predecessor_binding, dict)
        or predecessor
        != {
            **predecessor_binding,
            "reason": receipt.get("reason"),
        }
        or receipt.get("successor_campaign_id") != manifest.get("campaign_id")
        or receipt.get("successor_campaign_manifest_sha256")
        != file_sha256(campaign_dir / "campaign.json")
        or not SHA256_RE.fullmatch(str(digest))
        or digest != _fingerprint(unsigned)
    ):
        raise ConfigurationError("前序导入收据的本地摘要链不一致。")


def _imported_stage_checkpoint_path(
    campaign_dir: Path,
    canonical: str,
    candidate_id: str | None,
) -> Path:
    suffix = canonical if candidate_id is None else f"{canonical}-{candidate_id}"
    return campaign_dir / "verification-checkpoints" / f"{suffix}.json"


def _load_imported_stage_checkpoint(
    campaign_dir: Path,
    canonical: str,
    candidate_id: str | None,
    local_payload: Mapping[str, Any],
) -> dict[str, Any] | None:
    path = _imported_stage_checkpoint_path(campaign_dir, canonical, candidate_id)
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise ConfigurationError("导入阶段 checkpoint 路径不可信。")
    payload = _read_json(path, "导入阶段 checkpoint")
    unsigned = dict(payload)
    digest = unsigned.pop("checkpoint_digest", None)
    projected = payload.get("projected_stage")
    _, local_stage_path = _stage_path(campaign_dir, canonical, candidate_id)
    import_binding = local_payload.get("predecessor_import")
    _require_file_binding(import_binding, "前序导入收据")
    import_path = _campaign_file(campaign_dir, str(import_binding["path"]))
    if (
        set(payload)
        != {
            "schema_version",
            "created_at_utc",
            "campaign_id",
            "campaign_manifest_sha256",
            "stage",
            "candidate_id",
            "local_stage_sha256",
            "predecessor_import_sha256",
            "projected_stage",
            "projected_stage_sha256",
            "checkpoint_digest",
        }
        or payload.get("schema_version") != IMPORTED_STAGE_CHECKPOINT_SCHEMA
        or payload.get("campaign_id")
        != load_campaign_manifest(campaign_dir).get("campaign_id")
        or payload.get("campaign_manifest_sha256")
        != file_sha256(campaign_dir / "campaign.json")
        or payload.get("stage") != canonical
        or payload.get("candidate_id") != candidate_id
        or payload.get("local_stage_sha256") != file_sha256(local_stage_path)
        or payload.get("predecessor_import_sha256") != file_sha256(import_path)
        or not isinstance(projected, dict)
        or payload.get("projected_stage_sha256") != _fingerprint(projected)
        or digest != _fingerprint(unsigned)
    ):
        raise ConfigurationError("导入阶段 checkpoint 身份或摘要不一致。")
    _validate_stage_contract(projected)
    if canonical == "capture-official" and projected.get("evidence_manifest") is not None:
        _stage_evidence_manifest(
            campaign_dir,
            projected,
            verify_boundary=True,
        )
    return dict(projected)


def _write_imported_stage_checkpoint(
    campaign_dir: Path,
    canonical: str,
    candidate_id: str | None,
    local_payload: Mapping[str, Any],
    projected: Mapping[str, Any],
) -> Path:
    existing_path = _imported_stage_checkpoint_path(
        campaign_dir,
        canonical,
        candidate_id,
    )
    if existing_path.exists() or existing_path.is_symlink():
        existing = _load_imported_stage_checkpoint(
            campaign_dir,
            canonical,
            candidate_id,
            local_payload,
        )
        if existing != dict(projected):
            raise ConfigurationError("导入阶段 checkpoint 与当前显式复验结果不一致。")
        return existing_path
    _, local_stage_path = _stage_path(campaign_dir, canonical, candidate_id)
    import_binding = local_payload.get("predecessor_import")
    _require_file_binding(import_binding, "前序导入收据")
    import_path = _campaign_file(campaign_dir, str(import_binding["path"]))
    core: dict[str, Any] = {
        "schema_version": IMPORTED_STAGE_CHECKPOINT_SCHEMA,
        "created_at_utc": _utc_now(),
        "campaign_id": load_campaign_manifest(campaign_dir)["campaign_id"],
        "campaign_manifest_sha256": file_sha256(campaign_dir / "campaign.json"),
        "stage": canonical,
        "candidate_id": candidate_id,
        "local_stage_sha256": file_sha256(local_stage_path),
        "predecessor_import_sha256": file_sha256(import_path),
        "projected_stage": dict(projected),
        "projected_stage_sha256": _fingerprint(projected),
    }
    checkpoint = {**core, "checkpoint_digest": _fingerprint(core)}
    path = existing_path
    ensure_private_directory(path.parent, campaign_dir)
    _write_or_verify_json(path, checkpoint)
    return path


def _load_stage_result(
    campaign_dir: Path,
    stage: str,
    candidate_id: str | None = None,
    *,
    _import_chain: frozenset[Path] | None = None,
    _replay_machine_receipts: bool = True,
    _shallow: bool = False,
    _ignore_checkpoint: bool = False,
    _import_cache: dict[tuple[str, str, str | None], dict[str, Any]] | None = None,
    _skip_evidence_scan: bool = False,
) -> dict[str, Any]:
    campaign_manifest = _require_formal_campaign(campaign_dir)
    canonical, path = _stage_path(campaign_dir, stage, candidate_id)
    _reject_symlink_components(path, campaign_dir, f"{canonical} 阶段结果")
    if not path.is_file() or path.is_symlink():
        raise ConfigurationError(f"阶段尚未封存：{canonical}")
    payload = _read_json(path, f"{canonical} 阶段结果")
    expected = payload.get("package_digest")
    unsigned = dict(payload)
    unsigned.pop("package_digest", None)
    if not SHA256_RE.fullmatch(str(expected)) or _fingerprint(unsigned) != expected:
        raise ConfigurationError(f"{canonical} 阶段结果摘要不一致。")
    if payload.get("campaign_manifest_sha256") != file_sha256(
        campaign_dir / "campaign.json"
    ):
        raise ConfigurationError(f"{canonical} 未绑定当前 Campaign。")
    if (
        payload.get("stage") != canonical
        or payload.get("campaign_id") != campaign_manifest.get("campaign_id")
        or payload.get("campaign_mode") != campaign_manifest.get("campaign_mode")
        or payload.get("campaign_purpose")
        != campaign_manifest.get("campaign_purpose")
    ):
        raise ConfigurationError(f"{canonical} 阶段身份与路径不一致。")
    candidate_stage = canonical in {"capture-candidate", "compare", "accept"}
    if candidate_stage and payload.get("candidate_id") != candidate_id:
        raise ConfigurationError(f"{canonical} candidate-id 与路径不一致。")
    if not candidate_stage and "candidate_id" in payload:
        raise ConfigurationError(f"{canonical} 不得携带 candidate-id。")
    expected_candidate_purpose = (
        campaign_manifest.get("campaign_purpose") if candidate_stage else None
    )
    if payload.get("candidate_purpose") != expected_candidate_purpose:
        raise ConfigurationError(f"{canonical} candidate purpose 与 Campaign 不一致。")
    _validate_stage_contract(payload)
    if _shallow:
        if payload.get("predecessor_import") is not None:
            _verify_predecessor_import_shallow(
                campaign_dir,
                campaign_manifest,
                payload,
            )
        elif canonical in {"capture-official", "capture-candidate"}:
            _verify_campaign_binding(campaign_dir, payload.get("attempt"), "抓包 attempt")
            _verify_campaign_binding(campaign_dir, payload.get("seal_preview"), "seal 预览")
            if payload.get("evaluation_transition") is not None:
                _verify_campaign_binding(
                    campaign_dir,
                    payload.get("evaluation_transition"),
                    "评估工具 transition",
                )
            if payload.get("evidence_manifest") is not None:
                _stage_evidence_manifest(
                    campaign_dir,
                    payload,
                    verify_boundary=False,
                )
        elif canonical == "classify" and payload.get("status") in {
            "complete",
            "blocked",
        }:
            for field in (
                "target_rule_manifest",
                "migration_manifest",
                "scenario_manifest",
                "profile_manifest",
                "assertion_profile_manifest",
            ):
                _verify_campaign_binding(campaign_dir, payload.get(field), field)
        elif canonical == "accept" and payload.get("status") == "complete":
            candidate = _load_stage_result(
                campaign_dir,
                "capture-candidate",
                candidate_id,
                _replay_machine_receipts=False,
                _shallow=True,
            )
            _replay_bound_candidate_external_gate(
                payload.get("candidate_external_gate"),
                manifest=campaign_manifest,
                candidate_id=str(candidate_id),
                candidate=candidate,
            )
            _verify_campaign_binding(
                campaign_dir,
                payload.get("assertion_result"),
                "逐规则断言结果",
            )
            _verify_campaign_binding(
                campaign_dir,
                payload.get("evidence_seal"),
                "验收证据封印",
            )
        return payload
    if payload.get("predecessor_import") is not None:
        if not _ignore_checkpoint:
            checkpoint = _load_imported_stage_checkpoint(
                campaign_dir,
                canonical,
                candidate_id,
                payload,
            )
            if checkpoint is not None:
                return checkpoint
        projected = _validate_predecessor_import_receipt(
            campaign_dir,
            campaign_manifest,
            payload,
            canonical,
            _import_chain or frozenset(),
            import_cache=_import_cache,
            skip_evidence_scan=_skip_evidence_scan,
        )
        return projected
    if canonical in {"capture-official", "capture-candidate"}:
        _verify_campaign_binding(campaign_dir, payload.get("attempt"), "抓包 attempt")
        _verify_campaign_binding(
            campaign_dir, payload.get("seal_preview"), "seal 预览"
        )
        if payload.get("evaluation_transition") is not None:
            _verify_campaign_binding(
                campaign_dir,
                payload.get("evaluation_transition"),
                "评估工具 transition",
            )
        _verify_capture_seal_preview(campaign_dir, payload, canonical)
        if _replay_machine_receipts:
            _replay_capture_stage_receipts(campaign_dir, payload, canonical)
        if _skip_evidence_scan:
            if payload.get("evidence_manifest") is not None:
                _stage_evidence_manifest(
                    campaign_dir,
                    payload,
                    verify_boundary=True,
                )
        else:
            _verify_stage_evidence(
                payload,
                "官方" if canonical == "capture-official" else "候选",
                campaign_dir=campaign_dir,
            )
    if canonical == "classify" and payload.get("status") in {"complete", "blocked"}:
        fields = (
            "target_rule_manifest",
            "migration_manifest",
            "scenario_manifest",
            "profile_manifest",
            "assertion_profile_manifest",
        )
        for field in fields:
            _verify_campaign_binding(campaign_dir, payload.get(field), field)
        expected_joint = _fingerprint(
            {field: payload[field]["sha256"] for field in fields}
        )
        if payload.get("joint_manifest_sha256") != expected_joint:
            raise ConfigurationError("分类五件套联合摘要不一致。")
    if canonical == "accept" and payload.get("status") == "complete":
        candidate = _load_stage_result(
            campaign_dir,
            "capture-candidate",
            candidate_id,
        )
        _replay_bound_candidate_external_gate(
            payload.get("candidate_external_gate"),
            manifest=campaign_manifest,
            candidate_id=str(candidate_id),
            candidate=candidate,
        )
        seal_path = _campaign_file(
            campaign_dir,
            str(payload["evidence_seal"]["path"]),
        )
        seal = _read_json(seal_path, "验收证据封印")
        expected_seal_coordinates = {
            "campaign_mode": payload.get("campaign_mode"),
            "campaign_purpose": payload.get("campaign_purpose"),
            "candidate_purpose": payload.get("candidate_purpose"),
            "production_state": payload.get("production_state"),
            "candidate_external_gate": payload.get("candidate_external_gate"),
        }
        if any(
            seal.get(field) != value
            for field, value in expected_seal_coordinates.items()
        ):
            raise ConfigurationError("验收证据封印的用途、状态或外部门禁绑定不一致。")
    return payload


def _verify_campaign_binding(
    campaign_dir: Path,
    reference: Any,
    label: str,
) -> None:
    _require_file_binding(reference, label)
    path = _campaign_file(campaign_dir, reference["path"])
    if path.is_symlink() or not path.is_file() or file_sha256(path) != reference["sha256"]:
        raise ConfigurationError(f"{label}在封存后漂移或丢失。")


def _verify_capture_seal_preview(
    campaign_dir: Path,
    stage: dict[str, Any],
    canonical: str,
) -> None:
    """证明阶段 payload 仍是人工批准的同一组机器事实。"""

    phase = "candidate" if canonical == "capture-candidate" else "official"
    candidate_id = stage.get("candidate_id") if phase == "candidate" else None
    attempt_path = _campaign_file(
        campaign_dir,
        str(stage["attempt"]["path"]),
    )
    attempt_payload = _read_json(attempt_path, "抓包 attempt")
    attempt_id = attempt_payload.get("attempt_id")
    if not isinstance(attempt_id, str):
        raise ConfigurationError("抓包 attempt 缺少 attempt-id。")
    attempt_root, attempt = _load_capture_attempt(
        campaign_dir,
        phase,
        candidate_id,
        attempt_id,
    )
    preview_path = _campaign_file(
        campaign_dir,
        str(stage["seal_preview"]["path"]),
    )
    if preview_path.parent != attempt_root:
        raise ConfigurationError("seal 预览与抓包 attempt 不在同一目录。")
    preview = _read_json(preview_path, "seal 预览")
    preview_schema = preview.get("schema_version")
    if preview_schema not in {LEGACY_SEAL_PREVIEW_SCHEMA, SEAL_PREVIEW_SCHEMA}:
        raise ConfigurationError("seal 预览 schema_version 不受支持。")

    envelope_fields = {
        "schema_version",
        "stage",
        "campaign_id",
        "candidate_id",
        "campaign_manifest_sha256",
        "sealed_at_utc",
        "package_digest",
        "result_schema_version",
        "seal_preview",
    }
    stage_payload = {
        key: value for key, value in stage.items() if key not in envelope_fields
    }
    expected_core: dict[str, Any] = {
        "schema_version": preview_schema,
        "campaign_id": attempt["campaign_id"],
        "campaign_mode": attempt["campaign_mode"],
        "campaign_purpose": attempt["campaign_purpose"],
        "phase": phase,
        "candidate_id": candidate_id,
        "candidate_purpose": attempt["candidate_purpose"],
        "attempt_id": attempt_id,
        "attempt_digest": attempt["attempt_digest"],
        "stage_payload_sha256": _fingerprint(stage_payload),
        "evidence_inventory_digest": stage_payload["evidence_inventory"]["digest"],
        "assertion_manifest_sha256": stage_payload["assertion_context"][
            "capture_manifest"
        ]["sha256"],
        "restoration_report_sha256": stage_payload["restoration"]["report"][
            "sha256"
        ],
    }
    if preview_schema == SEAL_PREVIEW_SCHEMA:
        manifest = _stage_evidence_manifest(
            campaign_dir,
            stage_payload,
            verify_boundary=True,
        )
        draft = _load_seal_draft(
            campaign_dir,
            attempt_root,
            phase=phase,
            candidate_id=candidate_id,
            attempt=attempt,
        )
        if draft["stage_payload"] != stage_payload:
            raise ConfigurationError("阶段收据与冻结 seal 草案不一致。")
        expected_core.update(
            {
                "evidence_manifest_sha256": stage_payload["evidence_manifest"][
                    "sha256"
                ],
                "evidence_manifest_digest": manifest["manifest_digest"],
                "seal_draft_sha256": file_sha256(_seal_draft_path(attempt_root)),
                "scan_summary": stage_payload["scan_summary"],
            }
        )
    if phase == "candidate":
        expected_core.update(
            {
                "post_client_restoration_sha256": stage_payload["restoration"]
                ["post_client"]["report"]["sha256"],
                "observed_profile_sha256": stage_payload["observed_profile"][
                    "sha256"
                ],
                "client_receipt_sha256": {
                    item["client_id"]: item["receipt"]["sha256"]
                    for item in stage_payload["client_bindings"]
                },
            }
        )
    review_sha256 = _fingerprint(expected_core)
    expected_preview = {
        **expected_core,
        "status": "approval_required",
        "review_sha256": review_sha256,
    }
    if preview != expected_preview:
        raise ConfigurationError("阶段收据与人工批准的 seal 预览不一致。")


def _latest_attempt_summary(
    campaign_dir: Path,
    phase: str,
    candidate_id: str | None,
) -> dict[str, Any] | None:
    """返回指定抓包边界最近一个可验证 attempt 的摘要。"""

    for path, reservation in _ordered_capture_attempts(
        campaign_dir,
        phase,
        candidate_id,
    ):
        attempt_path = path / "attempt.json"
        if not attempt_path.exists():
            return {
                "attempt_id": path.name,
                "status": "reserved_or_interrupted",
                "seal_preview": False,
                "run_nonce": reservation["run_nonce"],
                "attempt_started_at_utc": reservation["started_at_utc"],
                "evidence_root": None,
            }
        _, attempt = _load_capture_attempt(
            campaign_dir, phase, candidate_id, path.name
        )
        client_checkpoint_at: str | None = None
        if phase == "candidate":
            environment = attempt.get("environment")
            evidence_root = Path(
                str(environment.get("evidence_root", ""))
                if isinstance(environment, dict)
                else ""
            )
            checkpoint_receipt = (
                evidence_root / "receipts" / "client-restoration-report.json"
            )
            checkpoint_manifest = (
                evidence_root
                / "environment"
                / "client-after"
                / "probe-manifest.json"
            )
            checkpoint_present = checkpoint_receipt.exists() or checkpoint_manifest.exists()
            if checkpoint_present:
                if (
                    not checkpoint_receipt.is_file()
                    or checkpoint_receipt.is_symlink()
                    or not checkpoint_manifest.is_file()
                    or checkpoint_manifest.is_symlink()
                ):
                    raise ConfigurationError("Kilo 后检查点材料不完整或不可信。")
                _validate_restoration_report(
                    checkpoint_receipt,
                    [evidence_root],
                    phase="candidate",
                    candidate_id=str(candidate_id),
                )
                checkpoint = _read_json(
                    checkpoint_manifest, "Kilo 后探针清单"
                )
                if checkpoint.get("phase") != "after" or not _is_rfc3339_timestamp(
                    checkpoint.get("observed_at_utc")
                ):
                    raise ConfigurationError("Kilo 后探针清单身份或时间非法。")
                client_checkpoint_at = str(checkpoint["observed_at_utc"])
        preview_path = path / "seal-preview.json"
        preview_exists = preview_path.exists() or preview_path.is_symlink()
        if preview_exists:
            if preview_path.is_symlink() or not preview_path.is_file():
                raise ConfigurationError("seal 预览路径不可信。")
            preview = _read_json(preview_path, "seal 预览")
            core = {
                key: value
                for key, value in preview.items()
                if key not in {"status", "review_sha256"}
            }
            if (
                preview.get("schema_version")
                not in {LEGACY_SEAL_PREVIEW_SCHEMA, SEAL_PREVIEW_SCHEMA}
                or preview.get("campaign_id") != attempt.get("campaign_id")
                or preview.get("phase") != phase
                or preview.get("candidate_id") != candidate_id
                or preview.get("attempt_id") != path.name
                or preview.get("attempt_digest") != attempt.get("attempt_digest")
                or preview.get("status") != "approval_required"
                or preview.get("review_sha256") != _fingerprint(core)
            ):
                raise ConfigurationError("seal 预览身份或复核摘要不一致。")
        return {
            "attempt_id": path.name,
            "status": attempt["status"],
            "seal_preview": preview_exists,
            "client_checkpoint_at_utc": client_checkpoint_at,
            "run_nonce": attempt["run_nonce"],
            "attempt_started_at_utc": attempt["started_at_utc"],
            "evidence_root": (
                attempt.get("environment", {}).get("evidence_root")
                if isinstance(attempt.get("environment"), dict)
                else None
            ),
        }
    return None


def _ordered_capture_attempts(
    campaign_dir: Path,
    phase: str,
    candidate_id: str | None,
) -> list[tuple[Path, dict[str, Any]]]:
    """按预约微秒时间倒序排列 attempt，编号仅作为同刻平局键。"""

    relative = _capture_attempt_relative(phase, candidate_id)
    root = campaign_dir / relative / "attempts"
    if not root.is_dir() or root.is_symlink():
        return []
    attempts: list[tuple[Path, dict[str, Any]]] = []
    for path in root.iterdir():
        if not path.is_dir() or path.is_symlink() or not SAFE_ID_RE.fullmatch(path.name):
            continue
        reservation = _load_capture_reservation(
            campaign_dir,
            path,
            phase=phase,
            candidate_id=candidate_id,
        )
        attempts.append((path, reservation))
    return sorted(
        attempts,
        key=lambda item: (
            _rfc3339_datetime(
                item[1]["started_at_utc"], "抓包预约 started_at_utc"
            ),
            item[0].name,
        ),
        reverse=True,
    )


def _campaign_attempt_roots(
    campaign_dir: Path,
) -> list[tuple[str, str | None, Path]]:
    """枚举 Campaign 内全部正式 attempt 目录，忽略未发布的隐藏临时目录。"""

    scopes: list[tuple[str, str | None, Path]] = [
        ("official", None, campaign_dir / "official" / "attempts")
    ]
    candidates_root = campaign_dir / "candidates"
    if candidates_root.exists():
        if candidates_root.is_symlink() or not candidates_root.is_dir():
            raise ConfigurationError("候选抓包目录不可信。")
        for candidate_root in sorted(candidates_root.iterdir()):
            if not candidate_root.is_dir() or candidate_root.is_symlink():
                continue
            if not SAFE_ID_RE.fullmatch(candidate_root.name):
                raise ConfigurationError("候选抓包目录包含非法 candidate-id。")
            scopes.append(
                (
                    "candidate",
                    candidate_root.name,
                    candidate_root / "attempts",
                )
            )

    attempts: list[tuple[str, str | None, Path]] = []
    for phase, current_candidate_id, attempts_root in scopes:
        if not attempts_root.exists():
            continue
        if attempts_root.is_symlink() or not attempts_root.is_dir():
            raise ConfigurationError("抓包 attempts 目录不可信。")
        for attempt_root in sorted(attempts_root.iterdir()):
            if not attempt_root.is_dir() or attempt_root.is_symlink():
                continue
            if not SAFE_ID_RE.fullmatch(attempt_root.name):
                if attempt_root.name.startswith(".reservation-"):
                    continue
                raise ConfigurationError("抓包目录包含非法 attempt-id。")
            attempts.append((phase, current_candidate_id, attempt_root))
    return attempts


def _campaign_contamination_records(campaign_dir: Path) -> list[str]:
    """从主 attempt／seal 失败事实推导污染，旁路 marker 仅作冗余提示。"""

    records: list[str] = []
    marker = campaign_dir / "environment-contaminated.json"
    if marker.exists() or marker.is_symlink():
        records.append("campaign-marker")
    for phase, current_candidate_id, attempt_root in _campaign_attempt_roots(
        campaign_dir
    ):
        _load_capture_reservation(
            campaign_dir,
            attempt_root,
            phase=phase,
            candidate_id=current_candidate_id,
        )
        attempt_path = attempt_root / "attempt.json"
        if attempt_path.exists() or attempt_path.is_symlink():
            if attempt_path.is_symlink() or not attempt_path.is_file():
                raise ConfigurationError("抓包 attempt 收据路径不可信。")
            _, attempt = _load_capture_attempt(
                campaign_dir,
                phase,
                current_candidate_id,
                attempt_root.name,
            )
            if attempt.get("status") == "environment_contaminated":
                records.append(
                    f"{current_candidate_id or phase}:{attempt_root.name}:attempt"
                )
        seal_failure = attempt_root / "seal-failure.json"
        if seal_failure.exists() or seal_failure.is_symlink():
            if seal_failure.is_symlink() or not seal_failure.is_file():
                raise ConfigurationError("候选 seal 失败收据路径不可信。")
            failure = _read_json(seal_failure, "候选 seal 失败收据")
            failure_digest = failure.get("failure_digest")
            unsigned_failure = dict(failure)
            unsigned_failure.pop("failure_digest", None)
            reservation = _load_capture_reservation(
                campaign_dir,
                attempt_root,
                phase=phase,
                candidate_id=current_candidate_id,
            )
            if (
                phase != "candidate"
                or failure.get("schema_version") != SEAL_FAILURE_SCHEMA
                or failure.get("campaign_id") != reservation.get("campaign_id")
                or failure.get("campaign_mode") != reservation.get("campaign_mode")
                or failure.get("campaign_purpose")
                != reservation.get("campaign_purpose")
                or failure.get("candidate_purpose")
                != reservation.get("candidate_purpose")
                or failure.get("campaign_manifest_sha256")
                != reservation.get("campaign_manifest_sha256")
                or failure.get("phase") != "candidate"
                or failure.get("candidate_id") != current_candidate_id
                or failure.get("attempt_id") != attempt_root.name
                or failure.get("run_nonce") != reservation.get("run_nonce")
                or not _is_rfc3339_timestamp(failure.get("failed_at_utc"))
                or failure.get("reason") != "Kilo 后环境恢复门禁失败"
                or not isinstance(failure.get("error_type"), str)
                or not failure["error_type"]
                or not SHA256_RE.fullmatch(str(failure_digest))
                or _fingerprint(unsigned_failure) != failure_digest
            ):
                raise ConfigurationError("候选 seal 失败收据身份或摘要不一致。")
            records.append(
                f"{current_candidate_id or phase}:{attempt_root.name}:seal"
            )
    return records


def _reject_contaminated_campaign(campaign_dir: Path) -> None:
    """任何主污染事实存在时，除只读 status 外禁止继续使用 Campaign。"""

    records = _campaign_contamination_records(campaign_dir)
    if records:
        raise ConfigurationError(
            "环境恢复失败已封锁 Campaign；只能只读 status，并在人工恢复后新建 "
            f"Campaign。污染事实={records}"
        )


def campaign_status(
    campaign_dir: Path,
    candidate_id: str | None = None,
) -> dict[str, Any]:
    """从不可变阶段收据推导状态，不回写 Campaign 核心清单。"""

    if candidate_id is not None and not SAFE_ID_RE.fullmatch(candidate_id):
        raise ConfigurationError("status --candidate-id 格式非法。")
    manifest = load_campaign_manifest(campaign_dir)
    mode, purpose = _campaign_coordinates(manifest)
    if mode == "preflight_only":
        forbidden = [
            name
            for name in (
                "official",
                "classification",
                "candidates",
                "comparisons",
                "acceptance",
                "assertions",
            )
            if (campaign_dir / name).exists() or (campaign_dir / name).is_symlink()
        ]
        if forbidden:
            raise ConfigurationError(
                "preflight_only Campaign 出现正式阶段制品，拒绝 continuation："
                f"{forbidden}"
            )
        return {
            "schema_version": "codex-upgrade-status/v2",
            "verification_mode": "shallow",
            "raw_evidence_scanned_bytes": 0,
            "campaign_id": manifest["campaign_id"],
            "campaign_mode": mode,
            "campaign_purpose": purpose,
            "status": "preflight_complete",
            "stages": {},
            "candidates": [],
            "comparisons": [],
            "accepted_candidates": [],
            "candidate_states": {},
            "candidate_purposes": {},
            "candidate_production_states": {},
            "production_status": None,
            "official_attempt": None,
            "candidate_attempt": None,
            "selected_candidate_id": candidate_id,
            "active_unsealed_attempts": {"official": [], "candidate": []},
            "failed_attempts": {"official": [], "candidate": []},
            "contamination_records": [],
            "next_command": (
                "P0 结果通过后，以 --campaign-mode formal 和同一 "
                "--campaign-purpose 创建新的持久 Campaign"
            ),
        }
    stage_status: dict[str, Any] = {}
    for stage in ("capture-official", "classify"):
        try:
            stage_status[stage] = _load_stage_result(
                campaign_dir,
                stage,
                _replay_machine_receipts=False,
                _shallow=True,
            ).get(
                "status", "unknown"
            )
        except ConfigurationError as error:
            if "尚未封存" not in str(error):
                raise
            stage_status[stage] = "pending"
    candidates_root = campaign_dir / "candidates"
    candidates = sorted(
        path.name
        for path in candidates_root.iterdir()
        if (
            path.is_dir()
            and not path.is_symlink()
            and SAFE_ID_RE.fullmatch(path.name)
            and (path / "result.json").is_file()
            and not (path / "result.json").is_symlink()
        )
    ) if candidates_root.is_dir() else []
    comparisons: list[str] = []
    acceptance: list[str] = []
    candidate_states: dict[str, str] = {}
    candidate_purposes: dict[str, str] = {}
    candidate_production_states: dict[str, str] = {}
    for current_candidate_id in candidates:
        candidate_stage = _load_stage_result(
            campaign_dir,
            "capture-candidate",
            current_candidate_id,
            _replay_machine_receipts=False,
            _shallow=True,
        )
        if candidate_stage.get("status") != "complete":
            raise ConfigurationError("候选抓包阶段尚未完整封存。")
        candidate_purposes[current_candidate_id] = str(
            candidate_stage["candidate_purpose"]
        )
        candidate_states[current_candidate_id] = "candidate_sealed"
        for stage, output in (("compare", comparisons), ("accept", acceptance)):
            try:
                value = _load_stage_result(
                    campaign_dir,
                    stage,
                    current_candidate_id,
                    _replay_machine_receipts=False,
                    _shallow=True,
                )
            except ConfigurationError as error:
                if "尚未封存" not in str(error):
                    raise
                continue
            if value.get("status") == "complete":
                output.append(current_candidate_id)
                candidate_states[current_candidate_id] = (
                    "ready" if stage == "accept" else "compared"
                )
                if stage == "accept":
                    candidate_production_states[current_candidate_id] = str(
                        value["production_state"]
                    )
                    _verify_campaign_binding(
                        campaign_dir, value.get("assertion_result"), "逐规则断言结果"
                    )
                    _verify_campaign_binding(
                        campaign_dir, value.get("evidence_seal"), "验收证据封印"
                    )
    contamination_records = _campaign_contamination_records(campaign_dir)
    contaminated = bool(contamination_records)
    active_unsealed = {
        "official": _active_unsealed_attempts(campaign_dir, "official"),
        "candidate": _active_unsealed_attempts(campaign_dir, "candidate"),
    }
    failed_attempts = {
        "official": _failed_capture_attempts(campaign_dir, "official"),
        "candidate": _failed_capture_attempts(campaign_dir, "candidate"),
    }
    official_attempt = (
        None
        if stage_status["capture-official"] == "complete"
        else _latest_attempt_summary(campaign_dir, "official", None)
    )
    candidate_attempt = (
        _latest_attempt_summary(campaign_dir, "candidate", candidate_id)
        if candidate_id is not None and candidate_id not in candidate_states
        else None
    )
    if contaminated:
        status = "environment_contaminated"
        next_command = "人工恢复并证明环境洁净后新建 Campaign"
    elif (
        stage_status["capture-official"] == "complete"
        and active_unsealed["official"]
    ) or (
        candidate_id is not None
        and candidate_id in candidate_states
        and active_unsealed["candidate"]
    ):
        status = "capture_state_inconsistent"
        next_command = "人工审计额外未封存预约并新建 Campaign"
    elif candidate_id is not None and candidate_id in candidate_states:
        status = candidate_states[candidate_id]
        if status == "ready":
            next_command = (
                "validation_only 已验收交付，禁止进入生产激活"
                if candidate_purposes[candidate_id] == "validation_only"
                else (
                    "必须继续 Codex 手册 §4.6；在 promotion、canary、activation "
                    "和 rollback 收据完成前不得宣称生产升级完成"
                )
            )
        else:
            next_command = {
                "candidate_sealed": "compare",
                "compared": "accept",
            }[status]
    elif candidate_attempt is not None:
        if candidate_attempt["status"] == "reserved_or_interrupted":
            status = "candidate_capture_interrupted"
            next_command = "人工审计孤儿预约并新建 Campaign；不得自动重跑"
        elif candidate_attempt["status"] == "awaiting_receipts":
            if candidate_attempt["seal_preview"]:
                status = "candidate_awaiting_seal_approval"
                next_command = (
                    "capture-candidate seal --approve-seal-sha256 <review_sha256>"
                )
            elif candidate_attempt.get("client_checkpoint_at_utc"):
                status = "candidate_client_checkpoint_created"
                next_command = "生成 nonce／时间绑定收据后重新执行 capture-candidate seal"
            else:
                status = "candidate_awaiting_client_checkpoint"
                next_command = "Kilo 两入口完成后执行首次 capture-candidate seal"
        else:
            status = "candidate_capture_failed"
            next_command = "修复失败任务后使用 resume --rerun-failed"
    elif candidate_id is None and (
        active_unsealed["candidate"] or failed_attempts["candidate"]
    ):
        status = "candidate_selection_required"
        next_command = "从 attempt 列表选择原 candidate-id 执行 status／seal／resume"
    elif candidate_id is not None and stage_status["classify"] == "complete":
        status = "profile_approved"
        next_command = "capture-candidate"
    elif acceptance:
        status = "ready"
        next_command = "指定 --candidate-id 查看或续跑单个候选"
    elif comparisons:
        status = "compared"
        next_command = "指定 --candidate-id 执行 accept"
    elif candidates:
        status = "candidate_sealed"
        next_command = "指定 --candidate-id 执行 compare"
    elif stage_status["classify"] == "blocked":
        status = "blocked"
        next_command = "解决阻塞并创建新的分类 revision"
    elif stage_status["classify"] == "complete":
        status = "profile_approved"
        next_command = "capture-candidate"
    elif stage_status["capture-official"] == "complete":
        status = "official_sealed"
        next_command = "classify"
    elif official_attempt is not None:
        if official_attempt["status"] == "reserved_or_interrupted":
            status = "official_capture_interrupted"
            next_command = "人工审计孤儿预约并新建 Campaign；不得自动重跑"
        elif official_attempt["status"] == "awaiting_receipts":
            status = (
                "official_awaiting_seal_approval"
                if official_attempt["seal_preview"]
                else "official_awaiting_receipts"
            )
            next_command = (
                "capture-official seal --approve-seal-sha256 <review_sha256>"
                if official_attempt["seal_preview"]
                else "完成机器 finalizer 后执行 capture-official seal"
            )
        else:
            status = "official_capture_failed"
            next_command = "修复失败任务后使用 resume --rerun-failed"
    else:
        status = "planned"
        next_command = "capture-official"
    return {
        "schema_version": "codex-upgrade-status/v2",
        "verification_mode": "shallow",
        "raw_evidence_scanned_bytes": 0,
        "campaign_id": manifest["campaign_id"],
        "campaign_mode": mode,
        "campaign_purpose": purpose,
        "status": status,
        "stages": stage_status,
        "candidates": candidates,
        "comparisons": comparisons,
        "accepted_candidates": acceptance,
        "candidate_states": candidate_states,
        "candidate_purposes": candidate_purposes,
        "candidate_production_states": candidate_production_states,
        "production_status": (
            candidate_production_states.get(candidate_id)
            if candidate_id is not None
            else None
        ),
        "official_attempt": official_attempt,
        "candidate_attempt": candidate_attempt,
        "selected_candidate_id": candidate_id,
        "active_unsealed_attempts": active_unsealed,
        "failed_attempts": failed_attempts,
        "contamination_records": contamination_records,
        "next_command": next_command,
    }


def _campaign_arguments(
    campaign_dir: Path,
    manifest: dict[str, Any],
    *,
    candidate_id: str | None = None,
    runtime_image: str | None = None,
    profile_id: str | None = None,
    profile_digest: str | None = None,
    build_id: str | None = None,
    deployed_version: str | None = None,
    candidate_image_id: str | None = None,
    source_tree_sha256: str | None = None,
    candidate_purpose: str | None = None,
) -> argparse.Namespace:
    configuration = manifest["configuration"]
    run_id = manifest["campaign_id"]
    if candidate_id:
        run_id = f"{run_id}-{candidate_id}"
    inputs = manifest.get("inputs", {})
    extra_reference = inputs.get("extra_jobs")
    # v2 历史 Campaign 没有双清单坐标，仍允许只读重放其冻结事实；新 Campaign
    # 一律由 plan 写入 target_discovery_scenarios，并以它生成 official jobs。
    target_scenario_reference = inputs.get("target_discovery_scenarios")
    execution_scenario_reference = (
        target_scenario_reference or inputs["discovery_scenarios"]
    )
    return argparse.Namespace(
        command="capture-candidate" if candidate_id else "capture-official",
        baseline_version=manifest["baseline_version"],
        target_version=manifest["target_version"],
        baseline_source=Path(configuration["baseline_source"]),
        target_source=Path(configuration["target_source"]),
        baseline_evidence=Path(configuration["baseline_evidence"]),
        target_sha256=manifest["target_sha256"],
        target_package=Path(configuration["target_package"]),
        target_package_sha256=manifest["official_identity"]["package"][
            "asset_sha256"
        ],
        target_code_mode_host_sha256=manifest["official_identity"]["package"][
            "code_mode_host_sha256"
        ],
        target_package_identity=manifest["official_identity"]["package"],
        runtime_image=runtime_image or configuration["runtime_image"],
        output=campaign_dir,
        campaign_dir=campaign_dir,
        rule_manifest=_campaign_file(
            campaign_dir, inputs["baseline_rules"]["path"]
        ),
        scenario_manifest=_campaign_file(
            campaign_dir, execution_scenario_reference["path"]
        ),
        target_scenario_manifest=(
            _campaign_file(campaign_dir, target_scenario_reference["path"])
            if target_scenario_reference
            else None
        ),
        extra_jobs=(
            _campaign_file(campaign_dir, extra_reference["path"])
            if extra_reference
            else None
        ),
        suite=manifest["suite"],
        campaign_id=run_id,
        campaign_mode=manifest["campaign_mode"],
        campaign_purpose=manifest["campaign_purpose"],
        model=configuration["model"],
        # 历史 Campaign Schema 尚无 lite_model；只按其冻结 target_version
        # 恢复当时受管轨道。新 Campaign 在 plan 阶段必须显式写入该字段。
        lite_model=(
            configuration.get("lite_model")
            or track_models_for_version(manifest["target_version"], "lite")[0]
        ),
        capture_root=Path(configuration["capture_root"]),
        capture_container=configuration["capture_container"],
        service_container=configuration["service_container"],
        keeper_container=configuration["keeper_container"],
        postgres_container=configuration["postgres_container"],
        redis_container=configuration["redis_container"],
        capture_codex_bin=configuration["capture_codex_bin"],
        relay_codex_bin=configuration["relay_codex_bin"],
        capture_code_mode_host_bin=configuration["capture_code_mode_host_bin"],
        relay_code_mode_host_bin=configuration["relay_code_mode_host_bin"],
        codex_account_id=int(configuration["codex_account_id"]),
        api_key_id=int(configuration["api_key_id"]),
        live_attestation_compose_dir=str(
            configuration.get("live_attestation_compose_dir", "") or ""
        ),
        live_attestation_compose_files=str(
            configuration.get("live_attestation_compose_files", "") or ""
        ),
        candidate_id=candidate_id,
        profile_id=profile_id,
        profile_digest=profile_digest,
        build_id=build_id,
        deployed_version=deployed_version,
        candidate_image_id=candidate_image_id,
        source_tree_sha256=source_tree_sha256,
        candidate_purpose=candidate_purpose,
        max_wall_seconds=None,
        heartbeat_seconds=None,
    )


def _approved_rules(
    campaign_dir: Path,
    manifest: dict[str, Any],
    *,
    require_approved: bool,
) -> tuple[str, ...]:
    if require_approved:
        classification = _load_stage_result(campaign_dir, "classify")
        if classification.get("status") != "complete":
            raise ConfigurationError("目标规则迁移尚未批准。")
        reference = classification.get("target_rule_manifest")
        if not isinstance(reference, dict):
            raise ConfigurationError("分类收据缺少目标规则清单。")
        path = _campaign_file(campaign_dir, str(reference.get("path", "")))
        if not path.is_file() or file_sha256(path) != reference.get("sha256"):
            raise ConfigurationError("目标规则清单摘要不一致。")
        return load_rule_manifest(path, manifest["target_version"])
    reference = manifest["inputs"]["baseline_rules"]
    return load_rule_manifest(
        _campaign_file(campaign_dir, reference["path"]),
        manifest["baseline_version"],
    )


def _campaign_jobs(
    campaign_dir: Path,
    manifest: dict[str, Any],
    phase: str,
    *,
    candidate_id: str | None = None,
    runtime_image: str | None = None,
    profile_id: str | None = None,
    profile_digest: str | None = None,
    build_id: str | None = None,
    deployed_version: str | None = None,
    candidate_image_id: str | None = None,
    source_tree_sha256: str | None = None,
    candidate_purpose: str | None = None,
    use_approved_scenario: bool | None = None,
) -> list[Job]:
    arguments = _campaign_arguments(
        campaign_dir,
        manifest,
        candidate_id=candidate_id,
        runtime_image=runtime_image,
        profile_id=profile_id,
        profile_digest=profile_digest,
        build_id=build_id,
        deployed_version=deployed_version,
        candidate_image_id=candidate_image_id,
        source_tree_sha256=source_tree_sha256,
        candidate_purpose=candidate_purpose,
    )
    approved_target = (
        phase == "candidate"
        if use_approved_scenario is None
        else use_approved_scenario
    )
    if approved_target:
        classification = _load_stage_result(campaign_dir, "classify")
        if classification.get("status") != "complete":
            raise ConfigurationError("目标版本场景尚未批准。")
        scenario_reference = classification.get("scenario_manifest")
        if not isinstance(scenario_reference, dict):
            raise ConfigurationError("分类收据缺少目标场景清单。")
        scenario_path = _campaign_file(
            campaign_dir, str(scenario_reference.get("path", ""))
        )
        if (
            not scenario_path.is_file()
            or scenario_path.is_symlink()
            or file_sha256(scenario_path) != scenario_reference.get("sha256")
        ):
            raise ConfigurationError("目标场景清单摘要不一致。")
        arguments.scenario_manifest = scenario_path
    context = _job_context(arguments)
    uses_frozen_target_scenario = (
        manifest.get("inputs", {}).get("target_discovery_scenarios") is not None
    )
    jobs = load_scenario_jobs(
        arguments.scenario_manifest,
        context,
        expected_version=(
            manifest["target_version"]
            if approved_target or uses_frozen_target_scenario
            else manifest["baseline_version"]
        ),
        require_bindings=True,
    )
    if not approved_target:
        jobs.extend(load_extra_jobs(arguments.extra_jobs, context))
    jobs = [
        job
        for job in jobs
        if job.phase == phase and manifest["suite"] in job.suites
    ]
    rules = _approved_rules(
        campaign_dir, manifest, require_approved=approved_target
    )
    _validate_jobs(jobs, rules)
    if not jobs:
        raise ConfigurationError(f"场景清单没有 {phase} 阶段任务。")
    return jobs


def _verify_plan_identity(
    campaign_dir: Path,
    manifest: dict[str, Any],
    *,
    operation: str | None = None,
    attempt_root: Path | None = None,
    attempt: Mapping[str, Any] | None = None,
    deadline: incremental_recovery.WallClockDeadline | None = None,
    heartbeat: Any | None = None,
) -> dict[str, str] | None:
    # 先重放原 Campaign 的冻结控制事实，但暂不要求旧 Ledger 仍 active。
    # 工具缺陷恢复时旧 Ledger 必须已经 stop_the_line，批准后的 transition
    # 会另行绑定并重放新的 active 控制链；其他路径仍在下方要求旧控制 active。
    _verify_control_receipts(campaign_dir, manifest, require_active=False)
    target_source = Path(manifest["configuration"]["target_source"])
    expected = manifest["official_identity"]
    cargo_lock = target_source / "Cargo.lock"
    current_identity = {
        "source_tree_sha256": _directory_tree_digest(target_source),
        "cargo_lock_sha256": file_sha256(cargo_lock) if cargo_lock.is_file() else None,
    }
    for field, value in current_identity.items():
        if value != expected.get(field):
            raise ConfigurationError(f"官方目标身份漂移：{field}")
    package_identity = expected.get("package")
    if not isinstance(package_identity, dict):
        raise ConfigurationError("官方目标身份缺少 package 闭包。")
    if deadline is not None:
        deadline.check("plan-identity:start")
    current_package_identity = _verify_codex_package(
        Path(manifest["configuration"]["target_package"]),
        expected_version=manifest["target_version"],
        expected_package_sha256=str(package_identity.get("asset_sha256", "")),
        expected_binary_sha256=manifest["target_sha256"],
        expected_code_mode_host_sha256=str(
            package_identity.get("code_mode_host_sha256", "")
        ),
        deadline=deadline,
        heartbeat=heartbeat,
    )
    if current_package_identity != package_identity:
        raise ConfigurationError("官方目标 package 身份漂移。")
    current_tool = _tool_identity(include_git=False)
    if deadline is not None:
        deadline.check("plan-identity:tool-summary")
    expected_tool = manifest["tool_identity"]
    if current_tool["files_sha256"] == expected_tool["files_sha256"]:
        _verify_control_receipts(campaign_dir, manifest, require_active=True)
        if deadline is not None:
            deadline.check("plan-identity:complete")
        return None
    component_drift = _tool_component_drift(expected_tool, current_tool)
    changed_components = set(component_drift.get("changed_components", []))
    if (
        changed_components
        and changed_components.issubset({"orchestrator", "evaluator"})
        and isinstance(attempt, Mapping)
        and attempt.get("incremental_tool_transition") is not None
    ):
        transition = _validate_incremental_tool_transition(
            attempt["incremental_tool_transition"],
            expected_tool,
            current_tool,
        )
        _verify_control_receipts(campaign_dir, manifest, require_active=True)
        if deadline is not None:
            deadline.check("plan-identity:complete")
        return transition
    # 编排／评估修复只改变结果判定或任务调度，不改变已经封存的官方字节。
    # 这类变化不再把整个 Campaign 拦在全局 files_sha256 门禁上；调用方会
    # 根据 Job／门禁依赖闭集决定需要补跑的项目。旧 Campaign 没有组件包时，
    # _tool_component_bundle 会从历史 entries 现场推导，仍保持 fail-close。
    if (
        operation == "capture-run"
        and changed_components
        and changed_components.issubset({"orchestrator", "evaluator"})
    ):
        _verify_control_receipts(campaign_dir, manifest, require_active=True)
        _record_evaluation_side_drift(
            campaign_dir,
            current_tool,
            expected_tool,
            {
                "evaluation": sorted(
                    path
                    for paths in component_drift.get("changed_paths", {}).values()
                    for path in paths
                )
            },
        )
        if deadline is not None:
            deadline.check("plan-identity:complete")
        return {
            "kind": "component_drift",
            "changed_components": sorted(changed_components),
            "changed_paths": component_drift.get("changed_paths", {}),
            "affected_job_ids": [],
            "from_component_identity_sha256": _fingerprint(
                _tool_component_bundle(expected_tool)
            ),
            "to_component_identity_sha256": _fingerprint(
                _tool_component_bundle(current_tool)
            ),
        }
    # 工具确实变了。按证据影响面分级判定，而不是一律拒绝：产出侧改动会改变证据字节，
    # 必须整轮重来；评估侧改动只改变「怎么判断」，已封存证据逐字节不变，重新评估即可。
    #
    # 兼容：plan 时未记录分组摘要的旧 Campaign 无法证明其分级前提，退回严格拒绝。
    if "production_sha256" not in expected_tool:
        raise ConfigurationError(
            "升级工具摘要在 plan 后发生变化（该 Campaign 的 plan 未记录分组摘要，"
            "无法分级判定，只能整轮重建）。"
        )
    drift = _tool_identity_drift(current_tool, expected_tool)
    # status、plan 后的廉价阶段校验也必须能观察纯编排器／评估器漂移；
    # 这里不要求旧 Ledger 继续 active，也不触碰证据正文。带 attempt 的
    # seal／deep-verify 仍走上面的 transition 分支，保留阶段边界。
    if (
        operation is None
        and changed_components
        and changed_components.issubset({"orchestrator", "evaluator"})
    ):
        low_risk_paths = sorted(
            path
            for paths in component_drift.get("changed_paths", {}).values()
            for path in paths
        )
        _verify_control_receipts(campaign_dir, manifest, require_active=True)
        _record_evaluation_side_drift(
            campaign_dir,
            current_tool,
            expected_tool,
            {"evaluation": low_risk_paths},
        )
        if deadline is not None:
            deadline.check("plan-identity:complete")
        return {
            "kind": "component_drift",
            "changed_components": sorted(changed_components),
            "changed_paths": component_drift.get("changed_paths", {}),
            "affected_job_ids": [],
            "from_component_identity_sha256": _fingerprint(
                _tool_component_bundle(expected_tool)
            ),
            "to_component_identity_sha256": _fingerprint(
                _tool_component_bundle(current_tool)
            ),
        }
    expected_production_sha256 = _tool_identity_side_digest(
        expected_tool, "production"
    )
    current_production_sha256 = _tool_identity_side_digest(
        current_tool, "production"
    )
    if drift["production"] or current_production_sha256 != expected_production_sha256:
        if operation is None or attempt_root is None or attempt is None:
            raise ConfigurationError(
                "升级工具的产出侧在 plan 后发生变化，证据字节前提已不成立："
                + "、".join(
                    drift["production"] or ["<摘要不一致但无法定位文件>"]
                )
            )
        transition = _load_phase_evaluation_transition(
            campaign_dir,
            manifest,
            attempt_root=attempt_root,
            attempt=attempt,
            operation=operation,
            current_tool=current_tool,
            drift=drift,
        )
        _record_evaluation_side_drift(
            campaign_dir,
            current_tool,
            expected_tool,
            drift,
        )
        if deadline is not None:
            deadline.check("plan-identity:complete")
        return transition
    # 只有评估侧变化：放行，但把变化清单落进台账供审计，避免静默放行。
    _verify_control_receipts(campaign_dir, manifest, require_active=True)
    _record_evaluation_side_drift(campaign_dir, current_tool, expected_tool, drift)
    if deadline is not None:
        deadline.check("plan-identity:complete")
    return None


TOOL_EVALUATION_DRIFT_SCHEMA = "codex-upgrade-tool-evaluation-drift/v1"
INCREMENTAL_TOOL_TRANSITION_SCHEMA = "codex-upgrade-incremental-tool-transition/v1"


def _record_evaluation_side_drift(
    campaign_dir: Path,
    current_tool: Mapping[str, Any],
    expected_tool: Mapping[str, Any],
    drift: Mapping[str, list[str]],
) -> None:
    """把被放行的评估侧漂移追加进独立台账，作为不可省略的审计痕迹。

    放行不等于无痕：每次评估侧改动都要留下「改了哪些文件、放行时的新摘要」，
    否则 accept 阶段无法解释某轮结果是用哪一版判据算出来的。

    台账另立文件而不写回 `campaign.json`——后者由 `campaign.sha256` 保护且一次封存
    不可变，追加内容会直接破坏 Campaign 完整性校验。
    """

    if not drift["evaluation"]:
        return
    path = campaign_dir / "tool-evaluation-drift.json"
    if path.is_symlink():
        raise ConfigurationError("评估侧漂移台账不允许是符号链接。")
    if path.is_file():
        ledger = _read_json(path, "评估侧漂移台账")
        if ledger.get("schema_version") != TOOL_EVALUATION_DRIFT_SCHEMA:
            raise ConfigurationError("评估侧漂移台账 schema_version 不受支持。")
        records = ledger.get("records")
        if not isinstance(records, list):
            raise ConfigurationError("评估侧漂移台账结构非法。")
    else:
        records = []
    record = {
        "changed_files": list(drift["evaluation"]),
        "plan_evaluation_sha256": _tool_identity_side_digest(
            expected_tool, "evaluation"
        ),
        "current_evaluation_sha256": _tool_identity_side_digest(
            current_tool, "evaluation"
        ),
        "production_sha256": _tool_identity_side_digest(
            current_tool, "production"
        ),
        "files_sha256": current_tool["files_sha256"],
    }
    # 同一份评估侧状态重复进入不再追加，台账按「不同的评估侧版本」计数。
    if records and records[-1].get("current_evaluation_sha256") == (
        record["current_evaluation_sha256"]
    ):
        return
    records.append(record)
    payload = {
        "schema_version": TOOL_EVALUATION_DRIFT_SCHEMA,
        "plan_production_sha256": _tool_identity_side_digest(
            expected_tool, "production"
        ),
        "records": records,
    }
    ensure_private_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(
                json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
                + "\n"
            )
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


_PHASE_EVALUATION_HYBRID_FILES = frozenset({"codex_upgrade.py"})
_PHASE_EVALUATION_OPERATIONS = {
    "official": ("capture-official-seal", "deep-verify"),
    "candidate": ("capture-candidate-seal", "compare", "accept", "deep-verify"),
}
MAX_PHASE_EVALUATION_TRANSITIONS = 3


def _evaluation_transition_preview_path(
    attempt_root: Path,
    transition_index: int = 1,
) -> Path:
    if transition_index == 1:
        return attempt_root / "evaluation-transition-preview.json"
    return attempt_root / f"evaluation-transition-{transition_index:02d}-preview.json"


def _evaluation_transition_path(
    attempt_root: Path,
    transition_index: int = 1,
) -> Path:
    if transition_index == 1:
        return attempt_root / "evaluation-transition.json"
    return attempt_root / f"evaluation-transition-{transition_index:02d}.json"


def _phase_evaluation_transition_index(
    attempt_root: Path,
    current_tool: Mapping[str, Any],
    *,
    allocate: bool,
) -> int:
    """选择当前工具的只追加 transition 槽位，并把总数限制为三次。"""

    current_sha256 = str(current_tool.get("files_sha256", ""))
    if not SHA256_RE.fullmatch(current_sha256):
        raise ConfigurationError("当前评估工具身份非法。")
    occupied: list[int] = []
    matching: list[int] = []
    for index in range(1, MAX_PHASE_EVALUATION_TRANSITIONS + 1):
        paths = (
            _evaluation_transition_preview_path(attempt_root, index),
            _evaluation_transition_path(attempt_root, index),
        )
        targets: set[str] = set()
        present = False
        for path in paths:
            if path.is_symlink() or (path.exists() and not path.is_file()):
                raise ConfigurationError("评估 transition 路径不可信。")
            if not path.is_file():
                continue
            present = True
            payload = _read_json(path, "评估工具 transition 槽位")
            target = str(payload.get("to_tool_files_sha256", ""))
            if not SHA256_RE.fullmatch(target):
                raise ConfigurationError("评估 transition 槽位缺少目标工具摘要。")
            targets.add(target)
        if not present:
            continue
        occupied.append(index)
        if len(targets) != 1:
            raise ConfigurationError("同一评估 transition 槽位的工具摘要不一致。")
        if current_sha256 in targets:
            matching.append(index)
    if occupied and occupied != list(range(1, max(occupied) + 1)):
        raise ConfigurationError("评估 transition 槽位不连续。")
    if len(matching) > 1:
        raise ConfigurationError("当前评估工具重复绑定多个 transition。")
    if matching:
        return matching[0]
    if not allocate:
        raise ConfigurationError(
            "当前工具含阶段限定变化；先执行 evaluation-transition 并批准摘要。"
        )
    for index in range(1, MAX_PHASE_EVALUATION_TRANSITIONS + 1):
        if index not in occupied:
            return index
    raise ConfigurationError("评估 transition 已达到三次上限，必须永久停线。")


def _phase_recovery_controls_from_arguments(
    arguments: argparse.Namespace,
    campaign_dir: Path,
    manifest: Mapping[str, Any],
    current_tool: Mapping[str, Any],
) -> dict[str, Any]:
    """绑定旧停线事实与当前工具的新计时、P0 和完整演练收据。"""

    required_names = (
        "predecessor_stop_ledger_dir",
        "predecessor_stop_receipt",
        "recovery_timing_ledger_dir",
        "recovery_timing_receipt",
        "recovery_arm64_environment_root",
        "recovery_arm64_environment_receipt",
        "job_rehearsal_root",
        "job_rehearsal_receipt",
    )
    values = {name: getattr(arguments, name, None) for name in required_names}
    if not all(isinstance(value, Path) for value in values.values()):
        raise ConfigurationError("评估 transition 必须完整提供八项恢复控制坐标。")

    _verify_control_receipts(campaign_dir, manifest, require_active=False)
    frozen_controls = manifest.get("control_receipts")
    if not isinstance(frozen_controls, Mapping):
        raise ConfigurationError("原 Formal Campaign 缺少冻结控制收据。")
    predecessor_timing = frozen_controls.get("upgrade_timing")
    predecessor_arm = frozen_controls.get("arm64_environment")
    if not isinstance(predecessor_timing, Mapping) or not isinstance(
        predecessor_arm, Mapping
    ):
        raise ConfigurationError("原 Formal Campaign 的计时或 ARM64 控制收据不完整。")

    stop_root = values["predecessor_stop_ledger_dir"]
    stop_receipt = values["predecessor_stop_receipt"]
    assert isinstance(stop_root, Path) and isinstance(stop_receipt, Path)
    stop_relative = _control_receipt_relative(
        stop_root,
        stop_receipt,
        "原 Campaign stop_the_line checkpoint",
    )
    try:
        stop_checkpoint = codex_upgrade_timing_ledger.replay(
            stop_root,
            stop_relative,
        )
    except (OSError, codex_upgrade_timing_ledger.TimingLedgerError) as error:
        raise ConfigurationError(f"原 Campaign 停线 checkpoint 未通过：{error}") from error
    stop_summary = stop_checkpoint.get("summary")
    if (
        not isinstance(stop_summary, Mapping)
        or stop_summary.get("status") != "stopped"
        or stop_summary.get("active_phase")
        not in codex_upgrade_timing_ledger.PHASE_ORDER[1:]
        or any(
            stop_summary.get(field) != manifest.get(field)
            for field in (
                "baseline_version",
                "target_version",
                "campaign_purpose",
            )
        )
        or stop_summary.get("upgrade_id") != predecessor_timing.get("upgrade_id")
        or stop_summary.get("evidence_decision")
        != predecessor_timing.get("evidence_decision")
    ):
        raise ConfigurationError("停线 checkpoint 不是原 Campaign 在 VC-1～VC-6 的事实。")
    resolved_stop_root = stop_root.resolve(strict=True)
    try:
        frozen_ledger_root = Path(
            str(predecessor_timing.get("ledger_dir", ""))
        ).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ConfigurationError("原 Campaign 的 Ledger 路径不可信。") from error
    if frozen_ledger_root != resolved_stop_root:
        raise ConfigurationError("停线 checkpoint 与原 Campaign 绑定的 Ledger 不一致。")

    recovery_arguments = argparse.Namespace(
        campaign_mode="preflight_only",
        campaign_purpose=manifest["campaign_purpose"],
        baseline_version=manifest["baseline_version"],
        target_version=manifest["target_version"],
        timing_ledger_dir=values["recovery_timing_ledger_dir"],
        timing_receipt=values["recovery_timing_receipt"],
        arm64_environment_root=values["recovery_arm64_environment_root"],
        arm64_environment_receipt=values[
            "recovery_arm64_environment_receipt"
        ],
    )
    recovery_controls = _plan_control_receipts(recovery_arguments)
    recovery_timing = recovery_controls["upgrade_timing"]
    if (
        recovery_timing["ledger_dir"] == predecessor_timing.get("ledger_dir")
        or recovery_timing["upgrade_id"] == predecessor_timing.get("upgrade_id")
        or recovery_timing["evidence_decision"]
        != predecessor_timing.get("evidence_decision")
    ):
        raise ConfigurationError(
            "恢复 Ledger 必须使用新的目录和 upgrade-id，并保留证据复用决定。"
        )

    current_tool_sha256 = str(current_tool.get("files_sha256", ""))
    if not SHA256_RE.fullmatch(current_tool_sha256):
        raise ConfigurationError("当前评估工具身份非法。")
    recovery_tool_identity = _tool_identity()
    if recovery_tool_identity["files_sha256"] != current_tool_sha256:
        raise ConfigurationError("恢复演练工具身份与当前评估工具不一致。")

    # 先证明演练来自同一新 Ledger、ARM64 P0 和当前工具的 preflight，
    # 再读取其受管版本化场景。Formal 只允许承接历史 source_spec 摘要，
    # 不能把 Campaign 内规范化副本反向当成新预检输入。
    recovery_manifest = json.loads(json.dumps(manifest, ensure_ascii=False))
    recovery_manifest["tool_identity"] = recovery_tool_identity
    recovery_manifest["control_receipts"] = recovery_controls
    preflight_dir, preflight_manifest = (
        _assert_recovery_rehearsal_uses_successor_controls(
            arguments,
            recovery_manifest,
        )
    )
    target_scenario_override = _recovery_rehearsal_target_scenario_override(
        campaign_dir,
        manifest,
        preflight_dir,
        preflight_manifest,
    )
    expected_rehearsal_contract = _job_rehearsal_contract_from_manifest(
        campaign_dir,
        manifest,
        target_scenario_override=target_scenario_override,
        tool_files_sha256_override=current_tool_sha256,
    )
    rehearsal_root = values["job_rehearsal_root"]
    rehearsal_receipt = values["job_rehearsal_receipt"]
    assert isinstance(rehearsal_root, Path) and isinstance(rehearsal_receipt, Path)
    recovery_controls["job_rehearsal"] = _job_rehearsal_control_from_receipt(
        rehearsal_root,
        rehearsal_receipt,
        expected_rehearsal_contract,
    )

    stop_file = resolved_stop_root / stop_relative
    return {
        "schema_version": TOOL_EVALUATION_RECOVERY_CONTROLS_SCHEMA,
        "predecessor": {
            "upgrade_timing": dict(predecessor_timing),
            "arm64_environment": dict(predecessor_arm),
        },
        "stop_checkpoint": {
            "ledger_dir": str(resolved_stop_root),
            "receipt": {
                "path": stop_relative,
                "sha256": file_sha256(stop_file),
                "bytes": stop_file.stat().st_size,
            },
            "upgrade_id": stop_summary["upgrade_id"],
            "evidence_decision": stop_summary["evidence_decision"],
            "active_phase": stop_summary["active_phase"],
            "head_sequence": stop_summary["head_sequence"],
            "head_sha256": stop_summary["head_sha256"],
            "total_elapsed_seconds": stop_summary["total_elapsed_seconds"],
            "total_live_request_count": stop_summary[
                "total_live_request_count"
            ],
        },
        "recovery": recovery_controls,
        "current_tool_files_sha256": current_tool_sha256,
    }


def _control_path_from_recovery_binding(
    value: Any,
    *,
    root_field: str,
    label: str,
) -> tuple[Path, Path]:
    if not isinstance(value, Mapping):
        raise ConfigurationError(f"{label}控制绑定不是对象。")
    root = Path(str(value.get(root_field, "")))
    receipt = value.get("receipt")
    if (
        not isinstance(receipt, Mapping)
        or set(receipt) != {"path", "sha256", "bytes"}
        or not isinstance(receipt.get("path"), str)
        or not SHA256_RE.fullmatch(str(receipt.get("sha256", "")))
        or not isinstance(receipt.get("bytes"), int)
        or isinstance(receipt.get("bytes"), bool)
        or int(receipt["bytes"]) <= 0
    ):
        raise ConfigurationError(f"{label}收据绑定非法。")
    return root, root / str(receipt["path"])


def _validate_phase_recovery_controls(
    campaign_dir: Path,
    manifest: Mapping[str, Any],
    payload: Any,
    current_tool: Mapping[str, Any],
) -> dict[str, Any]:
    """从 transition 内的路径重建恢复控制链并要求逐字段一致。"""

    if not isinstance(payload, Mapping) or set(payload) != {
        "schema_version",
        "predecessor",
        "stop_checkpoint",
        "recovery",
        "current_tool_files_sha256",
    }:
        raise ConfigurationError("评估 transition 的恢复控制结构非法。")
    if payload.get("schema_version") != TOOL_EVALUATION_RECOVERY_CONTROLS_SCHEMA:
        raise ConfigurationError("评估 transition 的恢复控制版本不受支持。")
    stop = payload.get("stop_checkpoint")
    recovery = payload.get("recovery")
    if not isinstance(stop, Mapping) or not isinstance(recovery, Mapping):
        raise ConfigurationError("评估 transition 缺少停线或恢复控制。")
    stop_root, stop_receipt = _control_path_from_recovery_binding(
        stop,
        root_field="ledger_dir",
        label="原 Campaign 停线 checkpoint",
    )
    timing_root, timing_receipt = _control_path_from_recovery_binding(
        recovery.get("upgrade_timing"),
        root_field="ledger_dir",
        label="恢复 UpgradeTimingLedger",
    )
    arm_root, arm_receipt = _control_path_from_recovery_binding(
        recovery.get("arm64_environment"),
        root_field="evidence_root",
        label="恢复 ARM64 P0",
    )
    rehearsal_root, rehearsal_receipt = _control_path_from_recovery_binding(
        recovery.get("job_rehearsal"),
        root_field="evidence_root",
        label="恢复完整 Job 演练",
    )
    arguments = argparse.Namespace(
        predecessor_stop_ledger_dir=stop_root,
        predecessor_stop_receipt=stop_receipt,
        recovery_timing_ledger_dir=timing_root,
        recovery_timing_receipt=timing_receipt,
        recovery_arm64_environment_root=arm_root,
        recovery_arm64_environment_receipt=arm_receipt,
        job_rehearsal_root=rehearsal_root,
        job_rehearsal_receipt=rehearsal_receipt,
    )
    expected = _phase_recovery_controls_from_arguments(
        arguments,
        campaign_dir,
        manifest,
        current_tool,
    )
    if dict(payload) != expected:
        raise ConfigurationError("评估 transition 的恢复控制身份或摘要漂移。")
    return expected


def _tool_entry_index(identity: Mapping[str, Any]) -> dict[str, str]:
    entries = identity.get("entries")
    if not isinstance(entries, list):
        return {}
    return {
        str(item.get("path")): str(item.get("sha256"))
        for item in entries
        if isinstance(item, dict)
        and isinstance(item.get("path"), str)
        and SHA256_RE.fullmatch(str(item.get("sha256", "")))
    }


def _phase_evaluation_changed_files(
    expected_tool: Mapping[str, Any],
    current_tool: Mapping[str, Any],
) -> list[dict[str, Any]]:
    before = _tool_entry_index(expected_tool)
    after = _tool_entry_index(current_tool)
    changed: list[dict[str, Any]] = []
    for path in sorted(set(before) | set(after)):
        if before.get(path) == after.get(path):
            continue
        changed.append(
            {
                "path": path,
                "from_sha256": before.get(path),
                "to_sha256": after.get(path),
                "classification": (
                    "phase_scoped_hybrid"
                    if path in _PHASE_EVALUATION_HYBRID_FILES
                    else "evaluation"
                ),
            }
        )
    return changed


def _build_phase_evaluation_transition_preview(
    campaign_dir: Path,
    manifest: Mapping[str, Any],
    *,
    phase: str,
    candidate_id: str | None,
    attempt_root: Path,
    attempt: Mapping[str, Any],
    current_tool: Mapping[str, Any],
    recovery_controls: Mapping[str, Any],
) -> dict[str, Any]:
    expected_tool = manifest.get("tool_identity")
    if not isinstance(expected_tool, Mapping):
        raise ConfigurationError("Campaign 缺少可分级的工具身份。")
    drift = _tool_identity_drift(current_tool, expected_tool)
    changed = _phase_evaluation_changed_files(expected_tool, current_tool)
    changed_paths = {item["path"] for item in changed}
    allowed_paths = set(_EVALUATION_SIDE_FILES) | set(
        _PHASE_EVALUATION_HYBRID_FILES
    )
    if (
        current_tool.get("files_sha256") == expected_tool.get("files_sha256")
        or not changed
    ):
        raise ConfigurationError("当前工具与 Campaign 冻结身份一致，无需 transition。")
    if (
        set(drift["production"]) - set(_PHASE_EVALUATION_HYBRID_FILES)
        or changed_paths - allowed_paths
    ):
        raise ConfigurationError(
            "评估 transition 包含产出侧变化，禁止原地续作："
            + "、".join(sorted(changed_paths - allowed_paths or drift["production"]))
        )
    if phase not in _PHASE_EVALUATION_OPERATIONS:
        raise ConfigurationError("评估 transition phase 非法。")
    if attempt.get("status") != "awaiting_receipts":
        raise ConfigurationError("评估 transition 只允许已完成请求、等待封存的 attempt。")
    if (
        attempt.get("phase") != phase
        or attempt.get("candidate_id") != candidate_id
        or attempt.get("campaign_id") != manifest.get("campaign_id")
        or attempt.get("campaign_manifest_sha256")
        != file_sha256(campaign_dir / "campaign.json")
    ):
        raise ConfigurationError("评估 transition 与 Campaign／attempt 身份不一致。")
    transition_path = _evaluation_transition_path(attempt_root).resolve(strict=False)
    for raw_root in attempt.get("evidence_roots", []):
        root = Path(str(raw_root)).resolve(strict=False)
        if transition_path == root or transition_path.is_relative_to(root):
            raise ConfigurationError("评估 transition 输出不得写入原始证据边界。")
    core: dict[str, Any] = {
        "schema_version": TOOL_EVALUATION_TRANSITION_PREVIEW_SCHEMA,
        "campaign_id": manifest["campaign_id"],
        "campaign_mode": manifest["campaign_mode"],
        "campaign_purpose": manifest["campaign_purpose"],
        "campaign_manifest_sha256": file_sha256(campaign_dir / "campaign.json"),
        "phase": phase,
        "candidate_id": candidate_id,
        "attempt_id": attempt["attempt_id"],
        "attempt_digest": attempt["attempt_digest"],
        "evidence_boundary_sha256": _fingerprint(
            {
                "attempt_digest": attempt["attempt_digest"],
                "evidence_roots": attempt.get("evidence_roots"),
            }
        ),
        "from_tool_files_sha256": expected_tool["files_sha256"],
        "to_tool_files_sha256": current_tool["files_sha256"],
        "from_production_sha256": expected_tool["production_sha256"],
        "to_production_sha256": current_tool["production_sha256"],
        "from_evaluation_sha256": expected_tool["evaluation_sha256"],
        "to_evaluation_sha256": current_tool["evaluation_sha256"],
        "changed_files": changed,
        "allowed_operations": list(_PHASE_EVALUATION_OPERATIONS[phase]),
        "recovery_controls": dict(recovery_controls),
        "raw_evidence_scanned_bytes": 0,
    }
    return {
        **core,
        "status": "approval_required",
        "review_sha256": _fingerprint(core),
    }


def _validate_phase_evaluation_transition(
    campaign_dir: Path,
    manifest: Mapping[str, Any],
    *,
    attempt_root: Path,
    attempt: Mapping[str, Any],
    current_tool: Mapping[str, Any],
    transition_index: int | None = None,
) -> dict[str, Any]:
    if transition_index is None:
        transition_index = _phase_evaluation_transition_index(
            attempt_root,
            current_tool,
            allocate=False,
        )
    path = _evaluation_transition_path(attempt_root, transition_index)
    if path.is_symlink() or not path.is_file():
        raise ConfigurationError(
            "当前工具含阶段限定变化；先执行 evaluation-transition 并批准摘要。"
        )
    receipt = _read_json(path, "评估工具 transition")
    unsigned = dict(receipt)
    digest = unsigned.pop("transition_digest", None)
    preview_binding = receipt.get("preview")
    expected_fields = {
        "schema_version",
        "approved_at_utc",
        "campaign_id",
        "campaign_manifest_sha256",
        "phase",
        "candidate_id",
        "attempt_id",
        "attempt_digest",
        "evidence_boundary_sha256",
        "from_tool_files_sha256",
        "to_tool_files_sha256",
        "from_production_sha256",
        "to_production_sha256",
        "from_evaluation_sha256",
        "to_evaluation_sha256",
        "changed_files",
        "allowed_operations",
        "recovery_controls",
        "preview",
        "review_sha256",
        "raw_evidence_scanned_bytes",
        "status",
        "transition_digest",
    }
    if (
        set(receipt) != expected_fields
        or receipt.get("schema_version") != TOOL_EVALUATION_TRANSITION_SCHEMA
        or receipt.get("status") != "approved"
        or not _is_rfc3339_timestamp(receipt.get("approved_at_utc"))
        or digest != _fingerprint(unsigned)
    ):
        raise ConfigurationError("评估工具 transition 结构或自摘要非法。")
    _require_file_binding(preview_binding, "评估工具 transition 预览")
    preview_path = _campaign_file(campaign_dir, str(preview_binding["path"]))
    if (
        preview_path
        != _evaluation_transition_preview_path(attempt_root, transition_index)
        or preview_path.is_symlink()
        or not preview_path.is_file()
        or file_sha256(preview_path) != preview_binding["sha256"]
    ):
        raise ConfigurationError("评估工具 transition 预览绑定漂移。")
    preview = _read_json(preview_path, "评估工具 transition 预览")
    phase = str(attempt.get("phase"))
    candidate_id = attempt.get("candidate_id")
    recovery_controls = _validate_phase_recovery_controls(
        campaign_dir,
        manifest,
        preview.get("recovery_controls"),
        current_tool,
    )
    expected_preview = _build_phase_evaluation_transition_preview(
        campaign_dir,
        manifest,
        phase=phase,
        candidate_id=(str(candidate_id) if candidate_id is not None else None),
        attempt_root=attempt_root,
        attempt=attempt,
        current_tool=current_tool,
        recovery_controls=recovery_controls,
    )
    projected = {
        key: value
        for key, value in receipt.items()
        if key
        not in {
            "schema_version",
            "approved_at_utc",
            "preview",
            "status",
            "transition_digest",
        }
    }
    preview_projection = {
        key: value
        for key, value in preview.items()
        if key not in {"schema_version", "campaign_mode", "campaign_purpose", "status"}
    }
    if (
        preview != expected_preview
        or projected != preview_projection
        or receipt.get("campaign_id") != manifest.get("campaign_id")
        or receipt.get("campaign_manifest_sha256")
        != file_sha256(campaign_dir / "campaign.json")
        or receipt.get("attempt_id") != attempt.get("attempt_id")
        or receipt.get("attempt_digest") != attempt.get("attempt_digest")
        or receipt.get("raw_evidence_scanned_bytes") != 0
    ):
        raise ConfigurationError("评估工具 transition 身份、范围或工具摘要漂移。")
    return receipt


def _load_phase_evaluation_transition(
    campaign_dir: Path,
    manifest: Mapping[str, Any],
    *,
    attempt_root: Path,
    attempt: Mapping[str, Any],
    operation: str,
    current_tool: Mapping[str, Any],
    drift: Mapping[str, list[str]],
) -> dict[str, str]:
    if set(drift["production"]) - set(_PHASE_EVALUATION_HYBRID_FILES):
        raise ConfigurationError("评估 transition 不能放行产出侧工具漂移。")
    transition_index = _phase_evaluation_transition_index(
        attempt_root,
        current_tool,
        allocate=False,
    )
    receipt = _validate_phase_evaluation_transition(
        campaign_dir,
        manifest,
        attempt_root=attempt_root,
        attempt=attempt,
        current_tool=current_tool,
        transition_index=transition_index,
    )
    if operation not in receipt.get("allowed_operations", []):
        raise ConfigurationError(f"评估 transition 未授权当前操作：{operation}")
    path = _evaluation_transition_path(attempt_root, transition_index)
    return {
        "path": path.relative_to(campaign_dir).as_posix(),
        "sha256": file_sha256(path),
    }


def create_phase_evaluation_transition(arguments: argparse.Namespace) -> dict[str, Any]:
    """两步审批只影响评估阶段的工具过渡，绝不读取原始证据内容。"""

    campaign_dir = arguments.campaign_dir
    manifest = _require_formal_campaign(campaign_dir)
    phase = arguments.phase
    candidate_id = arguments.candidate_id if phase == "candidate" else None
    if phase == "official" and arguments.candidate_id is not None:
        raise ConfigurationError("official transition 不得携带 --candidate-id。")
    if phase == "candidate" and not candidate_id:
        raise ConfigurationError("candidate transition 必须提供 --candidate-id。")
    attempt_root, attempt = _load_capture_attempt(
        campaign_dir,
        phase,
        candidate_id,
        arguments.attempt_id,
    )
    current_tool = _tool_identity(include_git=False)
    recovery_controls = _phase_recovery_controls_from_arguments(
        arguments,
        campaign_dir,
        manifest,
        current_tool,
    )
    transition_index = _phase_evaluation_transition_index(
        attempt_root,
        current_tool,
        allocate=True,
    )
    preview = _build_phase_evaluation_transition_preview(
        campaign_dir,
        manifest,
        phase=phase,
        candidate_id=candidate_id,
        attempt_root=attempt_root,
        attempt=attempt,
        current_tool=current_tool,
        recovery_controls=recovery_controls,
    )
    preview_path = _evaluation_transition_preview_path(
        attempt_root,
        transition_index,
    )
    _write_or_verify_json(preview_path, preview)
    approval = arguments.approve_transition_sha256
    if approval is None:
        return {
            "status": "approval_required",
            "phase": phase,
            "candidate_id": candidate_id,
            "attempt_id": attempt["attempt_id"],
            "preview": str(preview_path),
            "transition_index": transition_index,
            "review_sha256": preview["review_sha256"],
            "changed_files": preview["changed_files"],
            "raw_evidence_scanned_bytes": 0,
        }
    if not SHA256_RE.fullmatch(str(approval)) or approval != preview["review_sha256"]:
        raise ConfigurationError("评估 transition 批准摘要与预览不一致。")
    receipt_path = _evaluation_transition_path(attempt_root, transition_index)
    if receipt_path.is_file() and not receipt_path.is_symlink():
        receipt = _validate_phase_evaluation_transition(
            campaign_dir,
            manifest,
            attempt_root=attempt_root,
            attempt=attempt,
            current_tool=current_tool,
            transition_index=transition_index,
        )
    else:
        preview_projection = {
            key: value
            for key, value in preview.items()
            if key not in {"schema_version", "campaign_mode", "campaign_purpose", "status"}
        }
        core: dict[str, Any] = {
            "schema_version": TOOL_EVALUATION_TRANSITION_SCHEMA,
            "approved_at_utc": _utc_now(),
            "campaign_id": manifest["campaign_id"],
            "campaign_manifest_sha256": file_sha256(campaign_dir / "campaign.json"),
            "phase": phase,
            "candidate_id": candidate_id,
            "attempt_id": attempt["attempt_id"],
            "attempt_digest": attempt["attempt_digest"],
            "evidence_boundary_sha256": preview["evidence_boundary_sha256"],
            "from_tool_files_sha256": preview["from_tool_files_sha256"],
            "to_tool_files_sha256": preview["to_tool_files_sha256"],
            "from_production_sha256": preview["from_production_sha256"],
            "to_production_sha256": preview["to_production_sha256"],
            "from_evaluation_sha256": preview["from_evaluation_sha256"],
            "to_evaluation_sha256": preview["to_evaluation_sha256"],
            "changed_files": preview["changed_files"],
            "allowed_operations": preview["allowed_operations"],
            "recovery_controls": preview["recovery_controls"],
            "preview": {
                "path": preview_path.relative_to(campaign_dir).as_posix(),
                "sha256": file_sha256(preview_path),
            },
            "review_sha256": preview["review_sha256"],
            "raw_evidence_scanned_bytes": 0,
            "status": "approved",
        }
        receipt = {**core, "transition_digest": _fingerprint(core)}
        _write_or_verify_json(receipt_path, receipt)
        receipt = _validate_phase_evaluation_transition(
            campaign_dir,
            manifest,
            attempt_root=attempt_root,
            attempt=attempt,
            current_tool=current_tool,
            transition_index=transition_index,
        )
    return {
        "status": "approved",
        "phase": phase,
        "candidate_id": candidate_id,
        "attempt_id": attempt["attempt_id"],
        "transition": str(receipt_path),
        "transition_index": transition_index,
        "transition_digest": receipt["transition_digest"],
        "raw_evidence_scanned_bytes": 0,
    }


def _directory_tree_digest(root: Path) -> str:
    if not root.is_dir() or root.is_symlink():
        raise ConfigurationError(f"候选源码目录不存在或不可信：{root}")
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root)
        if any(part in SKIP_DIRECTORIES for part in relative.parts):
            continue
        entries.append(
            {
                "path": relative.as_posix(),
                "size": path.stat().st_size,
                "sha256": file_sha256(path),
            }
        )
    return _fingerprint({"entries": entries})


def _file_sha256_bounded(
    path: Path,
    *,
    deadline: incremental_recovery.WallClockDeadline | None = None,
    heartbeat: Any | None = None,
    operation: str = "file-hash",
) -> str:
    """分块计算大文件摘要，并在每个块边界检查 attempt deadline。"""

    if path.is_symlink() or not path.is_file():
        raise ConfigurationError(f"摘要文件不存在或不可信：{path}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            if deadline is not None:
                deadline.check(operation)
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            if heartbeat is not None:
                heartbeat(operation)
    if deadline is not None:
        deadline.check(operation)
    return digest.hexdigest()


def _container_image_id(
    container: str,
    *,
    deadline: incremental_recovery.WallClockDeadline | None = None,
    heartbeat: Any | None = None,
) -> str | None:
    try:
        command = ["docker", "inspect", "--format", "{{.Image}}", container]
        if deadline is not None:
            result = incremental_recovery.run_bounded_subprocess(
                command,
                timeout=30,
                deadline=deadline,
                operation=f"docker:inspect:{container}",
                check=True,
                capture_output=True,
                text=True,
                heartbeat=heartbeat,
            )
        else:
            result = subprocess.run(
                command,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=30,
            )
    except incremental_recovery.WallClockTimeoutError:
        raise
    except (OSError, subprocess.SubprocessError):
        return None
    value = result.stdout.strip()
    return value if value.startswith("sha256:") else None


def _image_repo_digests(
    image_id: str,
    *,
    deadline: incremental_recovery.WallClockDeadline | None = None,
    heartbeat: Any | None = None,
) -> set[str]:
    """读取 Docker config image ID 对应的 OCI 仓库摘要集合。"""

    try:
        command = [
            "docker",
            "image",
            "inspect",
            "--format",
            "{{json .RepoDigests}}",
            image_id,
        ]
        if deadline is not None:
            result = incremental_recovery.run_bounded_subprocess(
                command,
                timeout=30,
                deadline=deadline,
                operation=f"docker:image-inspect:{image_id}",
                check=True,
                capture_output=True,
                text=True,
                heartbeat=heartbeat,
            )
        else:
            result = subprocess.run(
                command,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=30,
            )
        payload = json.loads(result.stdout)
    except incremental_recovery.WallClockTimeoutError:
        raise
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        raise ConfigurationError("无法读取候选镜像 RepoDigests。") from error
    if (
        not isinstance(payload, list)
        or not payload
        or any(
            not isinstance(value, str)
            or not IMMUTABLE_IMAGE_RE.fullmatch(value)
            for value in payload
        )
    ):
        raise ConfigurationError("候选镜像缺少合法、不可变的 RepoDigests。")
    return set(payload)


def _verify_container_image_reference(
    container: str,
    image_reference: str,
    expected_image_id: str | None = None,
    *,
    deadline: incremental_recovery.WallClockDeadline | None = None,
    heartbeat: Any | None = None,
) -> str:
    """分别验证运行容器 config image ID 与其 OCI 仓库摘要。"""

    actual_image_id = _container_image_id(
        container,
        deadline=deadline,
        heartbeat=heartbeat,
    )
    if not actual_image_id or not IMAGE_ID_RE.fullmatch(actual_image_id):
        raise ConfigurationError("无法读取运行容器的实际 image ID。")
    if expected_image_id is not None and actual_image_id != expected_image_id:
        raise ConfigurationError("运行容器实际 image ID 与冻结身份不一致。")
    if image_reference not in _image_repo_digests(
        actual_image_id,
        deadline=deadline,
        heartbeat=heartbeat,
    ):
        raise ConfigurationError(
            "--runtime-image 不是运行镜像实际 RepoDigests 中的不可变引用。"
        )
    return actual_image_id


def _validate_codex_identity(
    *,
    path: str,
    sha256: str,
    version_output: str,
    expected_sha256: str,
    expected_version: str,
    label: str,
) -> dict[str, str]:
    match = re.fullmatch(r"codex-cli (?P<version>[0-9]+\.[0-9]+\.[0-9]+)", version_output)
    if sha256 != expected_sha256 or not match or match.group("version") != expected_version:
        raise ConfigurationError(f"{label} Codex 二进制版本或 SHA-256 不一致。")
    return {
        "label": label,
        "path": path,
        "version": match.group("version"),
        "version_output": version_output,
        "sha256": sha256,
    }


def _is_world_traversable_executable(path: Path) -> bool:
    """确认宿主执行副本及全部父目录可被无特权 bubblewrap 子进程读取。"""

    if path.is_symlink() or not path.is_file():
        return False
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & (stat.S_IROTH | stat.S_IXOTH) != (stat.S_IROTH | stat.S_IXOTH):
        return False
    return all(
        not parent.is_symlink()
        and parent.is_dir()
        and stat.S_IMODE(parent.stat().st_mode) & stat.S_IXOTH
        for parent in path.parents
    )


def _verify_official_binaries(
    manifest: dict[str, Any],
    *,
    deadline: incremental_recovery.WallClockDeadline | None = None,
    heartbeat: Any | None = None,
) -> dict[str, Any]:
    """在任何真实官方请求前验证所有可能执行的 Codex 二进制。"""

    configuration = manifest["configuration"]
    expected_sha256 = manifest["target_sha256"]
    expected_version = manifest["target_version"]
    container = configuration["capture_container"]
    runtime_image_reference = str(manifest["official_identity"]["runtime_image"])
    runtime_image_id = _verify_container_image_reference(
        container,
        runtime_image_reference,
        deadline=deadline,
        heartbeat=heartbeat,
    )
    container_probe = (
        "import hashlib,json,pathlib,stat,subprocess,sys;"
        "p=pathlib.Path(sys.argv[1]);"
        "m=stat.S_IMODE(p.stat().st_mode);"
        "parents=list(p.parents);"
        "h=hashlib.sha256(p.read_bytes()).hexdigest();"
        "r=subprocess.run([str(p),'--version'],capture_output=True,text=True,timeout=30);"
        "print(json.dumps({'sha256':h,'version':(r.stdout or r.stderr).strip(),"
        "'return_code':r.returncode,'world_readable_executable':"
        "(m & (stat.S_IROTH|stat.S_IXOTH)) == (stat.S_IROTH|stat.S_IXOTH),"
        "'parents_world_traversable':all((not x.is_symlink()) and x.is_dir() and "
        "(stat.S_IMODE(x.stat().st_mode) & stat.S_IXOTH) for x in parents)}))"
    )
    identities: list[dict[str, str]] = []
    for name in ("capture_codex_bin", "relay_codex_bin"):
        binary = str(configuration[name])
        try:
            command = [
                "docker",
                "exec",
                container,
                "python3",
                "-c",
                container_probe,
                binary,
            ]
            if deadline is not None:
                result = incremental_recovery.run_bounded_subprocess(
                    command,
                    timeout=60,
                    deadline=deadline,
                    operation=f"official-binary:{name}",
                    check=True,
                    capture_output=True,
                    text=True,
                    heartbeat=heartbeat,
                )
            else:
                result = subprocess.run(
                    command,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=60,
                )
            payload = json.loads(result.stdout)
        except incremental_recovery.WallClockTimeoutError:
            raise
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
            raise ConfigurationError(f"无法验证容器内 {name}：{error}") from error
        if (
            not isinstance(payload, dict)
            or payload.get("return_code") != 0
            or payload.get("world_readable_executable") is not True
            or payload.get("parents_world_traversable") is not True
        ):
            raise ConfigurationError(
                f"容器内 {name} 无法由无特权 bubblewrap 子进程安全执行。"
            )
        identities.append(
            _validate_codex_identity(
                path=binary,
                sha256=str(payload.get("sha256", "")),
                version_output=str(payload.get("version", "")),
                expected_sha256=expected_sha256,
                expected_version=expected_version,
                label=f"container:{name}",
            )
        )

    host_relay = Path(configuration["relay_codex_bin"])
    if (
        not _is_world_traversable_executable(host_relay)
        or not os.access(host_relay, os.X_OK)
    ):
        raise ConfigurationError(
            "宿主机 relay_codex_bin 不存在、不可信，或无法由无特权 bubblewrap 子进程执行。"
        )
    try:
        command = [str(host_relay), "--version"]
        if deadline is not None:
            host_version = incremental_recovery.run_bounded_subprocess(
                command,
                timeout=30,
                deadline=deadline,
                operation="official-binary:host-relay",
                check=True,
                capture_output=True,
                text=True,
                heartbeat=heartbeat,
            )
        else:
            host_version = subprocess.run(
                command,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
            )
    except incremental_recovery.WallClockTimeoutError:
        raise
    except (OSError, subprocess.SubprocessError) as error:
        raise ConfigurationError(f"无法验证宿主机 relay_codex_bin：{error}") from error
    identities.append(
        _validate_codex_identity(
            path=str(host_relay),
            sha256=file_sha256(host_relay),
            version_output=(host_version.stdout or host_version.stderr).strip(),
            expected_sha256=expected_sha256,
            expected_version=expected_version,
            label="host:relay_codex_bin",
        )
    )
    package_identity = manifest["official_identity"].get("package")
    if not isinstance(package_identity, dict):
        raise ConfigurationError("官方目标身份缺少 package 闭包。")
    expected_helper_sha256 = str(
        package_identity.get("code_mode_host_sha256", "")
    )
    helper_probe = (
        "import hashlib,json,os,pathlib,stat,sys;"
        "p=pathlib.Path(sys.argv[1]);"
        "m=stat.S_IMODE(p.stat().st_mode) if p.is_file() else 0;"
        "parents=list(p.parents);"
        "print(json.dumps({'is_file':p.is_file(),'is_symlink':p.is_symlink(),"
        "'executable':os.access(p,os.X_OK),'sha256':"
        "hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else '',"
        "'world_readable_executable':"
        "(m & (stat.S_IROTH|stat.S_IXOTH)) == (stat.S_IROTH|stat.S_IXOTH),"
        "'parents_world_traversable':all((not x.is_symlink()) and x.is_dir() and "
        "(stat.S_IMODE(x.stat().st_mode) & stat.S_IXOTH) for x in parents)}))"
    )
    helpers: list[dict[str, str]] = []
    for name in ("capture_code_mode_host_bin", "relay_code_mode_host_bin"):
        helper = str(configuration[name])
        try:
            command = [
                "docker",
                "exec",
                container,
                "python3",
                "-c",
                helper_probe,
                helper,
            ]
            if deadline is not None:
                result = incremental_recovery.run_bounded_subprocess(
                    command,
                    timeout=60,
                    deadline=deadline,
                    operation=f"official-helper:{name}",
                    check=True,
                    capture_output=True,
                    text=True,
                    heartbeat=heartbeat,
                )
            else:
                result = subprocess.run(
                    command,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=60,
                )
            payload = json.loads(result.stdout)
        except incremental_recovery.WallClockTimeoutError:
            raise
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
            raise ConfigurationError(f"无法验证容器内 {name}：{error}") from error
        if (
            not isinstance(payload, dict)
            or payload.get("is_file") is not True
            or payload.get("is_symlink") is not False
            or payload.get("executable") is not True
            or payload.get("world_readable_executable") is not True
            or payload.get("parents_world_traversable") is not True
            or payload.get("sha256") != expected_helper_sha256
        ):
            raise ConfigurationError(f"容器内 {name} 与官方 package 不一致。")
        helpers.append(
            {
                "label": f"container:{name}",
                "path": helper,
                "sha256": expected_helper_sha256,
            }
        )

    host_helper = Path(configuration["relay_code_mode_host_bin"])
    if (
        not _is_world_traversable_executable(host_helper)
        or not os.access(host_helper, os.X_OK)
        or file_sha256(host_helper) != expected_helper_sha256
    ):
        raise ConfigurationError(
            "宿主机 relay_code_mode_host_bin 与官方 package 不一致。"
        )
    helpers.append(
        {
            "label": "host:relay_code_mode_host_bin",
            "path": str(host_helper),
            "sha256": expected_helper_sha256,
        }
    )
    return {
        "passed": True,
        "expected_version": expected_version,
        "expected_sha256": expected_sha256,
        "runtime_image_reference": runtime_image_reference,
        "runtime_image_id": runtime_image_id,
        "identities": identities,
        "package": package_identity,
        "helpers": helpers,
    }


def _evidence_files(roots: Iterable[Path]) -> list[tuple[str, Path]]:
    root_map = _evidence_root_map(roots)
    output: dict[Path, str] = {}
    for root, prefix in root_map:
        if not root.exists() or root.is_symlink():
            continue
        files = [root] if root.is_file() else sorted(root.rglob("*"))
        for path in files:
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.name if root.is_file() else path.relative_to(root).as_posix()
            output[path.resolve()] = f"{prefix}/{relative}"
    return [(output[path], path) for path in sorted(output)]


def _evidence_root_map(roots: Iterable[Path]) -> list[tuple[Path, str]]:
    """为多个证据根生成稳定且无冲突的逻辑前缀。"""

    resolved = sorted({path.resolve(strict=False) for path in roots})
    counts: dict[str, int] = {}
    for root in resolved:
        counts[root.name] = counts.get(root.name, 0) + 1
    return [
        (
            root,
            root.name if counts[root.name] == 1 else f"{index:03d}-{root.name}",
        )
        for index, root in enumerate(resolved, 1)
    ]


def _evidence_file_binding(
    path: Path,
    roots: Iterable[Path],
    *,
    label: str,
) -> tuple[dict[str, str], Path, str]:
    """把非符号链接证据文件绑定到唯一证据根和逻辑清单路径。"""

    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ConfigurationError(f"{label}必须是证据根内的非符号链接普通文件。")
    resolved = path.resolve(strict=True)
    matches: list[tuple[Path, str, Path]] = []
    for root, prefix in _evidence_root_map(roots):
        if not root.is_dir() or root.is_symlink():
            continue
        try:
            relative = resolved.relative_to(root.resolve(strict=True))
        except ValueError:
            continue
        matches.append((root.resolve(strict=True), prefix, relative))
    if len(matches) != 1:
        raise ConfigurationError(f"{label}必须唯一归属于一个已收集证据根。")
    root, prefix, relative = matches[0]
    logical = f"{prefix}/{relative.as_posix()}"
    return {"path": logical, "sha256": file_sha256(resolved)}, root, prefix


def _evidence_inventory(roots: Iterable[Path]) -> dict[str, Any]:
    entries = [
        {
            "path": relative,
            "size": path.stat().st_size,
            "sha256": file_sha256(path),
        }
        for relative, path in _evidence_files(roots)
    ]
    return {
        "entry_count": len(entries),
        "entries": entries,
        "digest": _fingerprint({"entries": entries}),
    }


def _evidence_security(roots: Iterable[Path]) -> dict[str, Any]:
    secret_names = [
        name
        for name in (
            "ADMIN_BEARER_TOKEN",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "SUB2API_API_KEY",
        )
        if os.environ.get(name)
    ]
    report = scan_files_for_secrets(
        _evidence_files(roots), secret_env_names=secret_names
    )
    return {
        "known_secret_scan_passed": bool(report["passed"]),
        "known_secret_env_names": report["known_secret_env_names"],
        "file_count": report["file_count"],
        "scanned_bytes": report["scanned_bytes"],
        "findings": report["findings"],
        "limitation": (
            None
            if secret_names
            else "未读取容器内 OAuth 凭据值；仍执行令牌形态启发式扫描。"
        ),
    }


def _evidence_permissions_private(roots: Iterable[Path]) -> bool:
    """确认原始证据根、目录和文件均未向 group/other 开放。"""

    for root in {path.resolve(strict=False) for path in roots}:
        if not root.exists() or root.is_symlink():
            return False
        paths = [root] if root.is_file() else [root, *root.rglob("*")]
        for path in paths:
            if path.is_symlink() or path.stat().st_mode & 0o077:
                return False
    return True


def _resolve_receipt(
    explicit: Path | None,
    roots: list[Path],
    filename: str,
    *,
    label: str,
) -> Path:
    if explicit is not None:
        return explicit
    matches = sorted(
        path
        for root in roots
        if root.is_dir() and not root.is_symlink()
        for path in root.rglob(filename)
        if path.is_file() and not path.is_symlink()
    )
    if len(matches) != 1:
        raise ConfigurationError(f"{label}必须显式提供或在证据根内唯一发现。")
    return matches[0]


def _capture_assertion_context(
    manifest_path: Path | None,
    requested_root: Path | None,
    evidence_roots: list[Path],
    *,
    target_version: str,
) -> dict[str, Any]:
    """定位断言证据包并返回单根断言上下文。

    主手册 §4.4.3 规定：断言器只读取一个证据根，即 attempt 内的
    `assertion-bundle/`；它由 ACC-02 从各 job 根只读收口而来，自包含 manifest、
    原件与派生观测。因此这里返回的 `evidence_root` 是 bundle 目录本身，而
    `evidence_prefix` 是 bundle 在封存 inventory 中的逻辑前缀（`<所属根>/
    assertion-bundle`）——这是此前路径空间失配的修复点：
    机器 check 的相对路径加上该前缀后，必须逐字命中 inventory 条目。
    """

    path = _resolve_receipt(
        manifest_path,
        evidence_roots,
        "capture-manifest.json",
        label="统一 capture manifest",
    )
    binding, owning_root, owning_prefix = _evidence_file_binding(
        path, evidence_roots, label="统一 capture manifest"
    )
    bundle_dir = path.parent.resolve(strict=True)
    if bundle_dir.name != ASSERTION_BUNDLE_DIR_NAME:
        raise ConfigurationError(
            "统一 capture manifest 必须位于 attempt 的 "
            f"{ASSERTION_BUNDLE_DIR_NAME}/ 断言证据包内。"
        )
    if bundle_dir == owning_root:
        raise ConfigurationError(
            f"{ASSERTION_BUNDLE_DIR_NAME}/ 必须是已收集证据根内的子目录，"
            "不能自成独立证据根。"
        )
    relative_bundle = bundle_dir.relative_to(owning_root).as_posix()
    prefix = f"{owning_prefix}/{relative_bundle}"
    if requested_root is not None and requested_root.resolve(strict=True) != bundle_dir:
        raise ConfigurationError(
            "--assertion-evidence-root 与断言证据包目录不一致。"
        )
    try:
        load_assertion_observations(path, bundle_dir, target_version)
    except (OSError, ValueError) as error:
        raise ConfigurationError(f"统一 capture manifest 验证失败：{error}") from error
    return {
        "capture_manifest": binding,
        "capture_manifest_path": str(path.resolve(strict=True)),
        "evidence_root": str(bundle_dir),
        "evidence_prefix": prefix,
    }


def _run_seal_assertion_gate(
    assertion_context: dict[str, Any],
    roots: list[Path],
    *,
    phase: str,
    target_version: str,
) -> dict[str, Any]:
    """ACC-03：seal 前按分侧验收契约执行断言门禁，任一失败拒绝封存。"""

    bundle_dir = Path(assertion_context["evidence_root"])
    # provenance 里的 source_root 名即封存 inventory 的逻辑前缀，重放时按同一
    # 映射回到真实目录；bundle 是某个根内的子目录，不单独充当来源根。
    source_roots = {prefix: root for root, prefix in _evidence_root_map(roots)}
    try:
        profile = load_acceptance_profile(acceptance_profile_path())
        contract = verify_frozen_contract(profile)
        return run_assertion_gate(
            bundle_dir=bundle_dir,
            source_roots=source_roots,
            side="official" if phase == "official" else "candidate",
            profile=profile,
            contract=contract,
            target_version=target_version,
        )
    except (AcceptanceContractError, AssertionGateError) as error:
        raise ConfigurationError(
            f"{phase} seal 断言门禁失败：{error}"
        ) from error


def _validate_restoration_report(
    report_path: Path | None,
    evidence_roots: list[Path],
    *,
    phase: str,
    candidate_id: str | None,
) -> dict[str, Any]:
    path = _resolve_receipt(
        report_path,
        evidence_roots,
        "restoration-report.json",
        label="环境恢复报告",
    )
    binding, root, _ = _evidence_file_binding(
        path, evidence_roots, label="环境恢复报告"
    )
    try:
        report = replay_receipt(path, root, expected_subcommand="restoration")
    except (ReceiptFinalizerError, OSError, ValueError) as error:
        raise ConfigurationError(f"环境恢复报告无法由机器 finalizer 重放：{error}") from error
    if (
        report.get("schema_version") != RESTORATION_SCHEMA
        or report.get("phase") != phase
        or report.get("candidate_id") != candidate_id
        or report.get("status") != "restored"
    ):
        raise ConfigurationError("环境恢复报告身份或状态不一致。")
    checks = report.get("checks")
    required_checks = {
        "service_state_restored",
        "container_state_restored",
        "database_state_preserved",
        "account_state_preserved",
        "configuration_state_restored",
    }
    if not isinstance(checks, list):
        raise ConfigurationError("环境恢复报告 checks 必须是数组。")
    seen: set[str] = set()
    for check in checks:
        if not isinstance(check, dict):
            raise ConfigurationError("环境恢复检查结构非法。")
        check_id = check.get("id")
        if (
            not isinstance(check_id, str)
            or check_id in seen
            or check.get("passed") is not True
        ):
            raise ConfigurationError("环境恢复检查缺失、重复或未通过。")
        seen.add(check_id)
    if seen != required_checks:
        raise ConfigurationError(
            "环境恢复报告检查集合不闭合："
            f"缺少={sorted(required_checks - seen)}，多余={sorted(seen - required_checks)}"
        )
    return {"passed": True, "report": binding, "checks": checks}


def _validate_observed_profile_receipt(
    receipt_path: Path | None,
    evidence_roots: list[Path],
    *,
    campaign_id: str,
    attempt_id: str,
    run_nonce: str,
    attempt_started_at_utc: str,
    client_checkpoint_at_utc: str,
    candidate_id: str,
    target_version: str,
    expected_profile_id: str,
    expected_profile_digest: str,
    image_id: str,
    image_reference: str,
    source_tree_sha256: str,
    build_id: str,
    deployed_version: str,
) -> tuple[dict[str, str], dict[str, Any]]:
    path = _resolve_receipt(
        receipt_path,
        evidence_roots,
        "observed-profile.json",
        label="运行画像观测收据",
    )
    binding, root, _ = _evidence_file_binding(
        path, evidence_roots, label="运行画像观测收据"
    )
    try:
        receipt = replay_receipt(
            path, root, expected_subcommand="observed-profile"
        )
    except (ReceiptFinalizerError, OSError, ValueError) as error:
        raise ConfigurationError(
            f"运行画像观测收据无法由机器 finalizer 重放：{error}"
        ) from error
    expected = {
        "schema_version": OBSERVED_PROFILE_SCHEMA,
        "status": "active",
        "campaign_id": campaign_id,
        "attempt_id": attempt_id,
        "run_nonce": run_nonce,
        "attempt_started_at_utc": attempt_started_at_utc,
        "client_checkpoint_at_utc": client_checkpoint_at_utc,
        "candidate_id": candidate_id,
        "target_version": target_version,
        "profile_id": expected_profile_id,
        "profile_digest": expected_profile_digest,
        "image_id": image_id,
        "image_reference": image_reference,
        "source_tree_sha256": source_tree_sha256,
        "build_id": build_id,
        "deployed_version": deployed_version,
        "source": "sub2api-runtime",
    }
    for field, value in expected.items():
        if receipt.get(field) != value:
            raise ConfigurationError(f"运行画像观测收据 {field} 不一致。")
    return binding, receipt


def _third_party_client_model(configuration: Mapping[str, Any]) -> str:
    """返回第三方客户端验证使用的冻结模型。

    Kilo 双入口用于验证兼容客户端经 HTTP／Responses 进入同一候选画像，模型坐标
    应与 Campaign 的 Lite 轨一致；主轨 ``model`` 属于官方／候选场景任务，不能
    再被隐式复用于第三方客户端。历史 Campaign 尚无 ``lite_model`` 时才回退主轨，
    以便只读重放既有制品。
    """

    model = configuration.get("lite_model") or configuration.get("model")
    if not isinstance(model, str) or not model.strip():
        raise ConfigurationError("Campaign 缺少第三方客户端冻结模型。")
    return model


def _parse_client_evidence(
    values: Iterable[str],
    evidence_roots: list[Path],
    *,
    campaign_id: str,
    attempt_id: str,
    run_nonce: str,
    attempt_started_at_utc: str,
    client_checkpoint_at_utc: str,
    candidate_id: str,
    target_version: str,
    model: str,
    identity: dict[str, Any],
) -> list[dict[str, Any]]:
    bindings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for value in values:
        client_id, separator, raw_path = value.partition("=")
        if (
            not separator
            or not SAFE_ID_RE.fullmatch(client_id)
            or client_id in seen
        ):
            raise ConfigurationError(f"--client-evidence 格式非法或重复：{value}")
        path = Path(raw_path)
        binding, root, _ = _evidence_file_binding(
            path, evidence_roots, label=f"第三方入口 {client_id} 收据"
        )
        try:
            receipt = replay_receipt(
                path, root, expected_subcommand="kilo-binding"
            )
        except (ReceiptFinalizerError, OSError, ValueError) as error:
            raise ConfigurationError(
                f"第三方入口 {client_id} 收据无法由机器 finalizer 重放：{error}"
            ) from error
        expected_protocols = {
            "kilo-compatible": "openai-compatible",
            "kilo-responses": "openai-responses",
        }
        expected_entrypoints = {
            "kilo-compatible": "/v1/chat/completions",
            "kilo-responses": "/v1/responses",
        }
        expected = {
            "schema_version": CLIENT_BINDING_SCHEMA,
            "status": "success",
            "campaign_id": campaign_id,
            "attempt_id": attempt_id,
            "run_nonce": run_nonce,
            "attempt_started_at_utc": attempt_started_at_utc,
            "client_checkpoint_at_utc": client_checkpoint_at_utc,
            "client_id": client_id,
            "protocol": expected_protocols.get(client_id),
            "entrypoint": expected_entrypoints.get(client_id),
            "model": model,
            "candidate_id": candidate_id,
            "target_version": target_version,
            "profile_id": identity.get("profile_id"),
            "profile_digest": identity.get("profile_digest"),
            "candidate_image_id": identity.get("image_id"),
            "source_tree_sha256": identity.get("source_tree_sha256"),
            "build_id": identity.get("build_id"),
            "deployed_version": identity.get("deployed_version"),
        }
        if expected["protocol"] is None:
            raise ConfigurationError(f"第三方入口 {client_id} 未声明协议契约。")
        for field, expected_value in expected.items():
            if receipt.get(field) != expected_value:
                raise ConfigurationError(f"第三方入口 {client_id} 的 {field} 不一致。")
        if not isinstance(receipt.get("client_version"), str) or not receipt["client_version"].strip():
            raise ConfigurationError(f"第三方入口 {client_id} 缺少客户端版本。")
        seen.add(client_id)
        bindings.append(
            {
                "client_id": client_id,
                "status": "success",
                "campaign_id": receipt["campaign_id"],
                "attempt_id": receipt["attempt_id"],
                "run_nonce": receipt["run_nonce"],
                "attempt_started_at_utc": receipt["attempt_started_at_utc"],
                "client_checkpoint_at_utc": receipt[
                    "client_checkpoint_at_utc"
                ],
                "client_version": receipt["client_version"],
                "protocol": receipt["protocol"],
                "entrypoint": receipt["entrypoint"],
                "model": receipt["model"],
                "profile_id": receipt["profile_id"],
                "profile_digest": receipt["profile_digest"],
                "receipt": binding,
                "source_tree_sha256": receipt["source_tree_sha256"],
                "build_id": receipt["build_id"],
                "deployed_version": receipt["deployed_version"],
                "request_evidence": receipt["request_evidence"],
                "response_evidence": receipt["response_evidence"],
                "request_proof": receipt["request_proof"],
                "response_proof": receipt["response_proof"],
                "raw_evidence": receipt["raw_evidence"],
            }
        )
    return bindings


def _load_capture_reservation(
    campaign_dir: Path,
    attempt_root: Path,
    *,
    phase: str,
    candidate_id: str | None,
) -> dict[str, Any]:
    """读取 attempt 原子发布前即存在的不可变预约收据。"""

    path = attempt_root / "reservation.json"
    _reject_symlink_components(path, campaign_dir, "抓包预约收据")
    if not path.is_file() or path.is_symlink():
        raise ConfigurationError(f"抓包 attempt 缺少原子预约收据：{attempt_root.name}")
    payload = _read_json(path, "抓包预约收据")
    required = {
        "schema_version",
        "campaign_id",
        "campaign_mode",
        "campaign_purpose",
        "campaign_manifest_sha256",
        "phase",
        "candidate_id",
        "candidate_purpose",
        "attempt_id",
        "run_nonce",
        "started_at_utc",
        "identity_sha256",
        "planned_jobs",
        "reservation_digest",
    }
    digest = payload.get("reservation_digest")
    unsigned = dict(payload)
    unsigned.pop("reservation_digest", None)
    manifest = load_campaign_manifest(campaign_dir)
    if (
        set(payload) != required
        or payload.get("schema_version") != CAPTURE_RESERVATION_SCHEMA
        or payload.get("campaign_id") != manifest["campaign_id"]
        or payload.get("campaign_mode") != manifest["campaign_mode"]
        or payload.get("campaign_purpose") != manifest["campaign_purpose"]
        or payload.get("campaign_manifest_sha256")
        != file_sha256(campaign_dir / "campaign.json")
        or payload.get("phase") != phase
        or payload.get("candidate_id")
        != (candidate_id if phase == "candidate" else None)
        or payload.get("candidate_purpose")
        != (manifest["campaign_purpose"] if phase == "candidate" else None)
        or payload.get("attempt_id") != attempt_root.name
        or not RUN_NONCE_RE.fullmatch(str(payload.get("run_nonce", "")))
        or not _is_rfc3339_timestamp(payload.get("started_at_utc"))
        or not SHA256_RE.fullmatch(str(payload.get("identity_sha256", "")))
        or not SHA256_RE.fullmatch(str(digest))
        or _fingerprint(unsigned) != digest
    ):
        raise ConfigurationError("抓包预约身份或摘要不一致。")
    planned_jobs = payload.get("planned_jobs")
    if not isinstance(planned_jobs, list) or not planned_jobs:
        raise ConfigurationError("抓包预约缺少计划任务。")
    seen: set[str] = set()
    for item in planned_jobs:
        if (
            not isinstance(item, dict)
            or set(item) != {"id", "required", "execution_sha256"}
            or not SAFE_ID_RE.fullmatch(str(item.get("id", "")))
            or item.get("id") in seen
            or not isinstance(item.get("required"), bool)
            or not SHA256_RE.fullmatch(str(item.get("execution_sha256", "")))
        ):
            raise ConfigurationError("抓包预约计划任务非法、重复或摘要缺失。")
        seen.add(str(item["id"]))
    return payload


def _reserve_capture_attempt(
    campaign_dir: Path,
    *,
    phase: str,
    candidate_id: str | None,
    identity: dict[str, Any],
    jobs: list[Job],
    allow_failed_rerun: bool = False,
    deadline: incremental_recovery.WallClockDeadline | None = None,
) -> tuple[Path, dict[str, Any]]:
    """在跨进程锁内原子发布预约，关闭 check-then-create 与空目录窗口。"""

    relative = _capture_attempt_relative(phase, candidate_id)
    if deadline is not None:
        deadline.check("attempt:reserve:start")
    with _campaign_lock(campaign_dir, deadline=deadline):
        _reject_contaminated_campaign(campaign_dir)
        canonical = "capture-official" if phase == "official" else "capture-candidate"
        _, result_path = _stage_path(campaign_dir, canonical, candidate_id)
        if result_path.exists() or result_path.is_symlink():
            raise ConfigurationError(f"{canonical} 已封存，禁止创建新 attempt。")
        active = _active_unsealed_attempts(campaign_dir, phase)
        if active:
            raise ConfigurationError(
                f"Campaign 存在未封存预约或 attempt，禁止并行 run：{active}"
            )
        failed = _failed_capture_attempts(campaign_dir, phase)
        if phase == "candidate":
            # candidate 身份变化必须新建 candidate，但旧 candidate 的失败事实仍须
            # 只读保留。失败门只阻止同一 candidate 绕过显式 resume；其他 candidate
            # 仍受全局并发预约门约束，却不能被无关失败永久锁死。
            failed = [
                item
                for item in failed
                if item.partition(":")[0] == candidate_id
            ]
        if failed and not allow_failed_rerun:
            raise ConfigurationError(
                "存在失败 attempt；只能显式使用 resume --rerun-failed，禁止直接 "
                f"capture-* run 绕过：{failed}"
            )

        attempts_root = ensure_private_directory(
            campaign_dir / relative / "attempts", campaign_dir
        )
        attempt_id = (
            time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            + f"-{secrets.token_hex(8)}"
        )
        final_root = attempts_root / attempt_id
        if final_root.exists() or final_root.is_symlink():
            raise ConfigurationError("随机 attempt-id 发生冲突。")
        run_nonce = secrets.token_hex(32)
        manifest = _require_formal_campaign(campaign_dir)
        if phase == "candidate" and identity.get("candidate_purpose") != manifest.get(
            "campaign_purpose"
        ):
            raise ConfigurationError(
                "候选预约身份用途与 Campaign 冻结用途不一致。"
            )
        reservation: dict[str, Any] = {
            "schema_version": CAPTURE_RESERVATION_SCHEMA,
            "campaign_id": manifest["campaign_id"],
            "campaign_mode": manifest["campaign_mode"],
            "campaign_purpose": manifest["campaign_purpose"],
            "campaign_manifest_sha256": file_sha256(
                campaign_dir / "campaign.json"
            ),
            "phase": phase,
            "candidate_id": candidate_id if phase == "candidate" else None,
            "candidate_purpose": (
                manifest["campaign_purpose"] if phase == "candidate" else None
            ),
            "attempt_id": attempt_id,
            "run_nonce": run_nonce,
            "started_at_utc": _utc_now(),
            "identity_sha256": _fingerprint(identity),
            "planned_jobs": [
                {
                    "id": job.job_id,
                    "required": job.required,
                    "execution_sha256": _job_execution_sha256(job),
                }
                for job in jobs
            ],
        }
        reservation["reservation_digest"] = _fingerprint(reservation)

        temporary_root = Path(
            tempfile.mkdtemp(prefix=".reservation-", dir=attempts_root)
        )
        temporary_root.chmod(0o700)
        try:
            _secure_write_json_once(
                temporary_root / "reservation.json", reservation
            )
            os.rename(temporary_root, final_root)
            directory_descriptor = os.open(
                attempts_root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except BaseException:
            if temporary_root.exists() and not temporary_root.is_symlink():
                (temporary_root / "reservation.json").unlink(missing_ok=True)
                try:
                    temporary_root.rmdir()
                except OSError:
                    pass
            raise
        if deadline is not None:
            deadline.check("attempt:reserve:complete")
        return final_root, reservation


def _prior_complete_results(
    campaign_dir: Path,
    relative: Path,
    jobs: list[Job],
    *,
    phase: str,
    candidate_id: str | None,
    identity: dict[str, Any],
    tool_identity: Mapping[str, Any] | None = None,
    affected_job_ids: Iterable[str] = (),
) -> list[dict[str, Any]]:
    """承接可复用结果，只返回未受影响且已经通过的 Job。

    旧收据没有组件键时仅在全局工具摘要完全相同的情况下承接；新收据按
    每个 Job 的组件依赖键判断。这样工具修复只会让失败项或真正受影响的
    Job 进入下一轮，已经通过且依赖未变的结果保持只读复用。
    """

    attempts_root = campaign_dir / relative / "attempts"
    if not attempts_root.is_dir() or attempts_root.is_symlink():
        raise ConfigurationError("--rerun-failed 找不到先前失败 attempt。")
    expected_jobs = {job.job_id: job for job in jobs}
    for attempt, _ in _ordered_capture_attempts(
        campaign_dir,
        phase,
        candidate_id,
    ):
        receipt = attempt / "attempt.json"
        if not receipt.is_file() or receipt.is_symlink():
            continue
        _, payload = _load_capture_attempt(
            campaign_dir,
            phase,
            candidate_id,
            attempt.name,
        )
        if payload.get("status") != "failed":
            continue
        if _fingerprint(payload.get("identity")) != _fingerprint(identity):
            raise ConfigurationError(
                "先前失败 attempt 身份与本次重跑不一致；不得在同一 Campaign 混用身份，"
                "请新建 Campaign。"
            )
        results = payload.get("results")
        if not isinstance(results, list):
            continue
        completed = []
        current_tool = tool_identity or _tool_identity(include_git=False)
        frozen_manifest = load_campaign_manifest(campaign_dir)
        frozen_tool = frozen_manifest.get("tool_identity")
        frozen_tool_files_sha256 = (
            frozen_tool.get("files_sha256")
            if isinstance(frozen_tool, Mapping)
            else None
        )
        affected = set(str(item) for item in affected_job_ids)
        global_tool_unchanged = (
            current_tool.get("files_sha256") == frozen_tool_files_sha256
        )
        for item in results:
            if not isinstance(item, dict) or item.get("status") != "complete":
                continue
            job_id = item.get("id")
            if (
                not isinstance(job_id, str)
                or job_id not in expected_jobs
                or item.get("execution_sha256")
                != _job_execution_sha256(expected_jobs[job_id])
            ):
                raise ConfigurationError("先前失败 attempt 的已完成任务定义漂移。")
            # 组件身份存在时做精确的 Job 级命中；旧 attempt 只在工具树
            # 完全不变时兼容承接，避免把旧代码产出的结果误当成新代码结果。
            if job_id in affected:
                continue
            expected_incremental = _job_incremental_metadata(
                expected_jobs[job_id], identity=identity, tool_identity=current_tool
            )
            recorded_key = item.get("incremental_result_key")
            if recorded_key is None:
                if not global_tool_unchanged:
                    continue
            elif recorded_key != expected_incremental["result_key"]:
                continue
            completed.append(item)
        if len({item["id"] for item in completed}) != len(completed):
            raise ConfigurationError("先前失败 attempt 含重复任务收据。")
        # 承接上一轮已完成的任务，只重跑失败项。这不是无条件复用：调用方必须在本轮
        # before 探针采完后调用 _verify_environment_continuity，证明「上一轮 after」到
        # 「本轮 before」之间环境没有漂移。窗口因此首尾相接，被承接的证据仍处在探针
        # 证明范围内；一旦环境变了，旧证据的前提就不成立，必须整轮重采。
        for item in completed:
            item["carried_from_attempt"] = attempt.name
            item["disposition"] = "reused"
            item["source_receipt"] = {
                "path": receipt.relative_to(campaign_dir).as_posix(),
                "sha256": file_sha256(receipt),
                "bytes": receipt.stat().st_size,
            }
        return completed
    raise ConfigurationError("--rerun-failed 找不到同身份失败 attempt。")


# 承接旧结果时要求逐字相同的探针种类。database 必然随采集增长（usage_logs 等水位表），
# 由 restoration 的 before_subset 规则单独覆盖，不在此处比较。
CONTINUITY_PROBE_KINDS = ("service", "containers", "account", "configuration")


def _probe_snapshot_digests(manifest: Mapping[str, Any]) -> dict[str, str]:
    digests: dict[str, str] = {}
    for snapshot in manifest.get("snapshots") or []:
        if not isinstance(snapshot, dict):
            continue
        kind = snapshot.get("kind")
        digest = snapshot.get("sha256")
        if isinstance(kind, str) and isinstance(digest, str):
            digests[kind] = digest
    return digests


def _verify_environment_continuity(
    campaign_dir: Path,
    relative: Path,
    carried_attempt_ids: set[str],
    before_manifest: Mapping[str, Any],
) -> dict[str, Any] | None:
    """证明被承接 attempt 的收尾环境与本轮起始环境一致。

    承接旧任务结果的前提是环境没有在两轮之间发生漂移——否则那些证据描述的是另一套
    环境。比较 service／containers／account／configuration 四类探针快照；database 会随
    采集自然增长，由 restoration 的 before_subset 规则单独覆盖。
    """

    if not carried_attempt_ids:
        return None
    if len(carried_attempt_ids) != 1:
        raise ConfigurationError("承接结果必须全部来自同一个先前 attempt。")
    source_attempt = next(iter(carried_attempt_ids))
    after_path = (
        campaign_dir
        / relative
        / "attempts"
        / source_attempt
        / "evidence"
        / "environment"
        / "after"
        / "probe-manifest.json"
    )
    if after_path.is_symlink() or not after_path.is_file():
        raise ConfigurationError("被承接 attempt 缺少 after 环境探针，无法证明连续性。")
    after_manifest = _read_json(after_path, "被承接 attempt 的 after 探针")
    previous = _probe_snapshot_digests(after_manifest)
    current = _probe_snapshot_digests(before_manifest)
    drifted = [
        kind
        for kind in CONTINUITY_PROBE_KINDS
        if previous.get(kind) != current.get(kind)
    ]
    if drifted:
        raise ConfigurationError(
            "承接失败：上一轮结束后环境已漂移（"
            + "、".join(drifted)
            + "），被承接任务的证据前提不再成立，请不带 --rerun-failed 整轮重采。"
        )
    return {
        "schema_version": "codex-upgrade-attempt-continuity/v1",
        "source_attempt_id": source_attempt,
        "compared_kinds": list(CONTINUITY_PROBE_KINDS),
        "source_after_probe_sha256": file_sha256(after_path),
    }


def _capture_attempt_relative(phase: str, candidate_id: str | None) -> Path:
    """返回抓包 attempt 的阶段相对目录。"""

    if phase == "official":
        return Path("official")
    if not candidate_id or not SAFE_ID_RE.fullmatch(candidate_id):
        raise ConfigurationError("候选 attempt 必须绑定合法 candidate-id。")
    return Path("candidates") / candidate_id


def _capture_attempt_path(
    campaign_dir: Path,
    phase: str,
    candidate_id: str | None,
    attempt_id: str,
) -> Path:
    """解析并约束一个既有抓包 attempt 路径。"""

    if not SAFE_ID_RE.fullmatch(attempt_id):
        raise ConfigurationError("--attempt-id 格式非法。")
    relative = _capture_attempt_relative(phase, candidate_id)
    path = campaign_dir / relative / "attempts" / attempt_id
    _reject_symlink_components(path, campaign_dir, "抓包 attempt")
    if not path.is_dir() or path.is_symlink():
        raise ConfigurationError(f"抓包 attempt 不存在或不可信：{attempt_id}")
    return path


def _validate_attempt_incremental_fields(
    payload: Mapping[str, Any],
    planned_job_ids: set[str],
) -> None:
    """校验 attempt 的增量计划和 Job 结果元数据。"""

    components = payload.get("tool_components")
    if components is not None:
        if not isinstance(components, Mapping):
            raise ConfigurationError("attempt 工具组件摘要必须是对象。")
        for name, value in components.items():
            if (
                not isinstance(name, str)
                or not isinstance(value, Mapping)
                or not isinstance(value.get("entries"), list)
                or not isinstance(value.get("entry_count"), int)
                or value.get("entry_count") != len(value["entries"])
                or not SHA256_RE.fullmatch(str(value.get("sha256", "")))
            ):
                raise ConfigurationError("attempt 工具组件摘要非法。")
    plan = payload.get("incremental_plan")
    if plan is not None:
        if not isinstance(plan, Mapping):
            raise ConfigurationError("attempt 增量计划必须是对象。")
        required = {
            "schema_version",
            "planned_job_ids",
            "changed_components",
            "affected_job_ids",
            "reused_job_ids",
            "executed_job_ids",
            "failed_job_ids",
            "pending_job_ids",
            "plan_sha256",
        }
        if set(plan) != required:
            raise ConfigurationError("attempt 增量计划字段不闭合。")
        arrays = [
            plan.get("changed_components"),
            plan.get("planned_job_ids"),
            plan.get("affected_job_ids"),
            plan.get("reused_job_ids"),
            plan.get("executed_job_ids"),
            plan.get("failed_job_ids"),
            plan.get("pending_job_ids"),
        ]
        if any(
            not isinstance(value, list)
            or not all(isinstance(item, str) and item for item in value)
            or value != sorted(set(value))
            for value in arrays
        ):
            raise ConfigurationError("attempt 增量计划列表非法。")
        if (
            plan.get("schema_version") != incremental_recovery.SCHEMA_VERSION
            or set(plan["planned_job_ids"]) != planned_job_ids
            or not set(plan["affected_job_ids"]).issubset(planned_job_ids)
            or not set(plan["reused_job_ids"]).issubset(planned_job_ids)
            or not set(plan["executed_job_ids"]).issubset(planned_job_ids)
            or set(plan["reused_job_ids"]) & set(plan["executed_job_ids"])
            or set(plan["failed_job_ids"]) - set(plan["executed_job_ids"])
            or set(plan["pending_job_ids"]) - planned_job_ids
            or set(plan["pending_job_ids"])
            & (set(plan["reused_job_ids"]) | set(plan["executed_job_ids"]))
            or (
                set(plan["reused_job_ids"])
                | set(plan["executed_job_ids"])
                | set(plan["pending_job_ids"])
            ) != planned_job_ids
            or not set(plan["affected_job_ids"]).issubset(
                set(plan["executed_job_ids"]) | set(plan["pending_job_ids"])
            )
            or not SHA256_RE.fullmatch(str(plan.get("plan_sha256", "")))
        ):
            raise ConfigurationError("attempt 增量计划身份或集合非法。")
        unsigned_plan = dict(plan)
        unsigned_plan.pop("plan_sha256", None)
        if plan.get("plan_sha256") != incremental_recovery.digest(unsigned_plan):
            raise ConfigurationError("attempt 增量计划摘要不一致。")
    results = payload.get("results", [])
    if not isinstance(results, list):
        raise ConfigurationError("attempt results 必须是数组。")
    for result in results:
        if not isinstance(result, Mapping):
            raise ConfigurationError("attempt Job 结果必须是对象。")
        _validate_incremental_job_result(result, label=f"attempt:{result.get('id', '')}")
    _validate_attempt_watchdog_fields(payload, planned_job_ids)


def _write_capture_attempt(
    campaign_dir: Path,
    attempt_root: Path,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """只写一次封存 run 阶段 attempt，不允许 seal 回写。"""

    _require_formal_campaign(campaign_dir)
    phase = str(payload.get("phase", ""))
    candidate_id = payload.get("candidate_id")
    reservation = _load_capture_reservation(
        campaign_dir,
        attempt_root,
        phase=phase,
        candidate_id=(str(candidate_id) if candidate_id is not None else None),
    )
    identity = payload.get("identity")
    if not isinstance(identity, dict) or _fingerprint(identity) != reservation.get(
        "identity_sha256"
    ):
        raise ConfigurationError("抓包 attempt 身份与原子预约不一致。")
    planned = {
        item["id"]: item["execution_sha256"]
        for item in reservation["planned_jobs"]
    }
    for result in payload.get("results", []):
        if (
            not isinstance(result, dict)
            or result.get("id") not in planned
            or result.get("execution_sha256") != planned[result["id"]]
        ):
            raise ConfigurationError("抓包 attempt 任务不在原子预约内或执行摘要漂移。")
    _validate_attempt_incremental_fields(payload, set(planned))

    document = dict(payload)
    document["schema_version"] = CAPTURE_ATTEMPT_SCHEMA
    document["campaign_mode"] = reservation["campaign_mode"]
    document["campaign_purpose"] = reservation["campaign_purpose"]
    document["candidate_purpose"] = reservation["candidate_purpose"]
    document["campaign_manifest_sha256"] = file_sha256(
        campaign_dir / "campaign.json"
    )
    document["attempt_id"] = attempt_root.name
    document["run_nonce"] = reservation["run_nonce"]
    document["started_at_utc"] = reservation["started_at_utc"]
    document["completed_at_utc"] = _utc_now()
    document["reservation"] = {
        "path": str((attempt_root / "reservation.json").relative_to(campaign_dir)),
        "sha256": file_sha256(attempt_root / "reservation.json"),
    }
    document["attempt_digest"] = _fingerprint(document)
    _secure_write_json_once(attempt_root / "attempt.json", document)
    return document


def _load_capture_attempt(
    campaign_dir: Path,
    phase: str,
    candidate_id: str | None,
    attempt_id: str,
) -> tuple[Path, dict[str, Any]]:
    """读取并重验 run 阶段的不可变 attempt。"""

    _require_formal_campaign(campaign_dir)
    attempt_root = _capture_attempt_path(
        campaign_dir, phase, candidate_id, attempt_id
    )
    path = attempt_root / "attempt.json"
    _reject_symlink_components(path, campaign_dir, "抓包 attempt 收据")
    payload = _read_json(path, "抓包 attempt 收据")
    reservation = _load_capture_reservation(
        campaign_dir,
        attempt_root,
        phase=phase,
        candidate_id=candidate_id,
    )
    expected_digest = payload.get("attempt_digest")
    unsigned = dict(payload)
    unsigned.pop("attempt_digest", None)
    expected_candidate = candidate_id if phase == "candidate" else None
    manifest = load_campaign_manifest(campaign_dir)
    if (
        payload.get("schema_version") != CAPTURE_ATTEMPT_SCHEMA
        or payload.get("campaign_id") != manifest["campaign_id"]
        or payload.get("campaign_mode") != manifest["campaign_mode"]
        or payload.get("campaign_purpose") != manifest["campaign_purpose"]
        or payload.get("candidate_purpose")
        != (manifest["campaign_purpose"] if phase == "candidate" else None)
        or payload.get("campaign_mode") != reservation.get("campaign_mode")
        or payload.get("campaign_purpose") != reservation.get("campaign_purpose")
        or payload.get("candidate_purpose")
        != reservation.get("candidate_purpose")
        or payload.get("campaign_manifest_sha256")
        != file_sha256(campaign_dir / "campaign.json")
        or payload.get("attempt_id") != attempt_id
        or payload.get("phase") != phase
        or payload.get("candidate_id") != expected_candidate
        or payload.get("run_nonce") != reservation.get("run_nonce")
        or payload.get("started_at_utc") != reservation.get("started_at_utc")
        or not _is_rfc3339_timestamp(payload.get("completed_at_utc"))
        or _fingerprint(payload.get("identity"))
        != reservation.get("identity_sha256")
        or payload.get("reservation")
        != {
            "path": str((attempt_root / "reservation.json").relative_to(campaign_dir)),
            "sha256": file_sha256(attempt_root / "reservation.json"),
        }
        or not SHA256_RE.fullmatch(str(expected_digest))
        or _fingerprint(unsigned) != expected_digest
    ):
        raise ConfigurationError("抓包 attempt 身份或摘要不一致。")
    if _rfc3339_datetime(
        payload["completed_at_utc"], "attempt.completed_at_utc"
    ) < _rfc3339_datetime(
        payload["started_at_utc"], "attempt.started_at_utc"
    ):
        raise ConfigurationError("抓包 attempt 完成时间早于原子预约时间。")
    if payload.get("status") not in {
        "awaiting_receipts",
        "failed",
        "environment_contaminated",
    }:
        raise ConfigurationError("抓包 attempt 状态非法。")
    _validate_attempt_incremental_fields(
        payload,
        {str(item["id"]) for item in reservation["planned_jobs"]},
    )
    _validate_attempt_watchdog_bindings(
        campaign_dir,
        attempt_root,
        payload,
        planned_job_ids={str(item["id"]) for item in reservation["planned_jobs"]},
    )
    return attempt_root, payload


def _active_unsealed_attempts(
    campaign_dir: Path,
    phase: str,
) -> list[str]:
    """列出未完成预约或未被阶段结果绑定的 attempt。"""

    scopes: list[tuple[str | None, Path]] = []
    if phase == "official":
        scopes.append((None, campaign_dir / "official"))
    else:
        candidates_root = campaign_dir / "candidates"
        if not candidates_root.exists():
            return []
        if candidates_root.is_symlink() or not candidates_root.is_dir():
            raise ConfigurationError("候选抓包目录不可信。")
        for candidate_root in sorted(candidates_root.iterdir()):
            if not candidate_root.is_dir() or candidate_root.is_symlink():
                continue
            if not SAFE_ID_RE.fullmatch(candidate_root.name):
                raise ConfigurationError("候选抓包目录包含非法 candidate-id。")
            scopes.append((candidate_root.name, candidate_root))

    active: list[str] = []
    for candidate_id, scope in scopes:
        sealed_attempt_id: str | None = None
        result_path = scope / "result.json"
        if result_path.exists() or result_path.is_symlink():
            if result_path.is_symlink() or not result_path.is_file():
                raise ConfigurationError("抓包阶段结果路径不可信。")
            stage = _load_stage_result(
                campaign_dir,
                "capture-official" if phase == "official" else "capture-candidate",
                candidate_id,
            )
            attempt_reference = stage.get("attempt")
            if not isinstance(attempt_reference, dict):
                raise ConfigurationError("已封存抓包阶段缺少 attempt 绑定。")
            sealed_attempt_id = Path(str(attempt_reference.get("path", ""))).parent.name
        attempts_root = scope / "attempts"
        if not attempts_root.exists():
            continue
        if attempts_root.is_symlink() or not attempts_root.is_dir():
            raise ConfigurationError("抓包 attempts 目录不可信。")
        for attempt_root in sorted(attempts_root.iterdir()):
            if not attempt_root.is_dir() or attempt_root.is_symlink():
                continue
            if not SAFE_ID_RE.fullmatch(attempt_root.name):
                # 原子发布前的隐藏临时目录不属于可见 attempt 命名空间。
                if attempt_root.name.startswith(".reservation-"):
                    continue
                raise ConfigurationError("抓包目录包含非法 attempt-id。")
            _load_capture_reservation(
                campaign_dir,
                attempt_root,
                phase=phase,
                candidate_id=candidate_id,
            )
            attempt_path = attempt_root / "attempt.json"
            if not attempt_path.exists():
                active.append(
                    f"{candidate_id or 'official'}:{attempt_root.name}:reserved_or_interrupted"
                )
                continue
            if attempt_path.is_symlink() or not attempt_path.is_file():
                raise ConfigurationError("抓包 attempt 收据路径不可信。")
            _, attempt = _load_capture_attempt(
                campaign_dir,
                phase,
                candidate_id,
                attempt_root.name,
            )
            if (
                attempt.get("status") == "awaiting_receipts"
                and attempt_root.name != sealed_attempt_id
            ):
                active.append(
                    f"{candidate_id or 'official'}:{attempt_root.name}"
                )
    return active


def _failed_capture_attempts(campaign_dir: Path, phase: str) -> list[str]:
    """列出尚未通过显式 resume 处理的失败 attempt。"""

    failed: list[str] = []
    for current_phase, candidate_id, attempt_root in _campaign_attempt_roots(
        campaign_dir
    ):
        if current_phase != phase or not (attempt_root / "attempt.json").is_file():
            continue
        _, attempt = _load_capture_attempt(
            campaign_dir,
            phase,
            candidate_id,
            attempt_root.name,
        )
        if attempt.get("status") == "failed":
            failed.append(f"{candidate_id or 'official'}:{attempt_root.name}")
    return failed


def _candidate_identity_for_run(
    arguments: argparse.Namespace,
    manifest: dict[str, Any],
    classification: dict[str, Any],
    *,
    verify_image: bool = True,
    image_id_override: str | None = None,
    deadline: incremental_recovery.WallClockDeadline | None = None,
    heartbeat: Any | None = None,
) -> dict[str, Any]:
    """在任何候选请求发出前冻结实际候选身份。

    ``verify_image=False`` 只用于增量计划阶段：它不触碰 Docker，只使用调用方
    提供的 image ID（或前序失败 attempt 的只读身份提示）生成计划坐标。只要计划
    确定仍有任务需要执行，调用方必须随后以 ``verify_image=True`` 重验运行容器。
    """

    if deadline is not None:
        deadline.check("candidate-identity:start")
    required = {
        "runtime_image": getattr(arguments, "runtime_image", None),
        "build_id": getattr(arguments, "build_id", None),
        "deployed_version": getattr(arguments, "deployed_version", None),
        "profile_id": getattr(arguments, "profile_id", None),
        "profile_digest": getattr(arguments, "profile_digest", None),
        "candidate_purpose": getattr(arguments, "candidate_purpose", None),
    }
    missing = sorted(field for field, value in required.items() if not value)
    if missing:
        raise ConfigurationError(f"候选 run 缺少身份参数：{missing}")
    if not IMMUTABLE_IMAGE_RE.fullmatch(str(arguments.runtime_image)):
        raise ConfigurationError(
            "候选 --runtime-image 必须是 repository@sha256:<manifest-digest>。"
        )
    if not SHA256_RE.fullmatch(str(arguments.profile_digest)):
        raise ConfigurationError("--profile-digest 必须是 64 位小写 SHA-256。")
    if arguments.candidate_purpose not in CANDIDATE_PURPOSES:
        raise ConfigurationError(
            "--candidate-purpose 必须显式为 validation_only 或 "
            "production_replacement。"
        )
    if arguments.candidate_purpose != manifest.get("campaign_purpose"):
        raise ConfigurationError(
            "candidate purpose 与 Campaign 冻结用途不一致；必须新建 Campaign。"
        )
    for field in ("profile_id", "build_id", "deployed_version"):
        if not SAFE_ID_RE.fullmatch(str(getattr(arguments, field))):
            raise ConfigurationError(f"--{field.replace('_', '-')} 格式非法。")
    approved_profile_id, approved_profile_digest = _profile_binding_from_manifest(
        arguments.campaign_dir, classification
    )
    if (
        arguments.profile_id != approved_profile_id
        or arguments.profile_digest != approved_profile_digest
    ):
        raise ConfigurationError("候选运行画像 ID／digest 与批准画像不一致。")
    supplied_image_id = getattr(arguments, "candidate_image_id", None)
    if supplied_image_id and not IMAGE_ID_RE.fullmatch(
        str(supplied_image_id)
    ):
        raise ConfigurationError("--candidate-image-id 格式非法。")
    source_root = arguments.candidate_source or Path(__file__).resolve().parents[2]
    if not source_root.is_dir() or source_root.is_symlink():
        raise ConfigurationError("--candidate-source 不存在或不是可信目录。")
    image_id = image_id_override or supplied_image_id
    if verify_image:
        image_id = _verify_container_image_reference(
            manifest["configuration"]["service_container"],
            str(arguments.runtime_image),
            supplied_image_id,
            deadline=deadline,
            heartbeat=heartbeat,
        )
    elif not image_id or not IMAGE_ID_RE.fullmatch(str(image_id)):
        raise ConfigurationError(
            "增量计划阶段缺少候选 image ID；请提供 --candidate-image-id，"
            "或绑定可读取的前序失败 attempt。"
        )
    result = {
        "git_commit": _git_commit(source_root),
        "source_root": str(source_root.resolve(strict=True)),
        "source_tree_sha256": _directory_tree_digest(source_root),
        "image_reference": arguments.runtime_image,
        "image_digest": "sha256:"
        + arguments.runtime_image.rsplit("sha256:", 1)[-1],
        "image_id": image_id,
        "build_id": arguments.build_id,
        "deployed_version": arguments.deployed_version,
        "profile_id": arguments.profile_id,
        "profile_digest": arguments.profile_digest,
        "candidate_purpose": arguments.candidate_purpose,
    }
    if deadline is not None:
        deadline.check("candidate-identity:complete")
    return result


def _verify_candidate_attempt_identity(
    manifest: dict[str, Any], identity: dict[str, Any]
) -> None:
    """seal 前重验源码树和运行容器，防止 run／seal 间换包。"""

    source_root = Path(str(identity.get("source_root", "")))
    if (
        identity.get("candidate_purpose") not in CANDIDATE_PURPOSES
        or identity.get("candidate_purpose") != manifest.get("campaign_purpose")
    ):
        raise ConfigurationError("候选 attempt 用途与 Campaign 冻结用途不一致。")
    if (
        not source_root.is_absolute()
        or not source_root.is_dir()
        or source_root.is_symlink()
        or _directory_tree_digest(source_root) != identity.get("source_tree_sha256")
    ):
        raise ConfigurationError("候选源码树在 run／seal 之间发生漂移。")
    _verify_container_image_reference(
        manifest["configuration"]["service_container"],
        str(identity.get("image_reference", "")),
        str(identity.get("image_id", "")),
    )


def _deduplicate_evidence_roots(
    values: Iterable[Path], *, require_nonempty: bool = True
) -> list[Path]:
    """解析证据根并拒绝符号链接、文件和重复别名。"""

    roots: list[Path] = []
    seen: set[Path] = set()
    for value in values:
        if not value.is_absolute() or value.is_symlink() or not value.is_dir():
            raise ConfigurationError(f"证据根不存在或不可信：{value}")
        resolved = value.resolve(strict=True)
        if resolved in seen:
            continue
        seen.add(resolved)
        roots.append(resolved)
    if require_nonempty and not roots:
        raise ConfigurationError("抓包 attempt 没有可封存证据根。")
    return roots


def _environment_probe_arguments(
    manifest: dict[str, Any],
    output_dir: Path,
    phase: str,
) -> EnvironmentProbeArguments:
    """只从不可变 Campaign 配置构造环境探针参数。"""

    configuration = manifest["configuration"]
    return EnvironmentProbeArguments(
        output_dir=output_dir,
        service_container=configuration["service_container"],
        keeper_container=configuration["keeper_container"],
        postgres_container=configuration["postgres_container"],
        redis_container=configuration["redis_container"],
        capture_container=configuration["capture_container"],
        account_id=configuration["codex_account_id"],
        api_key_id=configuration["api_key_id"],
        phase=phase,
    )


def _invoke_with_optional_deadline(
    target: Any,
    *args: Any,
    deadline: incremental_recovery.WallClockDeadline | None = None,
    heartbeat: Any | None = None,
    **kwargs: Any,
) -> Any:
    """调用可选 deadline 接口，并兼容旧的离线适配器签名。

    只在真正调用前检查签名；绝不通过捕获调用后的 ``TypeError`` 重试，避免
    一个已经触碰外部环境的操作被重复执行。
    """

    if deadline is not None or heartbeat is not None:
        callable_target = getattr(target, "side_effect", None)
        if not callable(callable_target):
            callable_target = target
        try:
            signature = inspect.signature(callable_target)
            accepts_kwargs = any(
                parameter.kind == inspect.Parameter.VAR_KEYWORD
                for parameter in signature.parameters.values()
            )
            if deadline is not None and (
                accepts_kwargs or "deadline" in signature.parameters
            ):
                kwargs["deadline"] = deadline
            if heartbeat is not None and (
                accepts_kwargs or "heartbeat" in signature.parameters
            ):
                kwargs["heartbeat"] = heartbeat
        except (TypeError, ValueError):
            # 无法反射的真实 callable 仍按新接口传递；调用失败应直接停线。
            if deadline is not None:
                kwargs["deadline"] = deadline
            if heartbeat is not None:
                kwargs["heartbeat"] = heartbeat
    return target(*args, **kwargs)


def _probe_capture_environment(
    manifest: dict[str, Any],
    output_dir: Path,
    phase: str,
    *,
    deadline: incremental_recovery.WallClockDeadline | None = None,
    heartbeat: Any | None = None,
) -> dict[str, Any]:
    """执行独立只读探针；单独包装便于离线测试替换执行边界。"""

    if deadline is not None:
        deadline.check(f"environment-probe:{phase}:start")
    result = run_environment_probe(
        _environment_probe_arguments(manifest, output_dir, phase),
        deadline=deadline,
        heartbeat=heartbeat,
    )
    if deadline is not None:
        deadline.check(f"environment-probe:{phase}:complete")
    return result


def _capture_arm64_environment_receipt(
    output_root: Path,
    *,
    phase: str,
    subject_id: str,
    deadline: incremental_recovery.WallClockDeadline | None = None,
    heartbeat: Any | None = None,
) -> tuple[Path, dict[str, Any]]:
    """只读采集并立即重放一次 ARM64 固定网络与磁盘收据。"""

    if deadline is not None:
        deadline.check(f"arm64-receipt:{phase}:start")
    ensure_private_directory(output_root)
    codex_upgrade_arm64_environment_receipt.collect(
        output_root,
        "facts.json",
        phase=phase,
        subject_id=subject_id,
        deadline=deadline,
        heartbeat=heartbeat,
    )
    receipt = codex_upgrade_arm64_environment_receipt.finalize(
        output_root,
        "facts.json",
        "receipt.json",
    )
    replayed = codex_upgrade_arm64_environment_receipt.replay(
        output_root, "receipt.json"
    )
    if deadline is not None:
        deadline.check(f"arm64-receipt:{phase}:complete")
    if replayed != receipt:
        raise ConfigurationError("ARM64 环境收据 finalize／replay 结果不一致。")
    return output_root / "receipt.json", receipt


def _finalize_attempt_restoration(
    evidence_root: Path,
    *,
    phase: str,
    candidate_id: str | None,
    before_directory: str = "before",
    after_directory: str = "after",
    output_name: str = "restoration-report.json",
) -> tuple[Path, dict[str, Any]]:
    """只根据自动探针的十份快照生成恢复收据。"""

    receipts_root = ensure_private_directory(evidence_root / "receipts", evidence_root)
    output = receipts_root / output_name
    state_names = {
        "service": ENVIRONMENT_STATE_FILES["service"],
        "container": ENVIRONMENT_STATE_FILES["containers"],
        "database": ENVIRONMENT_STATE_FILES["database"],
        "account": ENVIRONMENT_STATE_FILES["account"],
        "configuration": ENVIRONMENT_STATE_FILES["configuration"],
    }
    values: dict[str, Any] = {
        "evidence_root": evidence_root,
        "output": output.relative_to(evidence_root),
        "phase": phase,
        "candidate_id": candidate_id,
    }
    for _, before_name, after_name, _ in RESTORATION_INPUTS:
        state_key = before_name.removesuffix("_before")
        filename = state_names[state_key]
        values[before_name] = Path("environment") / before_directory / filename
        values[after_name] = Path("environment") / after_directory / filename
    receipt = finalize_restoration(argparse.Namespace(**values))
    return output, receipt


def _candidate_post_client_restoration(
    manifest: dict[str, Any],
    evidence_root: Path,
    candidate_id: str,
) -> tuple[Path, dict[str, Any], str, bool]:
    """在 Kilo 两入口完成后，再证明其间没有丢失环境或持久数据。"""

    client_after = evidence_root / "environment" / "client-after"
    receipt_path = evidence_root / "receipts" / "client-restoration-report.json"
    if receipt_path.exists():
        if receipt_path.is_symlink() or not receipt_path.is_file():
            raise ConfigurationError("Kilo 后恢复收据路径不可信。")
        try:
            receipt = replay_receipt(
                receipt_path,
                evidence_root,
                expected_subcommand="restoration",
            )
        except (ReceiptFinalizerError, OSError, ValueError) as error:
            raise ConfigurationError(f"Kilo 后恢复收据无法重放：{error}") from error
        probe_manifest = _read_json(
            client_after / "probe-manifest.json", "Kilo 后探针清单"
        )
        checkpoint_at = probe_manifest.get("observed_at_utc")
        if probe_manifest.get("phase") != "after" or not _is_rfc3339_timestamp(
            checkpoint_at
        ):
            raise ConfigurationError("Kilo 后探针清单缺少可信检查点时间。")
        return receipt_path, receipt, str(checkpoint_at), False
    if client_after.exists() or client_after.is_symlink():
        raise ConfigurationError("Kilo 后探针已存在但没有可重放恢复收据。")
    _probe_capture_environment(manifest, client_after, "after")
    receipt_path, receipt = _finalize_attempt_restoration(
        evidence_root,
        phase="candidate",
        candidate_id=candidate_id,
        before_directory="after",
        after_directory="client-after",
        output_name="client-restoration-report.json",
    )
    probe_manifest = _read_json(
        client_after / "probe-manifest.json", "Kilo 后探针清单"
    )
    checkpoint_at = probe_manifest.get("observed_at_utc")
    if probe_manifest.get("phase") != "after" or not _is_rfc3339_timestamp(
        checkpoint_at
    ):
        raise ConfigurationError("Kilo 后探针清单缺少可信检查点时间。")
    return receipt_path, receipt, str(checkpoint_at), True


def _record_candidate_seal_failure(
    campaign_dir: Path,
    attempt_root: Path,
    attempt: dict[str, Any],
    error: BaseException,
) -> None:
    """把 Kilo 后恢复失败写入 attempt 主证据；Campaign marker 仅作冗余。"""

    document: dict[str, Any] = {
        "schema_version": SEAL_FAILURE_SCHEMA,
        "campaign_id": attempt["campaign_id"],
        "campaign_mode": attempt["campaign_mode"],
        "campaign_purpose": attempt["campaign_purpose"],
        "candidate_purpose": attempt["candidate_purpose"],
        "campaign_manifest_sha256": attempt["campaign_manifest_sha256"],
        "phase": "candidate",
        "candidate_id": attempt["candidate_id"],
        "attempt_id": attempt["attempt_id"],
        "run_nonce": attempt["run_nonce"],
        "failed_at_utc": _utc_now(),
        "error_type": type(error).__name__,
        "reason": "Kilo 后环境恢复门禁失败",
    }
    document["failure_digest"] = _fingerprint(document)
    _secure_write_json_once(attempt_root / "seal-failure.json", document)
    marker = campaign_dir / "environment-contaminated.json"
    if marker.exists() or marker.is_symlink():
        return
    try:
        _secure_write_json_once(
            marker,
            {
                "schema_version": "codex-upgrade-environment-contamination/v1",
                "phase": "candidate",
                "candidate_id": attempt["candidate_id"],
                "attempt_id": attempt["attempt_id"],
                "reason": document["reason"],
            },
        )
    except (ConfigurationError, OSError):
        # 主 seal-failure 收据已经落盘；旁路提示写失败不得抹掉污染事实。
        pass


def _attempt_evidence_binding(evidence_root: Path, path: Path) -> dict[str, Any]:
    """生成相对 attempt 证据根且含字节数的稳定文件绑定。"""

    if path.is_symlink() or not path.is_file():
        raise ConfigurationError(f"attempt 派生证据不存在或不可信：{path}")
    return {
        "path": path.relative_to(evidence_root).as_posix(),
        "sha256": file_sha256(path),
        "bytes": path.stat().st_size,
    }


def _write_or_verify_json(path: Path, payload: dict[str, Any]) -> None:
    """创建派生 JSON；已存在时只允许逐字段一致。"""

    if path.exists():
        if path.is_symlink() or _read_json(path, "派生封存文件") != payload:
            raise ConfigurationError(f"派生封存文件已经存在且内容不一致：{path}")
        return
    _secure_write_json_once(path, payload)


def _evidence_manifest_path(attempt_root: Path) -> Path:
    return attempt_root / "evidence-manifest.json"


def _evidence_manifest_checkpoint_path(attempt_root: Path) -> Path:
    return attempt_root / "evidence-manifest.checkpoint.json"


def _seal_draft_path(attempt_root: Path) -> Path:
    return attempt_root / "seal-draft.json"


def _secret_environment_names() -> list[str]:
    return [
        name
        for name in (
            "ADMIN_BEARER_TOKEN",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "SUB2API_API_KEY",
        )
        if os.environ.get(name)
    ]


def _load_evidence_manifest(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ConfigurationError(f"EvidenceManifest 不存在或路径不可信：{path}")
    payload = _read_json(path, "EvidenceManifest")
    try:
        return codex_upgrade_evidence_manifest.validate_manifest_document(payload)
    except codex_upgrade_evidence_manifest.EvidenceManifestError as error:
        raise ConfigurationError(str(error)) from error


def _stage_evidence_manifest(
    campaign_dir: Path,
    stage_payload: Mapping[str, Any],
    *,
    verify_boundary: bool,
) -> dict[str, Any]:
    binding = stage_payload.get("evidence_manifest")
    _require_file_binding(binding, "EvidenceManifest")
    path = _campaign_file(campaign_dir, str(binding["path"]))
    if path.is_symlink() or not path.is_file() or file_sha256(path) != binding["sha256"]:
        raise ConfigurationError("EvidenceManifest 文件绑定漂移。")
    manifest = _load_evidence_manifest(path)
    roots = [Path(value) for value in stage_payload.get("evidence_roots", [])]
    if not roots:
        raise ConfigurationError("EvidenceManifest 阶段缺少证据根。")
    manifest_inventory = manifest.get("inventory")
    stage_inventory = stage_payload.get("evidence_inventory")
    if manifest_inventory != stage_inventory and (
        stage_payload.get("predecessor_import") is None
        or not _inventory_contents_equal(manifest_inventory, stage_inventory)
    ):
        raise ConfigurationError("EvidenceManifest 与阶段 inventory 不一致。")
    expected_security = stage_payload.get("security")
    manifest_security = manifest.get("security")
    if (
        not isinstance(expected_security, dict)
        or not isinstance(manifest_security, dict)
        or expected_security
        != {"raw_evidence_private": True, **manifest_security}
    ):
        raise ConfigurationError("EvidenceManifest 与阶段安全收据不一致。")
    if verify_boundary:
        try:
            codex_upgrade_evidence_manifest.verify_manifest_boundary(
                manifest,
                roots,
            )
        except codex_upgrade_evidence_manifest.EvidenceManifestError as error:
            raise ConfigurationError(str(error)) from error
    return manifest


def _seal_draft(
    campaign_dir: Path,
    attempt_root: Path,
    *,
    phase: str,
    candidate_id: str | None,
    attempt: Mapping[str, Any],
    stage_payload: Mapping[str, Any],
) -> dict[str, Any]:
    core: dict[str, Any] = {
        "schema_version": SEAL_DRAFT_SCHEMA,
        "campaign_id": attempt["campaign_id"],
        "phase": phase,
        "candidate_id": candidate_id,
        "attempt_id": attempt["attempt_id"],
        "attempt_digest": attempt["attempt_digest"],
        "campaign_manifest_sha256": file_sha256(campaign_dir / "campaign.json"),
        "stage_payload": dict(stage_payload),
        "stage_payload_sha256": _fingerprint(stage_payload),
    }
    draft = {**core, "draft_digest": _fingerprint(core)}
    _write_or_verify_json(_seal_draft_path(attempt_root), draft)
    return draft


def _load_seal_draft(
    campaign_dir: Path,
    attempt_root: Path,
    *,
    phase: str,
    candidate_id: str | None,
    attempt: Mapping[str, Any],
) -> dict[str, Any]:
    path = _seal_draft_path(attempt_root)
    if path.is_symlink() or not path.is_file():
        raise ConfigurationError("seal 批准缺少冻结 seal-draft.json。")
    draft = _read_json(path, "seal 冻结草案")
    unsigned = dict(draft)
    digest = unsigned.pop("draft_digest", None)
    stage_payload = draft.get("stage_payload")
    if (
        set(draft)
        != {
            "schema_version",
            "campaign_id",
            "phase",
            "candidate_id",
            "attempt_id",
            "attempt_digest",
            "campaign_manifest_sha256",
            "stage_payload",
            "stage_payload_sha256",
            "draft_digest",
        }
        or draft.get("schema_version") != SEAL_DRAFT_SCHEMA
        or draft.get("campaign_id") != attempt.get("campaign_id")
        or draft.get("phase") != phase
        or draft.get("candidate_id") != candidate_id
        or draft.get("attempt_id") != attempt.get("attempt_id")
        or draft.get("attempt_digest") != attempt.get("attempt_digest")
        or draft.get("campaign_manifest_sha256")
        != file_sha256(campaign_dir / "campaign.json")
        or not isinstance(stage_payload, dict)
        or draft.get("stage_payload_sha256") != _fingerprint(stage_payload)
        or digest != _fingerprint(unsigned)
    ):
        raise ConfigurationError("seal 冻结草案身份或摘要不一致。")
    return draft


def _verification_manifest_paths(
    campaign_dir: Path,
    canonical: str,
    candidate_id: str | None,
) -> tuple[Path, Path]:
    suffix = canonical if candidate_id is None else f"{canonical}-{candidate_id}"
    root = campaign_dir / "verification-checkpoints" / "evidence-manifests"
    return root / f"{suffix}.json", root / f"{suffix}.checkpoint.json"


def _inventory_content_index(value: Any) -> dict[str, tuple[int, str]] | None:
    """忽略条目顺序比较历史 Inventory 内容，同时拒绝重复路径。"""

    if not isinstance(value, Mapping):
        return None
    entries = value.get("entries")
    if (
        not isinstance(entries, list)
        or value.get("entry_count") != len(entries)
    ):
        return None
    output: dict[str, tuple[int, str]] = {}
    for entry in entries:
        if not isinstance(entry, Mapping) or set(entry) != {
            "path",
            "size",
            "sha256",
        }:
            return None
        path = entry.get("path")
        size = entry.get("size")
        sha256 = entry.get("sha256")
        if (
            not isinstance(path, str)
            or not path
            or path in output
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or not isinstance(sha256, str)
            or not SHA256_RE.fullmatch(sha256)
        ):
            return None
        output[path] = (size, sha256)
    return output


def _inventory_contents_equal(left: Any, right: Any) -> bool:
    left_index = _inventory_content_index(left)
    right_index = _inventory_content_index(right)
    return (
        left_index is not None
        and right_index is not None
        and left_index == right_index
    )


def _materialize_stage_evidence_manifest(
    campaign_dir: Path,
    canonical: str,
    candidate_id: str | None,
    projected: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """用一次联合 hash／secret 扫描为历史阶段建立本地 manifest 投影。"""

    roots = [Path(value) for value in projected.get("evidence_roots", [])]
    if not roots:
        raise ConfigurationError(f"{canonical} 历史阶段缺少证据根。")
    manifest_path, scanner_checkpoint = _verification_manifest_paths(
        campaign_dir,
        canonical,
        candidate_id,
    )
    ensure_private_directory(manifest_path.parent, campaign_dir)
    if manifest_path.exists() or manifest_path.is_symlink():
        evidence_manifest = _load_evidence_manifest(manifest_path)
        try:
            codex_upgrade_evidence_manifest.verify_manifest_boundary(
                evidence_manifest,
                roots,
            )
        except codex_upgrade_evidence_manifest.EvidenceManifestError as error:
            raise ConfigurationError(str(error)) from error
    else:
        try:
            evidence_manifest = codex_upgrade_evidence_manifest.build_evidence_manifest(
                roots,
                checkpoint_path=scanner_checkpoint,
                secret_env_names=_secret_environment_names(),
            )
        except codex_upgrade_evidence_manifest.EvidenceManifestError as error:
            raise ConfigurationError(str(error)) from error
        _write_or_verify_json(manifest_path, evidence_manifest)
    expected_security = projected.get("security")
    if (
        not _inventory_contents_equal(
            evidence_manifest.get("inventory"),
            projected.get("evidence_inventory"),
        )
        or not isinstance(expected_security, dict)
        or expected_security
        != {"raw_evidence_private": True, **evidence_manifest["security"]}
        or evidence_manifest["security"].get("known_secret_scan_passed") is not True
    ):
        raise ConfigurationError(
            f"{canonical} 历史阶段与新 EvidenceManifest 的清单或安全结论不一致。"
        )
    overlay = dict(projected)
    overlay["evidence_manifest"] = {
        "path": manifest_path.relative_to(campaign_dir).as_posix(),
        "sha256": file_sha256(manifest_path),
    }
    overlay["scan_summary"] = evidence_manifest["scan"]
    _validate_stage_contract(overlay)
    return overlay, evidence_manifest


def _deep_verify_receipt_path(
    campaign_dir: Path,
    canonical: str,
    candidate_id: str | None,
) -> Path:
    suffix = canonical if candidate_id is None else f"{canonical}-{candidate_id}"
    return campaign_dir / "verification-checkpoints" / f"deep-verify-{suffix}.json"


def _write_deep_verify_receipt(
    campaign_dir: Path,
    canonical: str,
    candidate_id: str | None,
    *,
    stage_path: Path,
    evidence_manifest_binding: Mapping[str, Any] | None,
    imported_checkpoint: Path | None,
    scan: Mapping[str, Any],
    evaluation_transition: Mapping[str, Any] | None,
) -> dict[str, Any]:
    core: dict[str, Any] = {
        "schema_version": DEEP_VERIFY_RECEIPT_SCHEMA,
        "completed_at_utc": _utc_now(),
        "campaign_id": load_campaign_manifest(campaign_dir)["campaign_id"],
        "campaign_manifest_sha256": file_sha256(campaign_dir / "campaign.json"),
        "stage": canonical,
        "candidate_id": candidate_id,
        "stage_result_sha256": file_sha256(stage_path),
        "evidence_manifest": (
            dict(evidence_manifest_binding)
            if evidence_manifest_binding is not None
            else None
        ),
        "imported_checkpoint": (
            {
                "path": imported_checkpoint.relative_to(campaign_dir).as_posix(),
                "sha256": file_sha256(imported_checkpoint),
            }
            if imported_checkpoint is not None
            else None
        ),
        "scan": dict(scan),
        "evaluation_transition": (
            dict(evaluation_transition)
            if evaluation_transition is not None
            else None
        ),
        "status": "passed",
    }
    receipt = {**core, "receipt_digest": _fingerprint(core)}
    path = _deep_verify_receipt_path(campaign_dir, canonical, candidate_id)
    if path.is_file() and not path.is_symlink():
        existing = _read_json(path, "deep-verify 收据")
        existing_completed_at = existing.get("completed_at_utc")
        if not _is_rfc3339_timestamp(existing_completed_at):
            raise ConfigurationError("deep-verify 收据完成时间非法。")
        expected_core = {
            **core,
            "completed_at_utc": existing_completed_at,
        }
        expected = {
            **expected_core,
            "receipt_digest": _fingerprint(expected_core),
        }
        if existing != expected:
            raise ConfigurationError("deep-verify 收据与当前预期事实不一致。")
        return existing
    _write_or_verify_json(path, receipt)
    return receipt


def deep_verify_campaign(
    campaign_dir: Path,
    *,
    candidate_id: str | None,
    attempt_id: str | None,
) -> dict[str, Any]:
    """显式建立历史导入 checkpoint，并按需重哈希已封存 candidate。"""

    _reject_contaminated_campaign(campaign_dir)
    manifest = _require_formal_campaign(campaign_dir)
    evaluation_transition: dict[str, str] | None = None
    if attempt_id is not None:
        if not candidate_id:
            raise ConfigurationError("deep-verify 绑定 attempt 时必须提供 --candidate-id。")
        attempt_root, attempt = _load_capture_attempt(
            campaign_dir,
            "candidate",
            candidate_id,
            attempt_id,
        )
        evaluation_transition = _verify_plan_identity(
            campaign_dir,
            manifest,
            operation="deep-verify",
            attempt_root=attempt_root,
            attempt=attempt,
        )
    else:
        _verify_plan_identity(campaign_dir, manifest)

    cache: dict[tuple[str, str, str | None], dict[str, Any]] = {}
    rows: list[dict[str, Any]] = []
    for canonical in ("capture-official", "classify"):
        try:
            local = _load_stage_result(
                campaign_dir,
                canonical,
                _replay_machine_receipts=False,
                _shallow=True,
            )
        except ConfigurationError as error:
            if "尚未封存" in str(error):
                continue
            raise
        if local.get("predecessor_import") is None:
            if canonical == "capture-official" and local.get("evidence_manifest") is not None:
                manifest_path = _campaign_file(
                    campaign_dir,
                    str(local["evidence_manifest"]["path"]),
                )
                evidence_manifest = _load_evidence_manifest(manifest_path)
                _, scanner_checkpoint = _verification_manifest_paths(
                    campaign_dir,
                    canonical,
                    None,
                )
                try:
                    scan = codex_upgrade_evidence_manifest.deep_verify_manifest(
                        evidence_manifest,
                        [Path(value) for value in local["evidence_roots"]],
                        checkpoint_path=scanner_checkpoint,
                        secret_env_names=_secret_environment_names(),
                    )
                except codex_upgrade_evidence_manifest.EvidenceManifestError as error:
                    raise ConfigurationError(str(error)) from error
                receipt = _write_deep_verify_receipt(
                    campaign_dir,
                    canonical,
                    None,
                    stage_path=campaign_dir / "official" / "result.json",
                    evidence_manifest_binding=local["evidence_manifest"],
                    imported_checkpoint=None,
                    scan=scan,
                    evaluation_transition=evaluation_transition,
                )
                rows.append({"stage": canonical, "receipt_digest": receipt["receipt_digest"], **scan})
            continue
        projected = _load_stage_result(
            campaign_dir,
            canonical,
            _replay_machine_receipts=False,
            _ignore_checkpoint=True,
            _import_cache=cache,
            _skip_evidence_scan=True,
        )
        evidence_manifest: dict[str, Any] | None = None
        if canonical == "capture-official":
            if projected.get("evidence_manifest") is None:
                projected, evidence_manifest = _materialize_stage_evidence_manifest(
                    campaign_dir,
                    canonical,
                    None,
                    projected,
                )
            else:
                evidence_manifest = _stage_evidence_manifest(
                    campaign_dir,
                    projected,
                    verify_boundary=True,
                )
        checkpoint_path = _write_imported_stage_checkpoint(
            campaign_dir,
            canonical,
            None,
            local,
            projected,
        )
        scan = (
            evidence_manifest["scan"]
            if evidence_manifest is not None
            else {
                "full_scan_count": 0,
                "scanned_bytes": 0,
                "reused_bytes": 0,
                "total_bytes": 0,
                "elapsed_seconds": 0.0,
            }
        )
        stage_path = (
            campaign_dir / "official" / "result.json"
            if canonical == "capture-official"
            else campaign_dir / "classification" / "result.json"
        )
        receipt = _write_deep_verify_receipt(
            campaign_dir,
            canonical,
            None,
            stage_path=stage_path,
            evidence_manifest_binding=projected.get("evidence_manifest"),
            imported_checkpoint=checkpoint_path,
            scan=scan,
            evaluation_transition=evaluation_transition,
        )
        rows.append(
            {
                "stage": canonical,
                "receipt_digest": receipt["receipt_digest"],
                **scan,
            }
        )

    if candidate_id is not None:
        candidate_path = campaign_dir / "candidates" / candidate_id / "result.json"
        if candidate_path.is_file() and not candidate_path.is_symlink():
            candidate = _load_stage_result(
                campaign_dir,
                "capture-candidate",
                candidate_id,
                _replay_machine_receipts=False,
                _skip_evidence_scan=True,
            )
            binding = candidate.get("evidence_manifest")
            _require_file_binding(binding, "candidate EvidenceManifest")
            evidence_manifest_path = _campaign_file(
                campaign_dir,
                str(binding["path"]),
            )
            evidence_manifest = _load_evidence_manifest(evidence_manifest_path)
            _, scanner_checkpoint = _verification_manifest_paths(
                campaign_dir,
                "capture-candidate",
                candidate_id,
            )
            try:
                scan = codex_upgrade_evidence_manifest.deep_verify_manifest(
                    evidence_manifest,
                    [Path(value) for value in candidate["evidence_roots"]],
                    checkpoint_path=scanner_checkpoint,
                    secret_env_names=_secret_environment_names(),
                )
            except codex_upgrade_evidence_manifest.EvidenceManifestError as error:
                raise ConfigurationError(str(error)) from error
            receipt = _write_deep_verify_receipt(
                campaign_dir,
                "capture-candidate",
                candidate_id,
                stage_path=candidate_path,
                evidence_manifest_binding=binding,
                imported_checkpoint=None,
                scan=scan,
                evaluation_transition=evaluation_transition,
            )
            rows.append(
                {
                    "stage": "capture-candidate",
                    "candidate_id": candidate_id,
                    "receipt_digest": receipt["receipt_digest"],
                    **scan,
                }
            )
    return {
        "schema_version": "codex-upgrade-deep-verify-result/v1",
        "status": "passed",
        "campaign_id": manifest["campaign_id"],
        "candidate_id": candidate_id,
        "stages": rows,
        "full_scan_count": sum(int(row.get("full_scan_count", 0)) for row in rows),
        "scanned_bytes": sum(int(row.get("scanned_bytes", 0)) for row in rows),
        "reused_bytes": sum(int(row.get("reused_bytes", 0)) for row in rows),
        "total_bytes": sum(int(row.get("total_bytes", 0)) for row in rows),
    }


def _seal_preview(
    campaign_dir: Path,
    attempt_root: Path,
    *,
    phase: str,
    candidate_id: str | None,
    attempt: dict[str, Any],
    stage_payload: dict[str, Any],
    approve_sha256: str | None,
) -> tuple[dict[str, Any], bool]:
    """生成或复核 seal 预览；人工只批准机器事实联合摘要。"""

    evidence_manifest = stage_payload.get("evidence_manifest")
    preview_schema = (
        SEAL_PREVIEW_SCHEMA
        if isinstance(evidence_manifest, dict)
        else LEGACY_SEAL_PREVIEW_SCHEMA
    )
    core = {
        "schema_version": preview_schema,
        "campaign_id": attempt["campaign_id"],
        "campaign_mode": attempt["campaign_mode"],
        "campaign_purpose": attempt["campaign_purpose"],
        "phase": phase,
        "candidate_id": candidate_id,
        "candidate_purpose": attempt["candidate_purpose"],
        "attempt_id": attempt["attempt_id"],
        "attempt_digest": attempt["attempt_digest"],
        "stage_payload_sha256": _fingerprint(stage_payload),
        "evidence_inventory_digest": stage_payload["evidence_inventory"]["digest"],
        "assertion_manifest_sha256": stage_payload["assertion_context"][
            "capture_manifest"
        ]["sha256"],
        "restoration_report_sha256": stage_payload["restoration"]["report"][
            "sha256"
        ],
    }
    if preview_schema == SEAL_PREVIEW_SCHEMA:
        manifest = _stage_evidence_manifest(
            campaign_dir,
            stage_payload,
            verify_boundary=True,
        )
        draft = _seal_draft(
            campaign_dir,
            attempt_root,
            phase=phase,
            candidate_id=candidate_id,
            attempt=attempt,
            stage_payload=stage_payload,
        )
        core.update(
            {
                "evidence_manifest_sha256": evidence_manifest["sha256"],
                "evidence_manifest_digest": manifest["manifest_digest"],
                "seal_draft_sha256": file_sha256(_seal_draft_path(attempt_root)),
                "scan_summary": stage_payload["scan_summary"],
            }
        )
    if phase == "candidate":
        core["post_client_restoration_sha256"] = stage_payload["restoration"][
            "post_client"
        ]["report"]["sha256"]
        core["observed_profile_sha256"] = stage_payload["observed_profile"][
            "sha256"
        ]
        core["client_receipt_sha256"] = {
            item["client_id"]: item["receipt"]["sha256"]
            for item in stage_payload["client_bindings"]
        }
    review_sha256 = _fingerprint(core)
    preview = {
        **core,
        "status": "approval_required",
        "review_sha256": review_sha256,
    }
    path = attempt_root / "seal-preview.json"
    _write_or_verify_json(path, preview)
    if approve_sha256 is None:
        return preview, False
    if not SHA256_RE.fullmatch(approve_sha256):
        raise ConfigurationError("--approve-seal-sha256 格式非法。")
    if approve_sha256 != review_sha256:
        raise ConfigurationError("seal 批准摘要与当前机器事实不一致。")
    if path.is_symlink() or not path.is_file():
        raise ConfigurationError("seal 预览路径不可信。")
    return preview, True


def _run_capture_attempt(
    arguments: argparse.Namespace,
    phase: str,
) -> dict[str, Any]:
    """执行真实抓包，并以独立前后探针自动证明环境恢复。"""

    manifest = _require_formal_campaign(arguments.campaign_dir)
    _reject_contaminated_campaign(arguments.campaign_dir)
    deadline = _attempt_deadline(arguments, phase)
    seal_only = {
        "attempt_id": getattr(arguments, "attempt_id", None),
        "capture_manifest": getattr(arguments, "capture_manifest", None),
        "assertion_evidence_root": getattr(
            arguments, "assertion_evidence_root", None
        ),
        "restoration_report": getattr(arguments, "restoration_report", None),
        "evidence_root": getattr(arguments, "evidence_root", []),
        "approve_seal_sha256": getattr(
            arguments, "approve_seal_sha256", None
        ),
        "observed_profile_receipt": getattr(
            arguments, "observed_profile_receipt", None
        ),
        "client_evidence": getattr(arguments, "client_evidence", []),
    }
    unexpected = sorted(name for name, value in seal_only.items() if value)
    if unexpected:
        raise ConfigurationError(
            f"run 不读取 seal 收据参数，请在 seal 阶段提供：{unexpected}"
        )
    campaign_dir = arguments.campaign_dir
    candidate_id: str | None = None
    identity: dict[str, Any]
    classification: dict[str, Any] | None = None
    if phase == "official":
        try:
            _load_stage_result(campaign_dir, "capture-official")
        except ConfigurationError as error:
            if "尚未封存" not in str(error):
                raise
        else:
            raise ConfigurationError("官方证据已经封存，禁止重复抓包。")
        active_attempts = _active_unsealed_attempts(campaign_dir, "official")
        if active_attempts:
            raise ConfigurationError(
                f"官方存在待封存 attempt，禁止再次 run：{active_attempts}"
            )
        jobs = _campaign_jobs(campaign_dir, manifest, "official")
        attempt_relative = _capture_attempt_relative("official", None)
        # 官方二进制验证属于真实执行前提；增量计划为空时不能触发该探针。
        binary_verification = None
        identity = dict(manifest["official_identity"])
    else:
        classification = _load_stage_result(campaign_dir, "classify")
        if classification.get("status") != "complete":
            raise ConfigurationError("目标画像尚未批准，禁止候选抓包。")
        candidate_id = arguments.candidate_id
        if not SAFE_ID_RE.fullmatch(candidate_id):
            raise ConfigurationError("--candidate-id 格式非法。")
        _, candidate_result_path = _stage_path(
            campaign_dir, "capture-candidate", candidate_id
        )
        if candidate_result_path.exists():
            raise ConfigurationError("candidate-id 已封存，必须使用新编号。")
        active_attempts = _active_unsealed_attempts(campaign_dir, "candidate")
        if active_attempts:
            raise ConfigurationError(
                "Campaign 存在待封存候选 attempt，必须先完成其 Kilo 后恢复与 seal："
                f"{active_attempts}"
            )
        # 失败重跑先尝试从前序 attempt 读取候选身份。这样只为判断增量执行集合，
        # 不会调用 Docker；真正仍有 Job 要执行时才重验运行容器。
        identity_hint = None
        if getattr(arguments, "rerun_failed", False) and not getattr(
            arguments, "candidate_image_id", None
        ):
            identity_hint = _latest_failed_attempt_identity_hint(
                campaign_dir,
                phase="candidate",
                candidate_id=candidate_id,
            )
        identity = _candidate_identity_for_run(
            arguments,
            manifest,
            classification,
            verify_image=not bool(getattr(arguments, "rerun_failed", False)),
            image_id_override=(
                identity_hint.get("image_id")
                if isinstance(identity_hint, Mapping)
                else None
            ),
            deadline=deadline,
            heartbeat=None,
        )
        if identity_hint is not None:
            # 用户显式传入的坐标必须与前序失败 attempt 完全一致；否则不能把
            # 新候选身份伪装成同一轮的恢复。
            for key in (
                "image_reference",
                "image_id",
                "source_tree_sha256",
                "build_id",
                "deployed_version",
                "profile_id",
                "profile_digest",
                "candidate_purpose",
            ):
                if key in identity_hint and identity.get(key) != identity_hint.get(key):
                    raise ConfigurationError(
                        f"候选失败重跑身份与前序 attempt 不一致：{key}"
                    )
        jobs = _campaign_jobs(
            campaign_dir,
            manifest,
            "candidate",
            candidate_id=candidate_id,
            runtime_image=identity["image_reference"],
            profile_id=identity["profile_id"],
            profile_digest=identity["profile_digest"],
            build_id=identity["build_id"],
            deployed_version=identity["deployed_version"],
            candidate_image_id=identity["image_id"],
            source_tree_sha256=identity["source_tree_sha256"],
            candidate_purpose=identity["candidate_purpose"],
        )
        attempt_relative = _capture_attempt_relative("candidate", candidate_id)
        binary_verification = None

    planned_jobs = list(jobs)
    # 这里只读取受管工具树并计算组件摘要。所有可能触碰 Docker、官方二进制、
    # bubblewrap、环境探针或 live 请求的操作都必须晚于增量空集判断。
    tool_identity = _tool_identity(include_git=False)
    cheap_impact = _cheap_capture_tool_impact(
        manifest, planned_jobs, tool_identity
    )
    affected_job_ids = set(
        str(item) for item in cheap_impact.get("affected_job_ids", [])
    )
    changed_components = set(
        str(item) for item in cheap_impact.get("changed_components", [])
    )
    prior_results: list[dict[str, Any]] = []
    if getattr(arguments, "rerun_failed", False):
        prior_results = _prior_complete_results(
            campaign_dir,
            attempt_relative,
            jobs,
            phase=phase,
            candidate_id=candidate_id,
            identity=identity,
            tool_identity=tool_identity,
            affected_job_ids=affected_job_ids,
        )
        completed_ids = {item["id"] for item in prior_results}
        jobs = [job for job in jobs if job.job_id not in completed_ids]
        if not jobs:
            # 失败项为空时必须在 reservation 前结束；这条路径不要求 live
            # acknowledgement，也不创建 attempt／容器探针／环境快照。
            return _write_incremental_noop_receipt(
                campaign_dir,
                manifest,
                phase=phase,
                candidate_id=candidate_id,
                identity=identity,
                planned_job_ids=[job.job_id for job in planned_jobs],
                reused_results=prior_results,
                changed_components=changed_components,
                affected_job_ids=(),
                tool_identity=tool_identity,
                deadline=deadline,
            )

    # 从这里开始确实存在需要执行的 Job，才允许进入昂贵前置检查。
    if not getattr(arguments, "acknowledge_live_requests", False):
        raise ConfigurationError(
            "抓包会产生真实请求，必须同时确认 --acknowledge-live-requests。"
        )
    if phase == "candidate" and getattr(arguments, "rerun_failed", False):
        # 计划阶段故意不触碰 Docker；现在确认仍有任务需要执行，再冻结并重验
        # 当前运行容器身份。任何漂移都停线，不得把新身份混入旧 attempt。
        verified_identity = _candidate_identity_for_run(
            arguments,
            manifest,
            classification or {},
            verify_image=True,
            deadline=deadline,
        )
        if verified_identity != identity:
            raise ConfigurationError("候选运行身份在增量计划与执行前校验之间发生漂移。")
    # 采集脚本与 relay 从 capture_root 下的副本执行，不是本文件所在的受管树；
    # 该校验同样不能在 no-op 路径触发。
    _verify_execution_tree(getattr(arguments, "capture_root", None))
    if phase == "official":
        binary_verification = _verify_official_binaries(
            manifest,
            deadline=deadline,
        )

    # 完整计划身份校验放在 no-op 之后。它会验证 package、控制收据和工具过渡，
    # 但不会再影响已经确定的空执行集合。
    tool_impact = _verify_plan_identity(
        campaign_dir,
        manifest,
        operation="capture-run",
        deadline=deadline,
    )
    if isinstance(tool_impact, Mapping):
        changed_components.update(
            str(item) for item in tool_impact.get("changed_components", [])
        )
        affected_job_ids.update(
            str(item) for item in tool_impact.get("affected_job_ids", [])
        )
        if tool_impact.get("kind") == "component_drift":
            affected_job_ids.update(
                _affected_job_ids(
                    planned_jobs,
                    tool_impact.get("changed_components", []),
                )
            )
    else:
        tool_impact = cheap_impact
    incremental_transition: dict[str, Any] | None = None
    if (
        isinstance(tool_impact, Mapping)
        and tool_impact.get("kind") == "component_drift"
        and set(str(item) for item in tool_impact.get("changed_components", []))
        .issubset({"orchestrator", "evaluator"})
    ):
        impact_for_transition = dict(tool_impact)
        impact_for_transition["affected_job_ids"] = sorted(affected_job_ids)
        incremental_transition = _build_incremental_tool_transition(
            manifest.get("tool_identity", {}),
            tool_identity,
            impact_for_transition,
            phase=phase,
            planned_job_ids=[job.job_id for job in planned_jobs],
        )
    if phase == "candidate":
        # 辅助场景排在多个耗时 Job 之后；凭据缺失或即将过期必须在 reservation
        # 和首个真实请求之前失败，不能等十几分钟后才发现。
        _validate_candidate_admin_credential(planned_jobs)

    attempt_root, reservation = _reserve_capture_attempt(
        campaign_dir,
        phase=phase,
        candidate_id=candidate_id,
        identity=identity,
        jobs=planned_jobs,
        allow_failed_rerun=bool(getattr(arguments, "rerun_failed", False)),
        deadline=deadline,
    )
    log_root = ensure_private_directory(attempt_root / "logs", campaign_dir)
    evidence_root = ensure_private_directory(
        attempt_root / "evidence", campaign_dir
    )
    environment_root = ensure_private_directory(
        evidence_root / "environment", evidence_root
    )
    heartbeat_path = attempt_root / "watchdog-heartbeat.json"
    checkpoint_store: incremental_recovery.CheckpointStore | None = None
    setup_error: BaseException | None = None
    try:
        checkpoint_store = _job_checkpoint_store(attempt_root)
        _write_attempt_heartbeat(
            heartbeat_path,
            deadline,
            operation="attempt:reserved",
            force=True,
            attempt_root=attempt_root,
        )
        # 复用项也必须写入本 attempt 的 checkpoint，明确记录本轮没有重新
        # 发起请求；这样中断恢复只读取当前上下文链，不会把旧 attempt 的
        # 结果直接拼接成“本轮完成”。
        for reused_result in prior_results:
            if checkpoint_store is None:
                raise ConfigurationError("Job checkpoint 存储未初始化。")
            records = checkpoint_store.records()
            previous_checkpoint_sha256 = (
                records[-1].get("checkpoint_sha256") if records else None
            )
            checkpoint_store.append(
                {
                    "checkpoint_schema_version": JOB_CHECKPOINT_SCHEMA,
                    "campaign_id": manifest["campaign_id"],
                    "phase": phase,
                    "attempt_id": attempt_root.name,
                    "run_nonce": reservation["run_nonce"],
                    "item_id": reused_result.get("id"),
                    "status": "complete",
                    "disposition": "reused",
                    "result_sha256": incremental_recovery.digest(reused_result),
                    "result_key": reused_result.get("incremental_result_key"),
                    "result": reused_result,
                    "source_receipt": reused_result.get("source_receipt"),
                    "previous_checkpoint_sha256": previous_checkpoint_sha256,
                }
            )
        if binary_verification is not None:
            _secure_write_json_once(
                attempt_root / "official-binary-verification.json",
                binary_verification,
            )
    except BaseException as error:
        # watchdog／checkpoint 初始化失败不能留下一个看似可继续的 attempt；
        # 仍进入统一 after 清理，最终以 failed 停线。
        setup_error = error
    results: list[dict[str, Any]] = list(prior_results)
    execution_error: BaseException | None = setup_error
    restoration_error: BaseException | None = None
    before_manifest: dict[str, Any] | None = None
    after_manifest: dict[str, Any] | None = None
    restoration_path: Path | None = None
    restoration_receipt: dict[str, Any] | None = None
    arm64_before_path: Path | None = None
    arm64_before_receipt: dict[str, Any] | None = None
    arm64_after_path: Path | None = None
    arm64_after_receipt: dict[str, Any] | None = None
    continuity: dict[str, Any] | None = None
    timeout_checkpoint_path: Path | None = None
    timeout_checkpoint_error: BaseException | None = None
    try:
        if setup_error is None:
            deadline.check("attempt:before")
            arm64_before_path, arm64_before_receipt = _invoke_with_optional_deadline(
                _capture_arm64_environment_receipt,
                environment_root / "arm64-before",
                phase="attempt_before",
                subject_id=attempt_root.name,
                deadline=deadline,
                heartbeat=lambda operation: _write_attempt_heartbeat(
                    heartbeat_path,
                    deadline,
                    operation=operation,
                    attempt_root=attempt_root,
                ),
            )
            deadline.check("attempt:before-probe")
            before_manifest = _invoke_with_optional_deadline(
                _probe_capture_environment,
                manifest,
                environment_root / "before",
                "before",
                deadline=deadline,
                heartbeat=lambda operation: _write_attempt_heartbeat(
                    heartbeat_path,
                    deadline,
                    operation=operation,
                    attempt_root=attempt_root,
                ),
            )
            deadline.check("attempt:continuity")
            continuity = _verify_environment_continuity(
                campaign_dir,
                attempt_relative,
                {
                    str(item.get("carried_from_attempt"))
                    for item in prior_results
                    if item.get("carried_from_attempt")
                },
                before_manifest,
            )
            scenario_context = ScenarioReceiptContext(
                campaign_id=str(manifest["campaign_id"]),
                attempt_id=attempt_root.name,
                run_nonce=str(reservation["run_nonce"]),
                evidence_root=evidence_root,
                campaign_dir=campaign_dir,
            )
            for job in jobs:
                _write_attempt_heartbeat(
                    heartbeat_path,
                    deadline,
                    operation=f"job:{job.job_id}:start",
                    attempt_root=attempt_root,
                )
                result = _run_job_with_retry(
                    job,
                    log_root,
                    scenario_context,
                    identity=identity,
                    tool_identity=tool_identity,
                    deadline=deadline,
                    heartbeat=lambda operation: _write_attempt_heartbeat(
                        heartbeat_path,
                        deadline,
                        operation=operation,
                        attempt_root=attempt_root,
                    ),
                )
                results.append(result)
                if checkpoint_store is None:
                    raise ConfigurationError("Job checkpoint 存储未初始化。")
                records = checkpoint_store.records()
                previous_checkpoint_sha256 = (
                    records[-1].get("checkpoint_sha256") if records else None
                )
                checkpoint_store.append(
                    {
                        "checkpoint_schema_version": JOB_CHECKPOINT_SCHEMA,
                        "campaign_id": manifest["campaign_id"],
                        "phase": phase,
                        "attempt_id": attempt_root.name,
                        "run_nonce": reservation["run_nonce"],
                        "item_id": job.job_id,
                        "status": (
                            "complete"
                            if result.get("status") == "complete"
                            else "failed"
                        ),
                        "disposition": result.get("disposition", "executed"),
                        "result_sha256": incremental_recovery.digest(result),
                        "result_key": result.get("incremental_result_key"),
                        "result": result,
                        "previous_checkpoint_sha256": previous_checkpoint_sha256,
                    }
                )
                _secure_write_json_once(
                    attempt_root / f"job-{job.job_id}.json", result
                )
                _write_attempt_heartbeat(
                    heartbeat_path,
                    deadline,
                    operation=f"job:{job.job_id}:complete",
                    last_completed_job_id=job.job_id,
                    force=True,
                    attempt_root=attempt_root,
                )
    except BaseException as error:
        # KeyboardInterrupt、超时和进程创建失败都必须先完成 after 探针。
        if execution_error is None:
            execution_error = error
    finally:
        try:
            # 到期时不再启动新的外部操作，但仍尝试一次受控 after／恢复；失败
            # 会与 timeout 一起写入 attempt，绝不吞掉清理错误。
            if not deadline.expired:
                deadline.check("attempt:after-probe")
                after_manifest = _invoke_with_optional_deadline(
                    _probe_capture_environment,
                    manifest,
                    environment_root / "after",
                    "after",
                    deadline=deadline,
                    heartbeat=lambda operation: _write_attempt_heartbeat(
                        heartbeat_path,
                        deadline,
                        operation=operation,
                        attempt_root=attempt_root,
                    ),
                )
                deadline.check("attempt:restoration")
                restoration_path, restoration_receipt = (
                    _finalize_attempt_restoration(
                        evidence_root,
                        phase=phase,
                        candidate_id=candidate_id,
                    )
                )
        except BaseException as error:
            restoration_error = error
        try:
            if not deadline.expired:
                deadline.check("attempt:arm64-after")
                arm64_after_path, arm64_after_receipt = _invoke_with_optional_deadline(
                    _capture_arm64_environment_receipt,
                    environment_root / "arm64-after",
                    phase="attempt_after",
                    subject_id=attempt_root.name,
                    deadline=deadline,
                    heartbeat=lambda operation: _write_attempt_heartbeat(
                        heartbeat_path,
                        deadline,
                        operation=operation,
                        attempt_root=attempt_root,
                    ),
                )
                if (
                    arm64_before_receipt is None
                    or arm64_before_receipt.get("continuity_identity_sha256")
                    != arm64_after_receipt.get("continuity_identity_sha256")
                ):
                    raise ConfigurationError("attempt 前后 ARM64 网络或运行身份漂移。")
        except BaseException as error:
            if restoration_error is None:
                restoration_error = error

    if isinstance(execution_error, incremental_recovery.WallClockTimeoutError) or deadline.expired:
        # 超时是不可恢复的 attempt 终态：即使剩余清理预算为零，也必须尽力写入
        # 一次不可覆盖 checkpoint；写 checkpoint 失败会升级为停线错误。
        try:
            _write_attempt_heartbeat(
                heartbeat_path,
                deadline,
                operation="attempt:timeout",
                force=True,
                allow_expired=True,
                attempt_root=attempt_root,
            )
        except BaseException as error:
            timeout_checkpoint_error = error
        try:
            timeout_checkpoint_path = _write_timeout_checkpoint(
                attempt_root,
                deadline,
                operation=(
                    execution_error.operation
                    if isinstance(
                        execution_error,
                        incremental_recovery.WallClockTimeoutError,
                    )
                    else "attempt:deadline"
                ),
                last_completed_job_id=getattr(
                    deadline, "last_completed_job_id", None
                ),
            )
        except BaseException as error:
            timeout_checkpoint_error = timeout_checkpoint_error or error
        if timeout_checkpoint_error is not None and execution_error is None:
            execution_error = timeout_checkpoint_error

    result_by_id = {
        result.get("id"): result
        for result in results
        if isinstance(result, dict) and isinstance(result.get("id"), str)
    }
    required_jobs_ok = execution_error is None and all(
        result_by_id.get(job.job_id, {}).get("status") == "complete"
        and result_by_id[job.job_id].get("execution_sha256")
        == _job_execution_sha256(job)
        for job in planned_jobs
        if job.required
    )
    try:
        job_evidence_roots = _deduplicate_evidence_roots(
            (
                Path(root)
                for result in results
                for root in result.get("evidence_roots", [])
            ),
            require_nonempty=required_jobs_ok,
        )
    except ConfigurationError as error:
        if execution_error is None:
            execution_error = error
        required_jobs_ok = False
        job_evidence_roots = []
    evidence_roots = _deduplicate_evidence_roots(
        [
            *job_evidence_roots,
            evidence_root,
            log_root,
        ],
        require_nonempty=False,
    )

    environment: dict[str, Any] = {
        "evidence_root": str(evidence_root.resolve(strict=True)),
        "before_probe": None,
        "after_probe": None,
        "restoration_report": None,
        "arm64_before_receipt": None,
        "arm64_after_receipt": None,
    }
    before_probe_path = environment_root / "before" / "probe-manifest.json"
    after_probe_path = environment_root / "after" / "probe-manifest.json"
    if before_manifest is not None:
        environment["before_probe"] = _attempt_evidence_binding(
            evidence_root, before_probe_path
        )
    if after_manifest is not None:
        environment["after_probe"] = _attempt_evidence_binding(
            evidence_root, after_probe_path
        )
    if restoration_path is not None and restoration_receipt is not None:
        environment["restoration_report"] = _attempt_evidence_binding(
            evidence_root, restoration_path
        )
    if arm64_before_path is not None and arm64_before_receipt is not None:
        environment["arm64_before_receipt"] = _attempt_evidence_binding(
            evidence_root, arm64_before_path
        )
    if arm64_after_path is not None and arm64_after_receipt is not None:
        environment["arm64_after_receipt"] = _attempt_evidence_binding(
            evidence_root, arm64_after_path
        )

    contamination: dict[str, Any] | None = None
    if before_manifest is not None and restoration_error is not None:
        contamination = {
            "schema_version": "codex-upgrade-environment-contamination/v1",
            "phase": phase,
            "candidate_id": candidate_id,
            "attempt_id": attempt_root.name,
            "reason": (
                "独立 after 探针或恢复 finalizer 未通过："
                f"{type(restoration_error).__name__}"
            ),
        }
    # 形成 attempt 收据前固定 watchdog／checkpoint 绑定。这里仅读取小型摘要，
    # 不扫描 Job 证据内容；任何绑定读取失败都按停线处理。
    watchdog_heartbeat: dict[str, Any] | None = None
    if heartbeat_path.is_file() and not heartbeat_path.is_symlink():
        watchdog_heartbeat = {
            "path": str(heartbeat_path.relative_to(campaign_dir)),
            "sha256": file_sha256(heartbeat_path),
            "bytes": heartbeat_path.stat().st_size,
        }
    elif setup_error is None:
        execution_error = execution_error or ConfigurationError(
            "attempt 缺少 watchdog heartbeat 收据。"
        )
    job_checkpoint: dict[str, Any] | None = None
    if checkpoint_store is not None:
        try:
            checkpoint_records = checkpoint_store.records()
            job_checkpoint = {
                "schema_version": JOB_CHECKPOINT_SCHEMA,
                "campaign_id": manifest["campaign_id"],
                "phase": phase,
                "attempt_id": attempt_root.name,
                "run_nonce": reservation["run_nonce"],
                "path": str(
                    checkpoint_store.root.resolve(strict=True).relative_to(
                        campaign_dir.resolve(strict=True)
                    )
                ),
                "record_count": len(checkpoint_records),
                "last_sequence": (
                    checkpoint_records[-1].get("checkpoint_sequence")
                    if checkpoint_records
                    else None
                ),
                "last_sha256": (
                    checkpoint_records[-1].get("checkpoint_sha256")
                    if checkpoint_records
                    else None
                ),
            }
        except BaseException as error:
            # checkpoint 自身损坏或读取失败必须停线，但不能让最终 attempt
            # 收据因为异常逃逸而永远缺失；把错误保留在 attempt 主事实中。
            if execution_error is None:
                execution_error = error
            job_checkpoint = None
    elif setup_error is None:
        execution_error = execution_error or ConfigurationError(
            "attempt 缺少 Job checkpoint 存储。"
        )
    watchdog = {
        "schema_version": WATCHDOG_HEARTBEAT_SCHEMA,
        "budget_seconds": deadline.budget_seconds,
        "heartbeat_seconds": getattr(
            deadline, "heartbeat_seconds", DEFAULT_HEARTBEAT_SECONDS
        ),
        "elapsed_seconds": round(deadline.elapsed_seconds, 3),
        "remaining_seconds": round(deadline.remaining_seconds, 3),
        "heartbeat": watchdog_heartbeat,
        "timeout_checkpoint": (
            {
                "path": str(timeout_checkpoint_path.relative_to(campaign_dir)),
                "sha256": file_sha256(timeout_checkpoint_path),
                "bytes": timeout_checkpoint_path.stat().st_size,
            }
            if timeout_checkpoint_path is not None
            and timeout_checkpoint_path.is_file()
            else None
        ),
        "last_completed_job_id": getattr(
            deadline, "last_completed_job_id", None
        ),
    }
    status = (
        "environment_contaminated"
        if contamination is not None
        else "awaiting_receipts"
        if required_jobs_ok and restoration_receipt is not None
        else "failed"
    )
    attempt = _write_capture_attempt(
        campaign_dir,
        attempt_root,
        {
            "campaign_id": manifest["campaign_id"],
            "phase": phase,
            "candidate_id": candidate_id,
            "status": status,
            "continuity": continuity,
            "tool_components": (
                tool_identity.get("components")
                if isinstance(tool_identity, Mapping)
                else None
            ),
            "incremental_tool_transition": incremental_transition,
            "incremental_plan": {
                "schema_version": incremental_recovery.SCHEMA_VERSION,
                "planned_job_ids": sorted(job.job_id for job in planned_jobs),
                "changed_components": sorted(
                    tool_impact.get("changed_components", [])
                    if isinstance(tool_impact, Mapping)
                    else []
                ),
                "affected_job_ids": sorted(affected_job_ids),
                "reused_job_ids": sorted(
                    str(item.get("id"))
                    for item in prior_results
                    if item.get("id")
                ),
                "executed_job_ids": sorted(
                    str(item.get("id"))
                    for item in results
                    if item.get("id")
                    and item.get("disposition", "executed") == "executed"
                ),
                "failed_job_ids": sorted(
                    str(item.get("id"))
                    for item in results
                    if item.get("id") and item.get("status") == "failed"
                ),
                "pending_job_ids": sorted(
                    {
                        job.job_id for job in planned_jobs
                    }
                    - {
                        str(item.get("id"))
                        for item in results
                        if item.get("id")
                    }
                ),
                "plan_sha256": incremental_recovery.digest(
                    {
                        "schema_version": incremental_recovery.SCHEMA_VERSION,
                        "planned_job_ids": sorted(
                            job.job_id for job in planned_jobs
                        ),
                        "changed_components": sorted(
                            tool_impact.get("changed_components", [])
                            if isinstance(tool_impact, Mapping)
                            else []
                        ),
                        "affected_job_ids": sorted(affected_job_ids),
                        "reused_job_ids": sorted(
                            str(item.get("id"))
                            for item in prior_results
                            if item.get("id")
                        ),
                        "executed_job_ids": sorted(
                            str(item.get("id"))
                            for item in results
                            if item.get("id")
                            and item.get("disposition", "executed") == "executed"
                        ),
                        "failed_job_ids": sorted(
                            str(item.get("id"))
                            for item in results
                            if item.get("id") and item.get("status") == "failed"
                        ),
                        "pending_job_ids": sorted(
                            {
                                job.job_id for job in planned_jobs
                            }
                            - {
                                str(item.get("id"))
                                for item in results
                                if item.get("id")
                            }
                        ),
                    }
                ),
            },
            "identity": identity,
            "results": results,
            "evidence_roots": [str(root) for root in evidence_roots],
            "environment": environment,
            "binary_verification": binary_verification,
            "watchdog": watchdog,
            "job_checkpoint": job_checkpoint,
            "execution_error": (
                {
                    "type": type(execution_error).__name__,
                    "message": str(execution_error)[:1000],
                }
                if execution_error is not None
                else None
            ),
            "restoration_error": (
                {
                    "type": type(restoration_error).__name__,
                    "message": str(restoration_error)[:1000],
                }
                if restoration_error is not None
                else None
            ),
            "next_gate": (
                "运行 capture manifest finalizer；候选还需完成运行画像与两种 Kilo 原始 witness。"
                if status == "awaiting_receipts"
                else None
            ),
        },
    )
    if contamination is not None:
        try:
            _secure_write_json_once(
                campaign_dir / "environment-contaminated.json", contamination
            )
        except (ConfigurationError, OSError):
            # attempt.json 的 environment_contaminated 是主事实，marker 仅为提示。
            pass
        raise RuntimeError(contamination["reason"])
    if execution_error is not None:
        raise execution_error
    return {
        "status": status,
        "phase": phase,
        "candidate_id": candidate_id,
        "attempt_id": attempt_root.name,
        "attempt": str(attempt_root),
        "attempt_digest": attempt["attempt_digest"],
        "run_nonce": reservation["run_nonce"],
        "started_at_utc": reservation["started_at_utc"],
        "environment": environment,
        "results": results,
        "incremental_plan": (
            attempt.get("incremental_plan") if isinstance(attempt, Mapping) else None
        ),
        "next_command": (
            f"capture-{phase} seal --attempt-id {attempt_root.name}"
            if status == "awaiting_receipts"
            else "修复失败任务后使用 resume --rerun-failed。"
        ),
    }


def _approve_frozen_capture_seal(
    arguments: argparse.Namespace,
    *,
    phase: str,
    campaign_dir: Path,
    attempt_root: Path,
    attempt: dict[str, Any],
    candidate_id: str | None,
) -> dict[str, Any]:
    """只重放冻结草案与 stat 边界完成批准，不重新读取证据内容。"""

    draft = _load_seal_draft(
        campaign_dir,
        attempt_root,
        phase=phase,
        candidate_id=candidate_id,
        attempt=attempt,
    )
    payload = dict(draft["stage_payload"])
    if payload.get("status") != "complete":
        raise ConfigurationError("seal 冻结草案不是可批准的完整阶段。")
    if phase == "candidate":
        candidate_purpose = getattr(arguments, "candidate_purpose", None)
        if candidate_purpose != payload.get("candidate_purpose"):
            raise ConfigurationError("seal 批准用途与冻结草案不一致。")
    preview, approved = _seal_preview(
        campaign_dir,
        attempt_root,
        phase=phase,
        candidate_id=candidate_id,
        attempt=attempt,
        stage_payload=payload,
        approve_sha256=getattr(arguments, "approve_seal_sha256", None),
    )
    if not approved:
        raise ConfigurationError("seal 批准缺少 --approve-seal-sha256。")
    payload["seal_preview"] = {
        "path": str((attempt_root / "seal-preview.json").relative_to(campaign_dir)),
        "sha256": file_sha256(attempt_root / "seal-preview.json"),
    }
    save_stage_result(
        campaign_dir,
        "capture-official" if phase == "official" else "capture-candidate",
        payload,
        candidate_id=candidate_id,
    )
    return {
        **payload,
        "status": "complete",
        "review_sha256": preview["review_sha256"],
        "approval_scan": {
            "full_scan_count": 0,
            "scanned_bytes": 0,
        },
    }


def _manifest_surface_files(evidence_manifest: Mapping[str, Any]) -> list[Path]:
    """由已冻结 manifest 显式定位表面文件，不再递归遍历证据目录。"""

    roots = evidence_manifest.get("roots")
    entries = evidence_manifest.get("entries")
    if not isinstance(roots, list) or not isinstance(entries, list):
        raise ConfigurationError("EvidenceManifest 缺少表面文件定位信息。")
    root_index: dict[str, Path] = {}
    for item in roots:
        if (
            not isinstance(item, Mapping)
            or not isinstance(item.get("prefix"), str)
            or not isinstance(item.get("path"), str)
        ):
            raise ConfigurationError("EvidenceManifest 的证据根结构非法。")
        prefix = str(item["prefix"])
        root = Path(str(item["path"]))
        if prefix in root_index:
            raise ConfigurationError("EvidenceManifest 的证据根前缀重复。")
        root_index[prefix] = root

    selected: set[Path] = set()
    for item in entries:
        logical = item.get("path") if isinstance(item, Mapping) else None
        if not isinstance(logical, str) or "/" not in logical:
            raise ConfigurationError("EvidenceManifest 的逻辑文件路径非法。")
        prefix, relative = logical.split("/", 1)
        if (
            not relative
            or relative.startswith("/")
            or "\\" in relative
            or any(part in {"", ".", ".."} for part in relative.split("/"))
        ):
            raise ConfigurationError("EvidenceManifest 的逻辑文件路径不规范。")
        root = root_index.get(prefix)
        if root is None:
            raise ConfigurationError("EvidenceManifest 文件引用未知证据根。")
        if root.is_file():
            if relative != root.name:
                raise ConfigurationError("EvidenceManifest 的单文件根映射非法。")
            path = root
        else:
            path = root / relative
            try:
                path.resolve(strict=True).relative_to(root.resolve(strict=True))
            except (OSError, RuntimeError, ValueError) as error:
                raise ConfigurationError(
                    "EvidenceManifest 表面文件越过证据根。"
                ) from error
        if path.is_symlink() or not path.is_file():
            raise ConfigurationError("EvidenceManifest 表面文件路径发生漂移。")
        if path.suffix.lower() in {".json", ".jsonl", ".pcap", ".bin"}:
            selected.add(path.resolve(strict=True))
    return sorted(selected)


def _validate_surface_document(
    payload: Any,
    *,
    label: str,
    input_paths: list[Path],
    expected_file_count: int,
) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "label",
        "input_paths",
        "file_count",
        "surface_count",
        "surfaces",
        "warnings",
    }:
        raise ConfigurationError("抓包表面结构非法。")
    surfaces = payload.get("surfaces")
    warnings = payload.get("warnings")
    if (
        payload.get("schema_version") != SURFACE_SCHEMA
        or payload.get("label") != label
        or payload.get("input_paths") != [str(path) for path in input_paths]
        or payload.get("file_count") != expected_file_count
        or not isinstance(surfaces, list)
        or payload.get("surface_count") != len(surfaces)
        or not isinstance(warnings, list)
        or not all(isinstance(value, str) for value in warnings)
    ):
        raise ConfigurationError("抓包表面与 attempt／manifest 边界不一致。")
    for item in surfaces:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("kind"), str)
            or not isinstance(item.get("sources"), list)
            or not all(isinstance(value, str) for value in item["sources"])
            or item.get("fingerprint")
            != _fingerprint(
                {
                    key: value
                    for key, value in item.items()
                    if key not in {"fingerprint", "sources"}
                }
            )
        ):
            raise ConfigurationError("抓包表面的条目摘要非法。")
    return payload


def _load_or_build_attempt_surface(
    campaign_dir: Path,
    attempt_root: Path,
    attempt: Mapping[str, Any],
    evidence_manifest: Mapping[str, Any],
    *,
    label: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    """优先复用既有 surface；缺失时只按 manifest 文件清单做有界解析。"""

    input_paths = [Path(str(value)) for value in attempt.get("evidence_roots", [])]
    files = _manifest_surface_files(evidence_manifest)
    derived_root = ensure_private_directory(attempt_root / "finalized", campaign_dir)
    surface_path = derived_root / "surface.json"
    if surface_path.exists() or surface_path.is_symlink():
        if surface_path.is_symlink() or not surface_path.is_file():
            raise ConfigurationError("既有抓包表面路径不可信。")
        surface = _validate_surface_document(
            _read_json(surface_path, "既有抓包表面"),
            label=label,
            input_paths=input_paths,
            expected_file_count=len(files),
        )
    else:
        surface = _scan_evidence_files(
            files,
            label,
            input_paths=input_paths,
        )
        surface = _validate_surface_document(
            surface,
            label=label,
            input_paths=input_paths,
            expected_file_count=len(files),
        )
        _write_or_verify_json(surface_path, surface)
    if surface["file_count"] == 0:
        raise ConfigurationError("attempt 没有可封存抓包证据。")
    return surface, {
        "path": str(surface_path.relative_to(campaign_dir)),
        "sha256": file_sha256(surface_path),
    }


def _seal_capture_attempt(
    arguments: argparse.Namespace,
    phase: str,
) -> dict[str, Any]:
    """从不可变 attempt 与机器收据构建预览，并经摘要复核后封存阶段。"""

    campaign_dir = arguments.campaign_dir
    _reject_contaminated_campaign(campaign_dir)
    manifest = _require_formal_campaign(campaign_dir)
    attempt_id = getattr(arguments, "attempt_id", None)
    if not attempt_id:
        raise ConfigurationError("seal 必须提供 --attempt-id。")
    candidate_id = arguments.candidate_id if phase == "candidate" else None
    attempt_root, attempt = _load_capture_attempt(
        campaign_dir, phase, candidate_id, attempt_id
    )
    evaluation_transition = _verify_plan_identity(
        campaign_dir,
        manifest,
        operation=f"capture-{phase}-seal",
        attempt_root=attempt_root,
        attempt=attempt,
    )
    if attempt.get("status") != "awaiting_receipts":
        raise ConfigurationError("只有 awaiting_receipts attempt 可以 seal。")
    if getattr(arguments, "approve_seal_sha256", None) and _seal_draft_path(
        attempt_root
    ).is_file():
        return _approve_frozen_capture_seal(
            arguments,
            phase=phase,
            campaign_dir=campaign_dir,
            attempt_root=attempt_root,
            attempt=attempt,
            candidate_id=candidate_id,
        )
    if phase == "official":
        try:
            _load_stage_result(campaign_dir, "capture-official")
        except ConfigurationError as error:
            if "尚未封存" not in str(error):
                raise
        else:
            raise ConfigurationError("官方证据已经封存，禁止覆盖。")
        jobs = _campaign_jobs(campaign_dir, manifest, "official")
        identity = attempt["identity"]
        classification = None
        current_binary_verification = _verify_official_binaries(manifest)
        if _fingerprint(current_binary_verification) != _fingerprint(
            attempt.get("binary_verification", {})
        ):
            raise ConfigurationError("官方 CLI 二进制在 run／seal 之间发生漂移。")
    else:
        classification = _load_stage_result(campaign_dir, "classify")
        if classification.get("status") != "complete":
            raise ConfigurationError("目标画像尚未批准，禁止候选 seal。")
        identity = attempt.get("identity")
        if not isinstance(identity, dict):
            raise ConfigurationError("候选 attempt 缺少不可变身份。")
        optional_identity = {
            "runtime_image": "image_reference",
            "candidate_image_id": "image_id",
            "build_id": "build_id",
            "deployed_version": "deployed_version",
            "profile_id": "profile_id",
            "profile_digest": "profile_digest",
            "candidate_purpose": "candidate_purpose",
        }
        for argument_name, identity_name in optional_identity.items():
            value = getattr(arguments, argument_name, None)
            if argument_name == "candidate_purpose" and value is None:
                raise ConfigurationError(
                    "候选 seal 必须重申 --candidate-purpose。"
                )
            if value is not None and value != identity.get(identity_name):
                raise ConfigurationError(
                    f"seal 参数 --{argument_name.replace('_', '-')} 与 run 身份不一致。"
                )
        candidate_source = getattr(arguments, "candidate_source", None)
        if (
            candidate_source is not None
            and candidate_source.resolve(strict=True)
            != Path(str(identity.get("source_root", ""))).resolve(strict=True)
        ):
            raise ConfigurationError("seal 的 --candidate-source 与 run 身份不一致。")
        _verify_candidate_attempt_identity(manifest, identity)
        approved_profile_id, approved_profile_digest = _profile_binding_from_manifest(
            campaign_dir, classification
        )
        if (
            identity.get("profile_id") != approved_profile_id
            or identity.get("profile_digest") != approved_profile_digest
        ):
            raise ConfigurationError("候选 attempt 与当前批准画像不一致。")
        jobs = _campaign_jobs(
            campaign_dir,
            manifest,
            "candidate",
            candidate_id=candidate_id,
            runtime_image=str(identity.get("image_reference", "")),
            profile_id=str(identity.get("profile_id", "")),
            profile_digest=str(identity.get("profile_digest", "")),
            build_id=str(identity.get("build_id", "")),
            deployed_version=str(identity.get("deployed_version", "")),
            candidate_image_id=str(identity.get("image_id", "")),
            source_tree_sha256=str(identity.get("source_tree_sha256", "")),
            candidate_purpose=str(identity.get("candidate_purpose", "")),
        )
    _validate_capture_job_results(jobs, attempt.get("results"), phase=phase)

    roots = _deduplicate_evidence_roots(
        Path(value) for value in attempt.get("evidence_roots", [])
    )
    requested_roots = _deduplicate_evidence_roots(
        getattr(arguments, "evidence_root", []),
        require_nonempty=False,
    )
    for requested_root in requested_roots:
        if not any(
            requested_root == root or requested_root.is_relative_to(root)
            for root in roots
        ):
            raise ConfigurationError(
                "seal 的 --evidence-root 不能扩展 run 已绑定的证据边界。"
            )
    try:
        preflight = codex_upgrade_evidence_manifest.preflight_evidence_roots(roots)
    except codex_upgrade_evidence_manifest.EvidenceManifestError as error:
        raise ConfigurationError(
            f"seal 廉价前检失败（scanned_bytes=0）：{error}"
        ) from error
    environment = attempt.get("environment")
    if not isinstance(environment, dict):
        raise ConfigurationError("抓包 attempt 缺少自动环境探针绑定。")
    attempt_evidence_root = Path(str(environment.get("evidence_root", "")))
    if (
        not attempt_evidence_root.is_absolute()
        or attempt_evidence_root.resolve(strict=True) not in roots
    ):
        raise ConfigurationError("抓包 attempt 的环境证据根未纳入 seal。")
    arm64_receipts: dict[str, dict[str, Any]] = {}
    for role, expected_phase in (
        ("arm64_before_receipt", "attempt_before"),
        ("arm64_after_receipt", "attempt_after"),
    ):
        reference = environment.get(role)
        if not isinstance(reference, dict) or set(reference) != {
            "path",
            "sha256",
            "bytes",
        }:
            raise ConfigurationError(f"抓包 attempt 缺少 {role} 绑定。")
        receipt_path = attempt_evidence_root / str(reference.get("path", ""))
        if (
            receipt_path.is_symlink()
            or not receipt_path.is_file()
            or receipt_path.stat().st_size != reference.get("bytes")
            or file_sha256(receipt_path) != reference.get("sha256")
        ):
            raise ConfigurationError(f"抓包 attempt 的 {role} 摘要漂移。")
        try:
            replayed = codex_upgrade_arm64_environment_receipt.replay(
                receipt_path.parent, receipt_path.name
            )
        except (
            OSError,
            codex_upgrade_arm64_environment_receipt.Arm64EnvironmentReceiptError,
        ) as error:
            raise ConfigurationError(f"抓包 attempt 的 {role} 无法重放：{error}") from error
        if (
            replayed.get("status") != "passed"
            or replayed.get("phase") != expected_phase
            or replayed.get("subject_id") != attempt_id
        ):
            raise ConfigurationError(f"抓包 attempt 的 {role} 身份不一致。")
        arm64_receipts[role] = replayed
    if (
        arm64_receipts["arm64_before_receipt"].get(
            "continuity_identity_sha256"
        )
        != arm64_receipts["arm64_after_receipt"].get(
            "continuity_identity_sha256"
        )
    ):
        raise ConfigurationError("抓包 attempt 前后 ARM64 环境身份不连续。")
    restoration_reference = environment.get("restoration_report")
    if (
        not isinstance(restoration_reference, dict)
        or set(restoration_reference) != {"path", "sha256", "bytes"}
    ):
        raise ConfigurationError("抓包 attempt 缺少机器恢复收据绑定。")
    restoration_path = attempt_evidence_root / str(
        restoration_reference.get("path", "")
    )
    if (
        restoration_path.is_symlink()
        or not restoration_path.is_file()
        or restoration_path.stat().st_size != restoration_reference.get("bytes")
        or file_sha256(restoration_path) != restoration_reference.get("sha256")
    ):
        raise ConfigurationError("抓包 attempt 的机器恢复收据发生漂移。")
    requested_restoration = getattr(arguments, "restoration_report", None)
    if (
        requested_restoration is not None
        and requested_restoration.resolve(strict=True)
        != restoration_path.resolve(strict=True)
    ):
        raise ConfigurationError(
            "--restoration-report 只能指向 run 自动生成的恢复收据。"
        )
    post_client_path: Path | None = None
    client_checkpoint_at: str | None = None
    client_checkpoint_created = False
    if phase == "candidate":
        try:
            with _campaign_lock(campaign_dir):
                _reject_contaminated_campaign(campaign_dir)
                (
                    post_client_path,
                    _,
                    client_checkpoint_at,
                    client_checkpoint_created,
                ) = _candidate_post_client_restoration(
                    manifest,
                    attempt_evidence_root,
                    str(candidate_id),
                )
            if _rfc3339_datetime(
                client_checkpoint_at, "Kilo 后检查点时间"
            ) < _rfc3339_datetime(
                attempt["completed_at_utc"], "attempt.completed_at_utc"
            ):
                raise ConfigurationError("Kilo 后检查点早于候选 run 完成时间。")
        except (
            ConfigurationError,
            EnvironmentProbeError,
            ReceiptFinalizerError,
            OSError,
            ValueError,
        ) as error:
            _record_candidate_seal_failure(
                campaign_dir,
                attempt_root,
                attempt,
                error,
            )
            raise RuntimeError("Kilo 后环境恢复门禁失败。") from error
        if client_checkpoint_created:
            return {
                "status": "client_checkpoint_created",
                "phase": "candidate",
                "campaign_id": attempt["campaign_id"],
                "candidate_id": candidate_id,
                "attempt_id": attempt["attempt_id"],
                "run_nonce": attempt["run_nonce"],
                "attempt_started_at_utc": attempt["started_at_utc"],
                "client_checkpoint_at_utc": client_checkpoint_at,
                "evidence_root": str(attempt_evidence_root),
                "next_command": (
                    "使用上述不可变边界生成 observed-profile 与两份 Kilo 收据；"
                    "随后重新执行 capture-candidate seal。"
                ),
            }
    restoration = _validate_restoration_report(
        restoration_path,
        roots,
        phase=phase,
        candidate_id=candidate_id,
    )
    assertion_context = _capture_assertion_context(
        getattr(arguments, "capture_manifest", None),
        getattr(arguments, "assertion_evidence_root", None),
        roots,
        target_version=manifest["target_version"],
    )
    assertion_gate = _run_seal_assertion_gate(
        assertion_context,
        roots,
        phase=phase,
        target_version=manifest["target_version"],
    )
    client_bindings: list[dict[str, Any]] = []
    observed_profile: dict[str, str] | None = None
    if phase == "candidate":
        if post_client_path is None or client_checkpoint_at is None:
            raise ConfigurationError("候选 seal 缺少 Kilo 后检查点。")
        observed_profile, observed_receipt = _validate_observed_profile_receipt(
            getattr(arguments, "observed_profile_receipt", None),
            [attempt_evidence_root],
            campaign_id=attempt["campaign_id"],
            attempt_id=attempt["attempt_id"],
            run_nonce=attempt["run_nonce"],
            attempt_started_at_utc=attempt["started_at_utc"],
            client_checkpoint_at_utc=client_checkpoint_at,
            candidate_id=str(candidate_id),
            target_version=manifest["target_version"],
            expected_profile_id=str(identity["profile_id"]),
            expected_profile_digest=str(identity["profile_digest"]),
            image_id=str(identity["image_id"]),
            image_reference=str(identity["image_reference"]),
            source_tree_sha256=str(identity["source_tree_sha256"]),
            build_id=str(identity["build_id"]),
            deployed_version=str(identity["deployed_version"]),
        )
        if (
            observed_receipt.get("profile_id") != identity["profile_id"]
            or observed_receipt.get("profile_digest") != identity["profile_digest"]
        ):
            raise ConfigurationError("运行画像收据与 attempt 身份不一致。")
        client_bindings = _parse_client_evidence(
            arguments.client_evidence,
            [attempt_evidence_root],
            campaign_id=attempt["campaign_id"],
            attempt_id=attempt["attempt_id"],
            run_nonce=attempt["run_nonce"],
            attempt_started_at_utc=attempt["started_at_utc"],
            client_checkpoint_at_utc=client_checkpoint_at,
            candidate_id=str(candidate_id),
            target_version=manifest["target_version"],
            model=_third_party_client_model(manifest["configuration"]),
            identity=identity,
        )
        required_clients = _required_client_bindings(campaign_dir, classification)
        observed_clients = {item["client_id"] for item in client_bindings}
        if not required_clients.issubset(observed_clients):
            raise ConfigurationError(
                "候选 seal 缺少目标场景要求的第三方客户端收据："
                f"{sorted(required_clients - observed_clients)}"
            )
        restoration["post_client"] = _validate_restoration_report(
            post_client_path,
            roots,
            phase="candidate",
            candidate_id=str(candidate_id),
        )

    manifest_path = _evidence_manifest_path(attempt_root)
    if manifest_path.exists() or manifest_path.is_symlink():
        evidence_manifest = _load_evidence_manifest(manifest_path)
        try:
            codex_upgrade_evidence_manifest.verify_manifest_boundary(
                evidence_manifest,
                roots,
            )
        except codex_upgrade_evidence_manifest.EvidenceManifestError as error:
            raise ConfigurationError(str(error)) from error
    else:
        try:
            evidence_manifest = (
                codex_upgrade_evidence_manifest.build_evidence_manifest(
                    roots,
                    checkpoint_path=_evidence_manifest_checkpoint_path(attempt_root),
                    secret_env_names=_secret_environment_names(),
                )
            )
        except codex_upgrade_evidence_manifest.EvidenceManifestError as error:
            raise ConfigurationError(str(error)) from error
        _write_or_verify_json(manifest_path, evidence_manifest)
    evidence_inventory = evidence_manifest["inventory"]
    security = evidence_manifest["security"]
    raw_evidence_private = True
    if not security["known_secret_scan_passed"]:
        raise ConfigurationError(
            f"{phase} 证据秘密扫描失败：{len(security['findings'])} 个命中。"
        )

    _, surface_binding = _load_or_build_attempt_surface(
        campaign_dir,
        attempt_root,
        attempt,
        evidence_manifest,
        label="target-official" if phase == "official" else "target-sub2api",
    )
    payload: dict[str, Any] = {
        "status": "complete",
        "campaign_mode": manifest["campaign_mode"],
        "campaign_purpose": manifest["campaign_purpose"],
        "candidate_purpose": (
            identity.get("candidate_purpose") if phase == "candidate" else None
        ),
        "identity": {
            key: value for key, value in identity.items() if key != "source_root"
        },
        "attempt": {
            "path": str((attempt_root / "attempt.json").relative_to(campaign_dir)),
            "sha256": file_sha256(attempt_root / "attempt.json"),
        },
        "results": attempt["results"],
        "evidence_roots": [str(root) for root in roots],
        "evidence_inventory": evidence_inventory,
        "evidence_manifest": {
            "path": str(manifest_path.relative_to(campaign_dir)),
            "sha256": file_sha256(manifest_path),
        },
        "scan_summary": evidence_manifest["scan"],
        "surface": surface_binding,
        "client_bindings": client_bindings,
        "assertion_context": assertion_context,
        "assertion_gate": assertion_gate,
        "restoration": restoration,
        "security": {"raw_evidence_private": raw_evidence_private, **security},
    }
    if evaluation_transition is not None:
        payload["evaluation_transition"] = evaluation_transition
    if observed_profile is not None:
        payload["observed_profile"] = observed_profile
    if phase == "official":
        binary_verification = attempt.get("binary_verification")
        if not isinstance(binary_verification, dict):
            raise ConfigurationError("官方 attempt 缺少二进制身份验证。")
        payload["binary_verification"] = binary_verification

    preview, approved = _seal_preview(
        campaign_dir,
        attempt_root,
        phase=phase,
        candidate_id=candidate_id,
        attempt=attempt,
        stage_payload=payload,
        approve_sha256=getattr(arguments, "approve_seal_sha256", None),
    )
    if not approved:
        return {
            "status": "approval_required",
            "phase": phase,
            "candidate_id": candidate_id,
            "attempt_id": attempt_id,
            "seal_preview": str(attempt_root / "seal-preview.json"),
            "review_sha256": preview["review_sha256"],
            "message": "复核机器 finalizer 事实后，以同一摘要再次执行 seal。",
        }
    payload["seal_preview"] = {
        "path": str((attempt_root / "seal-preview.json").relative_to(campaign_dir)),
        "sha256": file_sha256(attempt_root / "seal-preview.json"),
    }
    save_stage_result(
        campaign_dir,
        "capture-official" if phase == "official" else "capture-candidate",
        payload,
        candidate_id=candidate_id,
    )
    return {
        **payload,
        "status": "complete",
        "review_sha256": preview["review_sha256"],
    }


def _surface_from_stage(
    campaign_dir: Path,
    stage: str,
    *,
    candidate_id: str | None = None,
) -> dict[str, Any]:
    result = _load_stage_result(campaign_dir, stage, candidate_id)
    reference = result.get("surface")
    if isinstance(reference, dict):
        path = _campaign_file(campaign_dir, str(reference.get("path", "")))
        if not path.is_file() or file_sha256(path) != reference.get("sha256"):
            raise ConfigurationError(f"{stage} 的表面证据摘要不一致。")
        return _read_json(path, f"{stage} 规范化表面")
    roots = [Path(value) for value in result.get("evidence_roots", [])]
    if not roots:
        raise ConfigurationError(f"{stage} 阶段缺少证据根目录。")
    label = "target-official" if stage == "capture-official" else "target-sub2api"
    surface = scan_evidence(roots, label)
    relative_root = Path("official") if stage == "capture-official" else Path("candidates") / str(candidate_id)
    output = _campaign_file(campaign_dir, str(relative_root / "surface-derived.json"))
    if output.exists():
        existing = _read_json(output, f"{stage} 派生表面")
        if _fingerprint(existing) != _fingerprint(surface):
            raise ConfigurationError(f"{stage} 派生表面与封存证据不一致。")
        return existing
    ensure_private_directory(output.parent, campaign_dir)
    secure_write_json(output, surface)
    return surface


def _analysis_payload(
    campaign_dir: Path,
    manifest: dict[str, Any],
    name: str,
) -> dict[str, Any]:
    reference = manifest["analysis"][name]
    path = _campaign_file(campaign_dir, reference["path"])
    if file_sha256(path) != reference["sha256"]:
        raise ConfigurationError(f"计划期分析摘要漂移：{name}")
    return _read_json(path, f"计划期分析 {name}")


def _validate_migration_manifest(
    migration: dict[str, Any],
    *,
    baseline_version: str,
    target_version: str,
    baseline_rules: tuple[str, ...],
    target_rules: tuple[str, ...],
    source_diff: dict[str, Any],
    official_diff: dict[str, Any],
) -> dict[str, Any]:
    if migration.get("schema_version") != MIGRATION_SCHEMA:
        raise ConfigurationError("规则迁移清单 schema_version 不受支持。")
    if migration.get("baseline_version") != baseline_version:
        raise ConfigurationError("规则迁移清单 baseline_version 不一致。")
    if migration.get("target_version") != target_version:
        raise ConfigurationError("规则迁移清单 target_version 不一致。")
    entries = migration.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ConfigurationError("规则迁移清单 entries 不能为空。")
    seen_baseline: list[str] = []
    seen_target: list[str] = []
    blocked = False
    for index, entry in enumerate(entries, 1):
        if not isinstance(entry, dict):
            raise ConfigurationError(f"迁移项 {index} 必须是对象。")
        classification = entry.get("classification")
        baseline_rule = entry.get("baseline_rule")
        target_rule = entry.get("target_rule")
        if classification not in MIGRATION_CLASSIFICATIONS:
            raise ConfigurationError(f"迁移项 {index} classification 非法。")
        if baseline_rule is not None and (
            not isinstance(baseline_rule, str) or not RULE_RE.fullmatch(baseline_rule)
        ):
            raise ConfigurationError(f"迁移项 {index} baseline_rule 非法。")
        if target_rule is not None and (
            not isinstance(target_rule, str) or not RULE_RE.fullmatch(target_rule)
        ):
            raise ConfigurationError(f"迁移项 {index} target_rule 非法。")
        if classification == "add" and (baseline_rule is not None or target_rule is None):
            raise ConfigurationError("add 迁移必须只设置 target_rule。")
        if classification == "delete" and (baseline_rule is None or target_rule is not None):
            raise ConfigurationError("delete 迁移必须只设置 baseline_rule。")
        if classification in {"inherit", "change", "condition_change"} and (
            baseline_rule is None or target_rule is None
        ):
            raise ConfigurationError(f"{classification} 迁移必须同时绑定新旧规则。")
        if classification == "inherit" and baseline_rule != target_rule:
            raise ConfigurationError("inherit 迁移必须保持规则编号一致。")
        if classification == "blocked" and baseline_rule is None and target_rule is None:
            raise ConfigurationError("blocked 迁移至少要绑定一侧规则。")
        rationale = entry.get("rationale")
        if not isinstance(rationale, str) or not rationale.strip():
            raise ConfigurationError(f"迁移项 {index} 缺少 rationale。")
        evidence_refs = entry.get("evidence_refs", [])
        if not isinstance(evidence_refs, list) or not all(
            isinstance(value, str) and value for value in evidence_refs
        ):
            raise ConfigurationError(f"迁移项 {index} evidence_refs 非法。")
        if classification != "blocked" and not evidence_refs:
            raise ConfigurationError(f"迁移项 {index} 缺少证据引用。")
        if baseline_rule is not None:
            seen_baseline.append(baseline_rule)
        if target_rule is not None:
            seen_target.append(target_rule)
        blocked = blocked or classification == "blocked"
    if sorted(seen_baseline) != sorted(baseline_rules) or len(seen_baseline) != len(
        set(seen_baseline)
    ):
        raise ConfigurationError("规则迁移未使基线规则唯一闭环。")
    if sorted(seen_target) != sorted(target_rules) or len(seen_target) != len(
        set(seen_target)
    ):
        raise ConfigurationError("规则迁移未使目标规则唯一闭环。")

    expected_discoveries = {
        (source, change, item["fingerprint"])
        for source, change, values in (
            ("source", "added", source_diff.get("added", [])),
            ("source", "removed", source_diff.get("removed", [])),
            ("dynamic", "added", official_diff.get("added", [])),
            ("dynamic", "removed", official_diff.get("removed", [])),
        )
        for item in values
    }
    discoveries = migration.get("discovery_classifications", [])
    if not isinstance(discoveries, list):
        raise ConfigurationError("discovery_classifications 必须是数组。")
    seen_discoveries: list[tuple[str, str, str]] = []
    for index, item in enumerate(discoveries, 1):
        if not isinstance(item, dict):
            raise ConfigurationError(f"发现分类 {index} 必须是对象。")
        source = item.get("source")
        change = item.get("change")
        fingerprint = item.get("fingerprint")
        classification = item.get("classification")
        if (
            source not in {"source", "dynamic"}
            or change not in {"added", "removed"}
            or not SHA256_RE.fullmatch(str(fingerprint))
        ):
            raise ConfigurationError(f"发现分类 {index} 身份非法。")
        if classification not in MIGRATION_CLASSIFICATIONS:
            raise ConfigurationError(f"发现分类 {index} classification 非法。")
        target_rule = item.get("target_rule")
        if target_rule is not None and target_rule not in target_rules:
            raise ConfigurationError(f"发现分类 {index} 引用目标规则清单外编号。")
        rationale = item.get("rationale")
        if not isinstance(rationale, str) or not rationale.strip():
            raise ConfigurationError(f"发现分类 {index} 缺少 rationale。")
        evidence_refs = item.get("evidence_refs")
        if not isinstance(evidence_refs, list) or not evidence_refs or not all(
            isinstance(value, str) and value for value in evidence_refs
        ):
            raise ConfigurationError(f"发现分类 {index} 缺少证据引用。")
        allowed = (
            {"add", "change", "condition_change", "blocked"}
            if change == "added"
            else {"delete", "change", "condition_change", "blocked"}
        )
        if classification not in allowed:
            raise ConfigurationError(
                f"发现分类 {index} 的 {change}/{classification} 组合非法。"
            )
        if classification in {"add", "change", "condition_change"} and target_rule is None:
            raise ConfigurationError(f"发现分类 {index} 必须绑定 target_rule。")
        if classification == "delete" and target_rule is not None:
            raise ConfigurationError(f"发现分类 {index} delete 不能绑定 target_rule。")
        seen_discoveries.append((source, str(change), str(fingerprint)))
        blocked = blocked or classification == "blocked"
    if set(seen_discoveries) != expected_discoveries or len(seen_discoveries) != len(
        set(seen_discoveries)
    ):
        missing = sorted(expected_discoveries - set(seen_discoveries))
        extra = sorted(set(seen_discoveries) - expected_discoveries)
        raise ConfigurationError(
            f"源码／动态增删形态未唯一分类；缺失={missing}，多余={extra}。"
        )
    return {
        "blocked": blocked,
        "entry_count": len(entries),
        "discovery_count": len(discoveries),
        "unclassified_count": 0,
    }


def _classification_differences(
    campaign_dir: Path,
    manifest: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    source_diff = _analysis_payload(campaign_dir, manifest, "source-diff")
    baseline_surface = _analysis_payload(campaign_dir, manifest, "baseline-surface")
    official_surface = _surface_from_stage(campaign_dir, "capture-official")
    official_diff = compare_surfaces(baseline_surface, official_surface)
    discovery_root = ensure_private_directory(
        campaign_dir / "classification" / "discovery", campaign_dir
    )
    output = discovery_root / "baseline-to-target-official.json"
    if output.exists():
        existing = _read_json(output, "官方动态差异")
        if _fingerprint(existing) != _fingerprint(official_diff):
            raise ConfigurationError("官方动态差异与已封存证据不一致。")
    else:
        secure_write_json(output, official_diff)
    return source_diff, official_diff


def _json_pointer(path: tuple[str, ...]) -> str:
    """把 JSON 遍历路径编码为稳定、可审核的 JSON Pointer。"""

    if not path:
        return ""
    return "/" + "/".join(
        part.replace("~", "~0").replace("/", "~1") for part in path
    )


def _replace_json_string_literal(
    value: Any,
    old: str,
    new: str,
    path: tuple[str, ...] = (),
) -> tuple[Any, list[str]]:
    """只替换 JSON 字符串中的版本字面，并返回全部受影响坐标。"""

    if isinstance(value, dict):
        result: dict[str, Any] = {}
        changed: list[str] = []
        for key, child in value.items():
            replaced, child_paths = _replace_json_string_literal(
                child,
                old,
                new,
                (*path, str(key)),
            )
            result[key] = replaced
            changed.extend(child_paths)
        return result, changed
    if isinstance(value, list):
        result_list: list[Any] = []
        changed = []
        for index, child in enumerate(value):
            replaced, child_paths = _replace_json_string_literal(
                child,
                old,
                new,
                (*path, str(index)),
            )
            result_list.append(replaced)
            changed.extend(child_paths)
        return result_list, changed
    if isinstance(value, str) and old in value:
        return value.replace(old, new), [_json_pointer(path)]
    return value, []


def _json_string_paths_containing(
    value: Any,
    literal: str,
    path: tuple[str, ...] = (),
) -> list[str]:
    """列出仍含指定版本字面的所有 JSON 字符串坐标。"""

    if isinstance(value, dict):
        return [
            pointer
            for key, child in value.items()
            for pointer in _json_string_paths_containing(
                child,
                literal,
                (*path, str(key)),
            )
        ]
    if isinstance(value, list):
        return [
            pointer
            for index, child in enumerate(value)
            for pointer in _json_string_paths_containing(
                child,
                literal,
                (*path, str(index)),
            )
        ]
    if isinstance(value, str) and literal in value:
        return [_json_pointer(path)]
    return []


def _assertion_profile_version_coordinates(
    value: Any,
    path: tuple[str, ...] = (),
) -> list[tuple[str, str]]:
    """提取断言画像中具有 Codex 版本语义的字段、header/query 与 UA 坐标。"""

    coordinates: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = (*path, str(key))
            if (
                key in {"codex_version", "client_version", "version"}
                and isinstance(child, str)
                and VERSION_RE.fullmatch(child)
            ):
                coordinates.append((_json_pointer(child_path), child))
            coordinates.extend(
                _assertion_profile_version_coordinates(child, child_path)
            )
        return coordinates
    if isinstance(value, list):
        if (
            len(value) == 2
            and isinstance(value[0], str)
            and value[0].lower() in {"client_version", "version"}
            and isinstance(value[1], str)
            and VERSION_RE.fullmatch(value[1])
        ):
            coordinates.append((_json_pointer((*path, "1")), value[1]))
        for index, child in enumerate(value):
            coordinates.extend(
                _assertion_profile_version_coordinates(
                    child,
                    (*path, str(index)),
                )
            )
        return coordinates
    if isinstance(value, str):
        matches = CODEX_USER_AGENT_VERSION_RE.finditer(value)
        for index, match in enumerate(matches, 1):
            version = next(group for group in match.groups() if group is not None)
            coordinates.append((f"{_json_pointer(path)}#ua-{index}", version))
    return coordinates


def _apply_assertion_profile_overrides(
    profile: dict[str, Any],
    *,
    target_version: str,
    base_profile_path: Path,
) -> tuple[dict[str, Any], int]:
    """把版本专属、人工审核过的期望变更确定性应用到 classify 草案。

    selector 修正属于基线画像自身的缺陷，直接修在基线画像；真正的版本行为变化
    则必须留在目标版本 override 中。这样不会为了让 0.147 通过而反向篡改 0.145
    的冻结期望，同时每个变更都要求 before 精确命中，画像漂移时会失败关闭。
    """

    path = Path(__file__).with_name(
        f"candidate_rule_expectation_overrides_{target_version.replace('.', '_')}.json"
    )
    if not path.exists():
        return profile, 0
    payload = _read_json(path, "目标版本断言期望覆盖清单")
    required = {
        "schema_version",
        "base_codex_version",
        "target_codex_version",
        "base_profile_sha256",
        "operations",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise ConfigurationError("目标版本断言期望覆盖清单字段不闭合。")
    if payload["schema_version"] != "codex-candidate-rule-expectation-overrides/v2":
        raise ConfigurationError("目标版本断言期望覆盖清单 schema_version 不受支持。")
    if payload["base_codex_version"] != profile.get("codex_version"):
        raise ConfigurationError("目标版本断言期望覆盖清单基线版本不一致。")
    if payload["target_codex_version"] != target_version:
        raise ConfigurationError("目标版本断言期望覆盖清单目标版本不一致。")
    if payload["base_profile_sha256"] != file_sha256(base_profile_path):
        raise ConfigurationError("目标版本断言期望覆盖清单绑定的基线画像摘要不一致。")
    operations = payload["operations"]
    if not isinstance(operations, list) or not operations:
        raise ConfigurationError("目标版本断言期望覆盖清单 operations 不能为空。")

    updated = json.loads(json.dumps(profile, ensure_ascii=False))
    seen: set[tuple[str, str]] = set()
    for index, operation in enumerate(operations, 1):
        expected_keys = {"rule_id", "check_id", "before", "after", "rationale"}
        if not isinstance(operation, dict) or set(operation) != expected_keys:
            raise ConfigurationError(f"断言期望覆盖操作 {index} 字段不闭合。")
        identity = (operation["rule_id"], operation["check_id"])
        if (
            not all(isinstance(item, str) and item for item in identity)
            or identity in seen
            or not isinstance(operation["rationale"], str)
            or not operation["rationale"].strip()
        ):
            raise ConfigurationError(f"断言期望覆盖操作 {index} 身份非法或重复。")
        seen.add(identity)
        matches = [
            check
            for rule in updated.get("rules", [])
            if rule.get("rule_id") == identity[0]
            for check in rule.get("checks", [])
            if check.get("id") == identity[1]
        ]
        if len(matches) != 1:
            raise ConfigurationError(f"断言期望覆盖操作 {index} 未唯一命中 check。")
        before = operation["before"]
        after = operation["after"]
        if (
            not isinstance(before, dict)
            or not before
            or not isinstance(after, dict)
            or not after
        ):
            raise ConfigurationError(
                f"断言期望覆盖操作 {index} 的 before/after 必须是非空断言对象。"
            )
        assertion = matches[0].get("assertion")
        if not isinstance(assertion, dict) or assertion != before:
            raise ConfigurationError(f"断言期望覆盖操作 {index} 的 before 不匹配。")
        matches[0]["assertion"] = json.loads(
            json.dumps(after, ensure_ascii=False)
        )
    return updated, len(operations)


def _write_classification_draft(
    campaign_dir: Path,
    manifest: dict[str, Any],
    source_diff: dict[str, Any],
    official_diff: dict[str, Any],
) -> dict[str, Any]:
    revision = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + f"-{time.time_ns() % 1_000_000_000:09d}"
    draft_root = ensure_private_directory(
        campaign_dir / "classification" / "draft" / revision, campaign_dir
    )
    rules = tuple(manifest["required_rules"])
    target_rules = {
        "schema_version": RULE_SCHEMA,
        "codex_version": manifest["target_version"],
        "required_rules": list(rules),
    }
    target_scenario_reference = manifest.get("inputs", {}).get(
        "target_discovery_scenarios"
    )
    discovery_scenarios = _read_json(
        _campaign_file(
            campaign_dir,
            (
                target_scenario_reference["path"]
                if target_scenario_reference
                else manifest["inputs"]["discovery_scenarios"]["path"]
            ),
        ),
        (
            "冻结的 target 正式采集场景清单"
            if target_scenario_reference
            else "基线发现场景清单"
        ),
    )
    scenario = json.loads(json.dumps(discovery_scenarios, ensure_ascii=False))
    draft_profile_id = f"codex-{manifest['target_version']}-draft"
    scenario["codex_version"] = manifest["target_version"]
    scenario["profile_id"] = draft_profile_id
    scenario["rule_manifest"] = {
        "path": "target-rules.json",
        "sha256": _normalized_json_sha256(target_rules),
        "rule_count": len(rules),
    }
    discoveries = [
        {
            "source": source,
            "change": change,
            "fingerprint": item["fingerprint"],
            "classification": "blocked",
            "target_rule": None,
            "evidence_refs": [
                "source-diff.json"
                if source == "source"
                else "baseline-to-target-official.json"
            ],
            "rationale": "待人工分类。",
        }
        for source, change, values in (
            ("source", "added", source_diff.get("added", [])),
            ("source", "removed", source_diff.get("removed", [])),
            ("dynamic", "added", official_diff.get("added", [])),
            ("dynamic", "removed", official_diff.get("removed", [])),
        )
        for item in values
    ]
    migration = {
        "schema_version": MIGRATION_SCHEMA,
        "baseline_version": manifest["baseline_version"],
        "target_version": manifest["target_version"],
        "status": "draft",
        "entries": [
            {
                "baseline_rule": rule,
                "target_rule": rule,
                "classification": "inherit",
                "rationale": "草案占位；必须人工复核。",
                "evidence_refs": ["source-diff.json", "baseline-to-target-official.json"],
            }
            for rule in rules
        ],
        "discovery_classifications": discoveries,
    }
    profile = {
        "schema_version": PROFILE_SCHEMA,
        "codex_version": manifest["target_version"],
        "profile_id": draft_profile_id,
        "profile_payload": {"status": "待实现并审核"},
        "profile_payload_sha256": _fingerprint({"status": "待实现并审核"}),
        "profile_digest": "0" * 64,
        "status": "draft",
    }
    baseline_profile_path = Path(__file__).with_name(
        "candidate_rule_expectations_"
        f"{manifest['baseline_version'].replace('.', '_')}.json"
    )
    assertion_profile = _read_json(baseline_profile_path, "基线断言画像")
    assertion_profile, assertion_override_count = _apply_assertion_profile_overrides(
        assertion_profile,
        target_version=manifest["target_version"],
        base_profile_path=baseline_profile_path,
    )
    assertion_profile = json.loads(
        json.dumps(assertion_profile, ensure_ascii=False)
    )
    assertion_profile["codex_version"] = manifest["target_version"]
    assertion_profile, assertion_version_paths = _replace_json_string_literal(
        assertion_profile,
        manifest["baseline_version"],
        manifest["target_version"],
    )
    secure_write_json(draft_root / "target-rules.json", target_rules)
    secure_write_json(draft_root / "rule-migration.json", migration)
    secure_write_json(draft_root / "scenarios.json", scenario)
    secure_write_json(draft_root / "profile.json", profile)
    secure_write_json(draft_root / "assertion-profile.json", assertion_profile)
    receipt = {
        "status": "draft",
        "revision": revision,
        "path": str(draft_root),
        "source_added": source_diff.get("added_count", 0),
        "dynamic_added": official_diff.get("added_count", 0),
        "blocked_discoveries": len(discoveries),
        "assertion_version_replacements": {
            "baseline_version": manifest["baseline_version"],
            "target_version": manifest["target_version"],
            "count": len(assertion_version_paths),
            "paths": assertion_version_paths,
        },
        "assertion_override_count": assertion_override_count,
    }
    secure_write_json(draft_root / "draft.json", receipt)
    return receipt


def _validate_assertion_profile_manifest(
    payload: dict[str, Any],
    *,
    baseline_version: str,
    target_version: str,
    target_rules: tuple[str, ...],
) -> None:
    """验证目标版本断言画像的规则、场景和规格摘要闭环。"""

    if payload.get("schema_version") != ASSERTION_PROFILE_SCHEMA:
        raise ConfigurationError("目标断言画像 schema_version 不受支持。")
    if payload.get("codex_version") != target_version:
        raise ConfigurationError("目标断言画像 codex_version 不一致。")
    stale_paths = _json_string_paths_containing(payload, baseline_version)
    if baseline_version != target_version and stale_paths:
        raise ConfigurationError(
            "目标断言画像仍残留 baseline 版本坐标："
            + ", ".join(stale_paths[:8])
        )
    version_coordinates = _assertion_profile_version_coordinates(payload)
    behavior_coordinates = [
        (path, version)
        for path, version in version_coordinates
        if path != "/codex_version"
    ]
    if not behavior_coordinates:
        raise ConfigurationError("目标断言画像缺少可审核的行为版本坐标。")
    mismatches = [
        (path, version)
        for path, version in behavior_coordinates
        if version != target_version
    ]
    if mismatches:
        raise ConfigurationError(
            "目标断言画像行为版本坐标与 target_version 不一致："
            + ", ".join(f"{path}={version}" for path, version in mismatches[:8])
        )
    source_spec = payload.get("source_spec")
    source_sha = payload.get("source_spec_sha256")
    if not isinstance(source_spec, str) or not SHA256_RE.fullmatch(str(source_sha)):
        raise ConfigurationError("目标断言画像规格摘要绑定非法。")
    source_path_text, separator, fragment = source_spec.partition("#")
    source_path = Path(source_path_text)
    if (
        not separator
        or source_path.is_absolute()
        or ".." in source_path.parts
        or not fragment
    ):
        raise ConfigurationError("目标断言画像 source_spec 非法。")
    resolved_source = Path(__file__).resolve().parents[2] / source_path
    if (
        not resolved_source.is_file()
        or resolved_source.is_symlink()
        or source_spec_section_sha256(resolved_source, fragment) != source_sha
    ):
        raise ConfigurationError("目标断言画像规格第二章摘要不一致。")
    scenarios = payload.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise ConfigurationError("目标断言画像 scenarios 不能为空。")
    scenario_ids = [
        item.get("scenario_id") for item in scenarios if isinstance(item, dict)
    ]
    if (
        len(scenario_ids) != len(scenarios)
        or len(scenario_ids) != len(set(scenario_ids))
        or any(not isinstance(value, str) or not value for value in scenario_ids)
    ):
        raise ConfigurationError("目标断言画像 scenario_id 非法或重复。")
    raw_rules = payload.get("rules")
    if not isinstance(raw_rules, list):
        raise ConfigurationError("目标断言画像 rules 必须是数组。")
    rule_ids: list[str] = []
    for index, rule in enumerate(raw_rules, 1):
        if not isinstance(rule, dict):
            raise ConfigurationError(f"目标断言画像规则 {index} 必须是对象。")
        rule_id = rule.get("rule_id")
        selected_scenarios = rule.get("scenario_ids")
        checks = rule.get("checks")
        if (
            not isinstance(rule_id, str)
            or not RULE_RE.fullmatch(rule_id)
            or not isinstance(selected_scenarios, list)
            or not selected_scenarios
            or not set(selected_scenarios).issubset(set(scenario_ids))
            or not isinstance(checks, list)
            or not checks
        ):
            raise ConfigurationError(f"目标断言画像规则 {index} 结构非法。")
        rule_ids.append(rule_id)
    if tuple(rule_ids) != target_rules or len(rule_ids) != len(set(rule_ids)):
        raise ConfigurationError("目标断言画像未按顺序精确覆盖目标规则全集。")


def _approved_manifest_payload(source: Path, label: str) -> dict[str, Any]:
    if not source.is_file() or source.is_symlink():
        raise ConfigurationError(f"{label}不存在或不可信：{source}")
    return _read_json(source, label)


def _normalized_json_sha256(payload: dict[str, Any]) -> str:
    encoded = (
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _official_scenario_execution_contract(
    payload: dict[str, Any],
) -> dict[str, Any]:
    """提取会改变 official Attempt 实际字节或封存判定的目标场景字段。

    分类阶段允许在人工复核后调整规则归属、场景说明和 coverage；这些变化不应伪装成
    已执行过的新命令。真正影响进程、环境、证据根和必须收据的字段必须与 plan 冻结值
    完全一致，否则只能新建 Campaign。
    """

    execution_fields = {
        "id",
        "phase",
        "suites",
        "required",
        "steps",
        "evidence_roots",
        "required_scenario_receipts",
        "track",
        "model_id",
        "expected_use_responses_lite",
        "required_model_receipt",
    }
    return {
        "schema_version": payload.get("schema_version"),
        "codex_version": payload.get("codex_version"),
        "official_jobs": [
            {key: value for key, value in job.items() if key in execution_fields}
            for job in payload.get("capture_jobs", [])
            if isinstance(job, dict) and job.get("phase") == "official"
        ],
    }


def _approved_reference(
    campaign_dir: Path,
    destination: Path,
    payload: dict[str, Any],
) -> dict[str, str]:
    return {
        "path": destination.relative_to(campaign_dir).as_posix(),
        "sha256": _normalized_json_sha256(payload),
    }


def classify_campaign(
    campaign_dir: Path,
    *,
    target_rule_manifest: Path | None = None,
    migration_manifest: Path | None = None,
    scenario_manifest: Path | None = None,
    profile_manifest: Path | None = None,
    assertion_profile_manifest: Path | None = None,
    approve_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    """把已封存官方证据转为待审核或已批准的五件套。"""

    _reject_contaminated_campaign(campaign_dir)
    manifest = _require_formal_campaign(campaign_dir)
    _verify_plan_identity(campaign_dir, manifest)
    official = _load_stage_result(campaign_dir, "capture-official")
    if official.get("status") != "complete":
        raise ConfigurationError("官方证据尚未完整封存。")
    source_diff, official_diff = _classification_differences(campaign_dir, manifest)
    if target_rule_manifest is None and migration_manifest is None:
        return _write_classification_draft(
            campaign_dir, manifest, source_diff, official_diff
        )
    if (
        target_rule_manifest is None
        or migration_manifest is None
        or scenario_manifest is None
        or profile_manifest is None
        or assertion_profile_manifest is None
    ):
        raise ConfigurationError(
            "批准分类必须同时提供目标规则、迁移、场景、运行画像和断言画像清单。"
        )
    baseline_rules = tuple(manifest["required_rules"])
    target_rules = load_rule_manifest(target_rule_manifest, manifest["target_version"])
    target_payload = _approved_manifest_payload(target_rule_manifest, "目标规则清单")
    migration = _approved_manifest_payload(migration_manifest, "规则迁移清单")
    if migration.get("status") != "approved":
        raise ConfigurationError("规则迁移清单 status 必须是 approved。")
    validation = _validate_migration_manifest(
        migration,
        baseline_version=manifest["baseline_version"],
        target_version=manifest["target_version"],
        baseline_rules=baseline_rules,
        target_rules=target_rules,
        source_diff=source_diff,
        official_diff=official_diff,
    )
    scenario_payload = _approved_manifest_payload(
        scenario_manifest, "目标场景清单"
    )
    target_scenario_reference = manifest.get("inputs", {}).get(
        "target_discovery_scenarios"
    )
    if target_scenario_reference is not None:
        frozen_target_scenario = _read_json(
            _campaign_file(campaign_dir, target_scenario_reference["path"]),
            "Formal 冻结的 target 场景清单",
        )
        if _fingerprint(
            _official_scenario_execution_contract(scenario_payload)
        ) != _fingerprint(
            _official_scenario_execution_contract(frozen_target_scenario)
        ):
            raise ConfigurationError(
                "批准的目标场景 official 执行契约与 Formal Attempt 冻结值不一致；"
                "命令或证据身份变化必须新建 Campaign。"
            )
    profile_payload = _approved_manifest_payload(profile_manifest, "目标画像清单")
    if profile_payload.get("schema_version") != PROFILE_SCHEMA:
        raise ConfigurationError("目标画像清单 schema_version 不受支持。")
    if profile_payload.get("status") != "approved":
        raise ConfigurationError("目标画像清单 status 必须是 approved。")
    if profile_payload.get("codex_version") != manifest["target_version"]:
        raise ConfigurationError("目标画像清单 codex_version 不一致。")
    if not SAFE_ID_RE.fullmatch(str(profile_payload.get("profile_id", ""))):
        raise ConfigurationError("目标画像清单 profile_id 非法。")
    if not SHA256_RE.fullmatch(str(profile_payload.get("profile_digest", ""))):
        raise ConfigurationError("目标画像清单 profile_digest 非法。")
    profile_snapshot = profile_payload.get("profile_payload")
    if not isinstance(profile_snapshot, dict) or not profile_snapshot:
        raise ConfigurationError("目标画像清单 profile_payload 不能为空。")
    if profile_payload.get("profile_payload_sha256") != _fingerprint(profile_snapshot):
        raise ConfigurationError("目标画像 profile_payload 摘要不一致。")
    if scenario_payload.get("profile_id") != profile_payload.get("profile_id"):
        raise ConfigurationError("目标场景清单 profile_id 与运行画像不一致。")
    assertion_profile_payload = _approved_manifest_payload(
        assertion_profile_manifest, "目标断言画像清单"
    )
    _validate_assertion_profile_manifest(
        assertion_profile_payload,
        baseline_version=manifest["baseline_version"],
        target_version=manifest["target_version"],
        target_rules=target_rules,
    )
    scenario_arguments = _campaign_arguments(campaign_dir, manifest)
    scenario_arguments.scenario_manifest = scenario_manifest
    scenario_context = _job_context(scenario_arguments)
    scenario_jobs = load_scenario_jobs(
        scenario_manifest,
        scenario_context,
        expected_version=manifest["target_version"],
        expected_rule_sha256=file_sha256(target_rule_manifest),
        require_bindings=True,
    )
    scenario_jobs = [
        job for job in scenario_jobs if manifest["suite"] in job.suites
    ]
    _validate_jobs(scenario_jobs, target_rules)
    if manifest["suite"] == "full":
        _validate_phase_coverage(scenario_jobs, target_rules)
    # 后继 Campaign 承接的 official 结果仍绑定前序 Campaign 的原始执行坐标。
    # ``_load_stage_result`` 已沿不可变导入链在原始目录逐项重放预约、结果和
    # execution_sha256；这里若再用后继 campaign-id、仓库路径和证据根重算哈希，
    # 会把合法的坐标重绑定误报成执行定义漂移。批准场景仍在上方与当前 Formal
    # 冻结的 target 执行契约逐摘要一致，只有非导入 official 才需再次精确比对。
    if official.get("predecessor_import") is None:
        _validate_capture_job_results(
            [job for job in scenario_jobs if job.phase == "official"],
            official.get("results"),
            phase="official",
        )
    approved_root = campaign_dir / "classification" / "approved"
    target_destination = approved_root / "target-rules.json"
    migration_destination = approved_root / "rule-migration.json"
    scenario_destination = approved_root / "scenarios.json"
    profile_destination = approved_root / "profile.json"
    assertion_profile_destination = approved_root / "assertion-profile.json"
    target_reference = _approved_reference(
        campaign_dir, target_destination, target_payload
    )
    migration_reference = _approved_reference(
        campaign_dir, migration_destination, migration
    )
    scenario_reference = _approved_reference(
        campaign_dir, scenario_destination, scenario_payload
    )
    profile_reference = _approved_reference(
        campaign_dir, profile_destination, profile_payload
    )
    assertion_profile_reference = _approved_reference(
        campaign_dir,
        assertion_profile_destination,
        assertion_profile_payload,
    )
    references = {
        "target_rule_manifest": target_reference,
        "migration_manifest": migration_reference,
        "scenario_manifest": scenario_reference,
        "profile_manifest": profile_reference,
        "assertion_profile_manifest": assertion_profile_reference,
    }
    joint_digest = _fingerprint(
        {
            key: value["sha256"] if value else None
            for key, value in references.items()
        }
    )
    if approve_manifest_sha256 is None:
        return {
            "status": "approval_required",
            "joint_manifest_sha256": joint_digest,
            "message": "复核五份目标版本清单后，以该联合摘要再次执行 classify。",
        }
    if not SHA256_RE.fullmatch(approve_manifest_sha256):
        raise ConfigurationError("--approve-manifest-sha256 格式非法。")
    if approve_manifest_sha256 != joint_digest:
        raise ConfigurationError("批准联合摘要与清单内容不一致。")
    if approved_root.exists():
        raise ConfigurationError("分类批准目录已经存在，禁止覆盖。")
    ensure_private_directory(approved_root.parent, campaign_dir)
    try:
        approved_root.mkdir(mode=0o700)
    except FileExistsError as error:
        raise ConfigurationError("分类批准目录已经存在，禁止覆盖。") from error
    secure_write_json(target_destination, target_payload)
    secure_write_json(migration_destination, migration)
    secure_write_json(scenario_destination, scenario_payload)
    secure_write_json(profile_destination, profile_payload)
    secure_write_json(assertion_profile_destination, assertion_profile_payload)
    payload = {
        "status": "blocked" if validation["blocked"] else "complete",
        **references,
        "joint_manifest_sha256": joint_digest,
        "baseline_rule_count": len(baseline_rules),
        "target_rule_count": len(target_rules),
        "migration": validation,
        "source_diff_sha256": _fingerprint(source_diff),
        "official_diff_sha256": _fingerprint(official_diff),
    }
    save_stage_result(campaign_dir, "classify", payload)
    return payload


def _profile_binding_from_manifest(
    campaign_dir: Path,
    classification: dict[str, Any],
) -> tuple[str | None, str | None]:
    reference = classification.get("profile_manifest")
    if not isinstance(reference, dict):
        return None, None
    path = _campaign_file(campaign_dir, str(reference.get("path", "")))
    if not path.is_file() or file_sha256(path) != reference.get("sha256"):
        raise ConfigurationError("批准画像清单摘要不一致。")
    profile = _read_json(path, "批准画像清单")
    profile_id = profile.get("profile_id") or profile.get("id")
    profile_digest = profile.get("profile_digest") or profile.get("digest")
    if isinstance(profile.get("profile"), dict):
        profile_id = profile_id or profile["profile"].get("id")
        profile_digest = profile_digest or profile["profile"].get("digest")
    return (
        str(profile_id) if profile_id is not None else None,
        str(profile_digest) if profile_digest is not None else None,
    )


def prepare_profile_manifest(
    campaign_dir: Path,
    snapshot: Path,
    profile_id: str,
    output: Path,
) -> dict[str, Any]:
    """把官方取证形成的完整 Snapshot 规范化为 classify 审核输入。"""

    _require_formal_campaign(campaign_dir)
    _validate_existing_campaign_path(campaign_dir)
    _reject_contaminated_campaign(campaign_dir)
    manifest = load_campaign_manifest(campaign_dir)
    _verify_plan_identity(campaign_dir, manifest)
    if campaign_status(campaign_dir, None).get("status") != "official_sealed":
        raise ConfigurationError("prepare-profile 只允许从 official_sealed 状态执行。")
    if not SAFE_ID_RE.fullmatch(profile_id):
        raise ConfigurationError("--profile-id 格式非法。")
    if not snapshot.is_file() or snapshot.is_symlink():
        raise ConfigurationError("--snapshot 必须是非符号链接普通文件。")
    if not output.is_absolute() or output.is_symlink() or output.exists():
        raise ConfigurationError("--output 必须是不存在的非符号链接绝对路径。")
    resolved_output = output.resolve(strict=False)
    if resolved_output in {
        Path("/").resolve(),
        Path.home().resolve(),
        Path("/tmp").resolve(),
    }:
        raise ConfigurationError("--output 不能是根目录、HOME 或 /tmp 本身。")
    try:
        resolved_output.relative_to(campaign_dir.resolve(strict=True))
    except ValueError:
        pass
    else:
        raise ConfigurationError("画像草案不得写入不可变 Campaign 目录。")
    repository_root = Path(__file__).resolve().parents[2]
    completed = subprocess.run(
        [
            "go",
            "run",
            "./cmd/egresscatalogstage",
            "-prepare-snapshot",
            str(snapshot),
            "-prepare-profile-id",
            profile_id,
            "-prepare-output",
            str(output),
        ],
        cwd=repository_root / "backend",
        check=False,
        capture_output=True,
        text=True,
        timeout=PROFILE_GENERATOR_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise ConfigurationError("画像草案生成器失败：" + (detail or "无错误输出"))
    try:
        profile = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ConfigurationError("画像草案生成器未返回合法 JSON。") from error
    if (
        not isinstance(profile, dict)
        or profile.get("status") != "draft"
        or profile.get("codex_version") != manifest["target_version"]
        or profile.get("profile_id") != profile_id
        or not SHA256_RE.fullmatch(str(profile.get("profile_digest", "")))
        or not output.is_file()
        or output.is_symlink()
        or _fingerprint(_read_json(output, "画像草案")) != _fingerprint(profile)
    ):
        raise ConfigurationError("画像草案身份、版本或落盘内容不一致。")
    profile["output"] = str(output)
    return profile


def stage_profile_catalog(campaign_dir: Path, output: Path) -> dict[str, Any]:
    """验证 profile_approved 身份并调用 Go 契约生成离线候选目录。"""

    _require_formal_campaign(campaign_dir)
    _validate_existing_campaign_path(campaign_dir)
    _reject_contaminated_campaign(campaign_dir)
    manifest = load_campaign_manifest(campaign_dir)
    _verify_plan_identity(campaign_dir, manifest)
    status = campaign_status(campaign_dir, None)
    if status.get("status") != "profile_approved":
        raise ConfigurationError("stage-profile 只允许从 profile_approved 状态执行。")
    classification = _load_stage_result(campaign_dir, "classify")
    if (
        classification.get("status") != "complete"
        or classification.get("migration", {}).get("unclassified_count") != 0
    ):
        raise ConfigurationError("分类尚未完整批准或仍有未分类项。")
    references = {
        key: classification.get(key)
        for key in (
            "target_rule_manifest",
            "migration_manifest",
            "scenario_manifest",
            "profile_manifest",
            "assertion_profile_manifest",
        )
    }
    for label, reference in references.items():
        if not isinstance(reference, dict):
            raise ConfigurationError(f"批准分类缺少引用：{label}")
        approved_path = _campaign_file(
            campaign_dir,
            str(reference.get("path", "")),
        )
        if (
            not approved_path.is_file()
            or approved_path.is_symlink()
            or file_sha256(approved_path) != reference.get("sha256")
        ):
            raise ConfigurationError(f"批准分类引用摘要不一致：{label}")
    joint_digest = _fingerprint(
        {
            key: reference["sha256"]
            for key, reference in references.items()
            if isinstance(reference, dict)
        }
    )
    if joint_digest != classification.get("joint_manifest_sha256"):
        raise ConfigurationError("五份批准清单联合摘要不一致。")
    profile_reference = references["profile_manifest"]
    assert isinstance(profile_reference, dict)
    profile_path = _campaign_file(campaign_dir, profile_reference["path"])
    profile = _read_json(profile_path, "批准画像清单")
    if (
        profile.get("status") != "approved"
        or profile.get("codex_version") != manifest.get("target_version")
        or not SHA256_RE.fullmatch(str(profile.get("profile_digest", "")))
    ):
        raise ConfigurationError("批准画像身份不完整或与 Campaign 目标版本不一致。")

    if not output.is_absolute() or output.is_symlink():
        raise ConfigurationError("--output 必须是非符号链接绝对路径。")
    resolved_output = output.resolve(strict=False)
    if resolved_output in {
        Path("/").resolve(),
        Path.home().resolve(),
        Path("/tmp").resolve(),
    }:
        raise ConfigurationError("--output 不能是根目录、HOME 或 /tmp 本身。")
    if output.exists():
        raise ConfigurationError("--output 已存在，禁止覆盖候选目录。")
    try:
        resolved_output.relative_to(campaign_dir.resolve(strict=True))
    except ValueError:
        pass
    else:
        raise ConfigurationError("候选 RuntimeCatalog 不得写入不可变 Campaign 目录。")

    repository_root = Path(__file__).resolve().parents[2]
    backend_root = repository_root / "backend"
    command = [
        "go",
        "run",
        "./cmd/egresscatalogstage",
        "-profile-manifest",
        str(profile_path),
        "-campaign-id",
        str(manifest["campaign_id"]),
        "-classification-sha256",
        joint_digest,
        "-output",
        str(output),
    ]
    completed = subprocess.run(
        command,
        cwd=backend_root,
        check=False,
        capture_output=True,
        text=True,
        timeout=PROFILE_GENERATOR_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise ConfigurationError(
            "候选 RuntimeCatalog 生成器失败：" + (detail or "无错误输出")
        )
    try:
        receipt = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ConfigurationError("候选 RuntimeCatalog 生成器未返回合法收据。") from error
    if (
        not isinstance(receipt, dict)
        or receipt.get("campaign_id") != manifest["campaign_id"]
        or receipt.get("classification_sha256") != joint_digest
        or receipt.get("target_version") != manifest["target_version"]
        or receipt.get("target_profile_digest") != profile["profile_digest"]
        or receipt.get("active_unchanged") is not True
        or receipt.get("production_selector_changed") is not False
        or receipt.get("candidate_release_mode") != "previous"
    ):
        raise ConfigurationError("候选 RuntimeCatalog 收据身份或权限边界不一致。")
    _verify_catalog_stage_output(output, receipt)
    receipt["output"] = str(output)
    return receipt


def _verify_catalog_stage_output(output: Path, receipt: dict[str, Any]) -> None:
    """逐文件重算候选目录，拒绝收据与落盘资产分离。"""

    if not output.is_dir() or output.is_symlink():
        raise ConfigurationError("候选 RuntimeCatalog 输出目录不存在或不可信。")
    receipt_path = output / "catalog-stage-receipt.json"
    if not receipt_path.is_file() or receipt_path.is_symlink():
        raise ConfigurationError("候选 RuntimeCatalog 缺少可信生成收据。")
    stored_receipt = _read_json(receipt_path, "候选 RuntimeCatalog 收据")
    if _fingerprint(stored_receipt) != _fingerprint(receipt):
        raise ConfigurationError("候选 RuntimeCatalog 标准输出与落盘收据不一致。")
    inventory = receipt.get("inventory")
    if not isinstance(inventory, list) or not inventory:
        raise ConfigurationError("候选 RuntimeCatalog inventory 为空。")
    if _fingerprint(inventory) != receipt.get("inventory_sha256"):
        raise ConfigurationError("候选 RuntimeCatalog inventory 摘要不一致。")
    seen: set[str] = set()
    for item in inventory:
        if not isinstance(item, dict):
            raise ConfigurationError("候选 RuntimeCatalog inventory 条目非法。")
        relative_raw = item.get("path")
        if not isinstance(relative_raw, str):
            raise ConfigurationError("候选 RuntimeCatalog inventory 路径非法。")
        relative = Path(relative_raw)
        if (
            relative.is_absolute()
            or relative.as_posix() != relative_raw
            or ".." in relative.parts
            or relative_raw in seen
        ):
            raise ConfigurationError("候选 RuntimeCatalog inventory 路径越界或重复。")
        seen.add(relative_raw)
        target = output / relative
        if (
            not target.is_file()
            or target.is_symlink()
            or file_sha256(target) != item.get("sha256")
            or target.stat().st_size != item.get("size")
        ):
            raise ConfigurationError(
                f"候选 RuntimeCatalog inventory 文件漂移：{relative_raw}"
            )
    actual = {
        path.relative_to(output).as_posix()
        for path in output.rglob("*")
        if path.is_file() and path.name != "catalog-stage-receipt.json"
    }
    if actual != seen:
        raise ConfigurationError("候选 RuntimeCatalog inventory 未精确覆盖输出文件。")


def _verify_stage_evidence(
    stage: dict[str, Any],
    label: str,
    *,
    campaign_dir: Path | None = None,
) -> None:
    expected_inventory = stage.get("evidence_inventory")
    if not isinstance(expected_inventory, dict):
        raise ConfigurationError(f"{label}缺少封存证据清单。")
    roots = [Path(value) for value in stage.get("evidence_roots", [])]
    if not roots:
        raise ConfigurationError(f"{label}缺少证据根。")
    if stage.get("evidence_manifest") is not None:
        if campaign_dir is None:
            raise ConfigurationError(f"{label}EvidenceManifest 校验缺少 Campaign 路径。")
        _stage_evidence_manifest(
            campaign_dir,
            stage,
            verify_boundary=True,
        )
        return
    current = _evidence_inventory(roots)
    if current["digest"] != expected_inventory.get("digest"):
        raise ConfigurationError(f"{label}原始证据摘要在封存后发生变化。")
    security = stage.get("security")
    if (
        not isinstance(security, dict)
        or security.get("raw_evidence_private") is not True
        or security.get("known_secret_scan_passed") is not True
    ):
        raise ConfigurationError(f"{label}秘密扫描门禁未通过。")
    current_security = _evidence_security(roots)
    if not current_security.get("known_secret_scan_passed"):
        raise ConfigurationError(f"{label}当前证据秘密扫描未通过。")
    if not _evidence_permissions_private(roots):
        raise ConfigurationError(f"{label}当前证据权限不再私有。")


def _verify_sealed_official_binaries(
    official: dict[str, Any], manifest: dict[str, Any]
) -> bool:
    verification = official.get("binary_verification")
    identities = verification.get("identities") if isinstance(verification, dict) else None
    helpers = verification.get("helpers") if isinstance(verification, dict) else None
    expected_labels = {
        "container:capture_codex_bin",
        "container:relay_codex_bin",
        "host:relay_codex_bin",
    }
    expected_helper_labels = {
        "container:capture_code_mode_host_bin",
        "container:relay_code_mode_host_bin",
        "host:relay_code_mode_host_bin",
    }
    package_identity = manifest.get("official_identity", {}).get("package")
    return bool(
        isinstance(verification, dict)
        and verification.get("passed") is True
        and verification.get("expected_version") == manifest.get("target_version")
        and verification.get("expected_sha256") == manifest.get("target_sha256")
        and verification.get("runtime_image_reference")
        == manifest.get("official_identity", {}).get("runtime_image")
        and IMAGE_ID_RE.fullmatch(str(verification.get("runtime_image_id", "")))
        and isinstance(identities, list)
        and {item.get("label") for item in identities if isinstance(item, dict)}
        == expected_labels
        and all(
            isinstance(item, dict)
            and item.get("version") == manifest.get("target_version")
            and item.get("sha256") == manifest.get("target_sha256")
            for item in identities
        )
        and isinstance(package_identity, dict)
        and verification.get("package") == package_identity
        and isinstance(helpers, list)
        and {item.get("label") for item in helpers if isinstance(item, dict)}
        == expected_helper_labels
        and all(
            isinstance(item, dict)
            and item.get("sha256")
            == package_identity.get("code_mode_host_sha256")
            for item in helpers
        )
    )


def _capture_stage_attempt_context(
    campaign_dir: Path,
    stage: Mapping[str, Any],
    *,
    phase: str,
    candidate_id: str | None,
) -> tuple[Path, dict[str, Any]]:
    reference = stage.get("attempt")
    _require_file_binding(reference, "抓包 attempt")
    attempt_path = _campaign_file(campaign_dir, str(reference["path"]))
    attempt_root, attempt = _load_capture_attempt(
        campaign_dir,
        phase,
        candidate_id,
        attempt_path.parent.name,
    )
    if attempt_path != attempt_root / "attempt.json":
        raise ConfigurationError("抓包阶段 attempt 绑定路径不一致。")
    return attempt_root, attempt


def compare_campaign(campaign_dir: Path, candidate_id: str) -> dict[str, Any]:
    """只读取封存材料并写比较收据；本函数不运行任何命令或网络请求。"""

    _reject_contaminated_campaign(campaign_dir)
    manifest = _require_formal_campaign(campaign_dir)
    candidate = _load_stage_result(
        campaign_dir, "capture-candidate", candidate_id
    )
    attempt_root, attempt = _capture_stage_attempt_context(
        campaign_dir,
        candidate,
        phase="candidate",
        candidate_id=candidate_id,
    )
    _verify_plan_identity(
        campaign_dir,
        manifest,
        operation="compare",
        attempt_root=attempt_root,
        attempt=attempt,
    )
    official = _load_stage_result(campaign_dir, "capture-official")
    classification = _load_stage_result(campaign_dir, "classify")
    for label, value in (
        ("官方", official),
        ("分类", classification),
        ("候选", candidate),
    ):
        if value.get("status") != "complete":
            raise ConfigurationError(f"{label}阶段尚未完整封存。")
    if not official.get("restoration", {}).get("passed"):
        raise ConfigurationError("官方抓包环境恢复门禁未通过。")
    if not candidate.get("restoration", {}).get("passed"):
        raise ConfigurationError("候选抓包环境恢复门禁未通过。")
    if not _verify_sealed_official_binaries(official, manifest):
        raise ConfigurationError("官方抓包未绑定全部目标 Codex 二进制身份。")
    _verify_stage_evidence(official, "官方", campaign_dir=campaign_dir)
    _verify_stage_evidence(candidate, "候选", campaign_dir=campaign_dir)
    official_surface = _surface_from_stage(campaign_dir, "capture-official")
    candidate_surface = _surface_from_stage(
        campaign_dir, "capture-candidate", candidate_id=candidate_id
    )
    difference = compare_surfaces(official_surface, candidate_surface)
    rules = _approved_rules(campaign_dir, manifest, require_approved=True)
    official_jobs = _campaign_jobs(
        campaign_dir,
        manifest,
        "official",
        use_approved_scenario=True,
    )
    candidate_identity = candidate.get("identity", {})
    candidate_jobs = _campaign_jobs(
        campaign_dir,
        manifest,
        "candidate",
        candidate_id=candidate_id,
        runtime_image=str(candidate_identity.get("image_reference", "")),
        profile_id=str(candidate_identity.get("profile_id", "")),
        profile_digest=str(candidate_identity.get("profile_digest", "")),
        build_id=str(candidate_identity.get("build_id", "")),
        deployed_version=str(candidate_identity.get("deployed_version", "")),
        candidate_image_id=str(candidate_identity.get("image_id", "")),
        source_tree_sha256=str(candidate_identity.get("source_tree_sha256", "")),
        candidate_purpose=str(candidate_identity.get("candidate_purpose", "")),
    )
    # 后继 Campaign 的官方结果仍属于前序 Campaign 的原始执行坐标；导入门禁已用
    # 前序 ID 和冻结场景逐项重放 execution_sha256。这里不能把它伪装成新 ID 下执行，
    # 只继续用同一场景／规则集合计算覆盖。
    if official.get("predecessor_import") is None:
        _validate_capture_job_results(
            official_jobs,
            official.get("results"),
            phase="official",
        )
    _validate_capture_job_results(
        candidate_jobs,
        candidate.get("results"),
        phase="candidate",
    )
    results = list(official.get("results", [])) + list(candidate.get("results", []))
    coverage = build_coverage(rules, official_jobs + candidate_jobs, results)
    if not coverage.get("complete"):
        raise ConfigurationError("官方／候选逐规则抓包覆盖不完整。")
    approved_profile_id, approved_profile_digest = _profile_binding_from_manifest(
        campaign_dir, classification
    )
    candidate_profile_id = candidate_identity.get("profile_id")
    candidate_profile_digest = candidate_identity.get("profile_digest")
    profile_binding_matches = bool(candidate_profile_id and candidate_profile_digest)
    if approved_profile_id is not None:
        profile_binding_matches = (
            profile_binding_matches and candidate_profile_id == approved_profile_id
        )
    if approved_profile_digest is not None:
        profile_binding_matches = (
            profile_binding_matches
            and candidate_profile_digest == approved_profile_digest
        )
    report = {
        "schema_version": COMPARISON_SCHEMA,
        "status": "complete",
        "candidate_id": candidate_id,
        "campaign_mode": manifest["campaign_mode"],
        "campaign_purpose": manifest["campaign_purpose"],
        "candidate_purpose": candidate_identity.get("candidate_purpose"),
        "target_version": manifest["target_version"],
        "equal": difference["equal"],
        "official_to_candidate": difference,
        "coverage": coverage,
        "official_package_digest": official["package_digest"],
        "candidate_package_digest": candidate["package_digest"],
        "classification_package_digest": classification["package_digest"],
        "official_evidence_inventory_digest": official["evidence_inventory"]["digest"],
        "candidate_evidence_inventory_digest": candidate["evidence_inventory"]["digest"],
        "profile_id": candidate_profile_id,
        "profile_digest": candidate_profile_digest,
        "profile_binding_matches": profile_binding_matches,
        "offline_only": True,
    }
    assertion_root = ensure_private_directory(
        campaign_dir / "assertions" / candidate_id, campaign_dir
    )
    skeleton_path = assertion_root / "results.template.json"
    _, comparison_path = _stage_path(campaign_dir, "compare", candidate_id)
    if comparison_path.exists():
        sealed = _load_stage_result(campaign_dir, "compare", candidate_id)
        for field, expected in report.items():
            if field == "schema_version":
                continue
            if sealed.get(field) != expected:
                raise ConfigurationError("既有比较收据与当前封存证据不一致。")
    else:
        save_stage_result(campaign_dir, "compare", report, candidate_id=candidate_id)
        sealed = _load_stage_result(campaign_dir, "compare", candidate_id)
    machine_root = ensure_private_directory(
        assertion_root / "machine",
        campaign_dir,
    )
    ensure_private_directory(machine_root / "official", campaign_dir)
    ensure_private_directory(machine_root / "candidate", campaign_dir)
    validation_modes = _acceptance_validation_modes(
        campaign_dir, classification, rules
    )
    official_authority = _classification_official_authority(classification)
    template_rules: list[dict[str, Any]] = []
    for rule in rules:
        official_output = machine_root / "official" / f"{rule}.json"
        candidate_output = machine_root / "candidate" / f"{rule}.json"
        row: dict[str, Any] = {
            "rule": rule,
            "validation_mode": validation_modes[rule],
            "status": "blocked",
            "candidate_evidence_refs": [],
            "candidate_machine_result": {
                "path": candidate_output.relative_to(campaign_dir).as_posix(),
                "sha256": None,
            },
            "candidate_command": _campaign_machine_command(
                campaign_dir,
                manifest,
                classification,
                candidate,
                rule=rule,
                output=candidate_output,
                side="candidate",
            ),
            "evidence_level": "unreviewed",
            "rationale": "待执行机器断言并复核。",
        }
        if validation_modes[rule] == "dual_wire":
            row["official_evidence_refs"] = []
            row["official_machine_result"] = {
                "path": official_output.relative_to(campaign_dir).as_posix(),
                "sha256": None,
            }
            row["official_command"] = _campaign_machine_command(
                campaign_dir,
                manifest,
                classification,
                official,
                rule=rule,
                output=official_output,
                side="official",
            )
        else:
            row["official_authority"] = dict(official_authority)
        template_rules.append(row)
    skeleton = {
        "schema_version": ASSERTION_TEMPLATE_SCHEMA,
        "document_kind": "template",
        "candidate_id": candidate_id,
        "target_version": manifest["target_version"],
        "profile_id": candidate_profile_id,
        "profile_digest": candidate_profile_digest,
        "official_package_digest": official["package_digest"],
        "candidate_package_digest": candidate["package_digest"],
        "comparison_package_digest": sealed["package_digest"],
        "rules": template_rules,
    }
    if skeleton_path.exists():
        existing_skeleton = _read_json(skeleton_path, "逐规则断言模板")
        if _fingerprint(existing_skeleton) != _fingerprint(skeleton):
            raise ConfigurationError("逐规则断言模板已经存在且内容不同。")
    else:
        secure_write_json(skeleton_path, skeleton)
    report["assertion_template"] = str(skeleton_path)
    return report


def _acceptance_contract(
    campaign_dir: Path,
    classification: dict[str, Any],
) -> dict[str, Any]:
    """从本 Campaign **批准的**断言画像机器推导验收契约。

    权威是 classify 阶段人工批准并摘要绑定的 `assertion-profile.json`，不是仓库
    冻结画像——目标规则集允许相对基线增删，契约必须随批准画像走。仓库冻结摘要
    只用于 seal 前预检与工具自检（见 `acceptance_contract.FROZEN_CONTRACT_SHA256`）。
    """

    reference = classification.get("assertion_profile_manifest")
    if not isinstance(reference, dict):
        raise ConfigurationError("分类收据缺少批准断言画像。")
    path = _campaign_file(campaign_dir, str(reference.get("path", "")))
    if path.is_symlink() or not path.is_file() or file_sha256(path) != reference.get(
        "sha256"
    ):
        raise ConfigurationError("批准断言画像在封存后漂移或丢失。")
    try:
        return build_acceptance_contract(load_acceptance_profile(path))
    except AcceptanceContractError as error:
        raise ConfigurationError(f"验收契约不可用：{error}") from error


def _acceptance_validation_modes(
    campaign_dir: Path,
    classification: dict[str, Any],
    rules: tuple[str, ...],
) -> dict[str, str]:
    """推导每条规则的 validation_mode；规则集与批准画像不符即失败关闭。"""

    modes = _acceptance_contract(campaign_dir, classification)["validation_modes"]
    missing = sorted(set(rules) - set(modes))
    extra = sorted(set(modes) - set(rules))
    if missing or extra:
        raise ConfigurationError(
            f"目标规则集与批准断言画像不一致：缺失 {missing}，多余 {extra}。"
        )
    return {rule: modes[rule] for rule in rules}


def _acceptance_contract_sha256(
    campaign_dir: Path,
    classification: dict[str, Any],
) -> str:
    return acceptance_contract_sha256(
        _acceptance_contract(campaign_dir, classification)
    )


def _acceptance_expected_check_ids(
    campaign_dir: Path,
    classification: dict[str, Any],
    rule: str,
    side: str,
) -> list[str]:
    """本侧应执行的 check 全集；侧别限定项由验收契约按登记依据剔除。"""

    contract = _acceptance_contract(campaign_dir, classification)
    expected = contract["expected_check_ids"].get(rule)
    if not isinstance(expected, list) or not expected:
        raise ConfigurationError(f"批准断言画像缺少规则 {rule} 的 check 全集。")
    try:
        return expected_check_ids_for_side(contract, rule, side)
    except AcceptanceContractError as error:
        raise ConfigurationError(f"批准断言画像 check 全集不可用：{error}") from error


def _classification_official_authority(
    classification: dict[str, Any],
) -> dict[str, str]:
    """candidate_profile 行的官方权威：批准画像链的三个逐字摘要。"""

    reference = classification.get("assertion_profile_manifest")
    if not isinstance(reference, dict) or not SHA256_RE.fullmatch(
        str(reference.get("sha256", ""))
    ):
        raise ConfigurationError("分类收据缺少批准断言画像摘要。")
    package_digest = classification.get("package_digest")
    joint = classification.get("joint_manifest_sha256")
    if not SHA256_RE.fullmatch(str(package_digest or "")):
        raise ConfigurationError("分类收据缺少 classification package digest。")
    if not SHA256_RE.fullmatch(str(joint or "")):
        raise ConfigurationError("分类收据缺少批准联合摘要。")
    return {
        "assertion_profile_sha256": str(reference["sha256"]),
        "classification_package_digest": str(package_digest),
        "review_sha256": str(joint),
    }


def _inventory_index(stage: dict[str, Any], label: str) -> dict[str, str]:
    inventory = stage.get("evidence_inventory")
    if not isinstance(inventory, dict) or not isinstance(inventory.get("entries"), list):
        raise ConfigurationError(f"{label}阶段缺少封存证据清单。")
    result: dict[str, str] = {}
    for entry in inventory["entries"]:
        if not isinstance(entry, dict):
            raise ConfigurationError(f"{label}证据清单条目非法。")
        path = entry.get("path")
        digest = entry.get("sha256")
        if (
            not isinstance(path, str)
            or not path
            or not SHA256_RE.fullmatch(str(digest))
            or path in result
        ):
            raise ConfigurationError(f"{label}证据清单路径或摘要非法。")
        result[path] = str(digest)
    if not result:
        raise ConfigurationError(f"{label}证据清单为空。")
    return result


def _physical_evidence_index(stage: dict[str, Any], label: str) -> dict[str, Path]:
    roots = [Path(value) for value in stage.get("evidence_roots", [])]
    if not roots:
        raise ConfigurationError(f"{label}阶段缺少证据根。")
    index = {logical: path for logical, path in _evidence_files(roots)}
    if not index:
        raise ConfigurationError(f"{label}阶段当前证据为空。")
    return index


def _bound_evidence_path(
    stage: dict[str, Any],
    reference: Any,
    *,
    label: str,
) -> Path:
    _require_file_binding(reference, label)
    path = _physical_evidence_index(stage, label).get(reference["path"])
    if path is None or file_sha256(path) != reference["sha256"]:
        raise ConfigurationError(f"{label}证据文件漂移或丢失。")
    return path


def _candidate_stage_receipt_boundary(
    campaign_dir: Path,
    stage: dict[str, Any],
) -> tuple[dict[str, Any], Path, str]:
    """从阶段绑定的 attempt 推导收据根与 Kilo 后时间上界。"""

    attempt_reference = stage.get("attempt")
    _require_file_binding(attempt_reference, "候选 attempt")
    attempt_relative = Path(str(attempt_reference["path"]))
    attempt_id = attempt_relative.parent.name
    candidate_id = str(stage.get("candidate_id", ""))
    _, attempt = _load_capture_attempt(
        campaign_dir,
        "candidate",
        candidate_id,
        attempt_id,
    )
    environment = attempt.get("environment")
    if not isinstance(environment, dict):
        raise ConfigurationError("候选 attempt 缺少环境证据边界。")
    evidence_root = Path(str(environment.get("evidence_root", "")))
    stage_roots = {
        Path(value).resolve(strict=True)
        for value in stage.get("evidence_roots", [])
    }
    if (
        not evidence_root.is_absolute()
        or evidence_root.is_symlink()
        or not evidence_root.is_dir()
        or evidence_root.resolve(strict=True) not in stage_roots
    ):
        raise ConfigurationError("候选 attempt 收据根未绑定当前阶段。")
    checkpoint_path = (
        evidence_root
        / "environment"
        / "client-after"
        / "probe-manifest.json"
    )
    if checkpoint_path.is_symlink() or not checkpoint_path.is_file():
        raise ConfigurationError("候选阶段缺少 Kilo 后探针清单。")
    checkpoint = _read_json(checkpoint_path, "Kilo 后探针清单")
    checkpoint_at = checkpoint.get("observed_at_utc")
    if checkpoint.get("phase") != "after" or not _is_rfc3339_timestamp(
        checkpoint_at
    ):
        raise ConfigurationError("Kilo 后探针清单身份或时间非法。")
    if _rfc3339_datetime(
        checkpoint_at, "Kilo 后检查点时间"
    ) < _rfc3339_datetime(
        attempt["completed_at_utc"], "attempt.completed_at_utc"
    ):
        raise ConfigurationError("Kilo 后检查点早于候选 run 完成时间。")
    return attempt, evidence_root.resolve(strict=True), str(checkpoint_at)


def _replay_capture_stage_receipts(
    campaign_dir: Path,
    stage: dict[str, Any],
    label: str,
) -> None:
    """在 status／compare／accept 每次读取时重放机器 finalizer。"""

    roots = [Path(value) for value in stage.get("evidence_roots", [])]
    campaign = load_campaign_manifest(campaign_dir)
    phase = "candidate" if stage.get("stage") == "capture-candidate" else "official"
    candidate_id = stage.get("candidate_id") if phase == "candidate" else None
    restoration_path = _bound_evidence_path(
        stage,
        stage.get("restoration", {}).get("report"),
        label=f"{label}环境恢复报告",
    )
    restoration = _validate_restoration_report(
        restoration_path,
        roots,
        phase=phase,
        candidate_id=candidate_id,
    )
    sealed_restoration = stage.get("restoration")
    if not isinstance(sealed_restoration, dict):
        raise ConfigurationError(f"{label}环境恢复门禁缺失。")
    capture_restoration = {
        key: value
        for key, value in sealed_restoration.items()
        if key != "post_client"
    }
    if _fingerprint(restoration) != _fingerprint(capture_restoration):
        raise ConfigurationError(f"{label}环境恢复机器收据与阶段封存内容不一致。")
    if phase == "official":
        return

    post_client = sealed_restoration.get("post_client")
    if not isinstance(post_client, dict):
        raise ConfigurationError(f"{label}缺少 Kilo 后恢复门禁。")
    post_client_path = _bound_evidence_path(
        stage,
        post_client.get("report"),
        label=f"{label}Kilo 后恢复报告",
    )
    replayed_post_client = _validate_restoration_report(
        post_client_path,
        roots,
        phase="candidate",
        candidate_id=str(candidate_id),
    )
    if _fingerprint(replayed_post_client) != _fingerprint(post_client):
        raise ConfigurationError(f"{label}Kilo 后恢复机器收据与封存内容不一致。")

    identity = stage.get("identity")
    if not isinstance(identity, dict):
        raise ConfigurationError(f"{label}候选身份缺失。")
    attempt, receipt_root, client_checkpoint_at = (
        _candidate_stage_receipt_boundary(campaign_dir, stage)
    )
    observed_path = _bound_evidence_path(
        stage,
        stage.get("observed_profile"),
        label=f"{label}运行画像观测",
    )
    observed_binding, _ = _validate_observed_profile_receipt(
        observed_path,
        [receipt_root],
        campaign_id=attempt["campaign_id"],
        attempt_id=attempt["attempt_id"],
        run_nonce=attempt["run_nonce"],
        attempt_started_at_utc=attempt["started_at_utc"],
        client_checkpoint_at_utc=client_checkpoint_at,
        candidate_id=str(candidate_id),
        target_version=campaign["target_version"],
        expected_profile_id=str(identity.get("profile_id", "")),
        expected_profile_digest=str(identity.get("profile_digest", "")),
        image_id=str(identity.get("image_id", "")),
        image_reference=str(identity.get("image_reference", "")),
        source_tree_sha256=str(identity.get("source_tree_sha256", "")),
        build_id=str(identity.get("build_id", "")),
        deployed_version=str(identity.get("deployed_version", "")),
    )
    if observed_binding != stage.get("observed_profile"):
        raise ConfigurationError(f"{label}运行画像绑定与阶段封存内容不一致。")
    client_bindings = stage.get("client_bindings")
    if not isinstance(client_bindings, list):
        raise ConfigurationError(f"{label}第三方客户端绑定缺失。")
    client_specs: list[str] = []
    for item in client_bindings:
        if not isinstance(item, dict) or not isinstance(item.get("client_id"), str):
            raise ConfigurationError(f"{label}第三方客户端绑定结构非法。")
        receipt_path = _bound_evidence_path(
            stage,
            item.get("receipt"),
            label=f"{label}第三方入口 {item['client_id']} 收据",
        )
        client_specs.append(f"{item['client_id']}={receipt_path}")
    replayed = _parse_client_evidence(
        client_specs,
        [receipt_root],
        campaign_id=attempt["campaign_id"],
        attempt_id=attempt["attempt_id"],
        run_nonce=attempt["run_nonce"],
        attempt_started_at_utc=attempt["started_at_utc"],
        client_checkpoint_at_utc=client_checkpoint_at,
        candidate_id=str(candidate_id),
        target_version=campaign["target_version"],
        model=_third_party_client_model(campaign["configuration"]),
        identity=identity,
    )
    if _fingerprint({"items": replayed}) != _fingerprint(
        {"items": client_bindings}
    ):
        raise ConfigurationError(f"{label}Kilo 机器收据与阶段封存内容不一致。")


def _validate_evidence_bindings(
    values: Any,
    inventory: dict[str, str],
    *,
    rule: str,
    label: str,
) -> set[str]:
    if not isinstance(values, list) or not values:
        raise ConfigurationError(f"逐规则断言 {rule} 缺少{label}证据引用。")
    paths: set[str] = set()
    for value in values:
        if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
            raise ConfigurationError(f"逐规则断言 {rule} 的{label}证据引用非法。")
        path = value.get("path")
        digest = value.get("sha256")
        if not isinstance(path, str) or inventory.get(path) != digest:
            raise ConfigurationError(f"逐规则断言 {rule} 的{label}证据摘要不匹配。")
        if path in paths:
            raise ConfigurationError(f"逐规则断言 {rule} 的{label}证据重复。")
        paths.add(path)
    return paths


def _command_option(command: list[str], name: str, rule: str) -> str:
    positions = [index for index, value in enumerate(command) if value == name]
    if len(positions) != 1 or positions[0] + 1 >= len(command):
        raise ConfigurationError(f"逐规则断言 {rule} 的机器命令缺少唯一 {name}。")
    return command[positions[0] + 1]


def _campaign_machine_command(
    campaign_dir: Path,
    manifest: dict[str, Any],
    classification: dict[str, Any],
    capture_stage: dict[str, Any],
    *,
    rule: str,
    output: Path,
    side: str,
) -> list[str]:
    context = capture_stage.get("assertion_context")
    if not isinstance(context, dict):
        raise ConfigurationError("抓包阶段缺少 assertion_context。")
    profile_reference = classification.get("assertion_profile_manifest")
    rule_reference = classification.get("target_rule_manifest")
    if not isinstance(profile_reference, dict) or not isinstance(rule_reference, dict):
        raise ConfigurationError("分类收据缺少目标断言画像或规则清单。")
    profile_path = _campaign_file(campaign_dir, str(profile_reference.get("path", "")))
    rule_path = _campaign_file(campaign_dir, str(rule_reference.get("path", "")))
    return build_machine_assertion_command(
        rule_id=rule,
        capture_manifest=str(context.get("capture_manifest_path", "")),
        evidence_root=str(context.get("evidence_root", "")),
        profile=str(profile_path.resolve(strict=True)),
        rule_manifest=str(rule_path.resolve(strict=True)),
        expected_codex_version=manifest["target_version"],
        expected_profile_sha256=str(profile_reference.get("sha256", "")),
        side=side,
        output=str(output.resolve()),
    )


def _rerun_machine_assertion(
    command: list[str],
    submitted: dict[str, Any],
    *,
    rule: str,
    label: str,
) -> None:
    """在 accept 内离线重放 checker，防止手工伪造 pass 收据。"""

    output_positions = [index for index, value in enumerate(command) if value == "--output"]
    if len(output_positions) != 1 or output_positions[0] + 1 >= len(command):
        raise ConfigurationError(f"逐规则断言 {rule} {label}重放命令缺少输出路径。")
    with tempfile.TemporaryDirectory(prefix="codex-egress-assertion-") as temporary:
        replay_output = Path(temporary) / "result.json"
        replay_command = list(command)
        replay_command[output_positions[0] + 1] = str(replay_output)
        try:
            replay = subprocess.run(
                replay_command,
                cwd=Path(__file__).resolve().parents[2],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ConfigurationError(
                f"逐规则断言 {rule} {label}离线重放失败：{error}"
            ) from error
        if replay.returncode != 0 or not replay_output.is_file() or replay_output.is_symlink():
            detail = replay.stderr.strip() or replay.stdout.strip()
            raise ConfigurationError(
                f"逐规则断言 {rule} {label}离线重放未通过：{detail[:500]}"
            )
        replay_result = _read_json(replay_output, f"{rule} {label}重放结果")
    expected_fields = {
        "schema_version": MACHINE_ASSERTION_SCHEMA,
        "rule_id": rule,
        "status": "pass",
        "exit_code": 0,
        "checker_sha256": submitted.get("checker_sha256"),
        "command_sha256": machine_command_sha256(replay_command),
    }
    for field, expected in expected_fields.items():
        if replay_result.get(field) != expected:
            raise ConfigurationError(
                f"逐规则断言 {rule} {label}重放结果 {field} 不一致。"
            )
    if replay_result.get("checks") != submitted.get("checks"):
        raise ConfigurationError(
            f"逐规则断言 {rule} {label}提交检查项与离线重放不一致。"
        )


def _validate_machine_assertion(
    campaign_dir: Path,
    manifest: dict[str, Any],
    classification: dict[str, Any],
    capture_stage: dict[str, Any],
    row: dict[str, Any],
    rule: str,
    bound_paths: set[str],
    *,
    side: str,
) -> set[str]:
    label = "官方" if side == "official" else "候选"
    reference = row.get(f"{side}_machine_result")
    if not isinstance(reference, dict) or set(reference) != {"path", "sha256"}:
        raise ConfigurationError(f"逐规则断言 {rule} 缺少{label}机器结果绑定。")
    relative = reference.get("path")
    if not isinstance(relative, str) or Path(relative).is_absolute():
        raise ConfigurationError(f"逐规则断言 {rule} {label}机器结果路径必须位于 Campaign。")
    result_path = _campaign_file(campaign_dir, relative)
    if (
        not result_path.is_file()
        or result_path.is_symlink()
        or file_sha256(result_path) != reference.get("sha256")
    ):
        raise ConfigurationError(f"逐规则断言 {rule} {label}机器结果摘要不一致。")
    result = _read_json(result_path, f"{rule} {label}机器断言结果")
    if result.get("schema_version") != MACHINE_ASSERTION_SCHEMA:
        raise ConfigurationError(f"逐规则断言 {rule} {label}机器结果 schema 不受支持。")
    if (
        result.get("rule_id") != rule
        or result.get("status") != "pass"
        or result.get("exit_code") != 0
    ):
        raise ConfigurationError(f"逐规则断言 {rule} {label}机器结果未通过。")
    command = row.get(f"{side}_command")
    if not isinstance(command, list) or not command or not all(
        isinstance(value, str) and value for value in command
    ):
        raise ConfigurationError(f"逐规则断言 {rule} 缺少{label}机器命令。")
    context = capture_stage.get("assertion_context")
    if not isinstance(context, dict):
        raise ConfigurationError(f"{label}抓包阶段缺少 assertion_context。")
    expected_command = _campaign_machine_command(
        campaign_dir,
        manifest,
        classification,
        capture_stage,
        rule=rule,
        output=result_path,
        side=side,
    )
    if command != expected_command:
        raise ConfigurationError(f"逐规则断言 {rule} {label}机器命令未精确绑定当前版本 Campaign。")
    if machine_command_sha256(command) != result.get("command_sha256"):
        raise ConfigurationError(f"逐规则断言 {rule} {label}命令摘要不一致。")
    pinned_checkers = {
        entry.get("path"): entry.get("sha256")
        for entry in manifest.get("tool_identity", {}).get("entries", [])
        if isinstance(entry, dict)
    }
    checker_sha = pinned_checkers.get("candidate_rule_assertion.py")
    if not checker_sha or checker_sha != result.get("checker_sha256"):
        raise ConfigurationError(f"逐规则断言 {rule} checker 未绑定 plan 工具摘要。")
    checker_path = Path(__file__).resolve().parent / "candidate_rule_assertion.py"
    if not checker_path.is_file() or file_sha256(checker_path) != checker_sha:
        raise ConfigurationError(f"逐规则断言 {rule} checker 文件在 plan 后漂移。")
    checks = result.get("checks")
    if not isinstance(checks, list) or not checks:
        raise ConfigurationError(f"逐规则断言 {rule} 没有机器检查项。")
    check_ids: set[str] = set()
    for check in checks:
        if not isinstance(check, dict) or check.get("passed") is not True:
            raise ConfigurationError(f"逐规则断言 {rule} {label}存在未通过机器检查。")
        check_id = check.get("id")
        evidence_paths = check.get("evidence_paths")
        if (
            not isinstance(check_id, str)
            or not check_id
            or check_id in check_ids
            or check.get("expected") is None
            or check.get("actual") is None
            or not isinstance(evidence_paths, list)
            or not evidence_paths
        ):
            raise ConfigurationError(f"逐规则断言 {rule} {label}机器检查结构非法。")
        prefix = context.get("evidence_prefix")
        logical_paths = {
            f"{prefix}/{path}"
            for path in evidence_paths
            if isinstance(path, str) and not Path(path).is_absolute() and ".." not in Path(path).parts
        }
        if len(logical_paths) != len(evidence_paths) or not logical_paths.issubset(bound_paths):
            raise ConfigurationError(f"逐规则断言 {rule} {label}机器检查未精确引用封存证据。")
        check_ids.add(check_id)
    _rerun_machine_assertion(command, result, rule=rule, label=label)
    return check_ids


def _validate_assertion_results(
    campaign_dir: Path,
    assertions: dict[str, Any],
    *,
    rules: tuple[str, ...],
    manifest: dict[str, Any],
    candidate_id: str,
    classification: dict[str, Any],
    official: dict[str, Any],
    candidate: dict[str, Any],
    comparison: dict[str, Any],
) -> dict[str, Any]:
    required_top_fields = {
        "schema_version",
        "document_kind",
        "candidate_id",
        "target_version",
        "profile_id",
        "profile_digest",
        "official_package_digest",
        "candidate_package_digest",
        "comparison_package_digest",
        "acceptance_contract_sha256",
        "rules",
    }
    if assertions.get("schema_version") in LEGACY_RESULTS_SCHEMAS:
        raise ConfigurationError(
            "逐规则断言旧 schema 已废除：v1 的双侧同构与正负例契约没有事实来源，"
            "必须按 codex-egress-rule-assertions/v2 重新生成。"
        )
    if assertions.get("schema_version") != RESULTS_SCHEMA_V2:
        raise ConfigurationError("逐规则断言 schema_version 不受支持。")
    if not required_top_fields.issubset(assertions) or set(assertions) - required_top_fields - {"$schema"}:
        raise ConfigurationError("逐规则断言结果顶层字段不闭合。")
    if assertions.get("acceptance_contract_sha256") != _acceptance_contract_sha256(
        campaign_dir, classification
    ):
        raise ConfigurationError("逐规则断言未绑定冻结验收契约摘要。")
    if assertions.get("document_kind") != "results":
        raise ConfigurationError("逐规则断言 document_kind 必须是 results。")
    for field, expected in (
        ("candidate_id", candidate_id),
        ("target_version", manifest["target_version"]),
    ):
        if assertions.get(field) != expected:
            raise ConfigurationError(f"逐规则断言 {field} 与 Campaign 不一致。")
    identity = candidate.get("identity", {})
    for field in ("profile_id", "profile_digest"):
        if assertions.get(field) != identity.get(field):
            raise ConfigurationError(f"逐规则断言 {field} 未绑定候选身份。")
    required_bindings = (
        ("official_package_digest", comparison.get("official_package_digest")),
        ("candidate_package_digest", comparison.get("candidate_package_digest")),
        ("comparison_package_digest", comparison.get("package_digest")),
    )
    for field, expected in required_bindings:
        if assertions.get(field) != expected:
            raise ConfigurationError(f"逐规则断言 {field} 摘要不一致。")
    rows = assertions.get("rules")
    if not isinstance(rows, list):
        raise ConfigurationError("逐规则断言 rules 必须是数组。")
    official_inventory = _inventory_index(official, "官方")
    candidate_inventory = _inventory_index(candidate, "候选")
    validation_modes = _acceptance_validation_modes(
        campaign_dir, classification, rules
    )
    official_authority = _classification_official_authority(classification)
    seen: list[str] = []
    passed = 0
    for index, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise ConfigurationError(f"逐规则断言 {index} 必须是对象。")
        rule = row.get("rule")
        if rule not in rules:
            raise ConfigurationError(f"逐规则断言 {index} 引用清单外规则。")
        mode = validation_modes[str(rule)]
        if row.get("validation_mode") != mode:
            raise ConfigurationError(
                f"逐规则断言 {rule} 的 validation_mode 与验收契约不一致。"
            )
        common_row_fields = {
            "rule",
            "validation_mode",
            "status",
            "candidate_evidence_refs",
            "candidate_machine_result",
            "candidate_command",
            "evidence_level",
            "rationale",
        }
        if mode == MODE_DUAL_WIRE:
            required_row_fields = common_row_fields | {
                "official_evidence_refs",
                "official_machine_result",
                "official_command",
            }
        else:
            required_row_fields = common_row_fields | {"official_authority"}
        if set(row) != required_row_fields:
            raise ConfigurationError(f"逐规则断言 {index} 字段不闭合。")
        if row.get("status") != "pass":
            raise ConfigurationError(f"逐规则断言 {rule} 没有机器通过，不得接受。")
        if row.get("evidence_level") != "full":
            raise ConfigurationError(f"逐规则断言 {rule} 证据等级不是 full。")
        rationale = row.get("rationale")
        if not isinstance(rationale, str) or not rationale.strip():
            raise ConfigurationError(f"逐规则断言 {rule} 缺少 rationale。")
        candidate_expected_check_ids = set(
            _acceptance_expected_check_ids(
                campaign_dir, classification, str(rule), "candidate"
            )
        )
        candidate_paths = _validate_evidence_bindings(
            row.get("candidate_evidence_refs"),
            candidate_inventory,
            rule=str(rule),
            label="候选",
        )
        candidate_check_ids = _validate_machine_assertion(
            campaign_dir,
            manifest,
            classification,
            candidate,
            row,
            str(rule),
            candidate_paths,
            side="candidate",
        )
        if candidate_check_ids != candidate_expected_check_ids:
            raise ConfigurationError(
                f"逐规则断言 {rule} 候选机器检查与批准画像 check 全集不一致。"
            )
        if mode == MODE_DUAL_WIRE:
            official_paths = _validate_evidence_bindings(
                row.get("official_evidence_refs"),
                official_inventory,
                rule=str(rule),
                label="官方",
            )
            official_check_ids = _validate_machine_assertion(
                campaign_dir,
                manifest,
                classification,
                official,
                row,
                str(rule),
                official_paths,
                side="official",
            )
            official_expected_check_ids = set(
                _acceptance_expected_check_ids(
                    campaign_dir, classification, str(rule), "official"
                )
            )
            if official_check_ids != official_expected_check_ids:
                raise ConfigurationError(
                    f"逐规则断言 {rule} 官方机器检查与批准画像 check 全集不一致。"
                )
        else:
            if row.get("official_authority") != official_authority:
                raise ConfigurationError(
                    f"逐规则断言 {rule} 未逐字绑定批准画像官方权威。"
                )
        seen.append(str(rule))
        passed += 1
    if sorted(seen) != sorted(rules) or len(seen) != len(set(seen)):
        raise ConfigurationError("逐规则断言未使目标规则全集唯一闭环。")
    return {
        "complete": True,
        "rule_count": len(rules),
        "pass_count": passed,
        "not_applicable_count": 0,
        "failed_rules": [],
    }


def _required_client_bindings(
    campaign_dir: Path,
    classification: dict[str, Any],
) -> set[str]:
    reference = classification.get("scenario_manifest")
    if not isinstance(reference, dict):
        return set()
    path = _campaign_file(campaign_dir, str(reference.get("path", "")))
    payload = _read_json(path, "目标场景清单")
    raw = payload.get("required_client_bindings", [])
    if (
        not isinstance(raw, list)
        or not all(isinstance(item, str) for item in raw)
        or len(raw) != len(set(raw))
        or not REQUIRED_CLIENT_BINDINGS.issubset(set(raw))
    ):
        raise ConfigurationError("目标场景 required_client_bindings 非法。")
    return set(raw)


def _write_blocked_acceptance_attempt(
    campaign_dir: Path,
    candidate_id: str,
    result: dict[str, Any],
) -> Path:
    """把未通过的 accept 结果写入独立 attempt，保留失败门禁供复核。

    accept 成功结果按 candidate-id 只封存一次；失败结果则允许修复后重跑，因此不能写入
    成功结果的规范路径，也不能覆盖上一轮失败。这里沿用抓包 attempt 的时间戳加随机后缀
    规则，为每次失败建立不可覆盖的私有目录。
    """

    if not SAFE_ID_RE.fullmatch(candidate_id):
        raise ConfigurationError("accept candidate-id 格式非法。")
    attempts_root = ensure_private_directory(
        campaign_dir / "acceptance" / candidate_id / "attempts",
        campaign_dir,
    )
    attempt_id = (
        time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        + f"-{secrets.token_hex(8)}"
    )
    attempt_root = attempts_root / attempt_id
    if attempt_root.exists() or attempt_root.is_symlink():
        raise ConfigurationError("accept attempt-id 随机碰撞。")
    ensure_private_directory(attempt_root, campaign_dir)
    secure_write_json(attempt_root / "result.json", result)
    return attempt_root


def _candidate_external_gate_binding(
    *,
    evidence_root: Path,
    receipt_path: Path,
    manifest: dict[str, Any],
    candidate_id: str,
    candidate: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """独立重放 candidate 外部门禁，并与封存候选身份逐字段交叉验证。"""

    try:
        root = evidence_root.resolve(strict=True)
        candidate_receipt = (
            receipt_path.resolve(strict=True)
            if receipt_path.is_absolute()
            else (root / receipt_path).resolve(strict=True)
        )
        relative = candidate_receipt.relative_to(root).as_posix()
        payload = external_gate_receipt.replay(root, relative)
    except (
        OSError,
        RuntimeError,
        ValueError,
        external_gate_receipt.GateReceiptError,
    ) as error:
        raise ConfigurationError(f"candidate 外部门禁收据无法重放：{error}") from error
    identity = candidate.get("identity")
    subject = payload.get("subject")
    if not isinstance(identity, dict) or not isinstance(subject, dict):
        raise ConfigurationError("candidate 外部门禁缺少候选身份。")
    expected = {
        "campaign_id": manifest.get("campaign_id"),
        "campaign_mode": manifest.get("campaign_mode"),
        "campaign_purpose": manifest.get("campaign_purpose"),
        "candidate_id": candidate_id,
        "candidate_purpose": identity.get("candidate_purpose"),
        "target_version": manifest.get("target_version"),
        "profile_id": identity.get("profile_id"),
        "profile_digest": identity.get("profile_digest"),
        "candidate_package_digest": candidate.get("package_digest"),
        "candidate_source_tree_sha256": identity.get("source_tree_sha256"),
        "candidate_image_id": identity.get("image_id"),
        "candidate_image_reference": identity.get("image_reference"),
    }
    if (
        payload.get("phase") != external_gate_receipt.CANDIDATE_PHASE
        or payload.get("status") != "passed"
        or payload.get("failed_gate_ids") != []
        or any(subject.get(key) != value for key, value in expected.items())
    ):
        raise ConfigurationError("candidate 外部门禁收据与 Campaign／候选身份不一致。")
    binding = {
        "evidence_root": str(root),
        "receipt": {
            "path": relative,
            "sha256": file_sha256(candidate_receipt),
            "bytes": candidate_receipt.stat().st_size,
        },
    }
    return binding, payload


def _replay_bound_candidate_external_gate(
    value: Any,
    *,
    manifest: dict[str, Any],
    candidate_id: str,
    candidate: dict[str, Any],
) -> dict[str, Any]:
    """从 AcceptanceFact 保存的根与相对路径重放外部门禁。"""

    if not isinstance(value, dict) or set(value) != {"evidence_root", "receipt"}:
        raise ConfigurationError("AcceptanceFact candidate 外部门禁绑定非法。")
    receipt = value.get("receipt")
    if (
        not isinstance(value.get("evidence_root"), str)
        or not isinstance(receipt, dict)
        or set(receipt) != {"path", "sha256", "bytes"}
        or not isinstance(receipt.get("path"), str)
        or not SHA256_RE.fullmatch(str(receipt.get("sha256")))
        or not isinstance(receipt.get("bytes"), int)
        or receipt.get("bytes") <= 0
    ):
        raise ConfigurationError("AcceptanceFact candidate 外部门禁文件绑定非法。")
    binding, payload = _candidate_external_gate_binding(
        evidence_root=Path(value["evidence_root"]),
        receipt_path=Path(receipt["path"]),
        manifest=manifest,
        candidate_id=candidate_id,
        candidate=candidate,
    )
    if binding != value:
        raise ConfigurationError("AcceptanceFact candidate 外部门禁摘要或大小漂移。")
    return payload


def accept_campaign(
    campaign_dir: Path,
    candidate_id: str,
    assertions_path: Path,
    external_gate_root: Path,
    external_gate_path: Path,
) -> dict[str, Any]:
    """重放全部封存事实并签发用途冻结的 AcceptanceFact。"""

    _reject_contaminated_campaign(campaign_dir)
    if assertions_path.is_symlink() or not assertions_path.is_file():
        raise ConfigurationError("逐规则断言结果必须是非符号链接普通文件。")
    manifest = _require_formal_campaign(campaign_dir)
    candidate = _load_stage_result(
        campaign_dir, "capture-candidate", candidate_id
    )
    attempt_root, attempt = _capture_stage_attempt_context(
        campaign_dir,
        candidate,
        phase="candidate",
        candidate_id=candidate_id,
    )
    _verify_plan_identity(
        campaign_dir,
        manifest,
        operation="accept",
        attempt_root=attempt_root,
        attempt=attempt,
    )
    official = _load_stage_result(campaign_dir, "capture-official")
    classification = _load_stage_result(campaign_dir, "classify")
    comparison = _load_stage_result(campaign_dir, "compare", candidate_id)
    candidate_purpose = candidate.get("candidate_purpose")
    if (
        candidate_purpose not in CANDIDATE_PURPOSES
        or candidate_purpose != manifest["campaign_purpose"]
        or comparison.get("candidate_purpose") != candidate_purpose
    ):
        raise ConfigurationError("candidate／compare 用途与 Campaign 冻结用途不一致。")
    external_gate_binding, external_gate = _candidate_external_gate_binding(
        evidence_root=external_gate_root,
        receipt_path=external_gate_path,
        manifest=manifest,
        candidate_id=candidate_id,
        candidate=candidate,
    )
    _verify_stage_evidence(official, "官方", campaign_dir=campaign_dir)
    _verify_stage_evidence(candidate, "候选", campaign_dir=campaign_dir)
    rules = _approved_rules(campaign_dir, manifest, require_approved=True)
    assertions = _read_json(assertions_path, "逐规则断言结果")
    assertion_gate = _validate_assertion_results(
        campaign_dir,
        assertions,
        rules=rules,
        manifest=manifest,
        candidate_id=candidate_id,
        classification=classification,
        official=official,
        candidate=candidate,
        comparison=comparison,
    )
    identity = candidate.get("identity", {})
    required_identity_fields = {
        "git_commit",
        "source_tree_sha256",
        "image_reference",
        "image_digest",
        "image_id",
        "build_id",
        "deployed_version",
        "profile_id",
        "profile_digest",
        "candidate_purpose",
    }
    identity_complete = required_identity_fields.issubset(identity) and all(
        identity.get(field) for field in required_identity_fields
    )
    identity_complete = identity_complete and bool(
        re.fullmatch(r"[a-f0-9]{40,64}", str(identity.get("git_commit", "")))
        and SHA256_RE.fullmatch(str(identity.get("source_tree_sha256", "")))
        and IMMUTABLE_IMAGE_RE.fullmatch(str(identity.get("image_reference", "")))
        and IMAGE_ID_RE.fullmatch(str(identity.get("image_digest", "")))
        and IMAGE_ID_RE.fullmatch(str(identity.get("image_id", "")))
        and SAFE_ID_RE.fullmatch(str(identity.get("build_id", "")))
        and SAFE_ID_RE.fullmatch(str(identity.get("deployed_version", "")))
        and SAFE_ID_RE.fullmatch(str(identity.get("profile_id", "")))
        and SHA256_RE.fullmatch(str(identity.get("profile_digest", "")))
        and identity.get("candidate_purpose") == candidate_purpose
    )
    attempt, receipt_root, client_checkpoint_at = (
        _candidate_stage_receipt_boundary(campaign_dir, candidate)
    )
    observed_profile_path = _bound_evidence_path(
        candidate,
        candidate.get("observed_profile"),
        label="运行画像观测",
    )
    _, observed_profile_receipt = _validate_observed_profile_receipt(
        observed_profile_path,
        [receipt_root],
        campaign_id=attempt["campaign_id"],
        attempt_id=attempt["attempt_id"],
        run_nonce=attempt["run_nonce"],
        attempt_started_at_utc=attempt["started_at_utc"],
        client_checkpoint_at_utc=client_checkpoint_at,
        candidate_id=candidate_id,
        target_version=manifest["target_version"],
        expected_profile_id=str(identity.get("profile_id", "")),
        expected_profile_digest=str(identity.get("profile_digest", "")),
        image_id=str(identity.get("image_id", "")),
        image_reference=str(identity.get("image_reference", "")),
        source_tree_sha256=str(identity.get("source_tree_sha256", "")),
        build_id=str(identity.get("build_id", "")),
        deployed_version=str(identity.get("deployed_version", "")),
    )
    client_bindings = candidate.get("client_bindings")
    if not isinstance(client_bindings, list):
        raise ConfigurationError("候选阶段缺少第三方客户端绑定。")
    client_specs: list[str] = []
    for item in client_bindings:
        if not isinstance(item, dict) or not isinstance(item.get("client_id"), str):
            raise ConfigurationError("第三方客户端绑定结构非法。")
        receipt_path = _bound_evidence_path(
            candidate,
            item.get("receipt"),
            label=f"第三方入口 {item['client_id']} 收据",
        )
        client_specs.append(f"{item['client_id']}={receipt_path}")
    reparsed_client_bindings = _parse_client_evidence(
        client_specs,
        [receipt_root],
        campaign_id=attempt["campaign_id"],
        attempt_id=attempt["attempt_id"],
        run_nonce=attempt["run_nonce"],
        attempt_started_at_utc=attempt["started_at_utc"],
        client_checkpoint_at_utc=client_checkpoint_at,
        candidate_id=candidate_id,
        target_version=manifest["target_version"],
        model=_third_party_client_model(manifest["configuration"]),
        identity=identity,
    )
    observed_clients = {item.get("client_id") for item in client_bindings if isinstance(item, dict)}
    required_clients = _required_client_bindings(campaign_dir, classification)
    client_bindings_valid = all(
        isinstance(item, dict)
        and item.get("status", "success") == "success"
        and item.get("model")
        == _third_party_client_model(manifest["configuration"])
        and item.get("profile_id") == identity.get("profile_id")
        and item.get("profile_digest") == identity.get("profile_digest")
        and item.get("protocol")
        in {"openai-compatible", "openai-responses"}
        and isinstance(item.get("request_evidence"), list)
        and bool(item.get("request_evidence"))
        and isinstance(item.get("response_evidence"), list)
        and bool(item.get("response_evidence"))
        for item in client_bindings
    )
    coverage = comparison.get("coverage", {})
    official_inventory_digest = official.get("evidence_inventory", {}).get("digest")
    candidate_inventory_digest = candidate.get("evidence_inventory", {}).get("digest")
    gates = {
        "campaign_purpose_matches": manifest.get("campaign_purpose")
        == candidate_purpose,
        "candidate_purpose_matches": identity.get("candidate_purpose")
        == candidate_purpose,
        "full_suite": manifest.get("suite") == "full",
        "official_identity_matches": official.get("identity")
        == manifest.get("official_identity"),
        "official_binary_identity_matches": _verify_sealed_official_binaries(
            official, manifest
        ),
        "candidate_identity_complete": identity_complete,
        "profile_binding_matches": bool(comparison.get("profile_binding_matches"))
        and observed_profile_receipt.get("status") == "active",
        # compare 的完整动态形态差异用于发现与复核，不能直接充当验收门禁：官方侧与候选
        # 侧的采集计划分别是 28 个任务和 7 个必需任务，完整指纹集合天然不等。行为等价性
        # 由批准断言画像推导的 42 条规则逐侧重放负责；这里仅要求 compare 本身已离线完成，
        # 其 package digest、证据 inventory 与画像绑定仍由下方独立门禁逐项校验。
        "comparison_complete": comparison.get("status") == "complete"
        and comparison.get("offline_only") is True,
        "rule_evidence_coverage": bool(official.get("results"))
        and bool(candidate.get("results"))
        and bool(coverage.get("complete")),
        "rule_assertions_complete": assertion_gate["complete"],
        "classification_unblocked": classification.get("status") == "complete"
        and classification.get("migration", {}).get("unclassified_count") == 0,
        "official_restoration_passed": bool(
            official.get("restoration", {}).get("passed")
        ),
        "candidate_restoration_passed": bool(
            candidate.get("restoration", {}).get("passed")
        ),
        "official_security_passed": official.get("security", {}).get("known_secret_scan_passed") is True,
        "candidate_security_passed": candidate.get("security", {}).get("known_secret_scan_passed") is True,
        "evidence_inventory_binding_matches": (
            comparison.get("official_evidence_inventory_digest") == official_inventory_digest
            and comparison.get("candidate_evidence_inventory_digest") == candidate_inventory_digest
        ),
        "third_party_bindings_complete": client_bindings_valid
        and _fingerprint({"items": client_bindings})
        == _fingerprint({"items": reparsed_client_bindings})
        and required_clients.issubset(observed_clients),
        "candidate_external_gate_complete": external_gate.get("phase")
        == external_gate_receipt.CANDIDATE_PHASE,
    }
    accepted = all(gates.values())
    result = {
        "schema_version": ACCEPTANCE_SCHEMA,
        "status": "complete" if accepted else "blocked",
        "accepted": accepted,
        "candidate_id": candidate_id,
        "campaign_mode": manifest["campaign_mode"],
        "campaign_purpose": manifest["campaign_purpose"],
        "candidate_purpose": candidate_purpose,
        "production_state": "accepted_not_activated",
        "target_version": manifest["target_version"],
        "profile_id": identity.get("profile_id"),
        "profile_digest": identity.get("profile_digest"),
        "assertions": assertion_gate,
        "gates": gates,
        "failed_gates": sorted(key for key, value in gates.items() if not value),
        "official_package_digest": official["package_digest"],
        "candidate_package_digest": candidate["package_digest"],
        "comparison_package_digest": comparison["package_digest"],
        "classification_package_digest": classification["package_digest"],
        "official_evidence_inventory_digest": official_inventory_digest,
        "candidate_evidence_inventory_digest": candidate_inventory_digest,
        "candidate_identity": {
            "source_tree_sha256": identity.get("source_tree_sha256"),
            "image_id": identity.get("image_id"),
            "image_reference": identity.get("image_reference"),
            "build_id": identity.get("build_id"),
            "deployed_version": identity.get("deployed_version"),
            "candidate_purpose": identity.get("candidate_purpose"),
        },
        "candidate_external_gate": external_gate_binding,
        # 保留原始集合是否逐项相等的诊断事实，但不把不同采集计划造成的差集伪装成失败。
        "equal": bool(comparison.get("equal")),
    }
    if accepted:
        acceptance_root = ensure_private_directory(
            campaign_dir / "acceptance" / candidate_id, campaign_dir
        )
        canonical_assertions = campaign_dir / "assertions" / candidate_id / "results.json"
        if assertions_path.resolve(strict=True) != canonical_assertions.resolve(strict=False):
            if canonical_assertions.exists():
                existing_assertions = _read_json(
                    canonical_assertions, "已封存逐规则断言结果"
                )
                if _fingerprint(existing_assertions) != _fingerprint(assertions):
                    raise ConfigurationError("逐规则断言结果已经封存且内容不同。")
            else:
                secure_write_json(canonical_assertions, assertions)
        assertion_binding = {
            "path": canonical_assertions.relative_to(campaign_dir).as_posix(),
            "sha256": file_sha256(canonical_assertions),
        }
        seal_path = acceptance_root / "evidence-seal.json"
        evidence_seal = {
            "campaign_manifest_sha256": file_sha256(campaign_dir / "campaign.json"),
            "campaign_mode": manifest["campaign_mode"],
            "campaign_purpose": manifest["campaign_purpose"],
            "candidate_purpose": candidate_purpose,
            "production_state": "accepted_not_activated",
            "official_package_digest": official["package_digest"],
            "classification_package_digest": classification["package_digest"],
            "candidate_package_digest": candidate["package_digest"],
            "comparison_package_digest": comparison["package_digest"],
            "assertion_result": assertion_binding,
            "candidate_external_gate": external_gate_binding,
            "official_evidence_inventory_digest": official_inventory_digest,
            "candidate_evidence_inventory_digest": candidate_inventory_digest,
        }
        if seal_path.exists():
            existing_seal = _read_json(seal_path, "已封存验收证据封印")
            if _fingerprint(existing_seal) != _fingerprint(evidence_seal):
                raise ConfigurationError("验收证据封印已经存在且内容不同。")
        else:
            secure_write_json(seal_path, evidence_seal)
        result["assertion_result"] = assertion_binding
        result["evidence_seal"] = {
            "path": seal_path.relative_to(campaign_dir).as_posix(),
            "sha256": file_sha256(seal_path),
        }
        save_stage_result(campaign_dir, "accept", result, candidate_id=candidate_id)
    else:
        _write_blocked_acceptance_attempt(campaign_dir, candidate_id, result)
    return result


def _normalize_legacy_argv(argv: list[str]) -> tuple[list[str], str | None]:
    commands = {
        "plan",
        "successor",
        "capture-official",
        "classify",
        "prepare-profile",
        "stage-profile",
        "capture-candidate",
        "compare",
        "accept",
        "all",
        "status",
        "resume",
    }
    if argv and argv[0] in commands:
        return argv, None
    if "--dry-run" in argv:
        normalized = [value for value in argv if value != "--dry-run"]
        return ["plan", *normalized], "旧 --dry-run 已映射为 plan。"
    if "--execute" in argv:
        return argv, (
            "旧 --execute 已停用：真实抓包必须显式执行 plan、capture-official、"
            "classify、capture-candidate、compare、accept，避免自动跳过人工分类。"
        )
    return argv, None


def _resolve_classification_inputs(
    arguments: argparse.Namespace,
    manifest: dict[str, Any],
) -> None:
    if not arguments.approve_manifest_sha256:
        return
    if arguments.target_rule_manifest or arguments.migration_manifest:
        return
    version_root = (
        Path(__file__).resolve().parent
        / "versions"
        / manifest["target_version"]
    )
    candidates = {
        "target_rule_manifest": version_root / "target-rules.json",
        "migration_manifest": version_root / "rule-migration.json",
        "scenario_manifest": version_root / "scenarios.json",
        "profile_manifest": version_root / "profile.json",
        "assertion_profile_manifest": version_root / "assertion-profile.json",
    }
    missing = [str(path) for path in candidates.values() if not path.is_file()]
    if missing:
        raise ConfigurationError(
            f"批准摘要已提供，但目标版本清单不完整：{missing}"
        )
    for field, path in candidates.items():
        setattr(arguments, field, path)


def _default_assertions_path(campaign_dir: Path, candidate_id: str) -> Path:
    return campaign_dir / "assertions" / candidate_id / "results.json"


def _resume_campaign(arguments: argparse.Namespace) -> tuple[dict[str, Any], int]:
    _require_formal_campaign(arguments.campaign_dir)
    status = campaign_status(arguments.campaign_dir, arguments.candidate_id)
    current = status["status"]
    if current == "environment_contaminated":
        raise ConfigurationError("环境恢复失败已封锁 Campaign，不能自动 resume。")
    if current in {
        "official_capture_interrupted",
        "candidate_capture_interrupted",
        "capture_state_inconsistent",
    }:
        raise ConfigurationError("存在孤儿预约或并发残留；只能人工审计后新建 Campaign。")
    if current == "candidate_selection_required":
        raise ConfigurationError("请先按 status 输出选择原 candidate-id，resume 不会猜测。")
    if current in {"official_capture_failed", "candidate_capture_failed"}:
        if not arguments.rerun_failed:
            raise ConfigurationError(
                "失败 attempt 只能显式使用 resume --rerun-failed 创建新 attempt。"
            )
        phase = "official" if current == "official_capture_failed" else "candidate"
        if phase == "candidate":
            required = {
                "candidate_id": arguments.candidate_id,
                "runtime_image": arguments.runtime_image,
                "build_id": arguments.build_id,
                "profile_id": arguments.profile_id,
                "profile_digest": arguments.profile_digest,
                "deployed_version": arguments.deployed_version,
                "candidate_purpose": arguments.candidate_purpose,
            }
            missing = sorted(key for key, value in required.items() if not value)
            if missing:
                raise ConfigurationError(f"候选失败重跑缺少身份参数：{missing}")
        result = _run_capture_attempt(arguments, phase)
        return result, 0 if result.get("status") in CAPTURE_SUCCESS_STATUSES else 2
    if current == "planned":
        result = _run_capture_attempt(arguments, "official")
        return result, 0 if result.get("status") in CAPTURE_SUCCESS_STATUSES else 2
    if current in {"official_awaiting_receipts", "official_awaiting_seal_approval"}:
        raise ConfigurationError(
            "官方 attempt 正等待机器收据或 seal 摘要批准；resume 不会代替人工审核。"
        )
    if current == "official_sealed":
        raise ConfigurationError("下一步是人工 classify；resume 不会自动批准语义分类。")
    if current == "blocked":
        raise ConfigurationError("分类存在 blocker；解决后应以新 Campaign/revision 审核。")
    if current == "profile_approved":
        required = {
            "candidate_id": arguments.candidate_id,
            "runtime_image": arguments.runtime_image,
            "build_id": arguments.build_id,
            "profile_id": arguments.profile_id,
            "profile_digest": arguments.profile_digest,
            "deployed_version": arguments.deployed_version,
            "candidate_purpose": arguments.candidate_purpose,
        }
        missing = sorted(key for key, value in required.items() if not value)
        if missing:
            raise ConfigurationError(f"resume 候选抓包缺少参数：{missing}")
        result = _run_capture_attempt(arguments, "candidate")
        return result, 0 if result.get("status") in CAPTURE_SUCCESS_STATUSES else 2
    if current in {
        "candidate_awaiting_client_checkpoint",
        "candidate_client_checkpoint_created",
        "candidate_awaiting_seal_approval",
    }:
        raise ConfigurationError(
            "候选 attempt 正等待 Kilo／机器收据或 seal 摘要批准；resume 不会代替人工审核。"
        )
    if current == "candidate_sealed":
        if not arguments.candidate_id:
            raise ConfigurationError("resume compare 必须指定 --candidate-id。")
        result = compare_campaign(arguments.campaign_dir, arguments.candidate_id)
        return result, 0 if result["equal"] else 2
    if current == "compared":
        if not arguments.candidate_id:
            raise ConfigurationError("resume accept 必须指定 --candidate-id。")
        if not arguments.external_gate_root or not arguments.external_gate_receipt:
            raise ConfigurationError(
                "resume accept 必须提供 --external-gate-root 和 "
                "--external-gate-receipt。"
            )
        assertions = arguments.assertions or _default_assertions_path(
            arguments.campaign_dir, arguments.candidate_id
        )
        result = accept_campaign(
            arguments.campaign_dir,
            arguments.candidate_id,
            assertions,
            arguments.external_gate_root,
            arguments.external_gate_receipt,
        )
        return result, 0 if result["accepted"] else 2
    return status, 0


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    normalized_argv, legacy_message = _normalize_legacy_argv(raw_argv)
    if "--execute" in raw_argv and not normalized_argv[:1] in (["all"],):
        print(f"升级审计失败：{legacy_message}", file=sys.stderr)
        return 1
    parser = _build_parser()
    arguments = parser.parse_args(normalized_argv)
    if legacy_message:
        print(legacy_message, file=sys.stderr)
    try:
        command = arguments.command
        if command == "plan":
            manifest = create_campaign(arguments)
            result = {
                "status": (
                    "preflight_complete"
                    if manifest["campaign_mode"] == "preflight_only"
                    else "planned"
                ),
                "campaign_id": manifest["campaign_id"],
                "campaign_mode": manifest["campaign_mode"],
                "campaign_purpose": manifest["campaign_purpose"],
                "campaign_dir": str(arguments.campaign_dir),
                "required_rule_count": len(manifest["required_rules"]),
                "job_count": len(manifest["jobs"]),
            }
            return_code = 0
        elif command == "successor":
            result = create_successor_campaign(arguments)
            return_code = 0
        elif command == "capture-official":
            if arguments.capture_action == "run":
                result = _run_capture_attempt(arguments, "official")
            else:
                result = _seal_capture_attempt(arguments, "official")
            return_code = 0 if result.get("status") in CAPTURE_SUCCESS_STATUSES else 2
        elif command == "classify":
            manifest = load_campaign_manifest(arguments.campaign_dir)
            _resolve_classification_inputs(arguments, manifest)
            result = classify_campaign(
                arguments.campaign_dir,
                target_rule_manifest=arguments.target_rule_manifest,
                migration_manifest=arguments.migration_manifest,
                scenario_manifest=arguments.scenario_manifest,
                profile_manifest=arguments.profile_manifest,
                assertion_profile_manifest=arguments.assertion_profile_manifest,
                approve_manifest_sha256=arguments.approve_manifest_sha256,
            )
            return_code = 0 if result.get("status") in CAPTURE_SUCCESS_STATUSES else 2
        elif command == "prepare-profile":
            result = prepare_profile_manifest(
                arguments.campaign_dir,
                arguments.snapshot,
                arguments.profile_id,
                arguments.output,
            )
            return_code = 0
        elif command == "stage-profile":
            result = stage_profile_catalog(arguments.campaign_dir, arguments.output)
            return_code = 0
        elif command == "capture-candidate":
            if arguments.capture_action == "run":
                result = _run_capture_attempt(arguments, "candidate")
            else:
                result = _seal_capture_attempt(arguments, "candidate")
            return_code = 0 if result.get("status") in CAPTURE_SUCCESS_STATUSES else 2
        elif command == "compare":
            result = compare_campaign(arguments.campaign_dir, arguments.candidate_id)
            return_code = 0 if result["equal"] else 2
        elif command == "accept":
            assertions = arguments.assertions or _default_assertions_path(
                arguments.campaign_dir, arguments.candidate_id
            )
            result = accept_campaign(
                arguments.campaign_dir,
                arguments.candidate_id,
                assertions,
                arguments.external_gate_root,
                arguments.external_gate_receipt,
            )
            return_code = 0 if result["accepted"] else 2
        elif command == "all":
            if campaign_status(
                arguments.campaign_dir, arguments.candidate_id
            )["status"] != "profile_approved":
                raise ConfigurationError("all 只允许从 profile_approved 状态开始。")
            result = _run_capture_attempt(arguments, "candidate")
            result["next_command"] = (
                "完成 Kilo witness、机器 finalizer 与 seal 摘要复核；封存后再执行 compare。"
            )
            return_code = 2
        elif command == "evaluation-transition":
            result = create_phase_evaluation_transition(arguments)
            return_code = 0 if result.get("status") == "approved" else 2
        elif command == "deep-verify":
            result = deep_verify_campaign(
                arguments.campaign_dir,
                candidate_id=arguments.candidate_id,
                attempt_id=arguments.attempt_id,
            )
            return_code = 0
        elif command == "status":
            result = campaign_status(arguments.campaign_dir, arguments.candidate_id)
            return_code = 0
        elif command == "resume":
            result, return_code = _resume_campaign(arguments)
        else:
            raise ConfigurationError(f"不受支持的命令：{command}")
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return return_code
    except KeyboardInterrupt:
        print("升级抓包已中断；当前任务已收到终止信号。", file=sys.stderr)
        return 130
    except (
        ConfigurationError,
        OSError,
        RuntimeError,
        ValueError,
        subprocess.SubprocessError,
    ) as error:
        print(f"升级审计失败：{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
