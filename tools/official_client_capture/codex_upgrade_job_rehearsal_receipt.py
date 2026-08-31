#!/usr/bin/env python3
"""在 ARM64 上离线演练 Codex 升级全部 Job，并封存可重放收据。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping


FACTS_SCHEMA = "codex-upgrade-job-rehearsal-facts/v1"
RECEIPT_SCHEMA = "codex-upgrade-job-rehearsal-receipt/v1"
EXECUTION_CONTRACT_SCHEMA = "codex-upgrade-job-rehearsal-contract/v2"
PRODUCER_SCHEMA = "codex-upgrade-job-rehearsal-producer/v1"
PRODUCER_VERSION = "1"
EXPECTED_ARCHITECTURE = "linux/arm64"
MAX_JSON_BYTES = 16 * 1024 * 1024
ZSTD_FRAME = bytes.fromhex("28b52ffd045829000068656c6c6fa36d9f88")
ZSTD_OUTPUT = b"hello"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{64}$")
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)

# 这些字段会改变 Job 的真实启动环境，preflight 与 Formal 必须逐项一致。
EXECUTION_CONFIGURATION_FIELDS = (
    "runtime_image",
    "model",
    "lite_model",
    "capture_root",
    "capture_container",
    "service_container",
    "keeper_container",
    "postgres_container",
    "redis_container",
    "capture_codex_bin",
    "relay_codex_bin",
    "capture_code_mode_host_bin",
    "relay_code_mode_host_bin",
)

# 不执行 Job；只确认所有 wrapper 与内联脚本可能依赖的命令在对应执行域可用。
HOST_REQUIRED_COMMANDS = (
    "awk",
    "base64",
    "bash",
    "chmod",
    "cp",
    "curl",
    "cut",
    "date",
    "docker",
    "find",
    "flock",
    "grep",
    "head",
    "install",
    "jq",
    "mkdir",
    "mv",
    "openssl",
    "python3",
    "rm",
    "rmdir",
    "sed",
    "sha256sum",
    "sort",
    "stat",
    "tail",
    "tee",
    "timeout",
    "uniq",
)
CAPTURE_CONTAINER_REQUIRED_COMMANDS = (
    "bash",
    "bwrap",
    "chmod",
    "cp",
    "curl",
    "cut",
    "env",
    "flock",
    "getent",
    "install",
    "jq",
    "mitmdump",
    "mv",
    "openssl",
    "pgrep",
    "pkill",
    "python3",
    "rm",
    "seq",
    "sha256sum",
    "sh",
    "sleep",
    "stat",
    "tar",
    "tcpdump",
    "timeout",
    "update-ca-certificates",
)


class JobRehearsalReceiptError(ValueError):
    """完整 Job 离线演练不完整、发生漂移或无法重放。"""


def _json_bytes(value: Any, *, newline: bool) -> bytes:
    raw = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return raw + (b"\n" if newline else b"")


def _canonical(value: Any) -> bytes:
    return _json_bytes(value, newline=True)


def _fingerprint(value: Any) -> str:
    return hashlib.sha256(_json_bytes(value, newline=False)).hexdigest()


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


def _expect(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise JobRehearsalReceiptError(f"{label}必须是对象")
    actual = set(value)
    if actual != fields:
        raise JobRehearsalReceiptError(
            f"{label}字段不闭合：缺失={sorted(fields - actual)}，"
            f"多余={sorted(actual - fields)}"
        )
    return value


def _safe_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SAFE_ID_RE.fullmatch(value):
        raise JobRehearsalReceiptError(f"{label}不是安全标识")
    return value


def _rfc3339(value: Any, label: str) -> str:
    if not isinstance(value, str) or not RFC3339_RE.fullmatch(value):
        raise JobRehearsalReceiptError(f"{label}不是带时区 RFC3339 时间")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise JobRehearsalReceiptError(f"{label}不是有效时间") from error
    if parsed.tzinfo is None:
        raise JobRehearsalReceiptError(f"{label}缺少时区")
    return value


def _private_root(root: Path) -> Path:
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise JobRehearsalReceiptError(
            "evidence root 必须是现有非符号链接绝对目录"
        )
    resolved = root.resolve(strict=True)
    if stat.S_IMODE(resolved.stat().st_mode) != 0o700:
        raise JobRehearsalReceiptError("evidence root 权限必须是 0700")
    return resolved


def _relative(root: Path, value: str, label: str) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise JobRehearsalReceiptError(f"{label}必须是证据根内 POSIX 相对路径")
    parsed = PurePosixPath(value)
    if (
        parsed.is_absolute()
        or str(parsed) != value
        or any(part in {"", ".", ".."} for part in parsed.parts)
    ):
        raise JobRehearsalReceiptError(f"{label}路径不规范")
    current = root
    for part in parsed.parts:
        current /= part
        if current.is_symlink():
            raise JobRehearsalReceiptError(f"{label}路径包含符号链接")
    try:
        current.resolve(strict=current.exists()).relative_to(root)
    except (OSError, RuntimeError, ValueError) as error:
        raise JobRehearsalReceiptError(f"{label}越过 evidence root") from error
    return current


def _load_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    if not path.is_file() or path.is_symlink():
        raise JobRehearsalReceiptError(f"{label}不是可信普通文件")
    metadata = path.stat()
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise JobRehearsalReceiptError(f"{label}权限必须是 0600")
    if metadata.st_size <= 0 or metadata.st_size > MAX_JSON_BYTES:
        raise JobRehearsalReceiptError(f"{label}大小非法")
    raw = path.read_bytes()
    try:
        payload = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise JobRehearsalReceiptError(f"{label}不是合法 UTF-8 JSON") from error
    if not isinstance(payload, dict):
        raise JobRehearsalReceiptError(f"{label}顶层必须是对象")
    return payload, raw


def _write_once(path: Path, payload: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise JobRehearsalReceiptError(f"输出已存在，禁止覆盖：{path}")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink() or stat.S_IMODE(path.parent.stat().st_mode) != 0o700:
        raise JobRehearsalReceiptError("输出父目录必须是 0700 非符号链接目录")
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


def _run(argv: list[str], label: str, timeout: int = 60) -> bytes:
    try:
        completed = subprocess.run(
            argv,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise JobRehearsalReceiptError(f"{label}执行失败：{error}") from error
    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", errors="replace")[:500].strip()
        raise JobRehearsalReceiptError(f"{label}失败：{message}")
    return completed.stdout


def _job_templates(
    target_scenario: Mapping[str, Any],
    extra_jobs: Mapping[str, Any] | None,
    suite: str,
) -> list[dict[str, Any]]:
    raw_jobs = target_scenario.get("capture_jobs")
    if not isinstance(raw_jobs, list) or not raw_jobs:
        raise JobRehearsalReceiptError("target 场景清单没有 capture_jobs")
    combined = list(raw_jobs)
    if extra_jobs is not None:
        extra = extra_jobs.get("jobs")
        if not isinstance(extra, list):
            raise JobRehearsalReceiptError("extra_jobs.jobs 非法")
        combined.extend(extra)
    selected: list[dict[str, Any]] = []
    for index, raw in enumerate(combined, 1):
        if not isinstance(raw, dict):
            raise JobRehearsalReceiptError(f"Job 模板 {index} 不是对象")
        job_id = raw.get("id")
        phase = raw.get("phase")
        suites = raw.get("suites", ["full"])
        steps = raw.get("steps")
        if (
            not isinstance(job_id, str)
            or not SAFE_ID_RE.fullmatch(job_id)
            or phase not in {"official", "candidate"}
            or not isinstance(suites, list)
            or not all(isinstance(item, str) for item in suites)
            or not isinstance(steps, list)
            or not steps
        ):
            raise JobRehearsalReceiptError(f"Job 模板 {index} 身份或步骤非法")
        if suite in suites:
            selected.append(dict(raw))
    ids = [str(item["id"]) for item in selected]
    if not selected or len(ids) != len(set(ids)):
        raise JobRehearsalReceiptError("目标 Job 集为空或 ID 重复")
    return sorted(selected, key=lambda item: (str(item["phase"]), str(item["id"])))


def _target_evidence_label_declaration_sha256(
    target_version: str,
    target_scenario: Mapping[str, Any],
    *,
    tool_root: Path | None = None,
) -> str:
    """验证目标版本证据标签声明完整覆盖正式 Job 集。"""

    from tools.official_client_capture import build_evidence_catalog

    root = tool_root or Path(__file__).resolve().parent
    version_key = target_version.replace(".", "_")
    path = root / f"codex_upgrade_evidence_labels_{version_key}.json"
    if path.is_symlink() or not path.is_file():
        raise JobRehearsalReceiptError(
            f"目标版本 {target_version} 缺少证据标签声明：{path}"
        )
    try:
        declaration = build_evidence_catalog.load_label_declaration(
            path,
            expected_codex_version=target_version,
        )
    except (OSError, build_evidence_catalog.EvidenceCatalogError) as error:
        raise JobRehearsalReceiptError(
            f"目标版本 {target_version} 证据标签声明非法：{error}"
        ) from error

    raw_jobs = target_scenario.get("capture_jobs")
    if not isinstance(raw_jobs, list) or not raw_jobs:
        raise JobRehearsalReceiptError("target 场景清单没有 capture_jobs")
    scenario_jobs = {
        str(item.get("id")): str(item.get("phase"))
        for item in raw_jobs
        if isinstance(item, dict)
    }
    declared_jobs = {
        str(item.get("job_id")): str(item.get("side"))
        for item in declaration["entries"]
        if isinstance(item, dict)
    }
    if (
        len(scenario_jobs) != len(raw_jobs)
        or len(declared_jobs) != len(declaration["entries"])
        or declared_jobs != scenario_jobs
    ):
        missing = sorted(set(scenario_jobs) - set(declared_jobs))
        extra = sorted(set(declared_jobs) - set(scenario_jobs))
        mismatched = sorted(
            job_id
            for job_id in set(scenario_jobs) & set(declared_jobs)
            if scenario_jobs[job_id] != declared_jobs[job_id]
        )
        raise JobRehearsalReceiptError(
            "目标证据标签声明未精确覆盖正式 Job 集："
            f"missing={missing} extra={extra} phase_mismatch={mismatched}"
        )
    return _sha256_file(path)


def build_execution_contract(
    *,
    target_version: str,
    target_sha256: str,
    target_package_sha256: str,
    target_code_mode_host_sha256: str,
    suite: str,
    tool_files_sha256: str,
    configuration: Mapping[str, Any],
    target_scenario: Mapping[str, Any],
    extra_jobs: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """生成 preflight 与 Formal 之间不含 Campaign ID 的稳定执行合同。"""

    for label, value in (
        ("target_sha256", target_sha256),
        ("target_package_sha256", target_package_sha256),
        ("target_code_mode_host_sha256", target_code_mode_host_sha256),
        ("tool_files_sha256", tool_files_sha256),
    ):
        if not SHA256_RE.fullmatch(str(value)):
            raise JobRehearsalReceiptError(f"{label} 不是 SHA-256")
    if not isinstance(target_version, str) or not re.fullmatch(
        r"\d+\.\d+\.\d+", target_version
    ):
        raise JobRehearsalReceiptError("target_version 非法")
    if suite not in {"core", "full"}:
        raise JobRehearsalReceiptError("suite 非法")
    frozen_configuration = {
        field: configuration.get(field) for field in EXECUTION_CONFIGURATION_FIELDS
    }
    missing = [
        field
        for field, value in frozen_configuration.items()
        if value is None or (isinstance(value, str) and not value)
    ]
    if missing:
        raise JobRehearsalReceiptError(
            "Job 执行配置存在空值：" + "、".join(missing)
        )
    evidence_label_declaration_sha256 = (
        _target_evidence_label_declaration_sha256(
            target_version,
            target_scenario,
        )
    )
    templates = _job_templates(target_scenario, extra_jobs, suite)
    job_phases = {str(item["id"]): str(item["phase"]) for item in templates}
    step_counts = {
        str(item["id"]): len(item.get("steps", [])) for item in templates
    }
    c2pa: dict[str, dict[str, str]] = {}
    for item in templates:
        job_id = str(item["id"])
        if job_id not in {
            "official-relay-file-upload-c2pa-negative",
            "official-relay-file-upload-c2pa-positive",
        }:
            continue
        steps = item.get("steps")
        environment = steps[0].get("environment") if isinstance(steps, list) else None
        if not isinstance(environment, dict):
            raise JobRehearsalReceiptError(f"{job_id} 缺少环境变量")
        c2pa[job_id] = {
            "scenario_job_id": str(environment.get("SCENARIO_JOB_ID", "")),
            "expectation": str(environment.get("A14_C2PA_EXPECTATION", "")),
        }
    expected_c2pa = {
        "official-relay-file-upload-c2pa-negative": {
            "scenario_job_id": "official-relay-file-upload-c2pa-negative",
            "expectation": "negative",
        },
        "official-relay-file-upload-c2pa-positive": {
            "scenario_job_id": "official-relay-file-upload-c2pa-positive",
            "expectation": "positive",
        },
    }
    # 只在清单包含 A14 双 Job 时要求完整精确身份；旧版本测试清单不被强行扩写。
    if c2pa and c2pa != expected_c2pa:
        raise JobRehearsalReceiptError("A14 C2PA 正负 Job 身份未精确分离")
    phase_counts = {
        phase: sum(1 for value in job_phases.values() if value == phase)
        for phase in ("official", "candidate")
    }
    return {
        "schema_version": EXECUTION_CONTRACT_SCHEMA,
        "target_version": target_version,
        "target_sha256": target_sha256,
        "target_package_sha256": target_package_sha256,
        "target_code_mode_host_sha256": target_code_mode_host_sha256,
        "suite": suite,
        "tool_files_sha256": tool_files_sha256,
        "target_scenario_sha256": _fingerprint(target_scenario),
        "evidence_label_declaration_sha256": (
            evidence_label_declaration_sha256
        ),
        "extra_jobs_sha256": (
            _fingerprint(extra_jobs) if extra_jobs is not None else None
        ),
        "configuration": frozen_configuration,
        "job_count": len(templates),
        "phase_counts": phase_counts,
        "job_ids": sorted(job_phases),
        "job_phases": dict(sorted(job_phases.items())),
        "step_counts": dict(sorted(step_counts.items())),
        "job_templates_sha256": _fingerprint(templates),
        "c2pa_job_identities": c2pa,
    }


def execution_contract_sha256(contract: Mapping[str, Any]) -> str:
    validate_execution_contract(dict(contract))
    return _fingerprint(contract)


def validate_execution_contract(contract: dict[str, Any]) -> dict[str, Any]:
    _expect(
        contract,
        {
            "schema_version",
            "target_version",
            "target_sha256",
            "target_package_sha256",
            "target_code_mode_host_sha256",
            "suite",
            "tool_files_sha256",
            "target_scenario_sha256",
            "evidence_label_declaration_sha256",
            "extra_jobs_sha256",
            "configuration",
            "job_count",
            "phase_counts",
            "job_ids",
            "job_phases",
            "step_counts",
            "job_templates_sha256",
            "c2pa_job_identities",
        },
        "execution_contract",
    )
    if contract.get("schema_version") != EXECUTION_CONTRACT_SCHEMA:
        raise JobRehearsalReceiptError("execution_contract.schema_version 不匹配")
    for field in (
        "target_sha256",
        "target_package_sha256",
        "target_code_mode_host_sha256",
        "tool_files_sha256",
        "target_scenario_sha256",
        "evidence_label_declaration_sha256",
        "job_templates_sha256",
    ):
        if not SHA256_RE.fullmatch(str(contract.get(field, ""))):
            raise JobRehearsalReceiptError(f"execution_contract.{field} 非法")
    extra_sha = contract.get("extra_jobs_sha256")
    if extra_sha is not None and not SHA256_RE.fullmatch(str(extra_sha)):
        raise JobRehearsalReceiptError("execution_contract.extra_jobs_sha256 非法")
    configuration = contract.get("configuration")
    if not isinstance(configuration, dict) or set(configuration) != set(
        EXECUTION_CONFIGURATION_FIELDS
    ):
        raise JobRehearsalReceiptError("execution_contract.configuration 不闭合")
    if any(
        value is None or (isinstance(value, str) and not value)
        for value in configuration.values()
    ):
        raise JobRehearsalReceiptError("execution_contract.configuration 含空值")
    job_ids = contract.get("job_ids")
    phases = contract.get("job_phases")
    counts = contract.get("step_counts")
    phase_counts = contract.get("phase_counts")
    if (
        not isinstance(job_ids, list)
        or not job_ids
        or job_ids != sorted(job_ids)
        or len(job_ids) != len(set(job_ids))
        or not all(isinstance(item, str) and SAFE_ID_RE.fullmatch(item) for item in job_ids)
        or not isinstance(phases, dict)
        or set(phases) != set(job_ids)
        or not all(value in {"official", "candidate"} for value in phases.values())
        or not isinstance(counts, dict)
        or set(counts) != set(job_ids)
        or not all(isinstance(value, int) and not isinstance(value, bool) and value > 0 for value in counts.values())
        or not isinstance(phase_counts, dict)
        or set(phase_counts) != {"official", "candidate"}
        or any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in phase_counts.values())
        or contract.get("job_count") != len(job_ids)
        or sum(phase_counts.values()) != len(job_ids)
        or any(
            phase_counts[phase] != sum(value == phase for value in phases.values())
            for phase in phase_counts
        )
    ):
        raise JobRehearsalReceiptError("execution_contract Job 集非法")
    c2pa = contract.get("c2pa_job_identities")
    if not isinstance(c2pa, dict):
        raise JobRehearsalReceiptError("execution_contract C2PA 身份非法")
    return contract


def _host_tool_entries(root: Path) -> tuple[list[dict[str, str]], list[str]]:
    if not root.is_dir() or root.is_symlink():
        raise JobRehearsalReceiptError(f"工具树不存在或不可信：{root}")
    entries: list[dict[str, str]] = []
    symlinks: list[str] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if path.is_symlink():
            if path.suffix in {".py", ".sh", ".json"}:
                symlinks.append(relative.as_posix())
            continue
        if (
            path.is_file()
            and path.suffix in {".py", ".sh", ".json"}
            and "tests" not in relative.parts
            and "versions" not in relative.parts
            and "__pycache__" not in relative.parts
        ):
            entries.append(
                {"path": relative.as_posix(), "sha256": _sha256_file(path)}
            )
    return entries, symlinks


def _tool_tree_summary(root: Path) -> dict[str, Any]:
    entries, symlinks = _host_tool_entries(root)
    if not entries or symlinks:
        raise JobRehearsalReceiptError(
            f"工具树为空或含受管符号链接：{root}；symlinks={symlinks[:5]}"
        )
    return {
        "root": str(root.resolve(strict=True)),
        "entry_count": len(entries),
        "files_sha256": _fingerprint({"entries": entries}),
        "entries": entries,
    }


def _container_tool_tree(container: str, root: str) -> dict[str, Any]:
    probe = r'''
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1])
if not root.is_dir() or root.is_symlink():
    raise SystemExit("container tool root unavailable")
entries=[]; symlinks=[]
for path in sorted(root.rglob("*")):
    relative=path.relative_to(root)
    if path.is_symlink():
        if path.suffix in {".py",".sh",".json"}: symlinks.append(relative.as_posix())
        continue
    if (path.is_file() and path.suffix in {".py",".sh",".json"}
        and "tests" not in relative.parts and "versions" not in relative.parts
        and "__pycache__" not in relative.parts):
        entries.append({"path":relative.as_posix(),"sha256":hashlib.sha256(path.read_bytes()).hexdigest()})
print(json.dumps({"root":str(root.resolve()),"entries":entries,"symlinks":symlinks},sort_keys=True))
'''
    raw = _run(
        ["docker", "exec", container, "python3", "-c", probe, root],
        "capture-cli 容器工具树探针",
    )
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as error:
        raise JobRehearsalReceiptError("容器工具树探针输出非法") from error
    if (
        not isinstance(payload, dict)
        or payload.get("symlinks") != []
        or not isinstance(payload.get("entries"), list)
        or not payload["entries"]
    ):
        raise JobRehearsalReceiptError("容器工具树为空或含受管符号链接")
    entries = payload["entries"]
    return {
        "root": str(payload.get("root", "")),
        "entry_count": len(entries),
        "files_sha256": _fingerprint({"entries": entries}),
        "entries": entries,
    }


def _command_binding(name: str, path: Path) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise JobRehearsalReceiptError(f"命令不可执行：{name} -> {resolved}")
    return {
        "name": name,
        "path": str(resolved),
        "sha256": _sha256_file(resolved),
        "status": "passed",
    }


def _host_dependencies() -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for name in HOST_REQUIRED_COMMANDS:
        path = shutil.which(name)
        if not path:
            raise JobRehearsalReceiptError(f"ARM64 宿主缺少依赖：{name}")
        output.append(_command_binding(name, Path(path)))
    return output


def _container_dependencies(container: str) -> list[dict[str, Any]]:
    probe = r'''
import hashlib,json,os,pathlib,shutil,sys
output=[]
for name in sys.argv[1:]:
    found=shutil.which(name)
    if not found: raise SystemExit("missing:"+name)
    resolved=pathlib.Path(os.path.realpath(found))
    if not resolved.is_file() or not os.access(resolved,os.X_OK): raise SystemExit("not-executable:"+name)
    output.append({"name":name,"path":str(resolved),"sha256":hashlib.sha256(resolved.read_bytes()).hexdigest(),"status":"passed"})
print(json.dumps(output,sort_keys=True))
'''
    raw = _run(
        [
            "docker",
            "exec",
            container,
            "python3",
            "-c",
            probe,
            *CAPTURE_CONTAINER_REQUIRED_COMMANDS,
        ],
        "capture-cli 依赖探针",
    )
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as error:
        raise JobRehearsalReceiptError("capture-cli 依赖探针输出非法") from error
    if not isinstance(payload, list):
        raise JobRehearsalReceiptError("capture-cli 依赖探针结果不是数组")
    return payload


def _container_facts(configuration: Mapping[str, Any]) -> list[dict[str, Any]]:
    names = sorted(
        {
            str(configuration[field])
            for field in (
                "capture_container",
                "service_container",
                "keeper_container",
                "postgres_container",
                "redis_container",
            )
        }
    )
    raw = _run(["docker", "inspect", *names], "Job 依赖容器状态探针")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as error:
        raise JobRehearsalReceiptError("docker inspect 输出非法") from error
    if not isinstance(payload, list) or len(payload) != len(names):
        raise JobRehearsalReceiptError("docker inspect 未完整覆盖 Job 依赖容器")
    output: list[dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, dict):
            raise JobRehearsalReceiptError("docker inspect 项不是对象")
        name = str(item.get("Name", "")).lstrip("/")
        state = item.get("State") if isinstance(item.get("State"), dict) else {}
        container_id = str(item.get("Id", ""))
        image_id = str(item.get("Image", ""))
        if (
            name not in names
            or state.get("Running") is not True
            or not CONTAINER_ID_RE.fullmatch(container_id)
            or not IMAGE_ID_RE.fullmatch(image_id)
        ):
            raise JobRehearsalReceiptError(f"Job 依赖容器未运行或身份非法：{name}")
        output.append(
            {
                "name": name,
                "container_id": container_id,
                "image_id": image_id,
                "running": True,
            }
        )
    return sorted(output, key=lambda item: item["name"])


def _bwrap_probe(container: str) -> dict[str, Any]:
    version = _run(
        ["docker", "exec", container, "bwrap", "--version"],
        "bubblewrap 版本探针",
    ).decode("utf-8", errors="strict").strip()
    script = (
        "import pathlib;"
        "lines=pathlib.Path('/proc/net/route').read_text().splitlines()[1:];"
        "assert not any(len(x.split())>1 and x.split()[1]=='00000000' for x in lines);"
        "print('bwrap-offline-ok')"
    )
    output = _run(
        [
            "docker",
            "exec",
            container,
            "timeout",
            "15",
            "bwrap",
            "--unshare-user",
            "--uid",
            "65534",
            "--gid",
            "65534",
            "--unshare-pid",
            "--unshare-net",
            "--die-with-parent",
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--",
            "/usr/bin/python3",
            "-c",
            script,
        ],
        "bubblewrap 离线沙箱探针",
        timeout=30,
    ).decode("utf-8", errors="strict").strip()
    if output != "bwrap-offline-ok":
        raise JobRehearsalReceiptError("bubblewrap 离线沙箱结果不一致")
    return {
        "status": "passed",
        "version": version,
        "network_isolated": True,
    }


def _zstd_probe(container: str, tool_root: str) -> dict[str, Any]:
    script = (
        "import sys;"
        "sys.path.insert(0,sys.argv[1]);"
        "from relay_extract import decompress_zstd;"
        "raw=bytes.fromhex(sys.argv[2]);"
        "out=decompress_zstd(raw);"
        "assert out==b'hello';"
        "sys.stdout.buffer.write(out)"
    )
    output = _run(
        [
            "docker",
            "exec",
            container,
            "python3",
            "-c",
            script,
            tool_root,
            ZSTD_FRAME.hex(),
        ],
        "capture-cli zstd 离线解压探针",
    )
    if output != ZSTD_OUTPUT:
        raise JobRehearsalReceiptError("zstd 已知帧解压结果不一致")
    return {
        "status": "passed",
        "input_sha256": _sha256_bytes(ZSTD_FRAME),
        "output_sha256": _sha256_bytes(output),
        "output": output.decode("ascii"),
    }


def _syntax_probe(argv: list[str], container: str, label: str) -> tuple[str, list[dict[str, str]]]:
    checks: list[dict[str, str]] = []
    if argv[0] == "bash":
        if len(argv) < 2:
            raise JobRehearsalReceiptError(f"{label} 缺少 bash 参数")
        if argv[1] == "-c":
            if len(argv) != 3:
                raise JobRehearsalReceiptError(f"{label} bash -c 参数不闭合")
            _run(["bash", "-n", "-c", argv[2]], f"{label} 宿主内联脚本语法")
            checks.append({"kind": "host_inline_bash", "sha256": _sha256_bytes(argv[2].encode())})
            return "host", checks
        script = Path(argv[1])
        if not script.is_absolute() or not script.is_file() or script.is_symlink():
            raise JobRehearsalReceiptError(f"{label} 宿主脚本路径不可信：{script}")
        _run(["bash", "-n", str(script)], f"{label} 宿主脚本语法")
        checks.append({"kind": "host_script", "path": str(script), "sha256": _sha256_file(script)})
        return "host", checks
    if argv[0] != "docker" or len(argv) < 5 or argv[1] != "exec":
        raise JobRehearsalReceiptError(f"{label} 启动器未登记：{argv[:3]}")
    if argv[2] != container:
        raise JobRehearsalReceiptError(f"{label} docker exec 未绑定 capture-cli")
    command = argv[3]
    if command == "python3":
        script = argv[4]
        raw = _run(
            [
                "docker",
                "exec",
                container,
                "python3",
                "-c",
                "import hashlib,json,pathlib,sys;p=pathlib.Path(sys.argv[1]);"
                "assert p.is_file() and not p.is_symlink();"
                "print(json.dumps({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}))",
                script,
            ],
            f"{label} 容器 Python 路径",
        )
        payload = json.loads(raw)
        checks.append({"kind": "container_python_script", **payload})
        return "capture_container", checks
    if command == "bash" and argv[4] == "-c" and len(argv) == 6:
        _run(
            ["docker", "exec", container, "bash", "-n", "-c", argv[5]],
            f"{label} 容器内联脚本语法",
        )
        checks.append({"kind": "container_inline_bash", "sha256": _sha256_bytes(argv[5].encode())})
        return "capture_container", checks
    raise JobRehearsalReceiptError(f"{label} 容器启动器未登记：{argv[3:5]}")


def _job_document(job: Any) -> dict[str, Any]:
    return {
        "id": str(job.job_id),
        "phase": str(job.phase),
        "suites": list(job.suites),
        "description": str(job.description),
        "steps": [dict(step) for step in job.steps],
        "evidence_roots": list(job.evidence_roots),
        "covers": list(job.covers),
        "scenario_ids": list(job.scenario_ids),
        "required": bool(job.required),
        "required_scenario_receipts": list(job.required_scenario_receipts),
        "track": str(job.track),
        "model_id": str(job.model_id),
        "expected_use_responses_lite": bool(job.expected_use_responses_lite),
        "required_model_receipt": bool(job.required_model_receipt),
    }


def _job_probe(job: Any, container: str) -> dict[str, Any]:
    document = _job_document(job)
    steps: list[dict[str, Any]] = []
    for index, step in enumerate(document["steps"], 1):
        argv = step.get("argv")
        environment = step.get("environment")
        timeout = step.get("timeout")
        if (
            not isinstance(argv, list)
            or not argv
            or not all(isinstance(value, str) and value for value in argv)
            or not isinstance(environment, dict)
            or not all(isinstance(key, str) and isinstance(value, str) and value for key, value in environment.items())
            or not isinstance(timeout, int)
            or isinstance(timeout, bool)
            or timeout <= 0
        ):
            raise JobRehearsalReceiptError(
                f"{job.job_id} 第 {index} 步命令、环境或超时非法"
            )
        launcher, path_checks = _syntax_probe(
            argv, container, f"{job.job_id}:step-{index}"
        )
        steps.append(
            {
                "index": index,
                "status": "passed",
                "launcher": launcher,
                "argv_sha256": _fingerprint(argv),
                "environment_sha256": _fingerprint(environment),
                "timeout_seconds": timeout,
                "path_checks": path_checks,
                "dependencies": (
                    [f"host:{name}" for name in HOST_REQUIRED_COMMANDS]
                    if launcher == "host"
                    else ["host:docker"]
                    + [
                        f"capture_container:{name}"
                        for name in CAPTURE_CONTAINER_REQUIRED_COMMANDS
                    ]
                ),
            }
        )
    c2pa = None
    if job.job_id in {
        "official-relay-file-upload-c2pa-negative",
        "official-relay-file-upload-c2pa-positive",
    }:
        environment = document["steps"][0]["environment"]
        expected = "negative" if job.job_id.endswith("negative") else "positive"
        if (
            environment.get("SCENARIO_JOB_ID") != job.job_id
            or environment.get("A14_C2PA_EXPECTATION") != expected
        ):
            raise JobRehearsalReceiptError(f"{job.job_id} C2PA 身份漂移")
        c2pa = {
            "scenario_job_id": environment["SCENARIO_JOB_ID"],
            "expectation": environment["A14_C2PA_EXPECTATION"],
        }
    if job.required_model_receipt:
        environment = document["steps"][0]["environment"]
        if (
            environment.get("SCENARIO_JOB_ID") != job.job_id
            or environment.get("REQUIRE_MODEL_CONDITION_RECEIPT") != "1"
            or environment.get("MODEL_TRACK") != job.track
            or environment.get("EXPECT_USE_RESPONSES_LITE")
            != ("true" if job.expected_use_responses_lite else "false")
        ):
            raise JobRehearsalReceiptError(f"{job.job_id} 模型条件收据身份漂移")
    return {
        "id": job.job_id,
        "phase": job.phase,
        "status": "passed",
        "job_contract_sha256": _fingerprint(document),
        "step_count": len(steps),
        "steps": steps,
        "c2pa_identity": c2pa,
    }


def _producer() -> dict[str, str]:
    tool = Path(__file__).resolve()
    return {
        "schema_version": PRODUCER_SCHEMA,
        "tool": str(tool),
        "tool_sha256": _sha256_file(tool),
        "version": PRODUCER_VERSION,
    }


def _runtime_identity(facts: Mapping[str, Any]) -> str:
    return _fingerprint(
        {
            "host": facts["host"],
            "containers": facts["containers"],
            "tool_trees": facts["tool_trees"],
            "dependencies": facts["dependencies"],
            "binary_verification": facts["binary_verification"],
            "probes": facts["probes"],
            "jobs": facts["jobs"],
        }
    )


def collect_facts(campaign_dir: Path) -> dict[str, Any]:
    """只读展开 preflight 全部 Job 并执行离线路径、依赖和运行时探针。"""

    from tools.official_client_capture import codex_upgrade

    campaign_dir = campaign_dir.resolve(strict=True)
    manifest = codex_upgrade.load_campaign_manifest(campaign_dir)
    if manifest.get("campaign_mode") != "preflight_only":
        raise JobRehearsalReceiptError("完整 Job 演练只能消费 preflight_only Campaign")
    machine = platform.machine().lower()
    if platform.system().lower() != "linux" or machine not in {"aarch64", "arm64"}:
        raise JobRehearsalReceiptError("完整 Job 演练只能在 ARM64 Linux 宿主执行")
    inputs = manifest["inputs"]
    scenario_reference = inputs.get("target_discovery_scenarios")
    if not isinstance(scenario_reference, dict):
        raise JobRehearsalReceiptError("preflight 缺少 target 场景清单")
    target_scenario = json.loads(
        (campaign_dir / scenario_reference["path"]).read_text(encoding="utf-8")
    )
    extra_reference = inputs.get("extra_jobs")
    extra_jobs = (
        json.loads((campaign_dir / extra_reference["path"]).read_text(encoding="utf-8"))
        if isinstance(extra_reference, dict)
        else None
    )
    configuration = manifest["configuration"]
    contract = build_execution_contract(
        target_version=manifest["target_version"],
        target_sha256=manifest["target_sha256"],
        target_package_sha256=manifest["official_identity"]["package"]["asset_sha256"],
        target_code_mode_host_sha256=manifest["official_identity"]["package"]["code_mode_host_sha256"],
        suite=manifest["suite"],
        tool_files_sha256=manifest["tool_identity"]["files_sha256"],
        configuration=configuration,
        target_scenario=target_scenario,
        extra_jobs=extra_jobs,
    )
    jobs = [
        *codex_upgrade._campaign_jobs(
            campaign_dir,
            manifest,
            "official",
            use_approved_scenario=False,
        ),
        *codex_upgrade._campaign_jobs(
            campaign_dir,
            manifest,
            "candidate",
            use_approved_scenario=False,
        ),
    ]
    if sorted(job.job_id for job in jobs) != contract["job_ids"]:
        raise JobRehearsalReceiptError("展开 Job 集与目标模板不一致")
    capture_root = Path(str(configuration["capture_root"]))
    managed_root = Path(codex_upgrade.__file__).resolve().parent
    execution_root = capture_root / "tools" / "official_client_capture"
    codex_upgrade._verify_execution_tree(capture_root)
    managed_tree = _tool_tree_summary(managed_root)
    execution_tree = _tool_tree_summary(execution_root)
    container_tree = _container_tool_tree(
        str(configuration["capture_container"]), str(execution_root)
    )
    if not (
        managed_tree["entries"]
        == execution_tree["entries"]
        == container_tree["entries"]
        and managed_tree["files_sha256"] == contract["tool_files_sha256"]
    ):
        raise JobRehearsalReceiptError("受管、执行和 capture-cli 工具树不一致")
    binary_verification = codex_upgrade._verify_official_binaries(manifest)
    job_results = [
        _job_probe(job, str(configuration["capture_container"]))
        for job in sorted(jobs, key=lambda item: (item.phase, item.job_id))
    ]
    facts: dict[str, Any] = {
        "schema_version": FACTS_SCHEMA,
        "observed_at_utc": _utc_now(),
        "preflight_campaign": {
            "path": str(campaign_dir),
            "campaign_id": manifest["campaign_id"],
            "manifest_sha256": _sha256_file(campaign_dir / "campaign.json"),
            "campaign_mode": "preflight_only",
        },
        "execution_contract": contract,
        "execution_contract_sha256": execution_contract_sha256(contract),
        "host": {
            "architecture": EXPECTED_ARCHITECTURE,
            "machine": machine,
        },
        "containers": _container_facts(configuration),
        "tool_trees": {
            "managed_host": managed_tree,
            "execution_host": execution_tree,
            "execution_container": container_tree,
        },
        "dependencies": {
            "host": _host_dependencies(),
            "capture_container": _container_dependencies(
                str(configuration["capture_container"])
            ),
        },
        "binary_verification": binary_verification,
        "probes": {
            "bubblewrap": _bwrap_probe(str(configuration["capture_container"])),
            "zstd": _zstd_probe(
                str(configuration["capture_container"]), str(execution_root)
            ),
        },
        "jobs": job_results,
        "summary": {
            "job_count": len(job_results),
            "passed_job_count": len(job_results),
            "phase_counts": contract["phase_counts"],
            "job_set_sha256": _fingerprint(
                [
                    {
                        "id": item["id"],
                        "phase": item["phase"],
                        "job_contract_sha256": item["job_contract_sha256"],
                    }
                    for item in job_results
                ]
            ),
            "live_requests_sent": False,
            "status": "passed",
        },
        "collector": _producer(),
    }
    facts["runtime_identity_sha256"] = _runtime_identity(facts)
    validate_facts(facts)
    return facts


def _validate_tree(value: Any, label: str) -> dict[str, Any]:
    tree = _expect(
        value,
        {"root", "entry_count", "files_sha256", "entries"},
        label,
    )
    entries = tree.get("entries")
    if (
        not isinstance(tree.get("root"), str)
        or not tree["root"].startswith("/")
        or not isinstance(entries, list)
        or not entries
        or tree.get("entry_count") != len(entries)
        or tree.get("files_sha256") != _fingerprint({"entries": entries})
        or not all(
            isinstance(item, dict)
            and set(item) == {"path", "sha256"}
            and isinstance(item["path"], str)
            and not item["path"].startswith("/")
            and SHA256_RE.fullmatch(str(item["sha256"]))
            for item in entries
        )
    ):
        raise JobRehearsalReceiptError(f"{label}摘要或条目非法")
    return tree


def _validate_dependencies(value: Any, expected: Iterable[str], label: str) -> None:
    if not isinstance(value, list):
        raise JobRehearsalReceiptError(f"{label}必须是数组")
    names: list[str] = []
    for item in value:
        binding = _expect(item, {"name", "path", "sha256", "status"}, label)
        if (
            binding.get("status") != "passed"
            or not isinstance(binding.get("name"), str)
            or not isinstance(binding.get("path"), str)
            or not binding["path"].startswith("/")
            or not SHA256_RE.fullmatch(str(binding.get("sha256", "")))
        ):
            raise JobRehearsalReceiptError(f"{label}存在失败或非法依赖")
        names.append(binding["name"])
    if names != list(expected):
        raise JobRehearsalReceiptError(f"{label}命令集合漂移")


def validate_facts(facts: dict[str, Any]) -> dict[str, Any]:
    """严格校验离线演练事实，并返回收据摘要。"""

    _expect(
        facts,
        {
            "schema_version",
            "observed_at_utc",
            "preflight_campaign",
            "execution_contract",
            "execution_contract_sha256",
            "host",
            "containers",
            "tool_trees",
            "dependencies",
            "binary_verification",
            "probes",
            "jobs",
            "summary",
            "runtime_identity_sha256",
            "collector",
        },
        "facts",
    )
    if facts.get("schema_version") != FACTS_SCHEMA:
        raise JobRehearsalReceiptError("facts.schema_version 不匹配")
    _rfc3339(facts.get("observed_at_utc"), "facts.observed_at_utc")
    campaign = _expect(
        facts.get("preflight_campaign"),
        {"path", "campaign_id", "manifest_sha256", "campaign_mode"},
        "preflight_campaign",
    )
    if (
        not isinstance(campaign.get("path"), str)
        or not campaign["path"].startswith("/")
        or campaign.get("campaign_mode") != "preflight_only"
        or not SAFE_ID_RE.fullmatch(str(campaign.get("campaign_id", "")))
        or not SHA256_RE.fullmatch(str(campaign.get("manifest_sha256", "")))
    ):
        raise JobRehearsalReceiptError("preflight Campaign 绑定非法")
    contract = validate_execution_contract(facts.get("execution_contract"))
    contract_sha = execution_contract_sha256(contract)
    if facts.get("execution_contract_sha256") != contract_sha:
        raise JobRehearsalReceiptError("execution contract 摘要漂移")
    host = _expect(facts.get("host"), {"architecture", "machine"}, "host")
    if host.get("architecture") != EXPECTED_ARCHITECTURE or host.get("machine") not in {
        "aarch64",
        "arm64",
    }:
        raise JobRehearsalReceiptError("演练宿主不是 ARM64 Linux")
    configuration = contract["configuration"]
    expected_containers = sorted(
        {
            str(configuration[field])
            for field in (
                "capture_container",
                "service_container",
                "keeper_container",
                "postgres_container",
                "redis_container",
            )
        }
    )
    containers = facts.get("containers")
    if not isinstance(containers, list):
        raise JobRehearsalReceiptError("containers 必须是数组")
    container_names: list[str] = []
    for item in containers:
        current = _expect(
            item, {"name", "container_id", "image_id", "running"}, "containers"
        )
        if (
            current.get("running") is not True
            or not CONTAINER_ID_RE.fullmatch(str(current.get("container_id", "")))
            or not IMAGE_ID_RE.fullmatch(str(current.get("image_id", "")))
        ):
            raise JobRehearsalReceiptError("容器未运行或身份非法")
        container_names.append(str(current.get("name", "")))
    if container_names != expected_containers:
        raise JobRehearsalReceiptError("容器集合未完整覆盖 Job 依赖")
    trees = _expect(
        facts.get("tool_trees"),
        {"managed_host", "execution_host", "execution_container"},
        "tool_trees",
    )
    tree_values = [
        _validate_tree(trees[name], f"tool_trees.{name}")
        for name in ("managed_host", "execution_host", "execution_container")
    ]
    if (
        not all(tree["entries"] == tree_values[0]["entries"] for tree in tree_values)
        or tree_values[0]["files_sha256"] != contract["tool_files_sha256"]
    ):
        raise JobRehearsalReceiptError("三份工具树或 Campaign 工具摘要不一致")
    dependencies = _expect(
        facts.get("dependencies"), {"host", "capture_container"}, "dependencies"
    )
    _validate_dependencies(
        dependencies["host"], HOST_REQUIRED_COMMANDS, "dependencies.host"
    )
    _validate_dependencies(
        dependencies["capture_container"],
        CAPTURE_CONTAINER_REQUIRED_COMMANDS,
        "dependencies.capture_container",
    )
    binary = facts.get("binary_verification")
    if (
        not isinstance(binary, dict)
        or binary.get("passed") is not True
        or binary.get("expected_version") != contract["target_version"]
        or binary.get("expected_sha256") != contract["target_sha256"]
        or binary.get("runtime_image_reference")
        != configuration["runtime_image"]
        or not IMAGE_ID_RE.fullmatch(str(binary.get("runtime_image_id", "")))
    ):
        raise JobRehearsalReceiptError("Codex 二进制或运行镜像探针非法")
    package = binary.get("package")
    if (
        not isinstance(package, dict)
        or package.get("asset_sha256") != contract["target_package_sha256"]
        or package.get("code_mode_host_sha256")
        != contract["target_code_mode_host_sha256"]
    ):
        raise JobRehearsalReceiptError("Codex package 探针非法")
    identities = binary.get("identities")
    helpers = binary.get("helpers")
    if (
        not isinstance(identities, list)
        or {item.get("label") for item in identities if isinstance(item, dict)}
        != {
            "container:capture_codex_bin",
            "container:relay_codex_bin",
            "host:relay_codex_bin",
        }
        or any(item.get("sha256") != contract["target_sha256"] for item in identities)
        or not isinstance(helpers, list)
        or {item.get("label") for item in helpers if isinstance(item, dict)}
        != {
            "container:capture_code_mode_host_bin",
            "container:relay_code_mode_host_bin",
            "host:relay_code_mode_host_bin",
        }
        or any(
            item.get("sha256") != contract["target_code_mode_host_sha256"]
            for item in helpers
        )
    ):
        raise JobRehearsalReceiptError("Codex 主程序或 code-mode-host 身份未闭合")
    probes = _expect(facts.get("probes"), {"bubblewrap", "zstd"}, "probes")
    bubblewrap = _expect(
        probes.get("bubblewrap"),
        {"status", "version", "network_isolated"},
        "probes.bubblewrap",
    )
    zstd = _expect(
        probes.get("zstd"),
        {"status", "input_sha256", "output_sha256", "output"},
        "probes.zstd",
    )
    if (
        bubblewrap.get("status") != "passed"
        or bubblewrap.get("network_isolated") is not True
        or not isinstance(bubblewrap.get("version"), str)
        or not bubblewrap["version"]
        or zstd.get("status") != "passed"
        or zstd.get("input_sha256") != _sha256_bytes(ZSTD_FRAME)
        or zstd.get("output_sha256") != _sha256_bytes(ZSTD_OUTPUT)
        or zstd.get("output") != ZSTD_OUTPUT.decode("ascii")
    ):
        raise JobRehearsalReceiptError("bubblewrap 或 zstd 离线探针失败")
    jobs = facts.get("jobs")
    if not isinstance(jobs, list) or len(jobs) != contract["job_count"]:
        raise JobRehearsalReceiptError("Job 演练结果数量不完整")
    seen: list[str] = []
    for item in jobs:
        current = _expect(
            item,
            {
                "id",
                "phase",
                "status",
                "job_contract_sha256",
                "step_count",
                "steps",
                "c2pa_identity",
            },
            "jobs",
        )
        job_id = str(current.get("id", ""))
        if (
            current.get("status") != "passed"
            or contract["job_phases"].get(job_id) != current.get("phase")
            or contract["step_counts"].get(job_id) != current.get("step_count")
            or not SHA256_RE.fullmatch(str(current.get("job_contract_sha256", "")))
            or not isinstance(current.get("steps"), list)
            or len(current["steps"]) != current["step_count"]
        ):
            raise JobRehearsalReceiptError(f"Job 演练失败或身份非法：{job_id}")
        for step_index, step in enumerate(current["steps"], 1):
            if (
                not isinstance(step, dict)
                or set(step)
                != {
                    "index",
                    "status",
                    "launcher",
                    "argv_sha256",
                    "environment_sha256",
                    "timeout_seconds",
                    "path_checks",
                    "dependencies",
                }
                or step.get("index") != step_index
                or step.get("status") != "passed"
                or step.get("launcher") not in {"host", "capture_container"}
                or not SHA256_RE.fullmatch(str(step.get("argv_sha256", "")))
                or not SHA256_RE.fullmatch(str(step.get("environment_sha256", "")))
                or not isinstance(step.get("timeout_seconds"), int)
                or step["timeout_seconds"] <= 0
                or not isinstance(step.get("path_checks"), list)
                or not step["path_checks"]
                or not isinstance(step.get("dependencies"), list)
                or not step["dependencies"]
            ):
                raise JobRehearsalReceiptError(f"{job_id} 步骤演练不完整")
        expected_c2pa = contract["c2pa_job_identities"].get(job_id)
        if current.get("c2pa_identity") != expected_c2pa:
            raise JobRehearsalReceiptError(f"{job_id} C2PA 身份不一致")
        seen.append(job_id)
    if sorted(seen) != contract["job_ids"] or len(seen) != len(set(seen)):
        raise JobRehearsalReceiptError("Job 演练结果遗漏或重复")
    summary = _expect(
        facts.get("summary"),
        {
            "job_count",
            "passed_job_count",
            "phase_counts",
            "job_set_sha256",
            "live_requests_sent",
            "status",
        },
        "summary",
    )
    expected_job_set_sha = _fingerprint(
        [
            {
                "id": item["id"],
                "phase": item["phase"],
                "job_contract_sha256": item["job_contract_sha256"],
            }
            for item in jobs
        ]
    )
    if (
        summary.get("status") != "passed"
        or summary.get("live_requests_sent") is not False
        or summary.get("job_count") != contract["job_count"]
        or summary.get("passed_job_count") != contract["job_count"]
        or summary.get("phase_counts") != contract["phase_counts"]
        or summary.get("job_set_sha256") != expected_job_set_sha
    ):
        raise JobRehearsalReceiptError("完整 Job 演练汇总未通过")
    collector = _expect(
        facts.get("collector"),
        {"schema_version", "tool", "tool_sha256", "version"},
        "collector",
    )
    if collector != _producer():
        raise JobRehearsalReceiptError("Job 演练采集器身份漂移")
    runtime_sha = _runtime_identity(facts)
    if facts.get("runtime_identity_sha256") != runtime_sha:
        raise JobRehearsalReceiptError("Job 演练运行时身份摘要漂移")
    return {
        "execution_contract_sha256": contract_sha,
        "runtime_identity_sha256": runtime_sha,
        "job_count": contract["job_count"],
        "job_set_sha256": expected_job_set_sha,
    }


def build_receipt(root: Path, facts_relative: str) -> dict[str, Any]:
    root = _private_root(root)
    facts_path = _relative(root, facts_relative, "facts")
    facts, raw = _load_json(facts_path, "facts")
    validated = validate_facts(facts)
    campaign = facts["preflight_campaign"]
    return {
        "schema_version": RECEIPT_SCHEMA,
        "status": "passed",
        "observed_at_utc": facts["observed_at_utc"],
        "preflight_campaign": campaign,
        "execution_contract": facts["execution_contract"],
        "execution_contract_sha256": validated["execution_contract_sha256"],
        "runtime_identity_sha256": validated["runtime_identity_sha256"],
        "job_count": validated["job_count"],
        "job_set_sha256": validated["job_set_sha256"],
        "facts": {
            "path": facts_relative,
            "sha256": _sha256_bytes(raw),
            "bytes": len(raw),
        },
        "producer": _producer(),
    }


def collect(root: Path, output_relative: str, *, campaign_dir: Path) -> dict[str, Any]:
    root = _private_root(root)
    output = _relative(root, output_relative, "facts output")
    facts = collect_facts(campaign_dir)
    _write_once(output, facts)
    return facts


def finalize(root: Path, facts_relative: str, output_relative: str) -> dict[str, Any]:
    root = _private_root(root)
    output = _relative(root, output_relative, "receipt output")
    receipt = build_receipt(root, facts_relative)
    _write_once(output, receipt)
    return receipt


def replay(root: Path, receipt_relative: str) -> dict[str, Any]:
    root = _private_root(root)
    path = _relative(root, receipt_relative, "receipt")
    receipt, raw = _load_json(path, "receipt")
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        raise JobRehearsalReceiptError("receipt.schema_version 不匹配")
    facts = receipt.get("facts")
    if not isinstance(facts, dict) or not isinstance(facts.get("path"), str):
        raise JobRehearsalReceiptError("receipt.facts 缺失")
    expected = build_receipt(root, facts["path"])
    if _canonical(expected) != raw:
        raise JobRehearsalReceiptError("Job 演练收据重放结果不一致")
    return receipt


def assert_formal_compatible(
    receipt: Mapping[str, Any], expected_contract: Mapping[str, Any]
) -> None:
    """拒绝 Formal 使用不同 Job、工具、容器、二进制或运行镜像。"""

    validate_execution_contract(dict(expected_contract))
    actual = receipt.get("execution_contract")
    if not isinstance(actual, dict):
        raise JobRehearsalReceiptError("Job 演练收据缺少 execution_contract")
    validate_execution_contract(actual)
    if actual != dict(expected_contract):
        raise JobRehearsalReceiptError("Formal 执行合同与 ARM64 完整 Job 演练不一致")
    if (
        receipt.get("status") != "passed"
        or receipt.get("execution_contract_sha256")
        != execution_contract_sha256(dict(expected_contract))
        or receipt.get("job_count") != expected_contract.get("job_count")
    ):
        raise JobRehearsalReceiptError("Formal 所需完整 Job 演练收据未通过")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    collect_parser = commands.add_parser("collect", help="在 ARM64 离线演练全部 Job")
    collect_parser.add_argument("--campaign-dir", type=Path, required=True)
    collect_parser.add_argument("--evidence-root", type=Path, required=True)
    collect_parser.add_argument("--output", required=True)
    finalize_parser = commands.add_parser("finalize", help="封存完整 Job 演练收据")
    finalize_parser.add_argument("--evidence-root", type=Path, required=True)
    finalize_parser.add_argument("--facts", required=True)
    finalize_parser.add_argument("--output", required=True)
    replay_parser = commands.add_parser("replay", help="独立重放完整 Job 演练收据")
    replay_parser.add_argument("--evidence-root", type=Path, required=True)
    replay_parser.add_argument("--receipt", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "collect":
            result = collect(
                arguments.evidence_root,
                arguments.output,
                campaign_dir=arguments.campaign_dir,
            )
        elif arguments.command == "finalize":
            result = finalize(
                arguments.evidence_root, arguments.facts, arguments.output
            )
        else:
            result = replay(arguments.evidence_root, arguments.receipt)
    except (OSError, JobRehearsalReceiptError) as error:
        print(f"Codex 完整 Job 离线演练失败：{error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": result.get("status", "collected"),
                "job_count": (
                    result.get("job_count")
                    or result.get("summary", {}).get("job_count")
                ),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
