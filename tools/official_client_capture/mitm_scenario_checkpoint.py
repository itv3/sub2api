#!/usr/bin/env python3
"""管理 Candidate MITM 单场景的只写一次 checkpoint。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "sub2api-openai-mitm-scenario/v2"
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


class CheckpointError(RuntimeError):
    """表示 checkpoint 身份、内容或恢复边界不合法。"""


def _require_safe_id(value: str, label: str) -> str:
    if not SAFE_ID_RE.fullmatch(value):
        raise CheckpointError(f"{label} 不是安全运行坐标。")
    return value


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _jsonl_record_count(path: Path) -> int:
    with path.open("rb") as stream:
        return sum(1 for line in stream if line.strip())


def _secure_write_once(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CheckpointError(f"checkpoint 不可读：{path}: {error}") from error
    if not isinstance(payload, dict):
        raise CheckpointError(f"checkpoint 不是 JSON 对象：{path}")
    return payload


def _jsonl_inventory(run_root: Path) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    for path in sorted((run_root / "mitm").glob("*/*.jsonl")):
        if path.is_symlink() or not path.is_file():
            raise CheckpointError(f"MITM JSONL 不是可信普通文件：{path}")
        inventory.append(
            {
                "path": str(path.relative_to(run_root)),
                "records": _jsonl_record_count(path),
                "bytes": path.stat().st_size,
                "sha256": _file_sha256(path),
            }
        )
    return inventory


def seal_run(
    run_root: Path,
    *,
    run_id: str,
    subject: str,
    scenario: str,
    model: str,
    driver_return_code: int,
) -> dict[str, Any]:
    """封存一个场景；即使失败也保留摘要和已有 JSONL。"""

    for value, label in ((run_id, "run_id"), (subject, "subject"), (scenario, "scenario")):
        _require_safe_id(value, label)
    if run_root.is_symlink() or not run_root.is_dir() or run_root.name != run_id:
        raise CheckpointError("run root 必须是与 run_id 同名的可信目录。")
    if driver_return_code < 0 or driver_return_code > 255:
        raise CheckpointError("driver_return_code 超出合法范围。")

    scenario_summary_path = run_root / "result" / scenario / "summary.json"
    scenario_valid = False
    scenario_error = "summary-missing"
    if scenario_summary_path.is_file() and not scenario_summary_path.is_symlink():
        try:
            scenario_summary = _load_json(scenario_summary_path)
            scenario_valid = scenario_summary.get("valid") is True
            scenario_error = str(scenario_summary.get("error_type") or "")[:128]
        except CheckpointError:
            scenario_error = "summary-invalid"

    jsonl = _jsonl_inventory(run_root)
    complete = (
        driver_return_code == 0
        and scenario_valid
        and any(item["records"] > 0 for item in jsonl)
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "status": "complete" if complete else "failed",
        "subject": subject,
        "scenario": scenario,
        "model": model,
        "driver_return_code": driver_return_code,
        "scenario_result": {
            "valid": scenario_valid,
            "error_type": scenario_error,
        },
        "jsonl": jsonl,
        "pcap_expected": False,
        "pcap_scanned_bytes": 0,
    }
    _secure_write_once(run_root / "run-summary.json", payload)
    return payload


def _validate_complete_run(
    run_root: Path,
    *,
    run_id: str,
    subject: str,
    scenario: str,
    model: str,
) -> bool:
    summary_path = run_root / "run-summary.json"
    if summary_path.is_symlink() or not summary_path.is_file():
        return False
    try:
        payload = _load_json(summary_path)
    except CheckpointError:
        return False
    if any(
        (
            payload.get("schema_version") != SCHEMA_VERSION,
            payload.get("run_id") != run_id,
            payload.get("status") != "complete",
            payload.get("subject") != subject,
            payload.get("scenario") != scenario,
            payload.get("model") != model,
            payload.get("driver_return_code") != 0,
            payload.get("pcap_expected") is not False,
            payload.get("pcap_scanned_bytes") != 0,
        )
    ):
        return False
    result = payload.get("scenario_result")
    if not isinstance(result, dict) or result.get("valid") is not True:
        return False
    inventory = payload.get("jsonl")
    if not isinstance(inventory, list) or not inventory:
        return False
    positive_records = False
    for item in inventory:
        if not isinstance(item, dict) or set(item) != {"path", "records", "bytes", "sha256"}:
            return False
        relative = Path(str(item.get("path", "")))
        if relative.is_absolute() or ".." in relative.parts or relative.suffix != ".jsonl":
            return False
        path = run_root / relative
        if path.is_symlink() or not path.is_file():
            return False
        records = item.get("records")
        size = item.get("bytes")
        digest = item.get("sha256")
        if (
            not isinstance(records, int)
            or records < 0
            or not isinstance(size, int)
            or size < 0
            or not isinstance(digest, str)
            or not SHA256_RE.fullmatch(digest)
            or path.stat().st_size != size
            or _jsonl_record_count(path) != records
            or _file_sha256(path) != digest
        ):
            return False
        positive_records = positive_records or records > 0
    return positive_records


def inspect_coordinate(
    runs_root: Path,
    *,
    run_id_prefix: str,
    subject: str,
    scenario: str,
    window_id: str,
    model: str,
    attempt_limit: int,
    quarantine_incomplete: bool = False,
) -> dict[str, Any]:
    """廉价检查场景 checkpoint，并给出唯一下一 attempt。"""

    for value, label in (
        (run_id_prefix, "run_id_prefix"),
        (subject, "subject"),
        (scenario, "scenario"),
        (window_id, "window_id"),
    ):
        _require_safe_id(value, label)
    if attempt_limit < 1 or attempt_limit > 9:
        raise CheckpointError("attempt_limit 必须是 1～9。")
    if runs_root.is_symlink():
        raise CheckpointError("runs_root 不得是符号链接。")
    runs_root.mkdir(parents=True, exist_ok=True, mode=0o700)

    stem = f"{run_id_prefix}-{subject}-{scenario}-a"
    suffix = f"-{window_id}"
    pattern = re.compile(
        rf"^{re.escape(stem)}([1-9][0-9]*){re.escape(suffix)}(?:\.failed(?:-incomplete)?)?$"
    )
    attempts: set[int] = set()
    complete: list[str] = []
    quarantined: list[str] = []
    for path in sorted(runs_root.iterdir()):
        match = pattern.fullmatch(path.name)
        if match is None:
            continue
        if path.is_symlink() or not path.is_dir():
            raise CheckpointError(f"MITM 场景坐标不是可信目录：{path}")
        attempt = int(match.group(1))
        attempts.add(attempt)
        expected_run_id = f"{stem}{attempt}{suffix}"
        if path.name != expected_run_id:
            continue
        if _validate_complete_run(
            path,
            run_id=expected_run_id,
            subject=subject,
            scenario=scenario,
            model=model,
        ):
            complete.append(expected_run_id)
            continue
        if not quarantine_incomplete:
            raise CheckpointError(f"发现未封存的 MITM 场景目录：{path}")
        target = path.with_name(f"{path.name}.failed-incomplete")
        if target.exists() or target.is_symlink():
            raise CheckpointError(f"MITM 隔离目标已存在：{target}")
        os.replace(path, target)
        quarantined.append(str(target))

    if len(complete) > 1:
        raise CheckpointError("同一 MITM 场景存在多个成功 checkpoint。")
    next_attempt = max(attempts, default=0) + 1
    if complete:
        disposition = "complete"
        selected_run_id = complete[0]
    else:
        if next_attempt > attempt_limit:
            raise CheckpointError("MITM 场景尝试次数已到上限，必须停线诊断。")
        disposition = "pending"
        selected_run_id = ""
    return {
        "disposition": disposition,
        "run_id": selected_run_id,
        "next_attempt": next_attempt,
        "quarantined": quarantined,
        "pcap_scanned_bytes": 0,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    inspect = subparsers.add_parser("inspect")
    inspect.add_argument("--runs-root", type=Path, required=True)
    inspect.add_argument("--run-id-prefix", required=True)
    inspect.add_argument("--subject", required=True)
    inspect.add_argument("--scenario", required=True)
    inspect.add_argument("--window-id", required=True)
    inspect.add_argument("--model", required=True)
    inspect.add_argument("--attempt-limit", type=int, default=2)
    inspect.add_argument("--quarantine-incomplete", action="store_true")
    inspect.add_argument("--tsv", action="store_true")

    seal = subparsers.add_parser("seal")
    seal.add_argument("--run-root", type=Path, required=True)
    seal.add_argument("--run-id", required=True)
    seal.add_argument("--subject", required=True)
    seal.add_argument("--scenario", required=True)
    seal.add_argument("--model", required=True)
    seal.add_argument("--driver-return-code", type=int, required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        if arguments.command == "inspect":
            payload = inspect_coordinate(
                arguments.runs_root,
                run_id_prefix=arguments.run_id_prefix,
                subject=arguments.subject,
                scenario=arguments.scenario,
                window_id=arguments.window_id,
                model=arguments.model,
                attempt_limit=arguments.attempt_limit,
                quarantine_incomplete=arguments.quarantine_incomplete,
            )
            if arguments.tsv:
                print(
                    "\t".join(
                        (
                            payload["disposition"],
                            payload["run_id"] or "-",
                            str(payload["next_attempt"]),
                            str(len(payload["quarantined"])),
                        )
                    )
                )
            else:
                print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
            return 0
        payload = seal_run(
            arguments.run_root,
            run_id=arguments.run_id,
            subject=arguments.subject,
            scenario=arguments.scenario,
            model=arguments.model,
            driver_return_code=arguments.driver_return_code,
        )
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0 if payload["status"] == "complete" else 1
    except CheckpointError as error:
        print(str(error), file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
