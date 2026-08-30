"""Codex 升级控制收据测试使用的纯合成事实构造器。"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from tools.official_client_capture import codex_upgrade_arm64_environment_receipt as arm
from tools.official_client_capture import codex_upgrade_timing_ledger as timing


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def create_arm_receipt(
    root: Path,
    *,
    phase: str,
    subject_id: str,
    prefix: str,
    continuity_seed: str = "a",
) -> Path:
    """写入不联网的合成 ARM64 facts，并经正式 finalizer 封存。"""

    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    containers = []
    for index, name in enumerate(sorted(arm.CONTAINER_CONTRACTS), 1):
        expected = arm.CONTAINER_CONTRACTS[name]
        selected = {
            "name": expected["network"],
            "network_id": continuity_seed * 64,
            "endpoint_id": str(index) * 64,
            "ipv4_address": expected["ipv4_address"],
            "gateway": expected["gateway"],
        }
        containers.append(
            {
                "name": name,
                "container_id": str(index) * 64,
                "image_id": f"sha256:{str(index + 2) * 64}",
                "selected_network": selected,
                "network_bindings": [selected],
                "default_route": {
                    "interface": "eth0",
                    "gateway": expected["gateway"],
                },
                "public_egress": {
                    "url": arm.PUBLIC_EGRESS_URL,
                    "ip_address": arm.EXPECTED_PUBLIC_EGRESS,
                    "response_sha256": "e" * 64,
                },
                "raw_sha256": {
                    "docker_inspect": "f" * 64,
                    "proc_net_route": "0" * 64,
                },
            }
        )
    tool = Path(arm.__file__).resolve()
    facts = {
        "schema_version": arm.FACTS_SCHEMA,
        "phase": phase,
        "subject_id": subject_id,
        "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "contract_sha256": arm.contract_sha256(),
        "host": {"hostname": "arm64-test", "architecture": "linux/arm64"},
        "root_filesystem": {
            "mountpoint": "/",
            "total_bytes": 100 * 1024 * 1024 * 1024,
            "used_bytes": 40 * 1024 * 1024 * 1024,
            "available_bytes": 60 * 1024 * 1024 * 1024,
            "used_percent": 40,
        },
        "containers": containers,
        "collector": {
            "schema_version": arm.PRODUCER_SCHEMA,
            "tool": str(tool),
            "tool_sha256": hashlib.sha256(tool.read_bytes()).hexdigest(),
            "version": arm.PRODUCER_VERSION,
        },
    }
    facts_name = f"{prefix}-facts.json"
    receipt_name = f"{prefix}-receipt.json"
    _write(root / facts_name, facts)
    arm.finalize(root, facts_name, receipt_name)
    return root / receipt_name


def create_timing_checkpoint(
    root: Path,
    *,
    upgrade_id: str,
    baseline_version: str,
    target_version: str,
    campaign_purpose: str,
) -> Path:
    """创建处于 VC-0 active 的合成 UpgradeTimingLedger checkpoint。"""

    root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.parent.chmod(0o700)
    timing.create_ledger(
        root,
        upgrade_id=upgrade_id,
        baseline_version=baseline_version,
        target_version=target_version,
        campaign_purpose=campaign_purpose,
        evidence_decision="recapture",
    )
    timing.checkpoint(root, "receipts/p0.json")
    return root / "receipts" / "p0.json"
