#!/usr/bin/env python3
"""在场景计时前用最小 app-server 初始化独占 CODEX_HOME。"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import time
from pathlib import Path

from run_codex_compact_scenario import AppServerClient, protocol_requests, secure_write
from run_codex_scenario_target import validate_codex_binary


def build_command(codex_bin: str) -> list[str]:
    """构造不触发真实模型请求的最小严格配置。"""

    values = (
        "check_for_update_on_startup=false",
        "analytics.enabled=false",
        "feedback.enabled=false",
        'otel.exporter="none"',
        "otel.log_user_prompt=false",
        'approval_policy="never"',
        'sandbox_mode="read-only"',
        'shell_environment_policy.inherit="none"',
        "features.plugins=false",
        "features.apps=false",
        'model_provider="capture_prewarm"',
        'model_providers.capture_prewarm.name="Capture Prewarm"',
        'model_providers.capture_prewarm.base_url="http://127.0.0.1:9/v1"',
        'model_providers.capture_prewarm.env_key="CAPTURE_PREWARM_UNUSED"',
        'model_providers.capture_prewarm.wire_api="responses"',
        "model_providers.capture_prewarm.requires_openai_auth=false",
        "model_providers.capture_prewarm.supports_websockets=false",
    )
    command = [codex_bin, "app-server", "--strict-config", "--stdio"]
    for value in values:
        command.extend(("-c", value))
    return command


def prewarm(codex_bin: Path, codex_version: str, timeout: int) -> dict[str, object]:
    """只完成 initialize/initialized，并返回无秘密收据。"""

    validate_codex_binary(codex_bin, codex_version)
    started_wall = dt.datetime.now(dt.timezone.utc)
    started = time.monotonic()
    environment = dict(os.environ)
    environment["CAPTURE_PREWARM_UNUSED"] = "unused"
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        environment.pop(name, None)
    client = AppServerClient(build_command(str(codex_bin)), environment)
    try:
        deadline = time.monotonic() + timeout
        requests = protocol_requests("gpt-5.6-luna")
        client.send(requests["initialize"])
        client.wait_response(1, deadline)
        client.send(requests["initialized"])
    finally:
        client.close()
    ended = dt.datetime.now(dt.timezone.utc)
    return {
        "schema_version": "codex-home-prewarm/v1",
        "status": "passed",
        "codex_version": codex_version,
        "started_at_utc": started_wall.isoformat(),
        "ended_at_utc": ended.isoformat(),
        "duration_seconds": round(time.monotonic() - started, 3),
        "live_request_count": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex-bin", type=Path, required=True)
    parser.add_argument("--codex-version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=30)
    arguments = parser.parse_args()
    if not arguments.output.is_absolute() or arguments.output.is_symlink():
        raise SystemExit("预热收据必须使用非符号链接绝对路径。")
    if arguments.timeout < 5 or arguments.timeout > 60:
        raise SystemExit("预热 timeout 必须是 5～60 秒。")
    receipt = prewarm(arguments.codex_bin, arguments.codex_version, arguments.timeout)
    secure_write(
        arguments.output,
        json.dumps(receipt, ensure_ascii=False, sort_keys=True) + "\n",
    )
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
