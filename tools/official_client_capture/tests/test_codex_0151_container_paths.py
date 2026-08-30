"""锁定 Codex 0.151 在 capture-cli 内只调用受管执行副本。"""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from typing import Any


TOOL_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = TOOL_ROOT / "codex_upgrade_scenarios_0_151_0.json"
MANAGED_ROOT_ASSIGNMENT = (
    "capture_tool_root=${CAPTURE_TOOL_ROOT:-$capture_root/tools/official_client_capture}"
)
WRAPPER_PATHS = (
    "run_h1_wire_probe.sh",
    "run_images_wire_probe.sh",
    "run_official_codex_compact_capture.sh",
    "run_official_http_fallback_baseline.sh",
    "run_official_relay_scenario.sh",
    "run_sub2api_direct_matrix.sh",
    "run_sub2api_openai_mitm_matrix.sh",
)


def _capture_cli_repo_root_violations(payload: dict[str, Any]) -> list[str]:
    """列出 docker exec capture-cli 中泄漏的宿主机工作树占位符。"""

    violations: list[str] = []
    for job in payload.get("capture_jobs", []):
        for index, step in enumerate(job.get("steps", []), 1):
            argv = step.get("argv", [])
            if argv[:3] != ["docker", "exec", "{capture_container}"]:
                continue
            if any("{repo_root}" in str(argument) for argument in argv[3:]):
                violations.append(f"{job.get('id')}:{index}")
    return violations


def _wrapper_managed_root_violations(sources: dict[str, str]) -> list[str]:
    """列出仍按宿主脚本目录推导容器执行根的 wrapper。"""

    return sorted(
        path
        for path, source in sources.items()
        if MANAGED_ROOT_ASSIGNMENT not in source
    )


class Codex0151ContainerPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.wrapper_sources = {
            path: (TOOL_ROOT / path).read_text(encoding="utf-8")
            for path in WRAPPER_PATHS
        }

    def test_capture_cli_uses_managed_execution_copy(self) -> None:
        self.assertEqual(_capture_cli_repo_root_violations(self.payload), [])
        jobs = {job["id"]: job for job in self.payload["capture_jobs"]}
        for job_id in ("official-core", "official-ws-handshake-repeat"):
            self.assertEqual(
                jobs[job_id]["steps"][0]["argv"][4],
                "{capture_root}/tools/official_client_capture/capture.py",
            )

    def test_host_repo_path_mutation_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.payload)
        job = next(
            item
            for item in mutated["capture_jobs"]
            if item["id"] == "official-core"
        )
        job["steps"][0]["argv"][4] = (
            "{repo_root}/tools/official_client_capture/capture.py"
        )
        self.assertEqual(
            _capture_cli_repo_root_violations(mutated),
            ["official-core:1"],
        )

    def test_host_wrappers_default_to_managed_execution_root(self) -> None:
        self.assertEqual(
            _wrapper_managed_root_violations(self.wrapper_sources),
            [],
        )

    def test_wrapper_script_directory_mutation_fails_closed(self) -> None:
        mutated = dict(self.wrapper_sources)
        path = "run_official_codex_compact_capture.sh"
        mutated[path] = mutated[path].replace(
            MANAGED_ROOT_ASSIGNMENT,
            "capture_tool_root=${CAPTURE_TOOL_ROOT:-$(dirname -- \"${BASH_SOURCE[0]}\")}",
        )
        self.assertEqual(_wrapper_managed_root_violations(mutated), [path])


if __name__ == "__main__":
    unittest.main()
