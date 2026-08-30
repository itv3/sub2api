"""锁定 Codex 0.151 在 capture-cli 内只调用受管执行副本。"""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from typing import Any


MANIFEST = (
    Path(__file__).resolve().parents[1]
    / "codex_upgrade_scenarios_0_151_0.json"
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


class Codex0151ContainerPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = json.loads(MANIFEST.read_text(encoding="utf-8"))

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


if __name__ == "__main__":
    unittest.main()
