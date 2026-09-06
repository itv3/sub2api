"""Codex 场景目标二进制包装器的离线测试。"""

from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.official_client_capture import run_codex_scenario_target


class CodexScenarioTargetTest(unittest.TestCase):
    def _write_executable(self, path: Path, body: str) -> Path:
        path.write_text(body, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def test_接受版本完全一致的规范绝对文件(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = self._write_executable(
                Path(directory).resolve() / "codex",
                "#!/bin/sh\nprintf 'codex-cli 0.151.0\\n'\n",
            )
            self.assertEqual(
                run_codex_scenario_target.validate_codex_binary(
                    binary, "0.151.0"
                ),
                binary,
            )

    def test_拒绝旧版本和符号链接(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            binary = self._write_executable(
                root / "codex",
                "#!/bin/sh\nprintf 'codex-cli 0.149.1\\n'\n",
            )
            with self.assertRaisesRegex(RuntimeError, "版本不一致"):
                run_codex_scenario_target.validate_codex_binary(
                    binary, "0.151.0"
                )
            symlink = root / "codex-capture"
            symlink.symlink_to(binary)
            with self.assertRaisesRegex(RuntimeError, "非符号链接"):
                run_codex_scenario_target.validate_codex_binary(
                    symlink, "0.151.0"
                )

    def test_main_把冻结目标路径注入旧场景驱动(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            binary = self._write_executable(
                root / "codex",
                "#!/bin/sh\nprintf 'codex-cli 0.151.0\\n'\n",
            )
            delegate = root / "run_codex_scenario.py"
            delegate.write_text(
                "CODEX = 'codex'\n"
                "def main():\n"
                f"    return 0 if CODEX == {str(binary)!r} else 9\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(
                    run_codex_scenario_target, "DELEGATE_PATH", delegate
                ),
                mock.patch.dict(
                    os.environ,
                    {
                        "CODEX_VERSION": "0.151.0",
                        "CODEX_BIN": str(binary),
                    },
                    clear=False,
                ),
            ):
                self.assertEqual(run_codex_scenario_target.main(), 0)

    def test_0151_五个客户端_job_显式冻结目标路径(self) -> None:
        root = Path(__file__).parents[1]
        scenario = json.loads(
            (root / "codex_upgrade_scenarios_0_151_0.json").read_text(
                encoding="utf-8"
            )
        )
        expected = {
            "candidate-core-direct",
            "candidate-ws-handshake-repeat",
            "candidate-core-mitm",
            "candidate-compact-direct",
            "candidate-compact-mitm",
        }
        jobs = {
            job["id"]: job
            for job in scenario["capture_jobs"]
            if job["id"] in expected
        }
        self.assertEqual(set(jobs), expected)
        for job_id, job in jobs.items():
            with self.subTest(job=job_id):
                self.assertEqual(len(job["steps"]), 1)
                self.assertEqual(
                    job["steps"][0]["environment"]["CODEX_BIN"],
                    "{capture_codex_bin}",
                )


if __name__ == "__main__":
    unittest.main()
