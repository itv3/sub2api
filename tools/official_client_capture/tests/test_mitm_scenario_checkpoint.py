"""Candidate MITM 单场景 checkpoint 的离线回归测试。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.official_client_capture import mitm_scenario_checkpoint as checkpoint


class MitmScenarioCheckpointTest(unittest.TestCase):
    def _run_root(self, root: Path, attempt: int = 1) -> Path:
        path = root / f"campaign-codex-http-s1-a{attempt}-run"
        path.mkdir(parents=True)
        return path

    def _write_success_facts(self, run_root: Path) -> None:
        result = run_root / "result" / "s1"
        result.mkdir(parents=True)
        (result / "summary.json").write_text(
            json.dumps({"valid": True}) + "\n", encoding="utf-8"
        )
        mitm = run_root / "mitm" / "codex-http"
        mitm.mkdir(parents=True)
        (mitm / "requests.jsonl").write_text(
            '{"method":"POST"}\n', encoding="utf-8"
        )

    def test_成功坐标封存后只读复用(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_root = self._run_root(root)
            self._write_success_facts(run_root)
            payload = checkpoint.seal_run(
                run_root,
                run_id=run_root.name,
                subject="codex-http",
                scenario="s1",
                model="gpt-test",
                driver_return_code=0,
            )
            self.assertEqual(payload["status"], "complete")
            self.assertFalse(payload["pcap_expected"])
            self.assertEqual(payload["pcap_scanned_bytes"], 0)
            inspected = checkpoint.inspect_coordinate(
                root,
                run_id_prefix="campaign",
                subject="codex-http",
                scenario="s1",
                window_id="run",
                model="gpt-test",
                attempt_limit=2,
            )
            self.assertEqual(inspected["disposition"], "complete")
            self.assertEqual(inspected["run_id"], run_root.name)

    def test_失败坐标保留后只计划下一次(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_root = self._run_root(root)
            payload = checkpoint.seal_run(
                run_root,
                run_id=run_root.name,
                subject="codex-http",
                scenario="s1",
                model="gpt-test",
                driver_return_code=1,
            )
            self.assertEqual(payload["status"], "failed")
            failed = run_root.with_name(f"{run_root.name}.failed")
            run_root.rename(failed)
            inspected = checkpoint.inspect_coordinate(
                root,
                run_id_prefix="campaign",
                subject="codex-http",
                scenario="s1",
                window_id="run",
                model="gpt-test",
                attempt_limit=2,
            )
            self.assertEqual(inspected["disposition"], "pending")
            self.assertEqual(inspected["next_attempt"], 2)
            self.assertEqual(inspected["pcap_scanned_bytes"], 0)

    def test_强停遗留目录先隔离再恢复(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_root = self._run_root(root)
            with self.assertRaisesRegex(checkpoint.CheckpointError, "未封存"):
                checkpoint.inspect_coordinate(
                    root,
                    run_id_prefix="campaign",
                    subject="codex-http",
                    scenario="s1",
                    window_id="run",
                    model="gpt-test",
                    attempt_limit=2,
                )
            inspected = checkpoint.inspect_coordinate(
                root,
                run_id_prefix="campaign",
                subject="codex-http",
                scenario="s1",
                window_id="run",
                model="gpt-test",
                attempt_limit=2,
                quarantine_incomplete=True,
            )
            self.assertEqual(inspected["next_attempt"], 2)
            self.assertFalse(run_root.exists())
            self.assertTrue(Path(inspected["quarantined"][0]).is_dir())

    def test_达到尝试上限后失败关闭(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for attempt in (1, 2):
                run_root = self._run_root(root, attempt)
                run_root.rename(run_root.with_name(f"{run_root.name}.failed"))
            with self.assertRaisesRegex(checkpoint.CheckpointError, "次数已到上限"):
                checkpoint.inspect_coordinate(
                    root,
                    run_id_prefix="campaign",
                    subject="codex-http",
                    scenario="s1",
                    window_id="run",
                    model="gpt-test",
                    attempt_limit=2,
                )


if __name__ == "__main__":
    unittest.main()
