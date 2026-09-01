"""Codex 升级 attempt watchdog 与 Job checkpoint 的边界测试。"""

from __future__ import annotations

import tempfile
import unittest
import json
import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from tools.official_client_capture import codex_upgrade
from tools.official_client_capture import incremental_recovery


class WatchdogTests(unittest.TestCase):
    def test_watchdog_only_files_are_low_risk_evaluator_components(self) -> None:
        for path in (
            "codex_upgrade_arm64_environment_receipt.py",
            "codex_upgrade_environment_probe.py",
            "codex_upgrade_timing_ledger.py",
        ):
            self.assertEqual(codex_upgrade._tool_component_for_path(path), "evaluator")

    def test_legacy_shared_watchdog_classification_does_not_invalidate_jobs(self) -> None:
        current = codex_upgrade._tool_identity(include_git=False)
        legacy = copy.deepcopy(current)
        # 0.149.1 Campaign 将这三个接线文件记在 shared；模拟旧组件摘要，
        # 内容保持不变，比较器应把它们规范化到 evaluator 后判定无漂移。
        legacy.pop("component_identity_sha256", None)
        for path in codex_upgrade._WATCHDOG_ONLY_TOOL_FILES:
            moved = False
            for component, value in legacy["components"].items():
                for index, entry in enumerate(value["entries"]):
                    if entry["path"] == path:
                        legacy["components"]["shared"]["entries"].append(
                            value["entries"].pop(index)
                        )
                        moved = True
                        break
                if moved:
                    break
            self.assertTrue(moved, path)
        for value in legacy["components"].values():
            value["entries"].sort(key=lambda item: item["path"])
            value["entry_count"] = len(value["entries"])
            value["sha256"] = incremental_recovery.digest(
                {"entries": value["entries"]}
            )
        self.assertEqual(
            codex_upgrade._tool_component_drift(legacy, current)["changed_components"],
            [],
        )
        self.assertEqual(
            codex_upgrade._tool_identity_side_digest(legacy, "production"),
            codex_upgrade._tool_identity_side_digest(current, "production"),
        )

    def test_incremental_noop_isolated_from_attempts_and_validated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            campaign = root / "campaign"
            campaign.mkdir(mode=0o700)
            campaign_manifest = campaign / "campaign.json"
            campaign_manifest.write_text("{}\n", encoding="utf-8")
            campaign_manifest.chmod(0o600)
            source = campaign / "official" / "attempts" / "A1" / "attempt.json"
            source.parent.mkdir(parents=True, mode=0o700)
            source.write_text('{"status":"failed"}\n', encoding="utf-8")
            source.chmod(0o600)
            source_binding = {
                "path": source.relative_to(campaign).as_posix(),
                "sha256": codex_upgrade.file_sha256(source),
                "bytes": source.stat().st_size,
            }
            manifest = {"campaign_id": "camp-1"}
            result = codex_upgrade._write_incremental_noop_receipt(
                campaign,
                manifest,
                phase="official",
                candidate_id=None,
                identity={"cli_version": "0.151.0"},
                planned_job_ids=["job-1"],
                reused_results=[{"id": "job-1", "source_receipt": source_binding}],
                changed_components=["evaluator"],
                tool_identity={"components": {}},
            )
            self.assertEqual(result["status"], "incremental-noop")
            noop_path = Path(result["noop_receipt"]["path"])
            self.assertTrue(noop_path.is_file())
            self.assertIn("incremental-noop", noop_path.parts)
            self.assertNotIn("attempts", noop_path.parts)
            payload = json.loads(noop_path.read_text(encoding="utf-8"))
            codex_upgrade._validate_incremental_noop_receipt(
                campaign, payload, planned_job_ids=["job-1"]
            )
            self.assertEqual(payload["execute_job_ids"], [])
            self.assertEqual(payload["failed_job_ids"], [])
            self.assertEqual(payload["scanned_bytes"], 0)
            self.assertEqual(payload["live_request_count"], 0)

    def test_capture_noop_is_success_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(
                codex_upgrade,
                "_run_capture_attempt",
                return_value={"status": "incremental-noop"},
            ):
                code = codex_upgrade.main(
                    [
                        "capture-official",
                        "run",
                        "--campaign-dir",
                        str(Path(directory) / "campaign"),
                    ]
                )
            self.assertEqual(code, 0)

    def _valid_payload(self, root: Path) -> tuple[Path, dict[str, object], set[str]]:
        campaign = root / "campaign"
        campaign.mkdir(mode=0o700)
        attempt = campaign / "official" / "attempts" / "A1"
        attempt.mkdir(parents=True, mode=0o700)
        started = (
            datetime.now(timezone.utc) - timedelta(seconds=2)
        ).isoformat().replace("+00:00", "Z")
        deadline = incremental_recovery.WallClockDeadline(120)
        deadline.phase = "official"
        deadline.heartbeat_seconds = 30
        deadline.last_completed_job_id = None
        heartbeat = attempt / "watchdog-heartbeat.json"
        codex_upgrade._write_attempt_heartbeat(
            heartbeat,
            deadline,
            operation="attempt:reserved",
            force=True,
            attempt_root=attempt,
        )
        result = {
            "id": "job-1",
            "status": "complete",
            "disposition": "executed",
            "incremental_result_key": "a" * 64,
        }
        store = incremental_recovery.CheckpointStore(attempt / "checkpoints")
        store.append(
            {
                "checkpoint_schema_version": codex_upgrade.JOB_CHECKPOINT_SCHEMA,
                "campaign_id": "camp-id",
                "phase": "official",
                "attempt_id": "A1",
                "run_nonce": "b" * 64,
                "item_id": "job-1",
                "status": "complete",
                "disposition": "executed",
                "result_sha256": incremental_recovery.digest(result),
                "result_key": "a" * 64,
                "result": result,
                "previous_checkpoint_sha256": None,
            }
        )
        completed = codex_upgrade._utc_now()
        payload: dict[str, object] = {
            "campaign_id": "camp-id",
            "phase": "official",
            "attempt_id": "A1",
            "run_nonce": "b" * 64,
            "started_at_utc": started,
            "completed_at_utc": completed,
            "execution_error": None,
            "results": [result],
            "watchdog": {
                "schema_version": codex_upgrade.WATCHDOG_HEARTBEAT_SCHEMA,
                "budget_seconds": 120,
                "heartbeat_seconds": 30,
                "elapsed_seconds": 0,
                "remaining_seconds": 119,
                "heartbeat": {
                    "path": "official/attempts/A1/watchdog-heartbeat.json",
                    "sha256": codex_upgrade.file_sha256(heartbeat),
                    "bytes": heartbeat.stat().st_size,
                },
                "timeout_checkpoint": None,
                "last_completed_job_id": None,
            },
            "job_checkpoint": {
                "schema_version": codex_upgrade.JOB_CHECKPOINT_SCHEMA,
                "campaign_id": "camp-id",
                "phase": "official",
                "attempt_id": "A1",
                "run_nonce": "b" * 64,
                "path": "official/attempts/A1/checkpoints",
                "record_count": 1,
                "last_sequence": 1,
                "last_sha256": store.records()[-1]["checkpoint_sha256"],
            },
        }
        return campaign, payload, {"job-1"}

    def test_valid_bindings_replay_without_reading_other_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign, payload, planned = self._valid_payload(Path(directory))
            attempt = campaign / "official" / "attempts" / "A1"
            codex_upgrade._validate_attempt_watchdog_fields(payload, planned)
            codex_upgrade._validate_attempt_watchdog_bindings(
                campaign, attempt, payload, planned
            )

    def test_file_binding_cannot_cross_to_sibling_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign, payload, _ = self._valid_payload(Path(directory))
            sibling = campaign / "official" / "attempts" / "A2"
            sibling.mkdir(mode=0o700)
            binding = dict(payload["watchdog"]["heartbeat"])
            binding["path"] = "official/attempts/A2/watchdog-heartbeat.json"
            with self.assertRaisesRegex(codex_upgrade.ConfigurationError, "当前 attempt"):
                codex_upgrade._resolve_attempt_binding(
                    campaign,
                    campaign / "official" / "attempts" / "A1",
                    binding,
                    label="watchdog heartbeat",
                    expected_name="watchdog-heartbeat.json",
                )

    def test_checkpoint_identity_and_result_digest_are_checked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign, payload, planned = self._valid_payload(Path(directory))
            attempt = campaign / "official" / "attempts" / "A1"
            checkpoint = attempt / "checkpoints" / "00000001.json"
            original = checkpoint.read_text(encoding="utf-8")
            checkpoint.write_text(original.replace('"attempt_id": "A1"', '"attempt_id": "A2"'), encoding="utf-8")
            checkpoint.chmod(0o600)
            with self.assertRaisesRegex(codex_upgrade.ConfigurationError, "checkpoint"):
                codex_upgrade._validate_attempt_watchdog_bindings(
                    campaign, attempt, payload, planned
                )

    def test_heartbeat_rejects_secret_operation_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            attempt = Path(directory) / "attempt"
            attempt.mkdir(mode=0o700)
            deadline = incremental_recovery.WallClockDeadline(30)
            with self.assertRaises(codex_upgrade.ConfigurationError):
                codex_upgrade._write_attempt_heartbeat(
                    attempt / "watchdog-heartbeat.json",
                    deadline,
                    operation="authorization=do-not-write-this-token",
                    force=True,
                    attempt_root=attempt,
                )
            self.assertFalse((attempt / "watchdog-heartbeat.json").exists())

    def test_wait_process_raises_global_timeout_and_kills_group(self) -> None:
        process = mock.Mock()
        process.pid = 4242
        process.poll.return_value = None
        process.wait.side_effect = __import__("subprocess").TimeoutExpired("x", 0.01)
        deadline = incremental_recovery.WallClockDeadline(0.001)
        with mock.patch.object(codex_upgrade.os, "killpg") as killpg:
            with self.assertRaises(incremental_recovery.WallClockTimeoutError):
                codex_upgrade._wait_process(
                    process,
                    30,
                    deadline=deadline,
                    operation="job:job-1:step-1",
                )
            self.assertTrue(killpg.called)


if __name__ == "__main__":
    unittest.main()
