"""Codex 增量恢复的工作树路径迁移回归测试。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.official_client_capture import codex_upgrade


class JobPathRelocationTest(unittest.TestCase):
    """只允许受管工具坐标变化，拒绝其它 Job 合同漂移。"""

    def setUp(self) -> None:
        self.repo_root = str(Path(codex_upgrade.__file__).resolve().parents[2])

    def _job(self, evidence_root: str, argv: list[str]) -> codex_upgrade.Job:
        return codex_upgrade.Job(
            job_id="official-relocation-test",
            phase="official",
            suites=("full",),
            description="路径迁移测试",
            steps=(
                {
                    "argv": argv,
                    "environment": {
                        "TOOL_ROOT": f"{self.repo_root}/tools/official_client_capture",
                    },
                    "timeout": 60,
                },
            ),
            evidence_roots=(evidence_root,),
            covers=(),
            required=True,
        )

    def _frozen_and_hash(
        self,
        job: codex_upgrade.Job,
        historical_root: str,
    ) -> tuple[dict[str, object], str]:
        current_payload = codex_upgrade._job_execution_payload(job)
        historical_payload = codex_upgrade._relocate_job_execution_payload(
            current_payload,
            self.repo_root,
            historical_root,
        )
        frozen = {
            "id": job.job_id,
            "phase": job.phase,
            "steps": historical_payload["steps"],
            "evidence_roots": list(job.evidence_roots),
        }
        return frozen, codex_upgrade._fingerprint(historical_payload)

    def test_old_worktree_path_is_reusable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            historical_root = str(Path(temporary) / "old-worktree")
            evidence_root = str(Path(temporary) / "evidence")
            job = self._job(
                evidence_root,
                [
                    "bash",
                    f"{self.repo_root}/tools/official_client_capture/run.sh",
                ],
            )
            frozen, recorded = self._frozen_and_hash(job, historical_root)
            self.assertTrue(
                codex_upgrade._relocated_job_execution_matches(
                    job,
                    recorded,
                    frozen,
                )
            )

    def test_non_path_job_change_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            historical_root = str(Path(temporary) / "old-worktree")
            evidence_root = str(Path(temporary) / "evidence")
            original = self._job(
                evidence_root,
                [
                    "bash",
                    f"{self.repo_root}/tools/official_client_capture/run.sh",
                    "--model",
                    "gpt-5.5",
                ],
            )
            frozen, recorded = self._frozen_and_hash(original, historical_root)
            changed = self._job(
                evidence_root,
                [
                    "bash",
                    f"{self.repo_root}/tools/official_client_capture/run.sh",
                    "--model",
                    "gpt-5.6-terra",
                ],
            )
            self.assertFalse(
                codex_upgrade._relocated_job_execution_matches(
                    changed,
                    recorded,
                    frozen,
                )
            )

    def test_wham_self_mount_path_is_reusable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            historical_root = str(Path(temporary) / "old-worktree")
            evidence_root = str(Path(temporary) / "evidence")
            job = self._job(
                evidence_root,
                [
                    "bash",
                    "-c",
                    (
                        "docker run --rm "
                        f"-v {self.repo_root}:{self.repo_root}:ro "
                        f"python3 {self.repo_root}/tools/official_client_capture/drive.py"
                    ),
                ],
            )
            frozen, recorded = self._frozen_and_hash(job, historical_root)
            self.assertTrue(
                codex_upgrade._relocated_job_execution_matches(
                    job,
                    recorded,
                    frozen,
                )
            )

    def test_tokenized_volume_self_mount_is_relocated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            historical_root = str(Path(temporary) / "old-worktree")
            evidence_root = str(Path(temporary) / "evidence")
            job = self._job(
                evidence_root,
                [
                    "docker",
                    "run",
                    "--volume",
                    f"{self.repo_root}:{self.repo_root}:ro",
                    f"{self.repo_root}/tools/official_client_capture/drive.py",
                ],
            )
            frozen, recorded = self._frozen_and_hash(job, historical_root)
            self.assertTrue(
                codex_upgrade._relocated_job_execution_matches(
                    job,
                    recorded,
                    frozen,
                )
            )

    def test_prior_results_rebase_relocated_execution_identity(self) -> None:
        """接线测试：承接结果必须写入当前 execution_sha256。"""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            historical_root = str(root / "old-worktree")
            evidence_root = str(root / "evidence")
            current_job = self._job(
                evidence_root,
                [
                    "bash",
                    f"{self.repo_root}/tools/official_client_capture/run.sh",
                ],
            )
            frozen_job, historical_execution = self._frozen_and_hash(
                current_job,
                historical_root,
            )
            tool_identity = codex_upgrade._tool_identity(include_git=False)
            identity = {"version": "0.151.0"}
            historical_steps = tuple(
                {
                    **step,
                    "argv": [
                        value.replace(self.repo_root, historical_root)
                        if isinstance(value, str)
                        else value
                        for value in step["argv"]
                    ],
                }
                for step in current_job.steps
            )
            historical_job = codex_upgrade.Job(
                **{
                    **current_job.__dict__,
                    "steps": historical_steps,
                }
            )
            metadata = codex_upgrade._job_incremental_metadata(
                historical_job,
                identity=identity,
                tool_identity=tool_identity,
            )
            result = {
                "id": current_job.job_id,
                "phase": current_job.phase,
                "status": "complete",
                "execution_sha256": historical_execution,
                **metadata,
            }
            payload = {
                "status": "failed",
                "identity": identity,
                "results": [result],
            }
            manifest = {
                "campaign_id": "relocation-test",
                "tool_identity": tool_identity,
                "jobs": [frozen_job],
            }
            attempt_root = root / "official" / "attempts" / "A1"
            attempt_root.mkdir(parents=True)
            receipt = attempt_root / "attempt.json"
            receipt.write_text("{}\n", encoding="utf-8")
            with (
                mock.patch.object(
                    codex_upgrade,
                    "load_campaign_manifest",
                    return_value=manifest,
                ),
                mock.patch.object(
                    codex_upgrade,
                    "_ordered_capture_attempts",
                    return_value=[(attempt_root, {})],
                ),
                mock.patch.object(
                    codex_upgrade,
                    "_load_capture_attempt",
                    return_value=(attempt_root, payload),
                ),
            ):
                reused = codex_upgrade._prior_complete_results(
                    root,
                    Path("official"),
                    [current_job],
                    phase="official",
                    candidate_id=None,
                    identity=identity,
                    tool_identity=tool_identity,
                )
            self.assertEqual(len(reused), 1)
            self.assertEqual(
                reused[0]["execution_sha256"],
                codex_upgrade._job_execution_sha256(current_job),
            )
            self.assertEqual(reused[0]["disposition"], "reused")
            self.assertEqual(reused[0]["carried_from_attempt"], "A1")


if __name__ == "__main__":
    unittest.main()
