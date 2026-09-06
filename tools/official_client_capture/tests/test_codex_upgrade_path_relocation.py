"""Codex 增量恢复的工作树路径迁移回归测试。"""

from __future__ import annotations

import tempfile
import unittest
from unittest import mock
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

    def test_successor_combines_worktree_and_campaign_relocation(self) -> None:
        """暂存预览可同时投影工具根和后继 Campaign 坐标。"""

        with tempfile.TemporaryDirectory() as temporary:
            historical_root = str(Path(temporary) / "production-worktree")
            current_campaign = "campaign-new"
            predecessor_campaign = "campaign-old"
            job = self._job(
                str(Path(temporary) / current_campaign / "evidence"),
                [
                    "bash",
                    f"{self.repo_root}/tools/official_client_capture/run.sh",
                    f"/capture/{current_campaign}/result.json",
                ],
            )
            current_payload = codex_upgrade._job_execution_payload(job)
            historical_payload = codex_upgrade._relocate_job_execution_payload(
                current_payload,
                self.repo_root,
                historical_root,
            )

            def replace_campaign(value: object) -> object:
                if isinstance(value, str):
                    return value.replace(current_campaign, predecessor_campaign)
                if isinstance(value, list):
                    return [replace_campaign(item) for item in value]
                if isinstance(value, dict):
                    return {
                        key: replace_campaign(item)
                        for key, item in value.items()
                    }
                return value

            frozen = replace_campaign(historical_payload)
            assert isinstance(frozen, dict)
            recorded = codex_upgrade._fingerprint(frozen)
            self.assertTrue(
                codex_upgrade._successor_job_execution_matches(
                    job,
                    recorded,
                    frozen,
                    current_campaign_id=current_campaign,
                    predecessor_campaign_id=predecessor_campaign,
                    current_candidate_id="candidate-a",
                    predecessor_candidate_id="candidate-a",
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

    def test_recovery_scope_accepts_legacy_projection_with_relocated_tree(self) -> None:
        """旧版 Job 投影只要能证明为受管工作树迁移即可承接。"""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            historical_root = str(root / "old-worktree")
            job = self._job(
                str(root / "evidence"),
                [
                    "bash",
                    f"{self.repo_root}/tools/official_client_capture/run.sh",
                ],
            )
            current_payload = codex_upgrade._job_execution_payload(job)
            relocated_payload = codex_upgrade._relocate_job_execution_payload(
                current_payload,
                self.repo_root,
                historical_root,
            )
            # 模拟旧版 _safe_plan：保留执行步骤和证据根，但省略 suites、
            # required 等后来加入的字段；reservation 中的摘要仍是完整摘要。
            frozen_job = {
                "id": job.job_id,
                "phase": job.phase,
                "steps": relocated_payload["steps"],
                "evidence_roots": list(job.evidence_roots),
            }
            manifest = {"jobs": [frozen_job]}
            scope = {
                "planned_job_ids": [job.job_id],
                "completed_job_ids": [],
                "failed_job_ids": [job.job_id],
                "pending_job_ids": [],
                "execute_job_ids": [job.job_id],
            }
            reservation = {
                "planned_jobs": [
                    {
                        "id": job.job_id,
                        "execution_sha256": codex_upgrade._fingerprint(
                            relocated_payload
                        ),
                    }
                ]
            }
            with (
                mock.patch.object(
                    codex_upgrade,
                    "_load_capture_reservation",
                    return_value=reservation,
                ),
                mock.patch.object(
                    codex_upgrade,
                    "load_campaign_manifest",
                    return_value=manifest,
                ),
            ):
                completed, execute = codex_upgrade._validate_recovery_scope_plan(
                    root,
                    phase="official",
                    candidate_id=None,
                    source_root=root / "source",
                    scope=scope,
                    planned_jobs=(item for item in [job]),
                )
            self.assertEqual(completed, set())
            self.assertEqual(execute, {job.job_id})

    def test_recovery_scope_rejects_non_path_drift(self) -> None:
        """恢复校验不能把脚本或参数变化伪装成工作树迁移。"""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            historical_root = str(root / "old-worktree")
            original = self._job(
                str(root / "evidence"),
                [
                    "bash",
                    f"{self.repo_root}/tools/official_client_capture/run.sh",
                    "--model",
                    "gpt-5.5",
                ],
            )
            historical_payload = codex_upgrade._relocate_job_execution_payload(
                codex_upgrade._job_execution_payload(original),
                self.repo_root,
                historical_root,
            )
            frozen_job = {
                "id": original.job_id,
                "phase": original.phase,
                "steps": historical_payload["steps"],
                "evidence_roots": list(original.evidence_roots),
            }
            changed = self._job(
                str(root / "evidence"),
                [
                    "bash",
                    f"{self.repo_root}/tools/official_client_capture/run.sh",
                    "--model",
                    "gpt-5.6-terra",
                ],
            )
            scope = {
                "planned_job_ids": [changed.job_id],
                "completed_job_ids": [],
                "failed_job_ids": [changed.job_id],
                "pending_job_ids": [],
                "execute_job_ids": [changed.job_id],
            }
            reservation = {
                "planned_jobs": [
                    {
                        "id": changed.job_id,
                        "execution_sha256": codex_upgrade._fingerprint(
                            historical_payload
                        ),
                    }
                ]
            }
            with (
                mock.patch.object(
                    codex_upgrade,
                    "_load_capture_reservation",
                    return_value=reservation,
                ),
                mock.patch.object(
                    codex_upgrade,
                    "load_campaign_manifest",
                    return_value={"jobs": [frozen_job]},
                ),
            ):
                with self.assertRaisesRegex(
                    codex_upgrade.ConfigurationError,
                    "仅允许受管工作树路径迁移",
                ):
                    codex_upgrade._validate_recovery_scope_plan(
                        root,
                        phase="official",
                        candidate_id=None,
                        source_root=root / "source",
                        scope=scope,
                        planned_jobs=[changed],
                    )
if __name__ == "__main__":
    unittest.main()
