"""组件级增量恢复内核测试。"""

from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from tools.official_client_capture import incremental_recovery as ir


class IncrementalRecoveryTests(unittest.TestCase):
    def test_component_digest_isolated(self) -> None:
        entries = [
            {"path": "capture.py", "sha256": "a" * 64},
            {"path": "assertion_gate.py", "sha256": "b" * 64},
        ]
        first = ir.build_component_identities(
            entries,
            {"capture.py": "producer", "assertion_gate.py": "evaluator"},
        )
        changed = ir.build_component_identities(
            [
                {"path": "capture.py", "sha256": "c" * 64},
                {"path": "assertion_gate.py", "sha256": "b" * 64},
            ],
            {"capture.py": "producer", "assertion_gate.py": "evaluator"},
        )
        drift = ir.component_drift(first, changed)
        self.assertEqual(drift["changed_components"], ["producer"])
        self.assertEqual(drift["changed_paths"], {"producer": ["capture.py"]})
        self.assertEqual(
            first["components"]["evaluator"]["sha256"],
            changed["components"]["evaluator"]["sha256"],
        )

    def test_selects_failed_and_downstream_only(self) -> None:
        graph = {
            "job-a": (),
            "job-b": (),
            "gate-a": ("job-a",),
            "gate-b": ("job-b",),
            "final": ("gate-a", "gate-b"),
        }
        components = {
            "job-a": ("producer-a",),
            "job-b": ("producer-b",),
            "gate-a": ("evaluator",),
            "gate-b": ("evaluator",),
            "final": ("shared",),
        }
        previous = {
            node: {"status": "passed"}
            for node in graph
        }
        previous["job-b"] = {"status": "failed"}
        plan = ir.select_rerun(
            graph=graph,
            node_components=components,
            previous_results=previous,
            changed_components={"producer-a"},
        )
        self.assertEqual(
            plan["execute"], ["job-a", "gate-a", "job-b", "gate-b", "final"]
        )
        self.assertEqual(plan["reused"], [])

    def test_failed_job_invalidates_its_downstream_only(self) -> None:
        graph = {
            "job-a": (),
            "job-b": (),
            "gate-a": ("job-a",),
            "gate-b": ("job-b",),
            "final": ("gate-a", "gate-b"),
        }
        components = {node: () for node in graph}
        previous = {node: {"status": "passed"} for node in graph}
        previous["job-b"] = {"status": "failed"}
        plan = ir.select_rerun(
            graph=graph,
            node_components=components,
            previous_results=previous,
        )
        self.assertEqual(plan["execute"], ["job-b", "gate-b", "final"])
        self.assertEqual(plan["reused"], ["job-a", "gate-a"])

    def test_cycle_fails_closed(self) -> None:
        with self.assertRaises(ir.IncrementalRecoveryError):
            ir.topological_order({"a": ("b",), "b": ("a",)})

    def test_checkpoint_is_append_only_and_chained(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            store = ir.CheckpointStore(root)
            first = store.append({"item_id": "job-a", "status": "passed", "previous_checkpoint_sha256": None})
            second = store.append({
                "item_id": "gate-a",
                "status": "reused",
                "previous_checkpoint_sha256": first["checkpoint_sha256"],
            })
            self.assertEqual(second["checkpoint_sequence"], 2)
            with self.assertRaises(ir.IncrementalRecoveryError):
                store.append({"item_id": "bad", "status": "failed", "previous_checkpoint_sha256": None})
            self.assertEqual(len(store.records()), 2)

    def test_canonical_rule_partition_uses_only_migration_decisions(self) -> None:
        partition = ir.canonical_rule_partition(
            {
                "entries": [
                    {
                        "classification": "inherit",
                        "baseline_rule": "SPEC-A-001",
                        "target_rule": "SPEC-A-001",
                    },
                    {
                        "classification": "change",
                        "baseline_rule": "SPEC-A-002",
                        "target_rule": "SPEC-A-002",
                    },
                    {
                        "classification": "condition_change",
                        "baseline_rule": "SPEC-A-003",
                        "target_rule": "SPEC-A-003",
                    },
                ]
            }
        )
        self.assertEqual(partition["total_rule_count"], 3)
        self.assertEqual(
            partition["affected_rule_ids"], ["SPEC-A-002", "SPEC-A-003"]
        )
        self.assertEqual(partition["inherited_rule_ids"], ["SPEC-A-001"])

    def test_canonical_checkpoint_is_aggregate_and_append_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            store = ir.CanonicalCheckpointStore(root)
            started = time.time() - 60
            record = {
                "recorded_at_utc": "2026-09-05T09:00:00Z",
                "campaign": {
                    "campaign_id": "campaign-a",
                    "campaign_manifest_sha256": "a" * 64,
                    "baseline_version": "0.149.1",
                    "target_version": "0.151.0",
                    "candidate_id": "candidate-a",
                    "attempt_id": "attempt-a",
                },
                "phase": "VC-5",
                "migration": {
                    "manifest_sha256": "b" * 64,
                    "total_rule_count": 3,
                    "affected_rule_ids": ["SPEC-A-002", "SPEC-A-003"],
                    "inherited_rule_ids": ["SPEC-A-001"],
                },
                "plan": {
                    "execute_item_ids": [],
                    "reused_item_ids": ["candidate-job-a"],
                },
                "items": [
                    {
                        "item_id": "candidate-job-a",
                        "status": "complete",
                        "disposition": "reused",
                        "result_sha256": "c" * 64,
                        "result_key": "d" * 64,
                        "source": {
                            "path": "candidate/attempt.json",
                            "sha256": "e" * 64,
                            "bytes": 123,
                        },
                        "details": {},
                    }
                ],
                "evidence_manifest": None,
                "deadline": {
                    "started_at_epoch": started,
                    "budget_seconds": 3600.0,
                    "deadline_at_epoch": started + 3600.0,
                },
                "source": {
                    "kind": "historical-import",
                    "legacy_object_types": ["successor", "control-epoch"],
                    "receipt_refs": [],
                },
                "metrics": {"scanned_bytes": 0, "live_request_count": 0},
            }
            first = store.append(record)
            self.assertEqual(first["checkpoint_sequence"], 1)
            self.assertEqual(store.latest(), first)
            with self.assertRaises(ir.IncrementalRecoveryError):
                store.append({**record, "items": []})


if __name__ == "__main__":
    unittest.main()
