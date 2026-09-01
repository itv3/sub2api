"""组件级增量恢复内核测试。"""

from __future__ import annotations

import tempfile
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


if __name__ == "__main__":
    unittest.main()
