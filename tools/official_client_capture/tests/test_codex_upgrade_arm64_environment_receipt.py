"""Codex 升级 ARM64 网络与磁盘硬门禁收据测试。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.official_client_capture import codex_upgrade_arm64_environment_receipt as receipt
from tools.official_client_capture.tests.control_receipt_fixtures import (
    create_arm_receipt,
)


class Arm64EnvironmentReceiptTests(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[Path, dict[str, object]]:
        create_arm_receipt(
            root,
            phase="p0",
            subject_id="upgrade-0151",
            prefix="p0",
        )
        facts_path = root / "p0-facts.json"
        return facts_path, json.loads(facts_path.read_text(encoding="utf-8"))

    @staticmethod
    def _rewrite(path: Path, value: object) -> None:
        path.write_text(
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        path.chmod(0o600)

    def test_finalize_and_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            path = create_arm_receipt(
                root,
                phase="attempt_before",
                subject_id="attempt-001",
                prefix="before",
            )
            replayed = receipt.replay(root, path.name)
            self.assertEqual(replayed["status"], "passed")
            self.assertEqual(replayed["phase"], "attempt_before")
            self.assertEqual(replayed["resource_gate"]["passed"], True)

    def test_wrong_fixed_ip_gateway_or_public_egress_fails_closed(self) -> None:
        mutations = (
            ("selected_network", "ipv4_address", "172.25.0.99", "固定网络坐标"),
            ("default_route", "gateway", "172.25.0.99", "默认路由"),
            ("public_egress", "ip_address", "203.0.113.1", "公网出口"),
        )
        for index, (group, field, value, message) in enumerate(mutations):
            with self.subTest(group=group), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                root.chmod(0o700)
                path, facts = self._fixture(root)
                container = next(
                    item for item in facts["containers"] if item["name"] == "sub2apiplus"
                )
                container[group][field] = value
                self._rewrite(path, facts)
                with self.assertRaisesRegex(receipt.Arm64EnvironmentReceiptError, message):
                    receipt.build_receipt(root, "p0-facts.json")

    def test_disk_watermarks_fail_closed(self) -> None:
        for field, value in (("used_percent", 70), ("available_bytes", 30 * 1024**3 - 1)):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                root.chmod(0o700)
                path, facts = self._fixture(root)
                facts["root_filesystem"][field] = value
                self._rewrite(path, facts)
                with self.assertRaisesRegex(
                    receipt.Arm64EnvironmentReceiptError, "停线水位"
                ):
                    receipt.build_receipt(root, "p0-facts.json")

    def test_continuity_ignores_docker_restart_ephemeral_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            path, facts = self._fixture(root)
            before = receipt.validate_facts(facts)["continuity_identity_sha256"]

            container = next(
                item for item in facts["containers"] if item["name"] == "sub2apiplus"
            )
            container["container_id"] = "f" * 64
            container["default_route"]["interface"] = "eth9"
            container["selected_network"]["endpoint_id"] = "e" * 64
            for binding in container["network_bindings"]:
                binding["endpoint_id"] = (
                    "e" * 64 if binding["name"] == "proxy-network" else "d" * 64
                )
            self._rewrite(path, facts)

            after = receipt.validate_facts(facts)["continuity_identity_sha256"]
            self.assertEqual(before, after)

    def test_continuity_still_binds_network_membership(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            _, facts = self._fixture(root)
            before = receipt.validate_facts(facts)["continuity_identity_sha256"]

            container = next(
                item for item in facts["containers"] if item["name"] == "sub2apiplus"
            )
            container["selected_network"]["network_id"] = "c" * 64
            container["network_bindings"][0]["network_id"] = "c" * 64

            after = receipt.validate_facts(facts)["continuity_identity_sha256"]
            self.assertNotEqual(before, after)

    def test_replay_rejects_tampered_facts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            path, facts = self._fixture(root)
            facts["observed_at_utc"] = "2026-08-30T00:00:00Z"
            self._rewrite(path, facts)
            with self.assertRaises(receipt.Arm64EnvironmentReceiptError):
                receipt.replay(root, "p0-receipt.json")

    def test_contract_has_no_network_override_arguments(self) -> None:
        parser = receipt.build_parser()
        destinations = {
            action.dest
            for subparser in parser._actions
            if getattr(subparser, "choices", None)
            for choice in subparser.choices.values()
            for action in choice._actions
        }
        self.assertNotIn("public_egress_ip", destinations)
        self.assertNotIn("gateway", destinations)
        self.assertNotIn("ipv4_address", destinations)

    def test_schema_matches_runtime_version(self) -> None:
        schema = json.loads(
            Path(receipt.__file__)
            .with_name("codex_upgrade_arm64_environment_receipt.schema.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(
            schema["properties"]["schema_version"]["const"],
            receipt.RECEIPT_SCHEMA,
        )
        self.assertEqual(
            schema["properties"]["producer"]["properties"]["version"]["const"],
            receipt.PRODUCER_VERSION,
        )


if __name__ == "__main__":
    unittest.main()
