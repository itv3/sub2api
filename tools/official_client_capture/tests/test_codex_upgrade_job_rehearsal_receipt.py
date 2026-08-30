"""Codex 完整 Job ARM64 离线演练收据的正反向测试。"""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from tools.official_client_capture import codex_upgrade
from tools.official_client_capture import codex_upgrade_job_rehearsal_receipt as receipt
from tools.official_client_capture.tests.control_receipt_fixtures import (
    create_job_rehearsal_receipt,
)


class JobRehearsalReceiptTests(unittest.TestCase):
    def _contract(self, root: Path) -> dict[str, object]:
        scenario_path = Path(receipt.__file__).with_name(
            "codex_upgrade_scenarios_0_151_0.json"
        )
        scenario = json.loads(scenario_path.read_text(encoding="utf-8"))
        return receipt.build_execution_contract(
            target_version="0.151.0",
            target_sha256="1" * 64,
            target_package_sha256="2" * 64,
            target_code_mode_host_sha256="3" * 64,
            suite="full",
            tool_files_sha256=codex_upgrade._tool_identity()["files_sha256"],
            configuration={
                "runtime_image": f"capture-runtime@sha256:{'4' * 64}",
                "model": "gpt-5.5",
                "lite_model": "gpt-5.6-luna",
                "capture_root": "/root/oauth-capture",
                "capture_container": "capture-cli",
                "service_container": "sub2apiplus",
                "keeper_container": "sub2apiplus-keeper",
                "postgres_container": "sub2apiplus-postgres",
                "redis_container": "sub2apiplus-redis",
                "capture_codex_bin": "/opt/codex-0.151.0/bin/codex",
                "relay_codex_bin": "/opt/codex-0.151.0/bin/codex",
                "capture_code_mode_host_bin": (
                    "/opt/codex-0.151.0/bin/codex-code-mode-host"
                ),
                "relay_code_mode_host_bin": (
                    "/opt/codex-0.151.0/bin/codex-code-mode-host"
                ),
                "codex_account_id": 90,
                "api_key_id": 1,
                "live_attestation_compose_dir": str((root / "compose").resolve()),
                "live_attestation_compose_files": "-f compose.yml",
            },
            target_scenario=scenario,
            extra_jobs=None,
        )

    @staticmethod
    def _rewrite(path: Path, value: object) -> None:
        path.write_text(
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        path.chmod(0o600)

    def test_0151_contract_expands_all_38_jobs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            contract = self._contract(Path(directory))
        self.assertEqual(contract["job_count"], 38)
        self.assertEqual(contract["phase_counts"], {"official": 29, "candidate": 9})
        self.assertEqual(
            contract["c2pa_job_identities"],
            {
                "official-relay-file-upload-c2pa-negative": {
                    "scenario_job_id": "official-relay-file-upload-c2pa-negative",
                    "expectation": "negative",
                },
                "official-relay-file-upload-c2pa-positive": {
                    "scenario_job_id": "official-relay-file-upload-c2pa-positive",
                    "expectation": "positive",
                },
            },
        )

    def test_finalize_and_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            path = create_job_rehearsal_receipt(
                root,
                contract=self._contract(root),
                preflight_campaign_id="preflight-0151",
            )
            replayed = receipt.replay(root, path.name)
        self.assertEqual(replayed["status"], "passed")
        self.assertEqual(replayed["job_count"], 38)

    def test_missing_job_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            create_job_rehearsal_receipt(
                root,
                contract=self._contract(root),
                preflight_campaign_id="preflight-0151",
            )
            facts_path = root / "facts.json"
            facts = json.loads(facts_path.read_text(encoding="utf-8"))
            facts["jobs"].pop()
            self._rewrite(facts_path, facts)
            with self.assertRaisesRegex(
                receipt.JobRehearsalReceiptError, "数量不完整"
            ):
                receipt.build_receipt(root, "facts.json")

    def test_runtime_or_tool_contract_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            contract = self._contract(root)
            path = create_job_rehearsal_receipt(
                root,
                contract=contract,
                preflight_campaign_id="preflight-0151",
            )
            replayed = receipt.replay(root, path.name)
            for field, value in (
                ("runtime_image", f"capture-runtime@sha256:{'5' * 64}"),
                ("capture_container", "other-capture"),
                ("capture_codex_bin", "/opt/codex-0.151.0/bin/other"),
            ):
                with self.subTest(field=field):
                    changed = copy.deepcopy(contract)
                    changed["configuration"][field] = value
                    with self.assertRaisesRegex(
                        receipt.JobRehearsalReceiptError, "执行合同"
                    ):
                        receipt.assert_formal_compatible(replayed, changed)

    def test_c2pa_job_identity_mutation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scenario_path = Path(receipt.__file__).with_name(
                "codex_upgrade_scenarios_0_151_0.json"
            )
            scenario = json.loads(scenario_path.read_text(encoding="utf-8"))
            job = next(
                item
                for item in scenario["capture_jobs"]
                if item["id"] == "official-relay-file-upload-c2pa-positive"
            )
            job["steps"][0]["environment"]["SCENARIO_JOB_ID"] = (
                "official-relay-file-upload-c2pa-negative"
            )
            configuration = self._contract(root)["configuration"]
            with self.assertRaisesRegex(
                receipt.JobRehearsalReceiptError, "C2PA"
            ):
                receipt.build_execution_contract(
                    target_version="0.151.0",
                    target_sha256="1" * 64,
                    target_package_sha256="2" * 64,
                    target_code_mode_host_sha256="3" * 64,
                    suite="full",
                    tool_files_sha256=codex_upgrade._tool_identity()[
                        "files_sha256"
                    ],
                    configuration=configuration,
                    target_scenario=scenario,
                    extra_jobs=None,
                )

    def test_schema_matches_runtime_version(self) -> None:
        schema = json.loads(
            Path(receipt.__file__)
            .with_name("codex_upgrade_job_rehearsal_receipt.schema.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(
            schema["properties"]["schema_version"]["const"],
            receipt.RECEIPT_SCHEMA,
        )
        self.assertEqual(
            schema["$defs"]["executionContract"]["properties"][
                "schema_version"
            ]["const"],
            receipt.EXECUTION_CONTRACT_SCHEMA,
        )


if __name__ == "__main__":
    unittest.main()
