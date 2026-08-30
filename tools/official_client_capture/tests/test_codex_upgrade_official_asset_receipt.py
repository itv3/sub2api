from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.official_client_capture import codex_upgrade_official_asset_receipt as receipt


class OfficialAssetReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "evidence"
        self.root.mkdir(mode=0o700)
        self.metadata = Path(self.temporary.name) / "release.json"
        self.asset_name = "codex-package-aarch64-unknown-linux-musl.tar.gz"
        self.asset_sha256 = "a" * 64
        self.metadata.write_text(
            json.dumps(
                {
                    "tag_name": "rust-v0.151.0",
                    "published_at": "2026-08-29T09:55:39Z",
                    "assets": [
                        {
                            "name": self.asset_name,
                            "size": 122432916,
                            "digest": f"sha256:{self.asset_sha256}",
                            "browser_download_url": (
                                "https://github.com/openai/codex/releases/download/"
                                f"rust-v0.151.0/{self.asset_name}"
                            ),
                        }
                    ],
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self.metadata.chmod(0o600)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _probe(_host: str, address: str) -> dict[str, object]:
        passed = address == "185.199.108.133"
        return {
            "ipv4_address": address,
            "status": "passed" if passed else "failed",
            "tls_version": "TLSv1.3" if passed else None,
            "certificate_sha256": "b" * 64 if passed else None,
            "error_type": None if passed else "TimeoutError",
            "elapsed_milliseconds": 10 if passed else 8000,
        }

    def _facts(self) -> dict[str, object]:
        with (
            mock.patch.object(receipt.platform, "machine", return_value="aarch64"),
            mock.patch.object(
                receipt,
                "_resolve_ipv4",
                return_value=["185.199.108.133", "185.199.109.133"],
            ),
            mock.patch.object(receipt, "_probe_tls", side_effect=self._probe),
        ):
            return receipt.collect_facts(
                release_metadata=self.metadata,
                asset_name=self.asset_name,
                expected_size=122432916,
                expected_sha256=self.asset_sha256,
            )

    def test_finalize_and_replay_freeze_reachable_ipv4(self) -> None:
        receipt._write_once(self.root / "facts.json", self._facts())
        payload = receipt.build_receipt(self.root, "facts.json")
        self.assertEqual(payload["status"], "passed")
        self.assertEqual(payload["network"]["selected_ipv4"], "185.199.108.133")
        self.assertEqual(
            payload["network"]["curl_resolve"],
            "release-assets.githubusercontent.com:443:185.199.108.133",
        )
        receipt._write_once(self.root / "receipt.json", payload)
        self.assertEqual(
            receipt.replay(self.root, "receipt.json")["asset"]["sha256"],
            self.asset_sha256,
        )

    def test_metadata_digest_drift_fails_closed(self) -> None:
        receipt._write_once(self.root / "facts.json", self._facts())
        self.metadata.write_text("{}\n", encoding="utf-8")
        self.metadata.chmod(0o600)
        with self.assertRaisesRegex(receipt.OfficialAssetReceiptError, "漂移"):
            receipt.build_receipt(self.root, "facts.json")

    def test_all_tls_addresses_failed_is_rejected(self) -> None:
        failed = dict(self._probe("host", "185.199.109.133"))
        with (
            mock.patch.object(receipt.platform, "machine", return_value="aarch64"),
            mock.patch.object(
                receipt, "_resolve_ipv4", return_value=["185.199.109.133"]
            ),
            mock.patch.object(receipt, "_probe_tls", return_value=failed),
        ):
            with self.assertRaisesRegex(
                receipt.OfficialAssetReceiptError, "全部 IPv4 TLS"
            ):
                receipt.collect_facts(
                    release_metadata=self.metadata,
                    asset_name=self.asset_name,
                    expected_size=122432916,
                    expected_sha256=self.asset_sha256,
                )

    def test_schema_matches_runtime_version(self) -> None:
        schema = json.loads(
            Path(receipt.__file__)
            .with_name("codex_upgrade_official_asset_receipt.schema.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(
            schema["properties"]["schema_version"]["const"],
            receipt.RECEIPT_SCHEMA,
        )


if __name__ == "__main__":
    unittest.main()
