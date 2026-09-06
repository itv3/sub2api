from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class FingerprintMITMWiringTests(unittest.TestCase):
    def test_runner_requires_frozen_ids_and_uses_failed_scope_helper(self) -> None:
        source = (ROOT / "run_sub2api_openai_mitm_matrix.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "CODEX_ACCOUNT_ID:?必须由 Campaign 显式提供 CODEX_ACCOUNT_ID",
            source,
        )
        self.assertIn("API_KEY_ID:?必须由 Campaign 显式提供 API_KEY_ID", source)
        self.assertNotIn("CODEX_ACCOUNT_ID:-", source)
        self.assertNotIn("API_KEY_ID:-", source)
        self.assertIn("status = 'active' and deleted_at is null", source)
        self.assertIn("CAPTURE_FINGERPRINT_PROXY_BIN", source)
        self.assertIn("CAPTURE_CODEX_PROFILE", source)
        self.assertIn("prewarm_codex_home.py", source)
        self.assertLess(
            source.index("pending_coordinates"),
            source.index("fingerprint_proxy_host_path\" \"$codex_profile_host_path"),
        )

    def test_runtime_pair_keeps_mitm_capture_and_uses_local_utls_proxy(self) -> None:
        source = (
            ROOT / "runtime_scripts" / "run_fingerprint_mitm_pair.sh"
        ).read_text(encoding="utf-8")
        self.assertIn('--mode "upstream:http://127.0.0.1:$upstream_port"', source)
        self.assertIn("--set ssl_insecure=true", source)
        self.assertIn('-s "$mitm_addon"', source)
        self.assertIn('--profile "$profile_path"', source)
        self.assertIn('--version "$codex_version"', source)
        self.assertIn('--tcp-max-segment "$tcp_max_segment"', source)
        self.assertIn("CAPTURE_FINGERPRINT_TCP_MAXSEG:-1368", source)
        self.assertIn("CAPTURE_FINGERPRINT_PROXY_PORT:-18082", source)
        self.assertIn("CAPTURE_INGRESS_PORT:-18081", source)
        self.assertIn('$upstream_port == "$ingress_port"', source)

    def test_runtime_launcher_reserves_ingress_port(self) -> None:
        source = (ROOT / "runtime_scripts" / "start_mitm.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("CAPTURE_FINGERPRINT_PROXY_PORT:-18082", source)
        self.assertIn("CAPTURE_FINGERPRINT_TCP_MAXSEG:-1368", source)
        self.assertIn(
            'CAPTURE_FINGERPRINT_TCP_MAXSEG="$fingerprint_tcp_max_segment"',
            source,
        )
        self.assertIn("CAPTURE_INGRESS_PORT:-18081", source)
        self.assertIn('$fingerprint_proxy_port == "$ingress_port"', source)


if __name__ == "__main__":
    unittest.main()
