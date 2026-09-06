from __future__ import annotations

import unittest

from tools.official_client_capture import codex_upgrade
from tools.official_client_capture import codex_upgrade_legacy_boundary as boundary


class CodexUpgradeLegacyBoundaryTests(unittest.TestCase):
    def test_registry_contains_only_historical_write_commands(self) -> None:
        self.assertEqual(
            boundary.LEGACY_WRITE_COMMANDS,
            {
                "successor",
                "control-epoch",
                "evaluation-transition",
                "terminal-transition-preflight",
            },
        )
        self.assertEqual(
            set(boundary.LEGACY_WRITE_SYMBOLS),
            set(boundary.LEGACY_WRITE_COMMANDS),
        )

    def test_formal_context_is_fail_closed(self) -> None:
        for command in boundary.LEGACY_WRITE_COMMANDS:
            with self.subTest(command=command):
                self.assertIsNotNone(
                    boundary.formal_rejection_reason(
                        command,
                        campaign_run_context=True,
                        formal_target=False,
                    )
                )
                self.assertIsNotNone(
                    boundary.formal_rejection_reason(
                        command,
                        campaign_run_context=False,
                        formal_target=True,
                    )
                )
                self.assertIsNone(
                    boundary.formal_rejection_reason(
                        command,
                        campaign_run_context=False,
                        formal_target=False,
                    )
                )

    def test_dispatch_requires_explicit_compatibility_authorization(self) -> None:
        calls: list[str] = []

        def handler(_arguments: object) -> dict[str, object]:
            calls.append("called")
            return {"status": "ok"}

        with self.assertRaises(boundary.LegacyBoundaryError):
            boundary.dispatch_historical_write(
                "successor",
                object(),
                {"successor": handler},
                allow_compatibility=False,
            )
        self.assertEqual(calls, [])
        self.assertEqual(
            boundary.dispatch_historical_write(
                "successor",
                object(),
                {"successor": handler},
                allow_compatibility=True,
            ),
            {"status": "ok"},
        )
        self.assertEqual(calls, ["called"])

    def test_readonly_registry_matches_current_symbols(self) -> None:
        self.assertFalse(
            set(boundary.LEGACY_WRITE_SYMBOLS.values())
            & set(boundary.LEGACY_READONLY_SYMBOLS)
        )
        missing = [
            name
            for name in boundary.LEGACY_READONLY_SYMBOLS
            if not callable(getattr(codex_upgrade, name, None))
        ]
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
