from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import prewarm_codex_home


class CodexHomePrewarmTests(unittest.TestCase):
    def test_command_uses_non_networking_custom_provider(self) -> None:
        command = prewarm_codex_home.build_command("/opt/codex/bin/codex")
        joined = "\n".join(command)
        self.assertIn('model_provider="capture_prewarm"', joined)
        self.assertIn('base_url="http://127.0.0.1:9/v1"', joined)
        self.assertIn("features.plugins=false", joined)
        self.assertIn("features.apps=false", joined)
        self.assertNotIn("chatgpt.com", joined)


if __name__ == "__main__":
    unittest.main()
