"""校验当前 Codex CLI 0.151 工作区 successor，不读取或改写历史收据。"""

from __future__ import annotations

import hashlib
import json
import stat
import subprocess
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
SUCCESSOR = ROOT / "docs/egress/maintenance/codex-cli-0151-worktree-successor.json"
HISTORICAL_LEDGER = "docs/egress/maintenance/historical-source-drift-successor.json"
SHA256_LENGTH = 64


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git(*arguments: str) -> bytes:
    return subprocess.check_output(
        ["git", *arguments], cwd=ROOT, stderr=subprocess.DEVNULL
    )


def current_state(path: str) -> dict[str, Any]:
    absolute = ROOT / Path(path)
    metadata = absolute.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise AssertionError(f"当前 successor 路径不是普通文件：{path}")
    raw = absolute.read_bytes()
    return {
        "existence": "present",
        "file_type": "regular",
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "size": len(raw),
        "sha256": sha256(raw),
    }


def base_state(commit: str, path: str) -> dict[str, Any]:
    try:
        raw = git("show", f"{commit}:{path}")
    except subprocess.CalledProcessError:
        return {
            "existence": "absent",
            "file_type": "absent",
            "mode": "",
            "size": 0,
            "sha256": "",
        }
    tree = git("ls-tree", "-z", commit, "--", path).split(b"\0", 1)[0]
    mode = tree.split(b" ", 1)[0].decode("ascii")
    return {
        "existence": "present",
        "file_type": "regular",
        "mode": "0755" if mode == "100755" else "0644",
        "size": len(raw),
        "sha256": sha256(raw),
    }


class Codex0151WorktreeSuccessorTest(unittest.TestCase):
    def test_current_worktree_successor_is_frozen(self) -> None:
        payload = json.loads(SUCCESSOR.read_text(encoding="utf-8"))
        self.assertEqual(
            payload["schema_version"],
            "sub2apiplus-codex-cli-0151-worktree-successor/v1",
        )
        self.assertEqual(payload["scope"], "codex-cli-0.151-current-worktree")
        self.assertFalse(payload["policy"]["historical_receipts_rewrite_allowed"])
        self.assertFalse(payload["policy"]["historical_source_drift_ledger_used"])
        self.assertFalse(payload["policy"]["arm64_deployment_allowed"])
        self.assertEqual(payload["base_commit"], git("rev-parse", "HEAD").decode().strip())

        identity = payload["identity_sha256"]
        self.assertIsInstance(identity, str)
        self.assertEqual(len(identity), SHA256_LENGTH)
        unsigned = dict(payload)
        unsigned.pop("identity_sha256")
        canonical = (json.dumps(unsigned, ensure_ascii=False, indent=2) + "\n").encode()
        self.assertEqual(sha256(canonical), identity)

        entries = payload["entries"]
        paths = [entry["path"] for entry in entries]
        self.assertEqual(paths, sorted(paths))
        self.assertEqual(len(paths), len(set(paths)))
        self.assertGreater(len(paths), 0)
        for entry in entries:
            path = entry["path"]
            self.assertFalse(path.startswith("/"))
            self.assertFalse(path.startswith("../"))
            self.assertNotEqual(path, HISTORICAL_LEDGER)
            self.assertNotEqual(entry["before"], entry["after"])
            self.assertEqual(entry["before"], base_state(payload["base_commit"], path))
            self.assertEqual(entry["after"], current_state(path))


if __name__ == "__main__":
    unittest.main()
