#!/usr/bin/env python3
"""让既有 Codex 场景驱动使用并核验 Campaign 的目标二进制。"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
from pathlib import Path
from types import ModuleType


VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
DELEGATE_PATH = Path("/capture/scripts/run_codex_scenario.py")


def validate_codex_binary(path: Path, expected_version: str) -> Path:
    """验证目标二进制是可信绝对文件，且版本与 Campaign 完全一致。"""

    if not VERSION_RE.fullmatch(expected_version):
        raise RuntimeError("CODEX_VERSION 必须是完整的 x.y.z 版本。")
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise RuntimeError("CODEX_BIN 必须是存在、非符号链接的绝对文件。")
    resolved = path.resolve(strict=True)
    if resolved != path:
        raise RuntimeError("CODEX_BIN 必须是规范绝对路径。")
    completed = subprocess.run(
        [str(path), "--version"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    actual = completed.stdout.strip()
    expected = f"codex-cli {expected_version}"
    if completed.returncode != 0 or actual != expected:
        raise RuntimeError(
            f"Codex 二进制版本不一致：预期 {expected}，实际 {actual or '<empty>'}。"
        )
    return path


def load_delegate(path: Path) -> ModuleType:
    """加载既有场景驱动；执行入口仍由本包装器显式调用。"""

    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise RuntimeError("Codex 场景驱动不是可信绝对文件。")
    spec = importlib.util.spec_from_file_location("codex_capture_scenario", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("无法加载 Codex 场景驱动。")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not callable(getattr(module, "main", None)) or not hasattr(module, "CODEX"):
        raise RuntimeError("Codex 场景驱动缺少受管入口。")
    return module


def main() -> int:
    """核验目标版本、注入二进制路径并调用原场景驱动。"""

    expected_version = os.environ.get("CODEX_VERSION", "").strip()
    default_bin = f"/opt/codex-{expected_version}/bin/codex"
    codex_bin = Path(os.environ.get("CODEX_BIN", default_bin).strip())
    validate_codex_binary(codex_bin, expected_version)
    delegate = load_delegate(DELEGATE_PATH)
    delegate.CODEX = str(codex_bin)
    result = delegate.main()
    return int(result) if isinstance(result, int) else 0


if __name__ == "__main__":
    raise SystemExit(main())
