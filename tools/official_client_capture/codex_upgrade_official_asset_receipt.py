#!/usr/bin/env python3
"""生成并重放 Codex 官方发布制品 DNS／TLS 预连接收据。"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import platform
import re
import socket
import ssl
import stat
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse


FACTS_SCHEMA = "codex-upgrade-official-asset-facts/v1"
RECEIPT_SCHEMA = "codex-upgrade-official-asset-receipt/v1"
PRODUCER_SCHEMA = "codex-upgrade-official-asset-producer/v1"
PRODUCER_VERSION = "1"
EXPECTED_ASSET_HOST = "release-assets.githubusercontent.com"
EXPECTED_RELEASE_HOST = "github.com"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
SAFE_ASSET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
MAX_JSON_BYTES = 8 * 1024 * 1024


class OfficialAssetReceiptError(ValueError):
    """官方制品元数据、DNS／TLS 事实或收据无法可信重放。"""


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        .encode("utf-8")
        + b"\n"
    )


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _expect(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise OfficialAssetReceiptError(f"{label}必须是对象")
    actual = set(value)
    if actual != fields:
        raise OfficialAssetReceiptError(
            f"{label}字段不闭合：缺失={sorted(fields - actual)}，"
            f"多余={sorted(actual - fields)}"
        )
    return value


def _private_root(root: Path) -> Path:
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise OfficialAssetReceiptError("evidence root 必须是现有非符号链接绝对目录")
    resolved = root.resolve(strict=True)
    if stat.S_IMODE(resolved.stat().st_mode) != 0o700:
        raise OfficialAssetReceiptError("evidence root 权限必须是 0700")
    return resolved


def _relative(root: Path, value: str, label: str) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise OfficialAssetReceiptError(f"{label}必须是证据根内 POSIX 相对路径")
    parsed = PurePosixPath(value)
    if (
        parsed.is_absolute()
        or str(parsed) != value
        or any(part in {"", ".", ".."} for part in parsed.parts)
    ):
        raise OfficialAssetReceiptError(f"{label}路径不规范")
    current = root
    for part in parsed.parts:
        current /= part
        if current.is_symlink():
            raise OfficialAssetReceiptError(f"{label}路径包含符号链接")
    try:
        current.resolve(strict=current.exists()).relative_to(root)
    except (OSError, RuntimeError, ValueError) as error:
        raise OfficialAssetReceiptError(f"{label}越过 evidence root") from error
    return current


def _trusted_file(path: Path, label: str) -> Path:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise OfficialAssetReceiptError(f"{label}必须是可信绝对普通文件")
    resolved = path.resolve(strict=True)
    if stat.S_IMODE(resolved.stat().st_mode) != 0o600:
        raise OfficialAssetReceiptError(f"{label}权限必须是 0600")
    if resolved.stat().st_size <= 0 or resolved.stat().st_size > MAX_JSON_BYTES:
        raise OfficialAssetReceiptError(f"{label}大小非法")
    return resolved


def _load_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    trusted = _trusted_file(path, label)
    raw = trusted.read_bytes()
    try:
        payload = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise OfficialAssetReceiptError(f"{label}不是合法 UTF-8 JSON") from error
    if not isinstance(payload, dict):
        raise OfficialAssetReceiptError(f"{label}顶层必须是对象")
    return payload, raw


def _write_once(path: Path, payload: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise OfficialAssetReceiptError(f"输出已存在，禁止覆盖：{path}")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink() or stat.S_IMODE(path.parent.stat().st_mode) != 0o700:
        raise OfficialAssetReceiptError("输出父目录必须是 0700 非符号链接目录")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_canonical(payload))
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
        path.chmod(0o600)
    except FileExistsError as error:
        raise OfficialAssetReceiptError(f"输出已存在，禁止覆盖：{path}") from error
    finally:
        temporary.unlink(missing_ok=True)


def _producer() -> dict[str, Any]:
    tool = Path(__file__).resolve()
    return {
        "schema_version": PRODUCER_SCHEMA,
        "tool": str(tool),
        "tool_sha256": _sha256_file(tool),
        "version": PRODUCER_VERSION,
    }


def _release_asset(
    metadata_path: Path,
    *,
    asset_name: str,
    expected_size: int,
    expected_sha256: str,
) -> dict[str, Any]:
    if not SAFE_ASSET_RE.fullmatch(asset_name):
        raise OfficialAssetReceiptError("asset name 格式非法")
    if expected_size <= 0 or not SHA256_RE.fullmatch(expected_sha256):
        raise OfficialAssetReceiptError("asset 大小或摘要格式非法")
    metadata, raw = _load_json(metadata_path, "release metadata")
    tag_name = metadata.get("tag_name")
    published_at = metadata.get("published_at")
    if not isinstance(tag_name, str) or not tag_name.startswith("rust-v"):
        raise OfficialAssetReceiptError("release tag 非 Codex rust stable")
    if not isinstance(published_at, str) or not RFC3339_RE.fullmatch(published_at):
        raise OfficialAssetReceiptError("release published_at 非法")
    assets = metadata.get("assets")
    selected = (
        [
            item
            for item in assets
            if isinstance(item, dict) and item.get("name") == asset_name
        ]
        if isinstance(assets, list)
        else []
    )
    if len(selected) != 1:
        raise OfficialAssetReceiptError("release metadata 中 asset 缺失或重名")
    item = selected[0]
    digest = item.get("digest")
    url = item.get("browser_download_url")
    parsed = urlparse(url) if isinstance(url, str) else None
    expected_path = f"/openai/codex/releases/download/{tag_name}/{asset_name}"
    if (
        item.get("size") != expected_size
        or digest != f"sha256:{expected_sha256}"
        or parsed is None
        or parsed.scheme != "https"
        or parsed.hostname != EXPECTED_RELEASE_HOST
        or parsed.path != expected_path
        or parsed.query
        or parsed.fragment
    ):
        raise OfficialAssetReceiptError("release asset 身份与冻结坐标不一致")
    return {
        "release_metadata": {
            "path": str(metadata_path),
            "sha256": _sha256_bytes(raw),
            "bytes": len(raw),
        },
        "tag_name": tag_name,
        "published_at": published_at,
        "name": asset_name,
        "size": expected_size,
        "sha256": expected_sha256,
        "browser_download_url": url,
    }


def _resolve_ipv4(host: str) -> list[str]:
    try:
        results = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise OfficialAssetReceiptError("官方 asset host IPv4 解析失败") from error
    addresses = sorted({str(item[4][0]) for item in results})
    if not addresses:
        raise OfficialAssetReceiptError("官方 asset host 没有 IPv4 地址")
    for address in addresses:
        try:
            if not isinstance(ipaddress.ip_address(address), ipaddress.IPv4Address):
                raise ValueError(address)
        except ValueError as error:
            raise OfficialAssetReceiptError("DNS 返回了非法 IPv4 地址") from error
    return addresses


def _probe_tls(host: str, address: str) -> dict[str, Any]:
    started = time.monotonic()
    context = ssl.create_default_context()
    try:
        with socket.create_connection((address, 443), timeout=5) as raw:
            raw.settimeout(8)
            with context.wrap_socket(raw, server_hostname=host) as tls:
                certificate = tls.getpeercert(binary_form=True)
                version = tls.version()
        if not certificate or not version:
            raise OfficialAssetReceiptError("TLS 握手未返回证书或版本")
        return {
            "ipv4_address": address,
            "status": "passed",
            "tls_version": version,
            "certificate_sha256": _sha256_bytes(certificate),
            "error_type": None,
            "elapsed_milliseconds": max(0, int((time.monotonic() - started) * 1000)),
        }
    except (OSError, ssl.SSLError, OfficialAssetReceiptError) as error:
        return {
            "ipv4_address": address,
            "status": "failed",
            "tls_version": None,
            "certificate_sha256": None,
            "error_type": type(error).__name__,
            "elapsed_milliseconds": max(0, int((time.monotonic() - started) * 1000)),
        }


def collect_facts(
    *,
    release_metadata: Path,
    asset_name: str,
    expected_size: int,
    expected_sha256: str,
) -> dict[str, Any]:
    """从当前执行环境解析并逐地址预连接官方制品 CDN。"""

    machine = platform.machine().lower()
    if machine not in {"aarch64", "arm64"}:
        raise OfficialAssetReceiptError("官方制品预连接必须在 ARM64 执行环境运行")
    metadata_path = _trusted_file(release_metadata, "release metadata")
    asset = _release_asset(
        metadata_path,
        asset_name=asset_name,
        expected_size=expected_size,
        expected_sha256=expected_sha256,
    )
    addresses = _resolve_ipv4(EXPECTED_ASSET_HOST)
    probes = [_probe_tls(EXPECTED_ASSET_HOST, address) for address in addresses]
    passed = [item for item in probes if item["status"] == "passed"]
    if not passed:
        raise OfficialAssetReceiptError("官方 asset host 全部 IPv4 TLS 预连接失败")
    return {
        "schema_version": FACTS_SCHEMA,
        "observed_at_utc": _utc_now(),
        "host": {
            "hostname": socket.gethostname(),
            "architecture": "linux/arm64",
        },
        "asset": asset,
        "network": {
            "asset_host": EXPECTED_ASSET_HOST,
            "port": 443,
            "resolved_ipv4": addresses,
            "tls_probes": probes,
        },
        "collector": _producer(),
    }


def _validate_facts(facts: dict[str, Any]) -> dict[str, Any]:
    _expect(
        facts,
        {"schema_version", "observed_at_utc", "host", "asset", "network", "collector"},
        "facts",
    )
    if facts.get("schema_version") != FACTS_SCHEMA:
        raise OfficialAssetReceiptError("facts schema 不匹配")
    observed = facts.get("observed_at_utc")
    if not isinstance(observed, str) or not RFC3339_RE.fullmatch(observed):
        raise OfficialAssetReceiptError("facts observed_at_utc 非法")
    host = _expect(facts.get("host"), {"hostname", "architecture"}, "host")
    if (
        host.get("architecture") != "linux/arm64"
        or not isinstance(host.get("hostname"), str)
        or not host["hostname"]
    ):
        raise OfficialAssetReceiptError("facts 不是可信 ARM64 身份")
    asset = _expect(
        facts.get("asset"),
        {
            "release_metadata",
            "tag_name",
            "published_at",
            "name",
            "size",
            "sha256",
            "browser_download_url",
        },
        "asset",
    )
    binding = _expect(
        asset.get("release_metadata"), {"path", "sha256", "bytes"}, "release_metadata"
    )
    if (
        not isinstance(binding.get("path"), str)
        or not SHA256_RE.fullmatch(str(binding.get("sha256", "")))
        or not isinstance(binding.get("bytes"), int)
        or isinstance(binding.get("bytes"), bool)
        or binding["bytes"] <= 0
    ):
        raise OfficialAssetReceiptError("release metadata binding 非法")
    if (
        not isinstance(asset.get("name"), str)
        or not SAFE_ASSET_RE.fullmatch(asset["name"])
        or not isinstance(asset.get("size"), int)
        or isinstance(asset.get("size"), bool)
        or asset["size"] <= 0
        or not isinstance(asset.get("sha256"), str)
        or not SHA256_RE.fullmatch(asset["sha256"])
    ):
        raise OfficialAssetReceiptError("release asset 字段类型或格式非法")
    metadata_path = _trusted_file(Path(binding["path"]), "release metadata")
    if (
        binding.get("sha256") != _sha256_file(metadata_path)
        or binding.get("bytes") != metadata_path.stat().st_size
    ):
        raise OfficialAssetReceiptError("release metadata 摘要或字节数漂移")
    verified_asset = _release_asset(
        metadata_path,
        asset_name=asset["name"],
        expected_size=asset["size"],
        expected_sha256=asset["sha256"],
    )
    if verified_asset != asset:
        raise OfficialAssetReceiptError("release asset 事实无法从元数据复算")
    network = _expect(
        facts.get("network"), {"asset_host", "port", "resolved_ipv4", "tls_probes"}, "network"
    )
    if (
        network.get("asset_host") != EXPECTED_ASSET_HOST
        or network.get("port") != 443
    ):
        raise OfficialAssetReceiptError("官方 asset 网络坐标漂移")
    addresses = network.get("resolved_ipv4")
    probes = network.get("tls_probes")
    if (
        not isinstance(addresses, list)
        or not addresses
        or any(not isinstance(address, str) for address in addresses)
        or addresses != sorted(set(addresses))
        or not isinstance(probes, list)
        or len(probes) != len(addresses)
    ):
        raise OfficialAssetReceiptError("DNS 或 TLS probe 集合不闭合")
    try:
        if any(
            not isinstance(ipaddress.ip_address(address), ipaddress.IPv4Address)
            for address in addresses
        ):
            raise ValueError("非 IPv4 地址")
    except ValueError as error:
        raise OfficialAssetReceiptError("DNS 地址集合包含非法 IPv4") from error
    expected_probe_fields = {
        "ipv4_address",
        "status",
        "tls_version",
        "certificate_sha256",
        "error_type",
        "elapsed_milliseconds",
    }
    passed: list[dict[str, Any]] = []
    for address, value in zip(addresses, probes, strict=True):
        probe = _expect(value, expected_probe_fields, f"tls_probes.{address}")
        if probe.get("ipv4_address") != address or probe.get("status") not in {
            "passed",
            "failed",
        }:
            raise OfficialAssetReceiptError("TLS probe 地址或状态不一致")
        elapsed = probe.get("elapsed_milliseconds")
        if not isinstance(elapsed, int) or isinstance(elapsed, bool) or elapsed < 0:
            raise OfficialAssetReceiptError("TLS probe 耗时非法")
        if probe["status"] == "passed":
            if (
                not isinstance(probe.get("tls_version"), str)
                or not SHA256_RE.fullmatch(str(probe.get("certificate_sha256", "")))
                or probe.get("error_type") is not None
            ):
                raise OfficialAssetReceiptError("成功 TLS probe 事实不完整")
            passed.append(probe)
        elif (
            probe.get("tls_version") is not None
            or probe.get("certificate_sha256") is not None
            or not isinstance(probe.get("error_type"), str)
            or not probe["error_type"]
        ):
            raise OfficialAssetReceiptError("失败 TLS probe 事实不完整")
    if not passed:
        raise OfficialAssetReceiptError("没有可冻结的 TLS 成功地址")
    if facts.get("collector") != _producer():
        raise OfficialAssetReceiptError("collector 工具身份漂移")
    return min(passed, key=lambda item: item["ipv4_address"])


def build_receipt(root: Path, facts_relative: str) -> dict[str, Any]:
    root = _private_root(root)
    facts_path = _relative(root, facts_relative, "facts")
    facts, facts_raw = _load_json(facts_path, "facts")
    selected = _validate_facts(facts)
    asset = facts["asset"]
    host = facts["network"]["asset_host"]
    selected_ip = selected["ipv4_address"]
    return {
        "schema_version": RECEIPT_SCHEMA,
        "status": "passed",
        "observed_at_utc": facts["observed_at_utc"],
        "asset": asset,
        "network": {
            "asset_host": host,
            "port": 443,
            "resolved_ipv4": facts["network"]["resolved_ipv4"],
            "selected_ipv4": selected_ip,
            "tls_version": selected["tls_version"],
            "certificate_sha256": selected["certificate_sha256"],
            "curl_resolve": f"{host}:443:{selected_ip}",
        },
        "facts": {
            "path": facts_relative,
            "sha256": _sha256_bytes(facts_raw),
            "bytes": len(facts_raw),
        },
        "producer": _producer(),
    }


def replay(root: Path, receipt_relative: str) -> dict[str, Any]:
    root = _private_root(root)
    receipt_path = _relative(root, receipt_relative, "receipt")
    receipt, raw = _load_json(receipt_path, "receipt")
    facts_binding = receipt.get("facts")
    if not isinstance(facts_binding, dict) or set(facts_binding) != {"path", "sha256", "bytes"}:
        raise OfficialAssetReceiptError("receipt facts binding 非法")
    expected = build_receipt(root, str(facts_binding.get("path")))
    if _canonical(expected) != raw:
        raise OfficialAssetReceiptError("官方 asset receipt 重放结果不一致")
    return receipt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    collect = commands.add_parser("collect", help="解析 DNS 并逐 IPv4 完成 TLS 预连接")
    collect.add_argument("--evidence-root", type=Path, required=True)
    collect.add_argument("--output", required=True)
    collect.add_argument("--release-metadata", type=Path, required=True)
    collect.add_argument("--asset-name", required=True)
    collect.add_argument("--expected-size", type=int, required=True)
    collect.add_argument("--expected-sha256", required=True)
    finalize = commands.add_parser("finalize", help="封存精确 IP 与官方 asset 身份收据")
    finalize.add_argument("--evidence-root", type=Path, required=True)
    finalize.add_argument("--facts", required=True)
    finalize.add_argument("--output", required=True)
    replay_parser = commands.add_parser("replay", help="离线独立重放官方 asset 收据")
    replay_parser.add_argument("--evidence-root", type=Path, required=True)
    replay_parser.add_argument("--receipt", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    arguments = build_parser().parse_args(argv)
    try:
        root = _private_root(arguments.evidence_root)
        if arguments.command == "collect":
            facts = collect_facts(
                release_metadata=arguments.release_metadata,
                asset_name=arguments.asset_name,
                expected_size=arguments.expected_size,
                expected_sha256=arguments.expected_sha256,
            )
            _write_once(_relative(root, arguments.output, "output"), facts)
            result = {
                "status": "collected",
                "reachable_ipv4": sum(
                    item["status"] == "passed"
                    for item in facts["network"]["tls_probes"]
                ),
            }
        elif arguments.command == "finalize":
            receipt = build_receipt(root, arguments.facts)
            _write_once(_relative(root, arguments.output, "output"), receipt)
            result = {
                "status": receipt["status"],
                "selected_ipv4": receipt["network"]["selected_ipv4"],
            }
        else:
            receipt = replay(root, arguments.receipt)
            result = {
                "status": receipt["status"],
                "selected_ipv4": receipt["network"]["selected_ipv4"],
            }
    except (OSError, OfficialAssetReceiptError) as error:
        print(f"官方 asset 收据失败：{error}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
