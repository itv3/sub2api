#!/usr/bin/env python3
"""SCN-REALITY-01 场景原始事实构建器。

从一次 capture job 的原始证据（relay 明文字节、pcap ClientHello、驱动事件日志）
提取目标协议分支是否真实成立的事实，并写出 `scenario-facts/<场景>-facts.json`。

设计约束（R0 §4.1）：

- **只提取，不推断**。字段值必须能追溯到某个原始证据文件的字节；每个用到的文件
  都进 `evidence_bindings`，由 run 阶段按 job 证据根复核路径、大小与 SHA-256。
- **失败即不产出**。任一必填字段缺失就退出非 0，只写不参与判定的失败诊断。
  编排器据此判 job 失败——「脚本退出 0 且证据目录非空」不再等于场景成立。
- **不含 attempt 身份**。campaign／attempt／run_nonce 是编排侧的权威事实，
  由外层 finalizer 注入，采集侧无从声明。

用法：

    python3 build_scenario_facts.py --scenario A13 \\
        --job-id official-relay-oauth-refresh \\
        --run-id <RUN_ID> --run-root <run 目录>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.official_client_capture.pcap_clienthello import (
    iter_timed_packets,
    parse_client_hello,
    tcp_payload,
)
from tools.official_client_capture.scenario_receipts import (
    ScenarioReceiptError,
    SUPPORTED_SCENARIOS,
    build_facts_document,
    write_failure_diagnostic,
)


FACTS_DIR = "scenario-facts"
OBSERVATION_DIR = "scenario-observations"
RELAY_DIR = "relay"
PCAP_RELATIVE = ("direct/traffic.pcap",)
EVIDENCE_ROOT_ROLE = "job_evidence"
# pcap 全局头 24 字节；只有头没有包的文件不构成证据。
MIN_PCAP_BYTES = 25
MAX_EVIDENCE_BYTES = 512 * 1024 * 1024
REGIONAL_SNI_RE = re.compile(r"^[a-z0-9.-]+\.oaiusercontent\.com$")
# 真实观测形态：`Location: /v1/realtime/calls/rtc_u0_EBE4oHU6FYPaFejVfBpPW`。
CALL_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
A11_CONTROLLED_INTERVENTION = "synthesize_realtime_call_after_live_failure"
A14_C2PA_EXPECTATIONS = ("negative", "positive")


class ScenarioFactsError(ValueError):
    """原始证据不足以证明目标协议分支成立。"""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json_sha256(value: Any) -> str:
    """返回 JSON 语义摘要；字段顺序和空白不影响等值判定。"""

    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _utc(value: float) -> str:
    return (
        datetime.fromtimestamp(value, tz=timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


class EvidenceSet:
    """收集本次提取真实读过的证据文件，形成可复核的绑定。"""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._bindings: dict[str, dict[str, Any]] = {}

    def bind(self, path: Path) -> Path:
        if path.is_symlink() or not path.is_file():
            raise ScenarioFactsError(f"证据不是普通文件：{path}")
        resolved = path.resolve()
        if not resolved.is_relative_to(self.root.resolve()):
            raise ScenarioFactsError(f"证据越过 job 证据根：{path}")
        size = path.stat().st_size
        if size <= 0 or size > MAX_EVIDENCE_BYTES:
            raise ScenarioFactsError(f"证据大小不可用：{path}")
        relative = path.relative_to(self.root).as_posix()
        self._bindings[relative] = {
            "root_role": EVIDENCE_ROOT_ROLE,
            "path": relative,
            "sha256": _sha256(path),
            "bytes": size,
        }
        return path

    def bindings(self) -> list[dict[str, Any]]:
        if not self._bindings:
            raise ScenarioFactsError("没有任何证据被读取。")
        return [self._bindings[key] for key in sorted(self._bindings)]


def _load_observation(evidence: EvidenceSet, root: Path, name: str) -> dict[str, Any]:
    """读取采集脚本落下的场景观测事实。"""

    path = root / OBSERVATION_DIR / name
    if path.is_symlink() or not path.is_file():
        raise ScenarioFactsError(f"缺少场景观测记录：{OBSERVATION_DIR}/{name}")
    evidence.bind(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScenarioFactsError(f"场景观测记录不可读：{name}：{error}") from error
    if not isinstance(payload, dict):
        raise ScenarioFactsError(f"场景观测记录顶层必须是对象：{name}")
    return payload


def _require(payload: dict[str, Any], key: str, name: str) -> Any:
    if key not in payload:
        raise ScenarioFactsError(f"{name} 缺少字段 {key}")
    return payload[key]


# --------------------------------------------------------------------------
# HTTP/1.1 明文字节解析
#
# relay 落盘的是中继解密后的明文，可以直接切。这里不复用 relay_extract 的
# parse_h1_stream——那份实现只切请求、且对 body 做脱敏摘要，取不到 call_id 与
# upload_url 的精确值。
# --------------------------------------------------------------------------


def _split_head(payload: bytes, start: int) -> tuple[list[str], int] | None:
    end = payload.find(b"\r\n\r\n", start)
    if end < 0:
        return None
    head = payload[start:end].decode("latin-1", "replace")
    return head.split("\r\n"), end + 4


def _headers_of(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        if separator:
            headers.setdefault(name.strip().lower(), value.strip())
    return headers


def _body_of(payload: bytes, headers: dict[str, str], start: int) -> tuple[bytes, int]:
    """按 Content-Length 或 chunked 取出报文体，返回 (体, 下一条报文起点)。"""

    if headers.get("transfer-encoding", "").lower() == "chunked":
        body = bytearray()
        cursor = start
        while True:
            line_end = payload.find(b"\r\n", cursor)
            if line_end < 0:
                break
            try:
                size = int(payload[cursor:line_end].split(b";")[0], 16)
            except ValueError:
                break
            cursor = line_end + 2
            if size == 0:
                cursor = payload.find(b"\r\n\r\n", cursor - 2)
                cursor = cursor + 4 if cursor >= 0 else len(payload)
                break
            body.extend(payload[cursor : cursor + size])
            cursor += size + 2
        return bytes(body), cursor
    try:
        length = int(headers.get("content-length", "0"))
    except ValueError:
        length = 0
    return payload[start : start + length], start + length


def _iter_requests(payload: bytes) -> Iterator[dict[str, Any]]:
    cursor = 0
    while cursor < len(payload):
        request_start = cursor
        parsed = _split_head(payload, cursor)
        if parsed is None:
            return
        lines, body_start = parsed
        if not lines or " HTTP/1." not in lines[0]:
            return
        parts = lines[0].split(" ")
        if len(parts) < 3:
            return
        headers = _headers_of(lines)
        body, cursor = _body_of(payload, headers, body_start)
        yield {
            "method": parts[0],
            "target": parts[1],
            "headers": headers,
            "body": body,
            "start_offset": request_start,
        }
        if cursor <= body_start:
            cursor = body_start


def _iter_responses(payload: bytes) -> Iterator[dict[str, Any]]:
    cursor = 0
    while cursor < len(payload):
        parsed = _split_head(payload, cursor)
        if parsed is None:
            return
        lines, body_start = parsed
        if not lines or not lines[0].startswith("HTTP/1."):
            return
        parts = lines[0].split(" ")
        if len(parts) < 2 or not parts[1].isdigit():
            return
        headers = _headers_of(lines)
        body, cursor = _body_of(payload, headers, body_start)
        yield {"status": int(parts[1]), "headers": headers, "body": body}
        if cursor <= body_start:
            cursor = body_start


def _relay_streams(evidence: EvidenceSet, root: Path, direction: str) -> list[bytes]:
    """按连接序读出某个方向的全部明文字节。"""

    relay_root = root / RELAY_DIR
    if not relay_root.is_dir() or relay_root.is_symlink():
        raise ScenarioFactsError("缺少 relay 证据目录。")
    streams: list[bytes] = []
    for path in sorted(relay_root.glob(f"conn*.{direction}.bin")):
        evidence.bind(path)
        streams.append(path.read_bytes())
    if not streams:
        raise ScenarioFactsError(f"relay 未记录任何 {direction} 字节。")
    return streams


def _path_of(target: str) -> str:
    return target.split("?", 1)[0]


def _find_exchange(
    evidence: EvidenceSet,
    root: Path,
    method: str,
    path_predicate,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """在同一条连接上定位请求及其对应响应。

    relay 按连接分文件，同一连接的第 N 个请求对应第 N 个响应，因此可以按序配对。
    """

    relay_root = root / RELAY_DIR
    for request_path in sorted(relay_root.glob("conn*.client_to_upstream.bin")):
        response_path = request_path.with_name(
            request_path.name.replace("client_to_upstream", "upstream_to_client")
        )
        if response_path.is_symlink() or not response_path.is_file():
            continue
        evidence.bind(request_path)
        evidence.bind(response_path)
        requests = list(_iter_requests(request_path.read_bytes()))
        responses = list(_iter_responses(response_path.read_bytes()))
        for index, request in enumerate(requests):
            if request["method"] != method or not path_predicate(
                _path_of(request["target"])
            ):
                continue
            if index >= len(responses):
                raise ScenarioFactsError(
                    f"{method} {_path_of(request['target'])} 没有对应的响应字节。"
                )
            return request, responses[index]
    raise ScenarioFactsError(f"relay 字节中没有 {method} 目标请求。")


def _find_exchanges(
    evidence: EvidenceSet,
    root: Path,
    method: str,
    path_predicate,
) -> list[dict[str, Any]]:
    """返回所有目标交换及其连接编号，供同根多分支场景做精确归属。"""

    relay_root = root / RELAY_DIR
    exchanges: list[dict[str, Any]] = []
    for request_path in sorted(relay_root.glob("conn*.client_to_upstream.bin")):
        match = re.fullmatch(r"conn([0-9]+)\.client_to_upstream\.bin", request_path.name)
        if match is None:
            continue
        response_path = request_path.with_name(
            request_path.name.replace("client_to_upstream", "upstream_to_client")
        )
        if response_path.is_symlink() or not response_path.is_file():
            continue
        evidence.bind(request_path)
        evidence.bind(response_path)
        requests = list(_iter_requests(request_path.read_bytes()))
        responses = list(_iter_responses(response_path.read_bytes()))
        for index, request in enumerate(requests):
            if request["method"] != method or not path_predicate(
                _path_of(request["target"])
            ):
                continue
            if index >= len(responses):
                raise ScenarioFactsError(
                    f"{method} {_path_of(request['target'])} 没有对应的响应字节。"
                )
            exchanges.append({
                "connection_id": int(match.group(1)),
                "request": request,
                "response": responses[index],
                "request_path": request_path,
                "response_path": response_path,
            })
    if not exchanges:
        raise ScenarioFactsError(f"relay 字节中没有 {method} 目标请求。")
    return exchanges


def _relay_manifest_connections(
    evidence: EvidenceSet,
    root: Path,
) -> dict[int, dict[str, Any]]:
    """读取 relay.json，并把连接身份闭合为唯一整数编号。"""

    path = root / RELAY_DIR / "relay.json"
    if path.is_symlink() or not path.is_file():
        raise ScenarioFactsError("A11 缺少 relay/relay.json，无法区分自然与受控响应。")
    evidence.bind(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScenarioFactsError(f"relay.json 不可读：{error}") from error
    if not isinstance(payload, dict) or payload.get("schema_version") != "byte-relay/v1":
        raise ScenarioFactsError("relay.json schema_version 不匹配。")
    raw_connections = payload.get("connections")
    if not isinstance(raw_connections, list):
        raise ScenarioFactsError("relay.json connections 必须是数组。")
    connections: dict[int, dict[str, Any]] = {}
    for item in raw_connections:
        if not isinstance(item, dict):
            raise ScenarioFactsError("relay.json connection 必须是对象。")
        connection_id = item.get("connection_id")
        if (
            not isinstance(connection_id, int)
            or isinstance(connection_id, bool)
            or connection_id < 1
            or connection_id in connections
        ):
            raise ScenarioFactsError("relay.json connection_id 缺失、非法或重复。")
        connections[connection_id] = item
    return connections


def _verify_manifest_exchange(
    exchange: dict[str, Any],
    connection: dict[str, Any],
) -> None:
    """核对 relay 元数据确实绑定到本连接最终字节，而非旁路声明。"""

    if connection.get("valid") is not True:
        raise ScenarioFactsError("A11 目标连接未被 relay 标为 valid。")
    request = exchange["request"]
    expected_line = f"{request['method']} {request['target']} HTTP/1.1"
    if connection.get("request_line") != expected_line:
        raise ScenarioFactsError("A11 relay request_line 与目标请求字节不一致。")
    sizes = connection.get("bytes")
    digests = connection.get("sha256")
    if not isinstance(sizes, dict) or not isinstance(digests, dict):
        raise ScenarioFactsError("A11 relay 元数据缺少字节绑定。")
    for direction, key in (
        ("client_to_upstream", "request_path"),
        ("upstream_to_client", "response_path"),
    ):
        path = exchange[key]
        if sizes.get(direction) != path.stat().st_size or digests.get(direction) != _sha256(path):
            raise ScenarioFactsError(f"A11 relay {direction} 元数据与最终字节不一致。")


def _call_id_from_response(response: dict[str, Any]) -> str:
    """从 call-create 的 Location 头提取并校验 call_id。"""

    location = response["headers"].get("location", "")
    call_id = location.rstrip("/").rsplit("/", 1)[-1] if "/" in location else ""
    if not call_id or not CALL_ID_RE.fullmatch(call_id):
        raise ScenarioFactsError(
            f"call-create 响应的 Location 未给出 call_id：{location[:120]!r}"
        )
    return call_id


def _realtime_success_events(
    evidence: EvidenceSet,
    root: Path,
    name: str,
) -> tuple[str, int]:
    """从官方 app-server 事件中提取成功终态及收尾错误次数。"""

    events = _load_observation(evidence, root, name)
    notifications = _require(events, "notifications", "A11 事件日志")
    if not isinstance(notifications, list):
        raise ScenarioFactsError("A11 事件日志 notifications 必须是数组。")
    final_event = None
    final_index = -1
    for index, item in enumerate(notifications):
        method = _method_of(item)
        if method == "thread/realtime/started":
            final_event = "thread_realtime_started"
            final_index = index
        elif method == "thread/realtime/sdp":
            if final_event is None:
                final_event = "sdp_answer"
            final_index = index
    if final_event is None:
        raise ScenarioFactsError("realtime 没有 started／SDP 最终事件。")

    in_session_errors = 0
    teardown_errors = 0
    for index, item in enumerate(notifications):
        if _method_of(item) != "thread/realtime/error":
            continue
        if index <= final_index:
            in_session_errors += 1
            continue
        tail = {_method_of(x) for x in notifications[index + 1 :]}
        if tail - {"thread/realtime/closed", "thread/realtime/error"}:
            in_session_errors += 1
        else:
            teardown_errors += 1
    if in_session_errors:
        raise ScenarioFactsError(
            f"realtime 会话期内出现 {in_session_errors} 次异步 error。"
        )
    return final_event, teardown_errors


def _live_failure_message_sha256(
    evidence: EvidenceSet,
    root: Path,
    response: dict[str, Any],
) -> str:
    """绑定自然 400 响应与 app-server error，并返回规范化消息摘要。"""

    events = _load_observation(evidence, root, "A11-realtime-live-events.json")
    notifications = _require(events, "notifications", "A11 自然事件日志")
    if not isinstance(notifications, list):
        raise ScenarioFactsError("A11 自然事件日志 notifications 必须是数组。")
    if any(
        _method_of(item) in {"thread/realtime/started", "thread/realtime/sdp"}
        for item in notifications
    ):
        raise ScenarioFactsError("A11 自然失败事件中混入了成功终态。")
    messages: list[str] = []
    for item in notifications:
        if _method_of(item) != "thread/realtime/error" or not isinstance(item, dict):
            continue
        params = item.get("params")
        message = params.get("message") if isinstance(params, dict) else None
        if isinstance(message, str) and message:
            messages.append(message)
    if len(messages) != 1:
        raise ScenarioFactsError("A11 自然失败必须留下且只留下一个带消息的 realtime error。")

    try:
        response_payload = json.loads(response["body"].decode("utf-8"))
        event_payload = json.loads(messages[0])
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ScenarioFactsError(f"A11 自然 400 错误体不是可比对 JSON：{error}") from error
    if response_payload != event_payload:
        raise ScenarioFactsError("A11 自然 400 响应与 app-server error 消息不一致。")
    canonical = json.dumps(
        event_payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


# --------------------------------------------------------------------------
# pcap ClientHello
# --------------------------------------------------------------------------


def _client_hellos(evidence: EvidenceSet, root: Path) -> list[tuple[str, float]]:
    """返回 (SNI, 捕获时刻) 列表。缺少可解析的 ClientHello 即失败。"""

    found: list[tuple[str, float]] = []
    seen_pcap = False
    for relative in PCAP_RELATIVE:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            continue
        if path.stat().st_size < MIN_PCAP_BYTES:
            raise ScenarioFactsError(f"pcap 只有全局头，没有数据包：{relative}")
        seen_pcap = True
        evidence.bind(path)
        for link, captured_at, data in iter_timed_packets(path):
            segment = tcp_payload(link, data)
            if segment is None:
                continue
            hello = parse_client_hello(segment[2])
            if hello and hello[0]:
                found.append((hello[0], captured_at))
    if not seen_pcap:
        raise ScenarioFactsError("缺少 pcap 证据，无法取得 SNI。")
    if not found:
        raise ScenarioFactsError("pcap 中没有可解析的 ClientHello。")
    return found


def _require_sni(hellos: list[tuple[str, float]], expected: str) -> float:
    times = [when for name, when in hellos if name == expected]
    if not times:
        raise ScenarioFactsError(f"pcap 中没有 {expected} 的 ClientHello。")
    return min(times)


# --------------------------------------------------------------------------
# 逐场景提取
# --------------------------------------------------------------------------


def _facts_a11(evidence: EvidenceSet, root: Path) -> dict[str, Any]:
    exchanges = _find_exchanges(
        evidence,
        root,
        "POST",
        lambda path: path.endswith("/backend-api/codex/realtime/calls"),
    )
    connections = _relay_manifest_connections(evidence, root)
    by_connection = {exchange["connection_id"]: exchange for exchange in exchanges}
    if len(by_connection) != len(exchanges):
        raise ScenarioFactsError("A11 同一连接出现多个 call-create，无法闭合分支归属。")
    for connection_id, exchange in by_connection.items():
        connection = connections.get(connection_id)
        if connection is None:
            raise ScenarioFactsError(f"relay.json 缺少 A11 连接 {connection_id}。")
        _verify_manifest_exchange(exchange, connection)

    controlled_ids = [
        connection_id
        for connection_id, connection in connections.items()
        if connection.get("intervention") == A11_CONTROLLED_INTERVENTION
    ]
    hellos = _client_hellos(evidence, root)
    _require_sni(hellos, "api.openai.com")

    if controlled_ids:
        if len(controlled_ids) != 1:
            raise ScenarioFactsError("A11 复合模式必须且只能有一次受控 first-hop 响应。")
        controlled_id = controlled_ids[0]
        controlled = by_connection.get(controlled_id)
        controlled_meta = connections[controlled_id]
        if controlled is None:
            raise ScenarioFactsError("A11 受控干预没有对应的 call-create 字节。")
        live_candidates = [
            exchange
            for connection_id, exchange in by_connection.items()
            if connection_id != controlled_id
            and connections[connection_id].get("realtime_call_attempt") == 1
            and connections[connection_id].get("realtime_call_action")
            == "forward_to_production"
            and not connections[connection_id].get("intervention")
        ]
        if len(live_candidates) != 1:
            raise ScenarioFactsError("A11 复合模式缺少唯一的第一次自然上游请求。")
        live = live_candidates[0]
        live_meta = connections[live["connection_id"]]
        if (
            controlled_meta.get("realtime_call_attempt") != 2
            or controlled_meta.get("realtime_call_action") != "synthetic_response"
        ):
            raise ScenarioFactsError("A11 受控响应不是紧随自然请求的第二次 first-hop。")
        live_opened = live_meta.get("opened_at_unix_ms")
        controlled_opened = controlled_meta.get("opened_at_unix_ms")
        if (
            not isinstance(live_opened, int)
            or isinstance(live_opened, bool)
            or not isinstance(controlled_opened, int)
            or isinstance(controlled_opened, bool)
            or live_opened >= controlled_opened
        ):
            raise ScenarioFactsError("A11 自然请求与受控请求的墙钟顺序不成立。")
        live_response = live["response"]
        controlled_response = controlled["response"]
        if live_response["status"] != 400:
            raise ScenarioFactsError(
                f"A11 复合模式要求自然第一跳为 400，实际为 {live_response['status']}。"
            )
        if not 200 <= controlled_response["status"] <= 299:
            raise ScenarioFactsError("A11 受控第一跳没有返回 2xx。")
        live_message_sha256 = _live_failure_message_sha256(
            evidence,
            root,
            live_response,
        )
        call_id = _call_id_from_response(controlled_response)
        final_event, teardown_errors = _realtime_success_events(
            evidence,
            root,
            "A11-realtime-events.json",
        )
        if not _sideband_joins_call(evidence, root, call_id):
            raise ScenarioFactsError(
                "relay 字节中没有与受控 call-create 同 call_id 的官方 sideband 连接。"
            )
        return {
            "observation_mode": "live_failure_plus_controlled_branch",
            "live_failure_status": 400,
            "live_failure_message_sha256": live_message_sha256,
            "controlled_call_create_status": controlled_response["status"],
            "controlled_call_id_sha256": hashlib.sha256(
                call_id.encode("utf-8")
            ).hexdigest(),
            "controlled_intervention": A11_CONTROLLED_INTERVENTION,
            "sdp_or_started_event": final_event,
            "async_error_count": 0,
            "teardown_error_count": teardown_errors,
            "sideband_sni": "api.openai.com",
            "sideband_call_id_linked": True,
        }

    # 纯自然成功模式：目标 2xx 所在连接不得带任何受控干预。存在旧的立即合成
    # `synthesize_realtime_call` 时不会误入这里，因此受控诊断不能冒充正式成功。
    live_successes = [
        exchange
        for connection_id, exchange in by_connection.items()
        if 200 <= exchange["response"]["status"] <= 299
        and not connections[connection_id].get("intervention")
    ]
    if len(live_successes) != 1:
        statuses = [exchange["response"]["status"] for exchange in exchanges]
        raise ScenarioFactsError(
            f"A11 没有唯一、未受控的自然 2xx call-create：{statuses}。"
        )
    live = live_successes[0]
    response = live["response"]
    call_id = _call_id_from_response(response)
    live_events_name = (
        "A11-realtime-live-events.json"
        if (root / OBSERVATION_DIR / "A11-realtime-live-events.json").is_file()
        else "A11-realtime-events.json"
    )
    final_event, teardown_errors = _realtime_success_events(
        evidence,
        root,
        live_events_name,
    )
    if not _sideband_joins_call(evidence, root, call_id):
        raise ScenarioFactsError("relay 字节中没有与 call-create 同 call_id 的 sideband 连接。")
    return {
        "observation_mode": "live_success",
        "call_create_status": response["status"],
        "call_id_sha256": hashlib.sha256(call_id.encode("utf-8")).hexdigest(),
        "sdp_or_started_event": final_event,
        "async_error_count": 0,
        "teardown_error_count": teardown_errors,
        "sideband_sni": "api.openai.com",
        "sideband_call_id_linked": True,
    }


def _method_of(item: Any) -> str:
    return item.get("method", "") if isinstance(item, dict) else ""


def _sideband_joins_call(evidence: EvidenceSet, root: Path, call_id: str) -> bool:
    """在 relay 字节里找出与 call-create 同 call_id 的 sideband WS 升级请求。

    V3（FramelessBidi）把 call_id 拼在**路径末段**（`/v1/live/{call_id}`），
    V1／V2 才用 query `?call_id=`（`codex-api/.../methods.rs:985-993`）。两种形态都
    接受，但都必须是本轮 call-create 返回的那个 call_id——这正是 sideband 与第一跳
    真实关联的证明，而不是驱动自己声称的。
    """

    relay_root = root / RELAY_DIR
    for path in sorted(relay_root.glob("conn*.client_to_upstream.bin")):
        evidence.bind(path)
        for request in _iter_requests(path.read_bytes()):
            if request["headers"].get("upgrade", "").lower() != "websocket":
                continue
            target = request["target"]
            path_part = _path_of(target)
            query = target[len(path_part) + 1 :] if "?" in target else ""
            if path_part.rstrip("/").endswith(f"/{call_id}"):
                return True
            if f"call_id={call_id}" in query:
                return True
    return False


def _facts_a13(evidence: EvidenceSet, root: Path) -> dict[str, Any]:
    request, response = _find_exchange(
        evidence, root, "POST", lambda path: path.endswith("/oauth/token")
    )
    del response
    hellos = _client_hellos(evidence, root)
    _require_sni(hellos, "auth.openai.com")

    observation = _load_observation(evidence, root, "A13-jwt-exp.json")
    restore = _load_observation(evidence, root, "A13-credential-restore.json")
    before = _require(restore, "before_sha256", "A13 凭据记录")
    after = _require(restore, "after_sha256", "A13 凭据记录")
    if _require(restore, "capture_side_wrote_auth", "A13 凭据记录") is not False:
        raise ScenarioFactsError("采集侧写过 auth.json，A13 不接受受控篡改。")
    # 不再要求 before != after。SPEC-EP-002 只约束「刷新到 auth.openai.com」，不约束
    # 上游回什么；经中继时 TLS 指纹与官方 CLI 不同会被 Cloudflare 403，凭据因此不变。
    # 判据保留的是「采集侧没写过 auth.json」这条防伪造前提。
    return {
        "token_request_method": request["method"],
        "token_request_path": _path_of(request["target"]),
        "oauth_sni": "auth.openai.com",
        "jwt_exp_observation": {
            "exp_at_utc": _require(observation, "exp_at_utc", "A13 JWT 观测"),
            "observed_at_utc": _require(
                observation, "observed_at_utc", "A13 JWT 观测"
            ),
            "trigger": _require(observation, "trigger", "A13 JWT 观测"),
            "token_sha256": _require(observation, "token_sha256", "A13 JWT 观测"),
        },
        "credential_restore": {
            "before_sha256": before,
            "after_sha256": after,
            "capture_side_wrote_auth": False,
        },
    }


def _json_document(body: bytes, label: str) -> dict[str, Any]:
    """把原始 Body 解为闭合 JSON 对象。"""

    try:
        document = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ScenarioFactsError(f"{label}不可解析：{error}") from error
    if not isinstance(document, dict):
        raise ScenarioFactsError(f"{label}顶层必须是对象。")
    return document


def _json_boolean_state(document: dict[str, Any], field: str, label: str) -> str:
    """提取 JSON 布尔字段三态，拒绝数字、字符串等宽松值。"""

    if field not in document:
        return "absent"
    value = document[field]
    if value is True:
        return "true"
    if value is False:
        return "false"
    raise ScenarioFactsError(f"{label}.{field} 必须是 JSON 布尔值。")


def _exchange_seen_at(exchange: dict[str, Any], connection: dict[str, Any]) -> float:
    """用连接绝对时刻和原始 write segment 定位请求首字节的 Unix 秒。"""

    opened = connection.get("opened_at_unix_ms")
    segments = connection.get("segments")
    offset = exchange["request"].get("start_offset")
    if (
        not isinstance(opened, (int, float))
        or isinstance(opened, bool)
        or not isinstance(segments, list)
        or not isinstance(offset, int)
    ):
        raise ScenarioFactsError("A14 relay 缺少请求时刻或 segment 偏移。")
    matches = []
    for segment in segments:
        if not isinstance(segment, dict) or segment.get("direction") != "client_to_upstream":
            continue
        start = segment.get("offset")
        length = segment.get("length")
        elapsed = segment.get("t_ms")
        if (
            isinstance(start, int)
            and isinstance(length, int)
            and length > 0
            and isinstance(elapsed, (int, float))
            and not isinstance(elapsed, bool)
            and start <= offset < start + length
        ):
            matches.append(float(elapsed))
    if len(matches) != 1:
        raise ScenarioFactsError("A14 请求首字节无法唯一映射到 relay segment。")
    return float(opened) / 1000.0 + matches[0] / 1000.0


def _a14_original_create_response(
    evidence: EvidenceSet,
    root: Path,
    connection_id: int,
) -> dict[str, Any]:
    """读取正向受控场景保留的生产 create 原始响应。"""

    path = root / RELAY_DIR / f"conn{connection_id:03d}.upstream_original.bin"
    if path.is_symlink() or not path.is_file():
        raise ScenarioFactsError("A14 C2PA 正向样本缺少注入前生产响应原始字节。")
    evidence.bind(path)
    responses = list(_iter_responses(path.read_bytes()))
    if len(responses) != 1:
        raise ScenarioFactsError("A14 注入前生产响应必须且只能包含一个 HTTP 响应。")
    return responses[0]


def _facts_a14(
    evidence: EvidenceSet,
    root: Path,
    c2pa_expectation: str,
) -> dict[str, Any]:
    if c2pa_expectation not in A14_C2PA_EXPECTATIONS:
        raise ScenarioFactsError("A14 必须显式冻结 positive／negative C2PA 条件。")

    create_exchanges = _find_exchanges(
        evidence, root, "POST", lambda path: path == "/backend-api/files"
    )
    if len(create_exchanges) != 1:
        raise ScenarioFactsError("A14 必须且只能有一次 file create。")
    create_exchange = create_exchanges[0]
    create_request = create_exchange["request"]
    create_response = create_exchange["response"]
    if not 200 <= create_response["status"] <= 299:
        raise ScenarioFactsError(
            f"file create 返回 {create_response['status']}，上传链未开始。"
        )
    create_request_document = _json_document(
        create_request["body"], "file create 请求体"
    )
    create_response_document = _json_document(
        create_response["body"], "file create 响应体"
    )
    file_id = create_response_document.get("file_id")
    upload_url = create_response_document.get("upload_url")
    if not isinstance(file_id, str) or not file_id:
        raise ScenarioFactsError("file create 响应没有 file_id。")
    if not isinstance(upload_url, str) or "://" not in upload_url:
        raise ScenarioFactsError("file create 响应没有 upload_url。")
    delivered_state = _json_boolean_state(
        create_response_document,
        "pdf_c2pa_reservation",
        "file create 响应",
    )

    connections = _relay_manifest_connections(evidence, root)
    create_connection = connections.get(create_exchange["connection_id"])
    if create_connection is None:
        raise ScenarioFactsError("A14 create 连接不在 relay.json。")
    original_path = (
        root
        / RELAY_DIR
        / f"conn{create_exchange['connection_id']:03d}.upstream_original.bin"
    )
    control = create_connection.get("file_c2pa_control")
    request_control = create_connection.get("file_c2pa_request_control")

    if c2pa_expectation == "positive":
        if delivered_state != "true":
            raise ScenarioFactsError("A14 C2PA 正向样本的交付响应没有 true 条件。")
        original_response = _a14_original_create_response(
            evidence, root, create_exchange["connection_id"]
        )
        if not 200 <= original_response["status"] <= 299:
            raise ScenarioFactsError("A14 注入前生产 create 响应不是 2xx。")
        original_document = _json_document(
            original_response["body"], "A14 注入前生产响应体"
        )
        original_state = _json_boolean_state(
            original_document,
            "pdf_c2pa_reservation",
            "A14 注入前生产响应",
        )
        original_without_condition = dict(original_document)
        delivered_without_condition = dict(create_response_document)
        original_without_condition.pop("pdf_c2pa_reservation", None)
        delivered_without_condition.pop("pdf_c2pa_reservation", None)
        if original_without_condition != delivered_without_condition:
            raise ScenarioFactsError("A14 受控响应除 C2PA 条件外还改写了其他字段。")
        response_mutated = original_state != "true"
        expected_control = {
            "request_accept_encoding_forced_identity": True,
            "original_response_bound": True,
            "production_response_state": original_state,
            "delivered_response_state": "true",
            "response_mutated": response_mutated,
            "status_2xx": True,
        }
        if control != expected_control:
            raise ScenarioFactsError("A14 C2PA relay 控制元数据与原始响应不一致。")
        if (
            not isinstance(request_control, dict)
            or set(request_control)
            != {"accept_encoding_changed", "forwarded_accept_encoding"}
            or not isinstance(request_control["accept_encoding_changed"], bool)
            or request_control["forwarded_accept_encoding"] != "identity"
        ):
            raise ScenarioFactsError("A14 C2PA 正向样本没有冻结 identity 响应控制。")
        observation_mode = (
            "natural_positive" if original_state == "true" else "controlled_positive"
        )
        original_response_bound = True
        request_accept_encoding_forced_identity = True
    else:
        if delivered_state not in {"absent", "false"}:
            raise ScenarioFactsError("A14 C2PA 负向样本意外收到 true 条件。")
        if original_path.exists() or control is not None or request_control is not None:
            raise ScenarioFactsError("A14 C2PA 负向样本混入了正向受控响应。")
        original_state = delivered_state
        response_mutated = False
        observation_mode = "natural_negative"
        original_response_bound = False
        request_accept_encoding_forced_identity = False

    uploaded_path = f"/backend-api/files/{file_id}/uploaded"
    uploaded_exchanges = _find_exchanges(
        evidence, root, "POST", lambda path: path == uploaded_path
    )
    uploaded_documents = [
        _json_document(exchange["request"]["body"], "file uploaded 请求体")
        for exchange in uploaded_exchanges
    ]
    uploaded_body_hashes = {
        _canonical_json_sha256(document) for document in uploaded_documents
    }
    if len(uploaded_body_hashes) != 1:
        raise ScenarioFactsError("A14 uploaded retry 的 Body 语义不一致。")
    if c2pa_expectation == "positive":
        if any(
            set(document) != {"pdf_c2pa_create_request"}
            or document["pdf_c2pa_create_request"] != create_request_document
            for document in uploaded_documents
        ):
            raise ScenarioFactsError(
                "A14 C2PA 正向 uploaded Body 未逐 JSON 回放 create 请求。"
            )
        body_mode = "pdf_c2pa_create_request"
        embedded_create_request_matches = True
    else:
        if any(document != {} for document in uploaded_documents):
            raise ScenarioFactsError("A14 C2PA 负向 uploaded Body 必须是空对象。")
        body_mode = "empty_object"
        embedded_create_request_matches = False

    host = upload_url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
    if not REGIONAL_SNI_RE.fullmatch(host):
        raise ScenarioFactsError(f"upload_url 主机不是区域上传主机：{host}")
    hellos = _client_hellos(evidence, root)
    # 区域主机必须由本轮响应派生：预列域名凑出的 SNI 不满足这一条。
    regional_times = [when for name, when in hellos if name == host]
    if not regional_times:
        raise ScenarioFactsError(
            f"pcap 中没有响应返回的区域主机 {host} 的 ClientHello。"
        )

    create_at = _exchange_seen_at(create_exchange, create_connection)
    uploaded_times: list[float] = []
    for exchange in uploaded_exchanges:
        connection = connections.get(exchange["connection_id"])
        if connection is None:
            raise ScenarioFactsError("A14 uploaded 连接不在 relay.json。")
        uploaded_times.append(_exchange_seen_at(exchange, connection))
    first_seen = min(regional_times)
    last_seen = max(regional_times)
    if not create_at <= first_seen:
        raise ScenarioFactsError("create 不早于区域连接，URL 来源无法证明。")
    if not first_seen <= min(uploaded_times):
        raise ScenarioFactsError("区域 PUT 连接不早于 uploaded，请求顺序无法证明。")

    tool = _load_observation(evidence, root, "A14-tool-call.json")
    return {
        "tool_name": _require(tool, "tool_name", "A14 工具调用记录"),
        "tool_call_id": _require(tool, "tool_call_id", "A14 工具调用记录"),
        "create_request": {
            "method": "POST",
            "path": "/backend-api/files",
            "status_2xx": True,
            "json_sha256": _canonical_json_sha256(create_request_document),
        },
        "c2pa_condition": {
            "expectation": c2pa_expectation,
            "observation_mode": observation_mode,
            "production_response_state": original_state,
            "delivered_response_state": delivered_state,
            "response_mutated": response_mutated,
            "original_response_bound": original_response_bound,
            "request_accept_encoding_forced_identity": (
                request_accept_encoding_forced_identity
            ),
        },
        "uploaded_request": {
            "method": "POST",
            "file_id_linked": True,
            "attempt_count": len(uploaded_exchanges),
            "body_mode": body_mode,
            "body_json_sha256": next(iter(uploaded_body_hashes)),
            "embedded_create_request_matches": embedded_create_request_matches,
        },
        "upload_url_source_event": {
            "event": "file_create_response",
            "host": host,
            "url_sha256": hashlib.sha256(upload_url.encode("utf-8")).hexdigest(),
        },
        "put_destination": {
            "host": host,
            "sni": host,
            "first_seen_at_utc": _utc(first_seen),
            "last_seen_at_utc": _utc(last_seen),
        },
        "regional_sni": host,
        "regional_host_from_response": True,
        "upload_sequence": {
            "create_before_regional": True,
            "regional_before_uploaded": True,
        },
    }


def _ordered(earlier: str, later: str) -> bool:
    try:
        first = datetime.fromisoformat(str(earlier).replace("Z", "+00:00"))
        second = datetime.fromisoformat(str(later).replace("Z", "+00:00"))
    except ValueError as error:
        raise ScenarioFactsError(f"时间不可比较：{earlier} / {later}") from error
    if first.tzinfo is None or second.tzinfo is None:
        raise ScenarioFactsError("上传顺序时间必须带时区。")
    return first <= second


EXTRACTORS = {
    "A11": _facts_a11,
    "A13": _facts_a13,
}


def build(
    scenario_id: str,
    job_id: str,
    run_id: str,
    run_root: Path,
    output: Path | None = None,
    *,
    a14_c2pa_expectation: str | None = None,
) -> dict[str, Any]:
    """提取一个场景的原始事实；证据不足即抛 ScenarioFactsError。"""

    if scenario_id not in {*EXTRACTORS, "A14"}:
        raise ScenarioFactsError(f"R0 未登记场景：{scenario_id}")
    if run_root.is_symlink() or not run_root.is_dir():
        raise ScenarioFactsError(f"run 目录不可用：{run_root}")
    evidence = EvidenceSet(run_root)
    if scenario_id == "A14":
        facts = _facts_a14(
            evidence,
            run_root,
            a14_c2pa_expectation or "",
        )
    else:
        facts = EXTRACTORS[scenario_id](evidence, run_root)
    destination = output or (run_root / FACTS_DIR / f"{scenario_id}-facts.json")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        return build_facts_document(
            scenario_id=scenario_id,
            job_id=job_id,
            run_id=run_id,
            facts=facts,
            evidence_bindings=evidence.bindings(),
            observed_at_utc=_utc(datetime.now(tz=timezone.utc).timestamp()),
            approved_roots={EVIDENCE_ROOT_ROLE: run_root},
            output=destination,
        )
    except ScenarioReceiptError as error:
        raise ScenarioFactsError(f"原始事实未通过契约校验：{error}") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", required=True, choices=list(SUPPORTED_SCENARIOS))
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument(
        "--a14-c2pa-expectation",
        choices=A14_C2PA_EXPECTATIONS,
        default=None,
        help="A14 必填：冻结 uploaded Body 的正向或负向条件。",
    )
    args = parser.parse_args(argv)
    try:
        document = build(
            args.scenario,
            args.job_id,
            args.run_id,
            args.run_root,
            args.output,
            a14_c2pa_expectation=args.a14_c2pa_expectation,
        )
    except (ScenarioFactsError, OSError) as error:
        print(f"错误：{error}", file=sys.stderr)
        # 诊断不进收据体系、不参与判定，只为排障保留失败形态。
        try:
            diagnostic = args.run_root / FACTS_DIR / f"{args.scenario}-scenario-failure.json"
            diagnostic.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            write_failure_diagnostic(
                diagnostic, scenario_id=args.scenario, reason=str(error)
            )
        except OSError:
            pass
        return 2
    print(
        json.dumps(
            {
                "scenario_id": document["scenario_id"],
                "final_state": document["final_state"],
                "evidence_bindings": len(document["evidence_bindings"]),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
