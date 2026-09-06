#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# 本脚本由 start_mitm.sh 作为独立进程组的组长启动。第一层 mitmproxy 只负责
# 应用层 JSONL；第二层 Go 转发器负责以目标 Codex uTLS 画像连接真实上游。

proxy_bin=${CAPTURE_FINGERPRINT_PROXY_BIN:?缺少 CAPTURE_FINGERPRINT_PROXY_BIN}
profile_path=${CAPTURE_CODEX_PROFILE:?缺少 CAPTURE_CODEX_PROFILE}
codex_version=${CAPTURE_CODEX_VERSION:?缺少 CAPTURE_CODEX_VERSION}
mitmdump_bin=${CAPTURE_MITMDUMP_BIN:?缺少 CAPTURE_MITMDUMP_BIN}
mitm_addon=${CAPTURE_MITM_ADDON:?缺少 CAPTURE_MITM_ADDON}
mitm_confdir=${CAPTURE_MITM_CONFDIR:?缺少 CAPTURE_MITM_CONFDIR}
mitm_port=${CAPTURE_MITM_PORT:?缺少 CAPTURE_MITM_PORT}
upstream_port=${CAPTURE_FINGERPRINT_PROXY_PORT:-18082}
ingress_port=${CAPTURE_INGRESS_PORT:-18081}
tcp_max_segment=${CAPTURE_FINGERPRINT_TCP_MAXSEG:-1368}
target_hosts=${CAPTURE_TARGET_HOSTS:?缺少 CAPTURE_TARGET_HOSTS}

if [[ -L $proxy_bin || ! -f $proxy_bin || ! -x $proxy_bin ]]; then
  echo "指纹转发器不存在或不可信：$proxy_bin" >&2
  exit 1
fi
if [[ -L $profile_path || ! -f $profile_path ]]; then
  echo "Codex 画像不存在或不可信：$profile_path" >&2
  exit 1
fi
if [[ ! $upstream_port =~ ^[0-9]+$ ]] || (( upstream_port < 1024 || upstream_port > 65535 )); then
  echo "指纹转发器端口非法。" >&2
  exit 2
fi
if [[ ! $ingress_port =~ ^[0-9]+$ ]] || (( ingress_port < 1024 || ingress_port > 65535 )); then
  echo "Ingress 端口非法。" >&2
  exit 2
fi
if [[ $upstream_port == "$mitm_port" || $upstream_port == "$ingress_port" ]]; then
  echo "指纹转发器端口不得与 MITM 或 Ingress 端口相同。" >&2
  exit 2
fi
if [[ ! $tcp_max_segment =~ ^[0-9]+$ ]] || (( tcp_max_segment < 536 || tcp_max_segment > 65495 )); then
  echo "CAPTURE_FINGERPRINT_TCP_MAXSEG 必须为 536～65495 的整数。" >&2
  exit 2
fi

target_arguments=()
IFS=',' read -r -a target_values <<<"$target_hosts"
for target in "${target_values[@]}"; do
  [[ -n $target ]] || continue
  target_arguments+=(--target-host "$target")
done
if (( ${#target_arguments[@]} == 0 )); then
  echo "指纹转发器没有目标主机。" >&2
  exit 2
fi

proxy_pid=""
mitm_pid=""
cleanup() {
  local original_exit_code=$?
  trap - EXIT INT TERM
  set +e
  [[ -z $mitm_pid ]] || kill -TERM "$mitm_pid" >/dev/null 2>&1
  [[ -z $proxy_pid ]] || kill -TERM "$proxy_pid" >/dev/null 2>&1
  [[ -z $mitm_pid ]] || wait "$mitm_pid" >/dev/null 2>&1
  [[ -z $proxy_pid ]] || wait "$proxy_pid" >/dev/null 2>&1
  exit "$original_exit_code"
}
trap cleanup EXIT INT TERM

"$proxy_bin" \
  --listen "127.0.0.1:$upstream_port" \
  --profile "$profile_path" \
  --version "$codex_version" \
  --tcp-max-segment "$tcp_max_segment" \
  "${target_arguments[@]}" &
proxy_pid=$!

proxy_ready=0
for _ in $(seq 1 100); do
  if ! kill -0 "$proxy_pid" 2>/dev/null; then
    wait "$proxy_pid"
    exit $?
  fi
  if python3 - "$upstream_port" <<'PY'
import socket
import sys

with socket.socket() as client:
    client.settimeout(0.2)
    raise SystemExit(0 if client.connect_ex(("127.0.0.1", int(sys.argv[1]))) == 0 else 1)
PY
  then
    proxy_ready=1
    break
  fi
  sleep 0.1
done
if [[ $proxy_ready != 1 ]]; then
  echo "指纹转发器未在 10 秒内就绪。" >&2
  exit 1
fi

"$mitmdump_bin" \
  --listen-host 0.0.0.0 \
  --listen-port "$mitm_port" \
  --mode "upstream:http://127.0.0.1:$upstream_port" \
  --set "confdir=$mitm_confdir" \
  --set block_global=false \
  --set connection_strategy=lazy \
  --set ssl_insecure=true \
  -s "$mitm_addon" &
mitm_pid=$!

set +e
wait -n "$proxy_pid" "$mitm_pid"
pair_status=$?
set -e
exit "$pair_status"
