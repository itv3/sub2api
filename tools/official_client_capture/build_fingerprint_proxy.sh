#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# 在受管源码上确定性交叉构建 Linux ARM64 采集转发器。输出先落在同目录临时
# 文件，验证架构后再原子安装，避免中止时留下半个可执行文件。

output=${1:?必须提供输出绝对路径}
if [[ $output != /* ]]; then
  echo "输出路径必须是绝对路径。" >&2
  exit 2
fi
tool_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source_root="$tool_root/fingerprint_proxy"
output_parent=$(dirname -- "$output")
if [[ -L $source_root || ! -f $source_root/go.mod || ! -f $source_root/main.go ]]; then
  echo "指纹转发器源码不完整。" >&2
  exit 1
fi
install -d -m 0700 "$output_parent"
temporary=$(mktemp "$output_parent/.codex-fingerprint-proxy.XXXXXX")
cleanup() { rm -f -- "$temporary"; }
trap cleanup EXIT INT TERM

(
  cd "$source_root"
  env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
    go build -trimpath -buildvcs=false -ldflags='-s -w' -o "$temporary" .
)
if [[ $(file -b "$temporary") != *"ARM aarch64"* ]]; then
  echo "指纹转发器产物不是 Linux ARM64。" >&2
  exit 1
fi
chmod 0700 "$temporary"
mv -f -- "$temporary" "$output"
trap - EXIT INT TERM
printf 'fingerprint_proxy_sha256=%s\n' "$(shasum -a 256 "$output" | awk '{print $1}')"
