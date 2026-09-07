#!/bin/sh
# 容器健康检查与受控自愈：连续失败达到阈值时终止主进程，交给
# restart: unless-stopped 拉起；在时间窗口内达到上限后熔断，避免重启风暴。
set -eu

health_url="http://localhost:${SERVER_PORT:-8080}/health"
# 使用持久化数据卷保存熔断窗口；若放在 /tmp，容器每次重启都会清零计数，
# 无法阻止异常进程在短时间内反复重启。
state_dir="${SUB2API_HEALTHCHECK_STATE_DIR:-/app/data/.healthcheck}"
failure_file="$state_dir/failures"
restart_file="$state_dir/restarts"
now=$(date +%s)

parse_positive_integer() {
	value=$1
	default=$2
	case "$value" in
		''|*[!0-9]*) printf '%s' "$default" ;;
		0) printf '%s' "$default" ;;
		*) printf '%s' "$value" ;;
	esac
}

failure_threshold=$(parse_positive_integer "${SUB2API_HEALTHCHECK_FAILURE_THRESHOLD:-5}" 5)
restart_window=$(parse_positive_integer "${SUB2API_HEALTHCHECK_RESTART_WINDOW_SECONDS:-300}" 300)
max_restarts=$(parse_positive_integer "${SUB2API_HEALTHCHECK_MAX_RESTARTS:-3}" 3)
probe_timeout=$(parse_positive_integer "${SUB2API_HEALTHCHECK_TIMEOUT_SECONDS:-5}" 5)

mkdir -p "$state_dir"
cutoff=$((now - restart_window))

prune_timestamps() {
	file=$1
	[ -f "$file" ] || return 0
	tmp="$file.tmp"
	awk -v cutoff="$cutoff" '$1 >= cutoff {print $1}' "$file" > "$tmp"
	mv "$tmp" "$file"
}

prune_timestamps "$failure_file"
prune_timestamps "$restart_file"

if wget -q -T "$probe_timeout" -O /dev/null "$health_url"; then
	# 健康恢复后清除连续失败计数；重启计数保留到窗口自然过期，防止
	# “短暂恢复—再次失败”绕过重启熔断。
	rm -f "$failure_file"
	exit 0
fi

printf '%s\n' "$now" >> "$failure_file"
failure_count=$(wc -l < "$failure_file" | tr -d ' ')
if [ "$failure_count" -lt "$failure_threshold" ]; then
	echo "sub2apiplus health probe failed (${failure_count}/${failure_threshold})" >&2
	exit 1
fi

restart_count=$(wc -l < "$restart_file" | tr -d ' ')
if [ "$restart_count" -ge "$max_restarts" ]; then
	echo "sub2apiplus health recovery fuse open: ${restart_count} restarts in ${restart_window}s; manual intervention required" >&2
	exit 1
fi

printf '%s\n' "$now" >> "$restart_file"
echo "sub2apiplus health recovery: terminating PID 1 after ${failure_count} consecutive failed probes (${restart_count}/${max_restarts} restarts in window)" >&2
kill -TERM 1 2>/dev/null || true
# 对卡在 swap/系统调用中的进程保留一个很短的优雅退出窗口，随后强制结束，
# 确保 Docker 的 restart 策略能够真正接管恢复。
sleep 2
kill -KILL 1 2>/dev/null || true
exit 1
