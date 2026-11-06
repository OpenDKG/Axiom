#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Bounded soak for the Linux service + browser UI. It never changes firewall, DNS or proxy state;
# it runs from the published payload in an isolated data directory and prints measured metrics.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
duration="${DURATION:-90}"
payload="${PAYLOAD:-$root/artifacts/publish/linux}"
service_bin="$payload/service/Axiom.Service"
ui_bin="$payload/ui/Axiom.Desktop.Linux"

[[ -x "$service_bin" && -x "$ui_bin" ]] || {
  echo "published payload missing; run scripts/publish-linux.sh first" >&2
  exit 1
}

work="$(mktemp -d /tmp/axiom-soak.XXXXXX)"
data="$work/data"
run="$work/run"
mkdir -p "$data" "$run"
chmod 700 "$data" "$run"

port=$((20000 + RANDOM % 20000))
service_pid=""
ui_pid=""
cleanup() {
  for pid in "$ui_pid" "$service_pid"; do
    [[ -n "$pid" ]] && kill -TERM "$pid" 2>/dev/null || true
  done
  sleep 2
  for pid in "$ui_pid" "$service_pid"; do
    [[ -n "$pid" ]] && kill -KILL "$pid" 2>/dev/null || true
  done
  rm -rf "$work"
}
trap cleanup EXIT

AXIOM_DATA_DIR="$data" \
AXIOM_IPC_SOCKET="$run/service.sock" \
AXIOM_ALLOWED_UID="$(id -u)" \
setsid "$service_bin" > "$work/service.log" 2>&1 < /dev/null &
service_pid=$!

for _ in $(seq 1 100); do
  [[ -S "$run/service.sock" ]] && break
  sleep 0.1
done
[[ -S "$run/service.sock" ]] || { echo "service socket did not appear" >&2; cat "$work/service.log" >&2; exit 1; }

setsid "$ui_bin" --port "$port" --no-browser --socket "$run/service.sock" > "$work/ui.log" 2>&1 < /dev/null &
ui_pid=$!
for _ in $(seq 1 100); do
  grep -q "Axiom UI:" "$work/ui.log" && break
  sleep 0.1
done
token="$(grep -o 't=[A-F0-9]*' "$work/ui.log" | head -1 | cut -d= -f2)"
[[ -n "$token" ]] || { echo "UI token missing" >&2; cat "$work/ui.log" >&2; exit 1; }

base="http://127.0.0.1:$port"
header="X-Axiom-Token: $token"

traffic_port=$((20000 + RANDOM % 20000))
python3 -m http.server "$traffic_port" --bind 127.0.0.1 --directory "$work" > /dev/null 2>&1 &
traffic_pid=$!
cleanup_all() { kill "$traffic_pid" 2>/dev/null || true; cleanup; }
trap cleanup_all EXIT

read_rss() {
  awk '/VmRSS/ {print $2}' "/proc/$1/status" 2>/dev/null || echo 0
}
read_threads() {
  awk '/Threads/ {print $2}' "/proc/$1/status" 2>/dev/null || echo 0
}
read_cpu_ticks() {
  awk '{print $14 + $15}' "/proc/$1/stat" 2>/dev/null || echo 0
}

service_rss_start="$(read_rss "$service_pid")"
ui_rss_start="$(read_rss "$ui_pid")"
service_cpu_start="$(read_cpu_ticks "$service_pid")"
started="$(date +%s)"
requests=0

load_client() {
  local local_requests=0
  while (( $(date +%s) - started < duration )); do
    for endpoint in       "$base/api/connections"       "$base/api/status"       "$base/api/history?hours=1&limit=200"       "$base/api/firewall"       "$base/api/history.csv?hours=1"; do
      if curl -fsS -o /dev/null -H "$header" "$endpoint"; then
        local_requests=$((local_requests + 1))
      else
        echo x >> "$work/errors"
      fi
    done
    sleep 0.05
  done
  echo "$local_requests" > "$work/requests.$1"
}

load_pids=()
for worker in 1 2 3; do
  load_client "$worker" &
  load_pids+=($!)
done

while (( $(date +%s) - started < duration )); do
  curl -fsS -o /dev/null "http://127.0.0.1:$traffic_port/" || true
  sleep 0.2
done

for pid in "${load_pids[@]}"; do
  wait "$pid" || true
done
for file in "$work"/requests.*; do
  requests=$((requests + $(cat "$file")))
done

service_cpu_end="$(read_cpu_ticks "$service_pid")"
elapsed=$(( $(date +%s) - started ))
service_rss_end="$(read_rss "$service_pid")"
ui_rss_end="$(read_rss "$ui_pid")"
service_threads="$(read_threads "$service_pid")"
ui_threads="$(read_threads "$ui_pid")"
connections="$(curl -fsS -H "$header" "$base/api/status" | grep -o '"connectionCount":[0-9]*' | cut -d: -f2)"
history_rows="$(curl -fsS -H "$header" "$base/api/history?hours=1&limit=1" | grep -o '"totalCount":[0-9]*' | cut -d: -f2)"
errors_count="$(wc -l < "$work/errors" 2>/dev/null || echo 0)"
hz="$(getconf CLK_TCK)"

cat <<EOF
soak_seconds=$elapsed
http_requests=$requests
http_errors=$errors_count
service_rss_kb_start=$service_rss_start
service_rss_kb_end=$service_rss_end
ui_rss_kb_start=$ui_rss_start
ui_rss_kb_end=$ui_rss_end
service_threads=$service_threads
ui_threads=$ui_threads
service_cpu_seconds=$(( (service_cpu_end - service_cpu_start) / hz ))
connections_last=$connections
history_rows_last=$history_rows
data_dir=$data
EOF

kill -TERM "$ui_pid" "$service_pid" 2>/dev/null || true
sleep 2
if [[ -S "$run/service.sock" ]]; then
  echo "socket_cleanup=failed"
else
  echo "socket_cleanup=ok"
fi
if [[ -f "$data/axiom.db" ]]; then
  echo "data_preserved=ok"
else
  echo "data_preserved=failed"
fi
