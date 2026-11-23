#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Live negative canary for the Linux enforcement boundary (PR #276 round 3, item 4).
#
# For a blocked test executable it launches N fresh, short-lived processes that connect
# immediately after exec, over IPv4 AND IPv6, to a real (non-loopback) target, and counts how
# many connects slipped through. A slip is a connect() that completed although the rule blocks
# the executable: the exec-to-attribution window of the nftables `socket cgroupv2` boundary.
#
# Topology (created and removed by this script; nothing else on the host is touched):
#
#   host netns                                   netns axcanary
#   axc0  10.231.0.1/30   fd00:a51:a51::1/64 <-veth-> axc1  10.231.0.2/30  fd00:a51:a51::2/64
#                                                     listener [::]:18080 (dual stack, HTTP 204)
#
# Loopback (127/8, ::1) is exempt in both the nft chains and the BPF programs, so a loopback
# target would prove nothing; the veth peer forces the normal output path (no IPv6 default
# route is needed on the host).
#
# Probes (both are copies of system binaries under /opt/axiom-canary, so blocking them does not
# block the system tools):
#   curl    /opt/axiom-canary/curl -g --connect-timeout 2 http://<addr>:18080/
#   python  /opt/axiom-canary/python3 -I -c 'socket.create_connection(...)'
#
# Modes:
#   unscoped  one unscoped outbound block rule per probe exe (BPF exe key + nft; expect 0 slips
#             when the connect-time layer is active and the exe key is usable)
#   scoped    the same rules scoped to remote port 18080 (nft-only by design: records the slip rate
#             of the attribution window honestly)
#
# Usage: sudo scripts/linux/canary.sh [unscoped|scoped] [--count N] [--keep-topology] [--no-rules]
#   --no-rules       do not apply/remove rules (rules applied by the caller)
#   --keep-topology  leave netns/veth/listener for a follow-up run (cleanup: --cleanup)
#   --cleanup        remove the topology and the probe copies, then exit
#
# Output: one line per (probe, family): "canary <mode> <probe> <family>: slipped S/N blocked B/N".
# Exit 0 always after a completed run (the numbers are the result); 2 on setup errors.
set -euo pipefail

MODE=unscoped
COUNT=50
KEEP=0
RULES=1
CLEANUP_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    unscoped|scoped) MODE=$1 ;;
    --count) COUNT=$2; shift ;;
    --keep-topology) KEEP=1 ;;
    --no-rules) RULES=0 ;;
    --cleanup) CLEANUP_ONLY=1 ;;
    *) echo "usage: $0 [unscoped|scoped] [--count N] [--keep-topology] [--no-rules] [--cleanup]" >&2; exit 2 ;;
  esac
  shift
done

[ "$(id -u)" = 0 ] || { echo "canary: run as root (sudo)" >&2; exit 2; }
HERE=$(cd "$(dirname "$0")" && pwd)
AXIPC=${AXIPC:-$HERE/axipc.py}
NS=axcanary
DIR=/opt/axiom-canary
PORT=18080
V4=10.231.0.2
V6=fd00:a51:a51::2
LISTENER_PID=""
RULE_IDS=()
ENABLED_PROTECTION=0

cleanup_topology() {
  if [ -f /run/axcanary-listener.pid ]; then
    local pid
    pid=$(cat /run/axcanary-listener.pid)
    kill "$pid" 2>/dev/null || true
    rm -f /run/axcanary-listener.pid
  fi
  ip netns del "$NS" 2>/dev/null || true
  ip link del axc0 2>/dev/null || true
}

remove_rules() {
  for id in "${RULE_IDS[@]}"; do
    python3 -I "$AXIPC" rule.remove "{\"managedRuleId\":\"$id\"}" >/dev/null 2>&1 || true
  done
  RULE_IDS=()
  if [ "$ENABLED_PROTECTION" = 1 ]; then
    python3 -I "$AXIPC" protection.disable >/dev/null 2>&1 || true
  fi
}

finish() {
  [ "$RULES" = 1 ] && remove_rules
  if [ "$KEEP" = 0 ]; then
    cleanup_topology
    rm -rf "$DIR"
  fi
}

if [ "$CLEANUP_ONLY" = 1 ]; then
  cleanup_topology
  rm -rf "$DIR"
  echo "canary: topology and $DIR removed"
  exit 0
fi

setup_topology() {
  if ip netns list | grep -qw "$NS"; then
    return
  fi

  ip netns add "$NS"
  ip link add axc0 type veth peer name axc1
  ip link set axc1 netns "$NS"
  ip addr add 10.231.0.1/30 dev axc0
  ip -6 addr add fd00:a51:a51::1/64 dev axc0 nodad
  ip link set axc0 up
  ip netns exec "$NS" ip addr add 10.231.0.2/30 dev axc1
  ip netns exec "$NS" ip -6 addr add fd00:a51:a51::2/64 dev axc1 nodad
  ip netns exec "$NS" ip link set axc1 up
  ip netns exec "$NS" ip link set lo up
  ip netns exec "$NS" python3 -I -c '
import socket, socketserver
class H(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.recv(1024)
            self.request.sendall(b"HTTP/1.0 204 No Content\r\nConnection: close\r\n\r\n")
        except OSError:
            pass
class S(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True
    daemon_threads = True
    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()
S(("::", 18080), H).serve_forever()
' >/dev/null 2>&1 &
  echo $! > /run/axcanary-listener.pid
  for _ in $(seq 1 50); do
    if ip netns exec "$NS" ss -ltnH "sport = :$PORT" | grep -q LISTEN; then
      break
    fi
    sleep 0.1
  done
}

setup_probes() {
  mkdir -p "$DIR"
  cp -f "$(readlink -f /usr/bin/curl)" "$DIR/curl"
  cp -f "$(readlink -f /usr/bin/python3)" "$DIR/python3"
  chmod 0755 "$DIR/curl" "$DIR/python3"
  "$DIR/python3" -I -c 'import socket' || { echo "canary: the python3 copy does not run" >&2; exit 2; }
}

apply_rule() {
  local exe=$1 id
  id=$(cat /proc/sys/kernel/random/uuid)
  local scope=""
  if [ "$MODE" = scoped ]; then
    scope=",\"remotePorts\":\"$PORT\",\"protocol\":\"tcp\""
  fi
  python3 -I "$AXIPC" rule.apply "{\"managedRuleId\":\"$id\",\"appPath\":\"$exe\",\"direction\":\"outbound\",\"action\":\"block\",\"enabled\":true,\"createdBy\":\"canary\"$scope}" > "/run/axcanary-apply-$id.json"
  RULE_IDS+=("$id")
  echo "canary: rule $id ($MODE) for $exe: $(python3 -I -c 'import json,sys; r=json.load(open(sys.argv[1])); r=r.get("result",r); print(r.get("state"), "connectTimeBlockingProven=%s" % r.get("connectTimeBlockingProven"), r.get("errorCode") or "")' "/run/axcanary-apply-$id.json")"
  rm -f "/run/axcanary-apply-$id.json"
}

probe_once() {
  local probe=$1 addr=$2
  case "$probe" in
    curl)
      local url="http://$addr:$PORT/"
      [[ "$addr" == *:* ]] && url="http://[$addr]:$PORT/"
      "$DIR/curl" -g -s -o /dev/null --connect-timeout 2 --max-time 3 "$url"
      ;;
    python)
      "$DIR/python3" -I -c 'import socket,sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2).close()' "$addr" "$PORT" 2>/dev/null
      ;;
  esac
}

trap finish EXIT
setup_topology
setup_probes

# Reachability baseline with the system binaries (never blocked): the target must answer on both families.
curl -g -s -o /dev/null --connect-timeout 2 "http://$V4:$PORT/" || { echo "canary: IPv4 target unreachable" >&2; exit 2; }
curl -g -s -o /dev/null --connect-timeout 2 "http://[$V6]:$PORT/" || { echo "canary: IPv6 target unreachable" >&2; exit 2; }
echo "canary: target reachable over IPv4 $V4 and IPv6 $V6 (veth to netns $NS)"

if [ "$RULES" = 1 ]; then
  # rule.apply needs the write gate; "ask" lists pending apps and blocks nothing by itself.
  python3 -I "$AXIPC" protection.enable '{"defaultPolicy":"ask"}' >/dev/null
  ENABLED_PROTECTION=1
  apply_rule "$DIR/curl"
  apply_rule "$DIR/python3"
  sleep 2 # let the attribution loop settle; every probe below is still a fresh exec
fi

for probe in curl python; do
  for family in ipv4 ipv6; do
    addr=$V4
    [ "$family" = ipv6 ] && addr=$V6
    slipped=0
    blocked=0
    for _ in $(seq 1 "$COUNT"); do
      if probe_once "$probe" "$addr"; then
        slipped=$((slipped + 1))
      else
        blocked=$((blocked + 1))
      fi
    done
    echo "canary $MODE $probe $family: slipped $slipped/$COUNT blocked $blocked/$COUNT"
  done
done
