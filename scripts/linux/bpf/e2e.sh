#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# End-to-end proof of the connect-time BPF layer (src/Axiom.Infrastructure.Linux/Bpf/BpfEngine.cs,
# programs in src/Axiom.Infrastructure.Linux/Bpf/native) on a cgroup v2 box with bpftool, kernel BTF,
# clang and libbpf-dev.
#
#   scripts/linux/bpf/e2e.sh            # part A: the BPF objects alone (builds, then re-execs under sudo -n)
#   scripts/linux/bpf/e2e.sh --daemon   # part A, then part B: the full axiomd path (install in place, IPC)
#
# Part A never touches the daemon's pins (/sys/fs/bpf/axiom): it uses /sys/fs/bpf/axiom-e2e. The only
# verdict entry ever written is /usr/bin/curl's exe inode (never a shell, never a system cgroup); the
# only process killed is the event helper this script started; everything created is removed.
set -u
URL=${AXIOM_E2E_URL:-https://example.com}
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
NATIVE="$ROOT/src/Axiom.Infrastructure.Linux/Bpf/native"
OUT="$NATIVE/out"
PIN=/sys/fs/bpf/axiom-e2e
CGROUP_ROOT=/sys/fs/cgroup
TARGET=/usr/bin/curl
RULE_ID=0f8fad5b-d9cb-469f-a165-70867728950e
DAEMON=0
[ "${1:-}" = "--daemon" ] && DAEMON=1
FAILED=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAILED=1; }

if [ "$(id -u)" != 0 ]; then
  export PATH="$HOME/.dotnet:$PATH" DOTNET_CLI_TELEMETRY_OPTOUT=1
  if ! make -C "$NATIVE" -s check-tools; then
    echo "blocked: the BPF toolchain is missing (see above); apt install clang libbpf-dev and re-run"
    exit 3
  fi
  make -C "$NATIVE" || exit 1
  if [ $DAEMON = 1 ]; then
    make -C "$NATIVE" install || exit 1
    ( cd "$ROOT" && dotnet publish src/Axiom.Service -f net10.0 -r linux-x64 -c Release --self-contained -o build/linux/axiomd -nologo -v q -m:2 -nr:false -p:UseSharedCompilation=false ) || exit 1
    ( cd "$ROOT" && git checkout -- '*.lock.json' )
    ls -l "$ROOT/build/linux/axiomd/bpf/" || { echo "bpf objects not in the publish tree"; exit 1; }
  fi
  exec sudo -n env AXIOM_E2E_URL="$URL" DOTNET_ROOT="${DOTNET_ROOT:-$HOME/.dotnet}" "$0" "$@"
fi

echo "## host: $(. /etc/os-release; echo "$PRETTY_NAME") kernel $(uname -r) $(bpftool version | head -1) cgroup $(stat -fc %T $CGROUP_ROOT) btf $(ls /sys/kernel/btf/vmlinux)"
[ -e "$PIN" ] && { echo "$PIN already exists; refusing to run"; exit 1; }

# "<http code> rc=<curl rc>" plus curl's own error text; a bare curl, nothing slow, no pre-herding.
run_curl() { local out rc; out=$(curl -sS -m 8 -o /dev/null -w '%{http_code}' "$URL" 2>&1); rc=$?; echo "$out rc=$rc"; }

echo "## A1 control"
OUT1=$(run_curl); echo "$OUT1"
case "$OUT1" in *"rc=0"*) pass "control: curl reaches $URL";; *) fail "control curl failed: $OUT1";; esac

echo "## A2 load, pin, attach (multi) at the cgroup root"
bpftool prog loadall "$OUT/axiom_connect.bpf.o" "$PIN" pinmaps "$PIN/maps" || { fail "prog loadall"; exit 1; }
for hook in connect4 connect6 sendmsg4 sendmsg6; do
  bpftool cgroup attach "$CGROUP_ROOT" "$hook" pinned "$PIN/axiom_$hook" multi || fail "attach $hook"
done
ls "$PIN" "$PIN/maps" | sed 's/^/  pin: /'
bpftool cgroup tree "$CGROUP_ROOT" 2>/dev/null | grep -E "^$CGROUP_ROOT\$|axiom_" | sed 's/^/  tree: /'
# Count only this run's programs: a running axiomd keeps its own four axiom_* programs attached at the root.
BASELINE_ATTACHED=${BASELINE_ATTACHED:-0}
OURS=$(for hook in connect4 connect6 sendmsg4 sendmsg6; do bpftool prog show pinned "$PIN/axiom_$hook" -j 2>/dev/null | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])'; done | tr '\n' ' ')
echo "  our prog ids: $OURS"
attached_ours() { local n=0 id; for id in $OURS; do bpftool cgroup tree "$CGROUP_ROOT" 2>/dev/null | grep -qE "^\s*$id\s" && n=$((n+1)); done; echo $n; }
[ "$(attached_ours)" = 4 ] && pass "four axiom_* programs attached at $CGROUP_ROOT (ids $OURS)" || fail "expected four attachments"

echo "## A3 verdict entry for $TARGET only"
# Superblock dev (what the BPF program reads), not stat's st_dev: they differ on btrfs (see
# src/Axiom.Infrastructure.Linux/Bpf/BpfExeKey.cs).
IFS=: read -r MAJ MIN < <(findmnt -no MAJ:MIN -T "$(realpath -e "$TARGET")" | tail -n1 | tr -d ' ')
INO=$(stat -L -c '%i' "$TARGET")
# ABI 2: + btrfs subvolume id (statx STATX_SUBVOL / BTRFS_IOC_INO_LOOKUP), 0 on other filesystems.
SUBVOL=$(python3 -I "$(dirname "$0")/../btrfs-subvol.py" --key "$(realpath -e "$TARGET")")
echo "  $TARGET dev $MAJ:$MIN ino $INO subvol $SUBVOL"
KEY=$(python3 -I -c 'import struct,sys; print(" ".join(f"{b:02x}" for b in struct.pack("<IIQQ", int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]))))' "$MAJ" "$MIN" "$INO" "$SUBVOL")
VALUE=$(python3 -I -c 'import struct,sys,uuid; print(" ".join(f"{b:02x}" for b in struct.pack("<BBHI16s", 2, 7, 0, 1, uuid.UUID(sys.argv[1]).bytes_le)))' "$RULE_ID")
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/maps/axiom_exe_verdicts" key hex $KEY value hex $VALUE any && pass "exe verdict written (block, tcp|udp|other, generation 1)" || fail "map update"
bpftool map dump pinned "$PIN/maps/axiom_exe_verdicts" | sed 's/^/  map: /'

echo "## A4 bare curl right away: must fail at connect (EPERM) with an event"
EV=$(mktemp)
"$OUT/axiom-bpf-events" "$PIN/maps/axiom_events" > "$EV" 2>&1 &
EV_PID=$!
sleep 0.3
OUT2=$(run_curl); echo "$OUT2"
case "$OUT2" in *"rc=7"*) pass "bare curl blocked immediately (rc=7)";; *) fail "bare curl not blocked: $OUT2";; esac
sleep 0.5
kill "$EV_PID" 2>/dev/null; wait "$EV_PID" 2>/dev/null
sed 's/^/  event: /' "$EV"
grep -q '"verdict":"block"' "$EV" && pass "event helper reported the block" || fail "no block event"
bpftool map dump pinned "$PIN/maps/axiom_stats" -j | sed 's/^/  stats: /'

echo "## A5 remove the entry: curl works again"
# shellcheck disable=SC2086
bpftool map delete pinned "$PIN/maps/axiom_exe_verdicts" key hex $KEY || fail "map delete"
OUT3=$(run_curl); echo "$OUT3"
case "$OUT3" in *"rc=0"*) pass "after delete: curl reaches $URL";; *) fail "curl still failing: $OUT3";; esac

echo "## A6 detach, unpin, verify nothing of ours remains"
for hook in connect4 connect6 sendmsg4 sendmsg6; do
  bpftool cgroup detach "$CGROUP_ROOT" "$hook" pinned "$PIN/axiom_$hook" || fail "detach $hook"
done
rm -rf "$PIN"
[ ! -e "$PIN" ] && pass "$PIN removed" || fail "$PIN remains"
LEFT=0; for id in $OURS; do bpftool prog show id "$id" >/dev/null 2>&1 && LEFT=$((LEFT+1)); done
[ "$LEFT" = 0 ] && pass "bpftool prog list: none of our programs (ids $OURS) is loaded" || fail "$LEFT of our programs still loaded"
[ "$(attached_ours)" = 0 ] && pass "bpftool cgroup tree: none of our programs attached" || fail "our programs still attached"
[ "$(bpftool prog list 2>/dev/null | grep -c 'axiom_')" = "$(systemctl is-active axiomd >/dev/null 2>&1 && echo 4 || echo 0)" ] && pass "only the daemon's own axiom_* programs (if axiomd runs) remain" || echo "  note: $(bpftool prog list 2>/dev/null | grep -c 'axiom_') axiom_* programs loaded in total"

if [ $DAEMON = 1 ]; then
  echo "## B1 install/upgrade axiomd in place (daemon stays installed afterwards)"
  AXIPC="$ROOT/scripts/linux/axipc.py"
  "$ROOT/build/linux/axiomd/axiomd" --install-service || fail "install-service"
  sleep 3
  journalctl -u axiomd --since '-30s' --no-pager -o cat | grep -E 'BPF|bpf' | sed 's/^/  journal: /'
  journalctl -u axiomd --since '-30s' --no-pager -o cat | grep -q 'BPF layer attached' && pass "journal: BPF layer attached" || fail "journal: no 'BPF layer attached' line"
  ls "$ROOT/../" >/dev/null
  echo "## B2 protection.enable + rule.apply block $TARGET"
  python3 -I "$AXIPC" protection.enable '{"defaultPolicy":"ask"}' | head -3 | sed 's/^/  /'
  python3 -I "$AXIPC" rule.apply "{\"managedRuleId\":\"$RULE_ID\",\"appPath\":\"$TARGET\",\"direction\":\"outbound\",\"action\":\"block\",\"protocol\":\"any\",\"enabled\":true,\"createdBy\":\"uid:0\"}" | sed 's/^/  /'
  journalctl -u axiomd --since '-10s' --no-pager -o cat | grep 'BPF verdicts' | sed 's/^/  journal: /'
  OUT4=$(run_curl); echo "$OUT4"
  case "$OUT4" in *"rc=7"*) pass "daemon path: bare curl blocked immediately (rc=7)";; *) fail "daemon path: curl not blocked: $OUT4";; esac
  # The snapshot's connections carry no flow id (the BPF monitor's "bpf-N" ids stay internal), and a
  # blocked flow is listed only for about one poll interval: poll a few times for a Blocked entry of
  # $TARGET. connect() was refused before any packet left, so nft never traced it: the entry comes
  # from the BPF event helper.
  SNAP=""
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
    sleep 0.25
    SNAP=$(python3 -I "$AXIPC" snapshot | python3 -I -c 'import json,sys
r=json.load(sys.stdin).get("result") or {}
for c in r.get("connections") or []:
    if c.get("state") == "Blocked" and c.get("appPath") == sys.argv[1]:
        print(c.get("appPath"), c.get("protocol"), c.get("remoteEndpoint"), c.get("ruleStatus"))' "$TARGET")
    [ -n "$SNAP" ] && break
  done
  echo "$SNAP" | head -4 | sed 's/^/  snapshot: /'
  [ -n "$SNAP" ] && pass "snapshot: blocked flow for $TARGET (BPF event path)" || fail "snapshot: no blocked flow for $TARGET"
  echo "## B3 rule.remove, protection.disable"
  python3 -I "$AXIPC" rule.remove "{\"managedRuleId\":\"$RULE_ID\"}" | head -3 | sed 's/^/  /'
  OUT5=$(run_curl); echo "$OUT5"
  case "$OUT5" in *"rc=0"*) pass "after rule.remove: curl reaches $URL";; *) fail "curl still failing: $OUT5";; esac
  python3 -I "$AXIPC" protection.disable | head -2 | sed 's/^/  /'
  "$ROOT/build/linux/axiomd/axiomd" --doctor | grep -E 'bpf layer|enforcement' | sed 's/^/  doctor: /'
fi

echo "## RESULT: $([ $FAILED = 0 ] && echo PASS || echo FAIL)"
exit $FAILED
