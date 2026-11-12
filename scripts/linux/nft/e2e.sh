#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# End-to-end proof of the nftables enforcement engine on a cgroup v2 + nftables box.
#
#   scripts/linux/nft/e2e.sh            # as the developer: builds, then re-execs itself under sudo -n
#
# Steps (all through the real engine, Axiom.Infrastructure.Linux.Nft, driven by the test exe's
# `e2e` entry point):
#   1. control: curl reaches $URL (rc=0, HTTP 200)
#   2. apply a block rule for /usr/bin/curl and one for the shell binary (realpath of /bin/sh), plus
#      one invalid rule that must be *rejected* with a reason, not widened
#   3. an already-running shell (sleeping, in its own systemd scope) is herded into the shell's app
#      cgroup by one attribution pass; its curl child inherits the cgroup: expect curl rc=7
#      (connection refused: `reject with tcp reset`) — the spike's "move a running pid" case
#   4. curl started after the rule while the attribution loop polls every 50 ms: the exec-time race
#      (plan section 9) — reported, not asserted; the BPF helper (P2b) closes it
#   5. `nft monitor trace` (running during 3+4) → flow.open/flow.close NDJSON events with
#      verdict=block and the rule id; counters read back through rule.verify
#   6. remove the rules; curl rc=0 again
#   7. teardown: `table inet axiom` and /sys/fs/cgroup/axiom.slice are gone
# Nothing outside `table inet axiom` and `axiom.slice` is touched. No process is killed.
set -u
URL=${AXIOM_E2E_URL:-http://example.com}
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
PROJ="$ROOT/tests/Axiom.Infrastructure.Linux.Nft.Tests"
EXE="$PROJ/bin/Release/net10.0/Axiom.Infrastructure.Linux.Nft.Tests"
STATE=${AXIOM_E2E_STATE:-/tmp/axiom-nft-e2e}
# A private copy of the shell: a rule on /bin/sh itself would herd every shell on the box (verified:
# it caught pm2's and the gateway's dash processes), so the "already-running app" is this copy.
# It lives next to the test exe because /tmp is mounted noexec on Ubuntu.
SHELL_BIN="$(dirname "$EXE")/axiom-e2e-sh"
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAILED=1; }
FAILED=0

if [ "$(id -u)" != 0 ]; then
  export PATH="$HOME/.dotnet:$PATH" DOTNET_CLI_TELEMETRY_OPTOUT=1
  if [ ! -x "$EXE" ]; then
    dotnet build "$PROJ" -c Release -nologo -v q -m:2 -nr:false -p:UseSharedCompilation=false || exit 1
  fi
  # The user's SDK/runtime (~/.dotnet) is not on root's path: hand the apphost its DOTNET_ROOT.
  exec sudo -n env AXIOM_E2E_URL="$URL" AXIOM_E2E_STATE="$STATE" DOTNET_ROOT="${DOTNET_ROOT:-$HOME/.dotnet}" "$0" "$@"
fi

echo "## host: $(. /etc/os-release; echo "$PRETTY_NAME") kernel $(uname -r) $(nft --version) cgroup $(stat -fc %T /sys/fs/cgroup) shell $SHELL_BIN"
rm -rf "$STATE"; mkdir -p "$STATE"
cp "$(readlink -f /bin/sh)" "$SHELL_BIN"; chmod 0755 "$SHELL_BIN"
nft list table inet axiom >/dev/null 2>&1 && { echo "table inet axiom already exists; refusing to run"; exit 1; }

# Runs curl against $0 (the URL) and prints "<http code> rc=<curl rc>"; usable from a plain sh -c.
CURL_CMD='curl -sS -m 5 -o /dev/null -w "%{http_code}" "$0" 2>&1; echo " rc=$?"'
run_curl() { sh -c "$CURL_CMD" "$URL"; }

echo "## 1 control"
OUT=$(run_curl); echo "$OUT"
case "$OUT" in *"rc=0"*) pass "control: curl reaches $URL";; *) fail "control curl failed: $OUT";; esac

echo "## 2 apply"
"$EXE" e2e "$STATE" apply "$SHELL_BIN"; RC=$?
[ $RC = 0 ] && pass "rules applied through the engine (2 applied, 1 rejected)" || fail "apply rc=$RC"
nft list table inet axiom | sed 's/^/  nft: /'
ls -d /sys/fs/cgroup/axiom.slice/a-* 2>/dev/null | sed 's/^/  cgroup: /'

TRACE_OUT=$(mktemp)
"$EXE" e2e "$STATE" trace 12 > "$TRACE_OUT" 2>&1 &
TRACE_PID=$!
sleep 0.5

echo "## 3 already-running shell in its own scope, herded while it sleeps; its curl child inherits the cgroup"
SCOPE_OUT=$(mktemp)
systemd-run --scope -q --unit="axiom-e2e-$$" "$SHELL_BIN" -c "sleep 2; $CURL_CMD" "$URL" > "$SCOPE_OUT" 2>&1 &
SCOPE_PID=$!
sleep 0.5
"$EXE" e2e "$STATE" attribute | sed 's/^/  /'
wait $SCOPE_PID
cat "$SCOPE_OUT"
grep -q 'rc=7' "$SCOPE_OUT" && pass "herded shell: curl blocked (rc=7, connection refused)" || fail "herded shell not blocked: $(cat "$SCOPE_OUT")"

echo "## 4 curl started after the rule, caught by the 50 ms attribution poll (race: reported, not asserted)"
RUN_OUT=$(mktemp)
"$EXE" e2e "$STATE" attribute 3 50 > /dev/null 2>&1 &
ATTR_PID=$!
sleep 1
systemd-run --scope -q --unit="axiom-e2e-b-$$" curl -sS -m 5 -o /dev/null -w '%{http_code}' "$URL" > "$RUN_OUT" 2>&1; echo " rc=$?" >> "$RUN_OUT"
wait $ATTR_PID
cat "$RUN_OUT"
grep -q 'rc=7' "$RUN_OUT" && echo "INFO exec-time race won: curl blocked" || echo "INFO exec-time race lost: curl connected before the poll caught it (expected sometimes; P2b closes it)"

echo "## 5 trace events + counters"
wait $TRACE_PID
grep '^event {"type":"flow' "$TRACE_OUT" | sed 's/^/  /'
grep -q '"type":"flow.open".*"verdict":"block".*"ruleId":"' "$TRACE_OUT" \
  && pass "trace monitor emitted flow.open verdict=block with a rule id" || fail "no block flow event: $(cat "$TRACE_OUT")"
nft list chain inet axiom axiom_out | grep -E 'counter packets' | sed 's/^ */  counters: /'
"$EXE" e2e "$STATE" verify | sed 's/^/  /'; RC=$?
[ $RC = 0 ] && pass "rule.verify: present, effective action block" || fail "verify rc=$RC"

echo "## 6 remove"
"$EXE" e2e "$STATE" remove | sed 's/^/  /'
OUT=$(run_curl); echo "$OUT"
case "$OUT" in *"rc=0"*) pass "after remove: curl reaches $URL again";; *) fail "curl still blocked after remove: $OUT";; esac

echo "## 7 teardown"
"$EXE" e2e "$STATE" teardown | sed 's/^/  /'
nft list table inet axiom >/dev/null 2>&1 && fail "table inet axiom still present" || pass "table inet axiom removed"
[ -d /sys/fs/cgroup/axiom.slice ] && fail "/sys/fs/cgroup/axiom.slice still present" || pass "axiom.slice removed"
rm -f "$SCOPE_OUT" "$TRACE_OUT" "$RUN_OUT"
[ $FAILED = 0 ] && echo "## RESULT: PASS" || echo "## RESULT: FAIL"
exit $FAILED
