#!/bin/bash
# End-to-end check of the filter -> daemon socket resilience (run as root, filter enabled,
# no other listener on /var/run/axiom/filter.sock):
#   1. no socket file      -> traffic unaffected, extension keeps running
#   2. stale socket file   -> (ECONNREFUSED) same
#   3. listener appears    -> filter connects within ~2 s, sends filter.hello, then the
#                             events queued while the daemon was down (incl. the curl flows)
#   4. listener restarts   -> filter reconnects and says hello again
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
SOCK=/var/run/axiom/filter.sock
OUT=/tmp/e2e-socket.jsonl
fail=0
pass() { echo "[PASS] $*"; }
failed() { echo "[FAIL] $*"; fail=1; }
extpid() { pgrep -f 'com.axiom.firewall.filter.systemextension/Contents/MacOS' | head -1; }

[[ $EUID -eq 0 ]] || { echo "run as root"; exit 2; }
rm -f "$OUT" "$SOCK"
PID0=$(extpid); echo "extension pid $PID0"

code=$(/usr/bin/curl -s -m 8 -o /dev/null -w '%{http_code}' https://example.com)
[[ $code == 200 ]] && pass "no socket file: curl https://example.com -> $code" || failed "no socket: curl -> $code"

# stale socket: bound, never listening, file left behind
python3 -c "import socket; s=socket.socket(socket.AF_UNIX); s.bind('$SOCK')"
sleep 3
code=$(/usr/bin/curl -s -m 8 -o /dev/null -w '%{http_code}' https://apple.com)
[[ $code == 301 || $code == 200 ]] && pass "stale socket file: curl https://apple.com -> $code" || failed "stale socket: curl -> $code"
[[ "$(extpid)" == "$PID0" ]] && pass "extension still running (pid $PID0), no crash" || failed "extension pid changed: $(extpid)"
rm -f "$SOCK"

T0=$(python3 -c 'import time;print(time.time())')
python3 "$HERE/filter-listener.py" --out "$OUT" --seconds 6 2>/dev/null
python3 - "$OUT" "$T0" <<'EOF' || fail=1
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
t0 = float(sys.argv[2])
conn = [r for r in rows if r.get("_listener") == "connect"]
hello = [r for r in rows if r.get("type") == "filter.hello"]
curl = [r for r in rows if r.get("type") == "flow.open" and r.get("path") == "/usr/bin/curl"]
ok = bool(conn) and conn[0]["_t"] - t0 <= 2.5
print(f"[{'PASS' if ok else 'FAIL'}] listener appeared: filter connected after {conn[0]['_t'] - t0:.2f}s" if conn else "[FAIL] no connection")
first = next((r for r in rows if "type" in r), {})
ok2 = first.get("type") == "filter.hello"
print(f"[{'PASS' if ok2 else 'FAIL'}] first line is filter.hello (generation {first.get('generation')}, version {first.get('version')})")
ok3 = len(curl) >= 2
print(f"[{'PASS' if ok3 else 'FAIL'}] {len(curl)} curl flow.open events queued while the daemon was down were delivered: " +
      ", ".join(f"{r['remoteHost']}->{r['remoteAddress']}:{r['remotePort']}" for r in curl))
sys.exit(0 if ok and ok2 and ok3 else 1)
EOF

# listener went away (EOF on the filter side); a new one must get a fresh hello
T1=$(python3 -c 'import time;print(time.time())')
python3 "$HERE/filter-listener.py" --out "$OUT.2" --seconds 5 2>/dev/null
python3 - "$OUT.2" "$T1" <<'EOF' || fail=1
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
conn = [r for r in rows if r.get("_listener") == "connect"]
hello = [r for r in rows if r.get("type") == "filter.hello"]
ok = bool(conn) and bool(hello)
print(f"[{'PASS' if ok else 'FAIL'}] daemon restart: reconnected after {conn[0]['_t'] - float(sys.argv[2]):.2f}s, hello received" if ok else "[FAIL] no reconnect")
sys.exit(0 if ok else 1)
EOF
rm -f "$OUT.2"
[[ "$(extpid)" == "$PID0" ]] && pass "extension pid unchanged ($PID0)" || failed "extension pid changed: $(extpid)"
exit $fail
