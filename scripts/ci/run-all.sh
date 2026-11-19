#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Author-run gate: builds both solutions and runs every test project on this machine, then lists
# per-suite counts and every failed or skipped test by name. Nothing is marked continue-on-error:
# the exit code is non-zero when a build fails or any test fails.
#
# Usage: scripts/ci/run-all.sh [out-dir]            (default: ./artifacts/run-all-<sha>)
# Env:   CONFIGURATION=Release  UIA_REPEAT=3 (extra runs of Axiom.UI.Avalonia.Tests)
#        BUILD_WRAPPER="flock -w 3600 /path/lock" (optional prefix for every dotnet call)
#
# On Linux/macOS, Windows-only tests (WPF, named-pipe ACLs, Windows Firewall COM, DPAPI) fail by
# design; the summary lists them by name so a reviewer can compare the set against a base commit
# (diff the names, not the counts). On Windows the macOS/Linux/Unix test projects are not test
# projects (IsTestProject=false) and are skipped by `dotnet test`.
set -uo pipefail
cd "$(dirname "$0")/../.."
SHA=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
OUT=${1:-artifacts/run-all-$SHA}
CONF=${CONFIGURATION:-Release}
W=${BUILD_WRAPPER:-}
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
mkdir -p "$OUT"
SUM="$OUT/summary.txt"
FLAGS=(-c "$CONF" -m:2 -nr:false -p:UseSharedCompilation=false)
[[ "$(uname -s)" != MINGW* && "$(uname -s)" != MSYS* ]] && FLAGS+=(-p:EnableWindowsTargeting=true)
rc_all=0
{
  echo "head $(git log -1 --format='%H %s' 2>/dev/null)"
  echo "host $(uname -srm); dotnet $(dotnet --version)"
} > "$SUM"
for s in Axiom.sln Axiom.Portable.slnx; do
  [[ -f "$s" ]] || continue
  $W dotnet build "$s" "${FLAGS[@]}" > "$OUT/build-$s.log" 2>&1; rc=$?
  [[ $rc -ne 0 ]] && rc_all=1
  echo "build $s rc=$rc $(grep -E '^ +[0-9]+ (Warning|Error)' "$OUT/build-$s.log" | tr -s ' ' | tr '\n' ' ')" >> "$SUM"
done
run_suite() { # <csproj> <trx-name> [--no-build]
  local p=$1 n=$2; shift 2
  $W dotnet test "$p" "${FLAGS[@]}" "$@" --logger "trx;LogFileName=$n.trx" --results-directory "$OUT" \
    > "$OUT/$n.log" 2>&1
  local rc=$?
  [[ $rc -ne 0 ]] && rc_all=1
  echo "test $n rc=$rc $(grep -E '^(Passed|Failed|Skipped)!' "$OUT/$n.log" | tail -1 | sed 's/, Duration.*//')" >> "$SUM"
}
for p in tests/*/*.csproj; do
  run_suite "$p" "$(basename "$p" .csproj)"
done
if [[ -f tests/Axiom.UI.Avalonia.Tests/Axiom.UI.Avalonia.Tests.csproj ]]; then
  for i in $(seq 2 "${UIA_REPEAT:-3}"); do
    run_suite tests/Axiom.UI.Avalonia.Tests "Axiom.UI.Avalonia.Tests.run$i" --no-build
  done
fi
python3 - "$OUT" >> "$SUM" <<'PY'
import glob, os, sys, xml.etree.ElementTree as ET
for t in sorted(glob.glob(os.path.join(sys.argv[1], "*.trx"))):
    r = ET.parse(t).getroot(); ns = r.tag.split("}")[0][1:]
    res = list(r.iter("{%s}UnitTestResult" % ns))
    bad = [(u.get("outcome"), u.get("testName")) for u in res if u.get("outcome") not in ("Passed",)]
    print(f"== {os.path.basename(t)}: {len(res)} results, {len(bad)} not passed")
    for outcome, name in sorted(bad):
        print(f"   {outcome}: {name}")
PY
echo "exit=$rc_all" >> "$SUM"
cat "$SUM"
exit $rc_all
