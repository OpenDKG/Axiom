#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Install a built Axiom .deb on a disposable Ubuntu host and smoke-test both entry points:
#
#   * the package installs through apt (postinst installs and starts axiomd.service)
#   * axiomd is active and its IPC socket exists, and `axiomd --doctor --json` runs
#   * the desktop starts under Xvfb and is still running after the settle window
#
# Usage: scripts/linux/smoke-install.sh <path/to/axiom-firewall_*.deb>
#
# Intended for CI (sudo, systemd). It installs the package on the current machine.
set -euo pipefail

DEB=${1:?usage: smoke-install.sh <path/to/axiom-firewall_*.deb>}
DEB=$(readlink -f "$DEB")
[[ -f "$DEB" ]] || { echo "smoke-install: $DEB not found" >&2; exit 1; }

OUT=${RUNNER_TEMP:-$(mktemp -d)}

log() { printf '==> %s\n' "$*" >&2; }
fail() { printf 'smoke-install: %s\n' "$*" >&2; exit 1; }

log "installing $DEB"
sudo apt-get update
sudo apt-get install -y xvfb
sudo apt-get install -y "$DEB"

log "waiting for axiomd.service"
active=0
for _ in $(seq 1 30); do
  if systemctl is-active --quiet axiomd; then active=1; break; fi
  sleep 1
done
if [[ $active -ne 1 ]]; then
  systemctl status axiomd --no-pager || true
  journalctl -u axiomd --no-pager | tail -n 100 || true
  fail "axiomd.service did not become active after install"
fi
systemctl is-enabled --quiet axiomd || fail "axiomd.service is not enabled"
[[ -S /run/axiom/axiom.sock ]] || fail "the axiomd IPC socket /run/axiom/axiom.sock is missing"

log "axiomd --doctor (informational)"
sudo /usr/lib/axiom-firewall/axiomd/axiomd --doctor --json >"$OUT/axiomd-doctor.json" || doctor_status=$?
grep -q '"checks"' "$OUT/axiomd-doctor.json" || fail "axiomd --doctor did not print JSON"
log "doctor exit status: ${doctor_status:-0}"

log "starting the desktop under Xvfb"
set +e
timeout --signal=TERM 25s xvfb-run -a --server-args="-screen 0 1360x900x24" \
  /usr/bin/axiom-firewall >"$OUT/axiom-desktop.log" 2>&1
status=$?
set -e
if [[ $status -ne 124 ]]; then
  cat "$OUT/axiom-desktop.log" >&2 || true
  fail "the desktop exited before the smoke window (status $status)"
fi

log "smoke checks passed"
