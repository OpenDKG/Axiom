#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Removes an Axiom installation. Local history is preserved unless --remove-data is passed.
set -euo pipefail

scope="auto"
remove_data=0

usage() {
  cat <<'EOF'
uninstall-linux.sh [--system | --user] [--remove-data]

  --system       remove the /opt/axiom installation and the system unit
  --user         remove the per-user installation
  --remove-data  also delete the local database, settings and Privacy Shield files
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --system) scope="system"; shift ;;
    --user) scope="user"; shift ;;
    --remove-data) remove_data=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ "$scope" == "auto" ]]; then
  if [[ -f /etc/systemd/system/axiom.service ]]; then
    scope="system"
  else
    scope="user"
  fi
fi

if [[ "$scope" == "system" ]]; then
  [[ "$(id -u)" == "0" ]] || { echo "--system requires root (use sudo)" >&2; exit 1; }
  prefix="/opt/axiom"
  systemctl disable --now axiom.service 2>/dev/null || true
  rm -f /etc/systemd/system/axiom.service
  systemctl daemon-reload
  rm -rf "$prefix"
  if [[ "$remove_data" == "1" ]]; then
    rm -rf /var/lib/axiom
  fi
else
  prefix="$HOME/.local/opt/axiom"
  systemctl --user disable --now axiom.service 2>/dev/null || true
  rm -f "$HOME/.config/systemd/user/axiom.service"
  systemctl --user daemon-reload 2>/dev/null || true
  rm -f "$HOME/.local/share/applications/axiom.desktop"
  rm -rf "$prefix"
  if [[ "$remove_data" == "1" ]]; then
    rm -rf "$HOME/.local/share/Axiom"
  fi
fi

echo "Removed Axiom ($scope scope)."
if [[ "$remove_data" != "1" ]]; then
  echo "Local data was kept. Re-run with --remove-data to delete it."
fi
