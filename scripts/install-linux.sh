#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Installs the Linux build. User scope needs no privileges. System scope needs root and is the
# only mode in which the service can see every process and (in a future backend) enforce rules.
#
# The installer never changes firewall, proxy or DNS settings, never installs Blackbox/DKG and
# never downloads anything. Local data is kept on uninstall unless --remove-data is passed.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_dir="$root/artifacts/publish/linux"
scope="user"
start=1
allowed_uid="${SUDO_UID:-}"

usage() {
  cat <<'EOF'
install-linux.sh [--system | --user] [--source DIR] [--allow-uid UID] [--no-start]

  --system        install under /opt/axiom with a systemd system unit (requires root)
  --user          install under ~/.local/opt/axiom with a systemd user unit (default)
  --source DIR    published payload (default: artifacts/publish/linux)
  --allow-uid UID uid allowed to call the service (system scope; default: SUDO_UID)
  --no-start      install but do not start the service
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --system) scope="system"; shift ;;
    --user) scope="user"; shift ;;
    --source) source_dir="$2"; shift 2 ;;
    --allow-uid) allowed_uid="$2"; shift 2 ;;
    --no-start) start=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

for part in service ui mcp; do
  [[ -d "$source_dir/$part" ]] || { echo "missing payload: $source_dir/$part" >&2; exit 1; }
done

if [[ "$scope" == "system" ]]; then
  [[ "$(id -u)" == "0" ]] || { echo "--system requires root (use sudo)" >&2; exit 1; }
  [[ "$allowed_uid" =~ ^[0-9]{1,10}$ ]] && (( allowed_uid < 4294967295 )) || {
    echo "--allow-uid is required when installing as root without sudo" >&2
    exit 1
  }
  if (( allowed_uid == 0 )); then
    echo "warning: uid 0 only lets root connect; pass the desktop user's uid for a usable UI." >&2
  fi
  if [[ -e "$source_dir/service" && ! -d "$source_dir/service" ]] ||
     [[ -e "$source_dir/ui" && ! -d "$source_dir/ui" ]] ||
     [[ -e "$source_dir/mcp" && ! -d "$source_dir/mcp" ]]; then
    echo "payload entries must be directories: $source_dir" >&2
    exit 1
  fi
  if [[ -n "$(find "$source_dir" -type l -print -quit)" ]]; then
    echo "refusing a system install from a payload containing symlinks: $source_dir" >&2
    exit 1
  fi
  if [[ -n "$(find "$source_dir" -perm /6000 -print -quit)" ]]; then
    echo "refusing a system install from a payload containing setuid/setgid files: $source_dir" >&2
    exit 1
  fi
  prefix="/opt/axiom"
  unit_dir="/etc/systemd/system"
else
  prefix="$HOME/.local/opt/axiom"
  unit_dir="$HOME/.config/systemd/user"
fi

[[ -L "$prefix" ]] && { echo "refusing symlinked install prefix: $prefix" >&2; exit 1; }
if [[ "$scope" == "system" ]]; then
  # A root service executes this tree, so the prefix itself must be root-owned before anything is
  # copied: a user who owns /opt/axiom could otherwise rename the copied directories and swap the
  # executable.
  install -d -o root -g root -m 0755 "$prefix"
  [[ "$(stat -c %u "$prefix")" == "0" ]] || { echo "install prefix must be owned by root: $prefix" >&2; exit 1; }
else
  install -d -m 0755 "$prefix"
fi
rm -rf "$prefix/service" "$prefix/ui" "$prefix/mcp"
# Copy without preserving the payload owner/mode. A system service executes this tree as root,
# so files owned or writable by the invoking user would be a privilege-escalation path.
cp -R "$source_dir/service" "$prefix/service"
cp -R "$source_dir/ui" "$prefix/ui"
cp -R "$source_dir/mcp" "$prefix/mcp"
chmod -R u+rwX,go-w "$prefix/service" "$prefix/ui" "$prefix/mcp"
if [[ "$scope" == "system" ]]; then
  chown -R root:root "$prefix/service" "$prefix/ui" "$prefix/mcp"
fi

[[ -x "$prefix/service/Axiom.Service" ]] || { echo "service payload is missing its executable" >&2; exit 1; }
[[ -x "$prefix/ui/Axiom.Desktop.Linux" ]] || { echo "UI payload is missing its executable" >&2; exit 1; }

(
  cd "$prefix"
  find service ui mcp -type f -print0 | sort -z | xargs -0 sha256sum > install-manifest.sha256
)

install -d -m 0755 "$unit_dir"
if [[ "$scope" == "system" ]]; then
  sed "s/^Environment=AXIOM_ALLOWED_UID=.*/Environment=AXIOM_ALLOWED_UID=$allowed_uid/" \
    "$root/packaging/linux/axiom.service" > "$unit_dir/axiom.service"
  systemctl daemon-reload
  systemctl enable axiom.service >/dev/null
  [[ "$start" == "1" ]] && systemctl restart axiom.service
else
  install -m 0644 "$root/packaging/linux/axiom-user.service" "$unit_dir/axiom.service"
  install -d -m 0755 "$HOME/.local/share/applications"
  sed "s|@PREFIX@|$prefix|g" "$root/packaging/linux/axiom.desktop" \
    > "$HOME/.local/share/applications/axiom.desktop"
  chmod 0644 "$HOME/.local/share/applications/axiom.desktop"
  if command -v desktop-file-validate >/dev/null 2>&1; then
    desktop-file-validate "$HOME/.local/share/applications/axiom.desktop" >/dev/null || {
      echo "generated desktop entry is invalid" >&2
      exit 1
    }
  fi
  systemctl --user daemon-reload
  systemctl --user enable axiom.service >/dev/null
  [[ "$start" == "1" ]] && systemctl --user restart axiom.service
fi

echo "Installed Axiom ($scope scope) under $prefix."
if [[ "$scope" == "system" ]]; then
  echo "Service: systemctl status axiom"
else
  echo "Service: systemctl --user status axiom"
fi
echo "UI: $prefix/ui/Axiom.Desktop.Linux"
