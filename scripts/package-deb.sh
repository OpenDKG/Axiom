#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Builds a self-contained Debian package from the published Linux payload.
#
# The package never enables or starts the service, never changes firewall/DNS/proxy settings and
# never deletes /var/lib/axiom on uninstall. Per-executable firewall enforcement additionally
# needs the opt-in drop-in from packaging/linux/axiom-firewall.conf.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_dir="${SOURCE_DIR:-$root/artifacts/publish/linux}"
version="${VERSION:-$(sed -n 's/.*<Version>\(.*\)<\/Version>.*/\1/p' "$root/Directory.Build.props" | head -1)}"
architecture="${ARCHITECTURE:-$(dpkg --print-architecture)}"
out="${OUT:-$root/artifacts/packages}"
package="$out/axiom_${version}_${architecture}"
deb="$out/axiom_${version}_${architecture}.deb"

for part in service ui mcp; do
  [[ -d "$source_dir/$part" ]] || {
    echo "missing payload: $source_dir/$part (run scripts/publish-linux.sh first)" >&2
    exit 1
  }
done

rm -rf "$package"
mkdir -p "$package/DEBIAN" "$package/opt/axiom" "$package/lib/systemd/system" \
  "$package/usr/share/applications" "$package/usr/share/doc/axiom/examples"

cp -a "$source_dir/service" "$source_dir/ui" "$source_dir/mcp" "$package/opt/axiom/"

install -m 0644 "$root/packaging/linux/axiom.service" "$package/lib/systemd/system/axiom.service"
# The firewall drop-in is an example, not installed: it relaxes ProtectControlGroups and must stay
# an explicit operator decision.
install -m 0644 "$root/packaging/linux/axiom-firewall.conf" \
  "$package/usr/share/doc/axiom/examples/axiom-firewall.conf"
install -m 0644 "$root/packaging/linux/axiom.desktop" "$package/usr/share/applications/axiom.desktop"
sed -i 's|@PREFIX@|/opt/axiom|g' "$package/usr/share/applications/axiom.desktop"
install -m 0644 "$root/docs/LINUX.md" "$package/usr/share/doc/axiom/LINUX.md" 2>/dev/null || true
install -m 0644 "$root/README.md" "$package/usr/share/doc/axiom/README.md" 2>/dev/null || true

cat > "$package/DEBIAN/control" <<EOF
Package: axiom
Version: $version
Section: net
Priority: optional
Architecture: $architecture
Maintainer: The Axiom contributors <security@axiom.invalid>
Depends: libc6
Recommends: libbpf1, systemd
Description: Axiom local network monitor and privacy guard (Linux)
 Reads eBPF/procfs socket state through a root service and a local Unix socket, keeps history in
 SQLite and exposes a loopback-only browser UI. Firewall policy is opt-in and fail-closed.
EOF

cat > "$package/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
cat <<'MSG'
Axiom was installed but not started.

The service only accepts one uid. Allow your desktop user before starting it:
  sudo install -d -m 0755 /etc/systemd/system/axiom.service.d
  printf '[Service]\nEnvironment=AXIOM_ALLOWED_UID=%s\n' "$(id -u)" \
    | sudo tee /etc/systemd/system/axiom.service.d/allowed-uid.conf >/dev/null
  sudo systemctl daemon-reload
  sudo systemctl enable --now axiom
  /opt/axiom/ui/Axiom.Desktop.Linux

Do not run the browser UI as root. Per-executable firewall enforcement is disabled by default;
read /usr/share/doc/axiom/LINUX.md before enabling it.
MSG
EOF

cat > "$package/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
case "${1:-}" in
  remove|purge)
    if command -v systemctl >/dev/null 2>&1; then
      systemctl stop axiom.service >/dev/null 2>&1 || true
      systemctl disable axiom.service >/dev/null 2>&1 || true
    fi
    ;;
esac
exit 0
EOF

cat > "$package/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
EOF

chmod 0755 "$package/DEBIAN/postinst" "$package/DEBIAN/prerm" "$package/DEBIAN/postrm"
chmod 0755 "$package/opt/axiom/service/Axiom.Service" \
  "$package/opt/axiom/ui/Axiom.Desktop.Linux" \
  "$package/opt/axiom/mcp/Axiom.McpServer" 2>/dev/null || true

mkdir -p "$out"
dpkg-deb --build --root-owner-group "$package" "$deb" >/dev/null
echo "$deb"
