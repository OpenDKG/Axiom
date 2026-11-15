#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build the Linux packages of Axiom (docs/LINUX_PACKAGING.md):
#
#   build/linux/axiom_<version>_<amd64|arm64>.deb        (dpkg-deb; fakeroot when present)
#   build/linux/axiom-<version>-1.<x86_64|aarch64>.rpm   (nfpm, only when `nfpm` is on PATH)
#
# Usage:
#   scripts/linux/package.sh [deb|rpm|all] [--arch x64|arm64] [--skip-publish] [--no-bpf] [--snapshot]
#
#   deb (default) / rpm / all   which package formats to produce
#   --arch x64|arm64            .NET RID linux-<arch> (default x64; the BPF objects are CO-RE and
#                               arch-neutral, the events helper is compiled for the build host)
#   --skip-publish              reuse build/linux/axiomd and build/linux/Axiom from a previous run
#   --no-bpf                    do not build/ship the eBPF objects (daemon degrades to nft-only)
#   --snapshot                  version <props>~git<yyyymmdd>.<sha> (sorts before the release)
#
# Steps: 1. `make` the BPF objects when clang is available (otherwise reuse out/ or ship without),
#        2. `dotnet publish` axiomd (self-contained) into build/linux/axiomd and the desktop into
#           build/linux/Axiom (its PublishBundledDaemon target copies axiomd/ into the bundle),
#        3. stage the package root under build/linux/root (/opt/axiom, desktop entry, icons,
#           polkit action, docs), 4. compute Depends with dpkg-shlibdeps, 5. dpkg-deb, lintian
#           when present, 6. nfpm for the .rpm from the same root and maintainer-script logic.
#
# Environment: DOTNET (default: dotnet on PATH, then ~/.dotnet/dotnet), DOTNET_WRAPPER (command
# prefix for dotnet, e.g. a flock wrapper), AXIOM_DOTNET_ARGS (extra dotnet publish arguments,
# default "-m:2 -nr:false -p:UseSharedCompilation=false").
set -euo pipefail

cd "$(dirname "$0")/../.."
ROOT=$(pwd)

FORMATS=deb
ARCH=x64
SKIP_PUBLISH=0
NO_BPF=0
SNAPSHOT=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    deb|rpm|all) FORMATS=$1 ;;
    --arch) ARCH=$2; shift ;;
    --skip-publish) SKIP_PUBLISH=1 ;;
    --no-bpf) NO_BPF=1 ;;
    --snapshot) SNAPSHOT=1 ;;
    -h|--help) sed -n '3,30p' "$0"; exit 0 ;;
    *) printf 'package.sh: unknown argument %s\n' "$1" >&2; exit 64 ;;
  esac
  shift
done

log() { printf '==> %s\n' "$*" >&2; }
die() { printf 'package.sh: %s\n' "$*" >&2; exit 1; }

case "$ARCH" in
  x64) DEB_ARCH=amd64; RPM_ARCH=x86_64 ;;
  arm64) DEB_ARCH=arm64; RPM_ARCH=aarch64 ;;
  *) die "unsupported --arch $ARCH (x64 or arm64)" ;;
esac
RID=linux-$ARCH

VERSION=$(sed -n 's:.*<Version>\(.*\)</Version>.*:\1:p' "$ROOT/Directory.Build.props" | head -n 1)
[[ -n "$VERSION" ]] || die "no <Version> in Directory.Build.props"
if [[ $SNAPSHOT -eq 1 ]]; then
  VERSION="${VERSION}~git$(date -u +%Y%m%d).$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
fi

OUT="$ROOT/build/linux"
DAEMON="$OUT/axiomd"
APP="$OUT/Axiom"
STAGE="$OUT/root"
PKG="$ROOT/packaging/linux"
NATIVE="$ROOT/src/Axiom.Infrastructure.Linux/Bpf/native"
DEB="$OUT/axiom_${VERSION}_${DEB_ARCH}.deb"
mkdir -p "$OUT"

# ---------------------------------------------------------------------------------------------
# 1. BPF objects (docs/LINUX_EBPF.md): the Service csproj ships Bpf/native/out/* under bpf/ when
#    the objects exist, so building them before the publish is all that is needed.
# ---------------------------------------------------------------------------------------------
if [[ $NO_BPF -eq 1 ]]; then
  log "BPF objects skipped (--no-bpf): the daemon runs nft-only"
elif command -v clang >/dev/null 2>&1; then
  log "make BPF objects ($NATIVE)"
  make -C "$NATIVE" >/dev/null
elif [[ -f "$NATIVE/out/axiom_connect.bpf.o" ]]; then
  log "no clang on this host; reusing $NATIVE/out/axiom_connect.bpf.o"
else
  log "no clang and no prebuilt BPF objects: the package ships without the eBPF layer (nft-only)"
fi

# ---------------------------------------------------------------------------------------------
# 2. Publish
# ---------------------------------------------------------------------------------------------
if [[ $SKIP_PUBLISH -eq 0 ]]; then
  DOTNET=${DOTNET:-$(command -v dotnet || echo "$HOME/.dotnet/dotnet")}
  [[ -x "$DOTNET" ]] || die "dotnet not found (set DOTNET or use --skip-publish)"
  read -r -a WRAP <<<"${DOTNET_WRAPPER:-}"
  read -r -a DOTNET_ARGS <<<"${AXIOM_DOTNET_ARGS:--m:2 -nr:false -p:UseSharedCompilation=false}"
  rm -rf "$DAEMON" "$APP"
  log "dotnet publish Axiom.Service -> axiomd ($RID)"
  "${WRAP[@]}" "$DOTNET" publish "$ROOT/src/Axiom.Service/Axiom.Service.csproj" \
    -f net10.0 -c Release -r "$RID" --self-contained true -nologo -v:q "${DOTNET_ARGS[@]}" \
    -p:UseAppHost=true -o "$DAEMON"
  log "dotnet publish Axiom.Desktop.Avalonia.Linux ($RID, bundles $DAEMON)"
  "${WRAP[@]}" "$DOTNET" publish "$ROOT/src/Axiom.Desktop.Avalonia.Linux/Axiom.Desktop.Avalonia.Linux.csproj" \
    -c Release -r "$RID" --self-contained true -nologo -v:q "${DOTNET_ARGS[@]}" \
    -p:UseAppHost=true -p:PublishSingleFile=false -p:AxiomDaemonPublishDir="$DAEMON/" -o "$APP"
  "$DOTNET" build-server shutdown >/dev/null 2>&1 || true
  log "note: a RID publish adds sections to packages.lock.json; discard them with: git checkout -- '*.lock.json'"
fi
[[ -x "$APP/Axiom" ]] || die "missing $APP/Axiom (publish first)"
[[ -x "$APP/axiomd/axiomd" ]] || die "missing $APP/axiomd/axiomd (the PublishBundledDaemon target did not run)"

# ---------------------------------------------------------------------------------------------
# 3. Stage the package root
# ---------------------------------------------------------------------------------------------
log "staging $STAGE"
rm -rf "$STAGE"
mkdir -p "$STAGE/opt/axiom" "$STAGE/usr/share/applications" "$STAGE/usr/share/polkit-1/actions" \
  "$STAGE/usr/share/doc/axiom" "$STAGE/usr/share/icons/hicolor"
cp -a "$APP/." "$STAGE/opt/axiom/"
# Shared by prerm/%preun: verified BPF pin cleanup (see the file's header).
install -m 0644 "$PKG/bpf-pins.sh" "$STAGE/opt/axiom/bpf-pins.sh"
find "$STAGE/opt/axiom" -name '*.pdb' -delete
# The policy/desktop files are installed to their system locations below; the copies the desktop
# publish carries for reference are not needed in /opt.
rm -rf "$STAGE/opt/axiom/packaging"
# LTTng trace provider of the runtime: optional, needs liblttng-ust (not a dependency we want).
find "$STAGE/opt/axiom" -name 'libcoreclrtraceptprovider.so' -delete
install -m 0644 "$PKG/com.axiom.firewall.desktop" "$STAGE/usr/share/applications/"
# polkitd drops a malformed action file without a word (pkaction then lists nothing): check it.
if command -v python3 >/dev/null 2>&1; then
  python3 -I -c 'import sys, xml.dom.minidom; xml.dom.minidom.parse(sys.argv[1])' "$PKG/com.axiom.firewall.policy" \
    || die "$PKG/com.axiom.firewall.policy is not well-formed XML"
fi
if command -v desktop-file-validate >/dev/null 2>&1; then
  desktop-file-validate "$PKG/com.axiom.firewall.desktop" || die "desktop entry is invalid"
fi
install -m 0644 "$PKG/com.axiom.firewall.policy" "$STAGE/usr/share/polkit-1/actions/"
cp -a "$PKG/icons/hicolor/." "$STAGE/usr/share/icons/hicolor/"
install -m 0644 "$PKG/debian/copyright" "$STAGE/usr/share/doc/axiom/copyright"
install -m 0644 "$ROOT/README.md" "$STAGE/usr/share/doc/axiom/README.md"
[[ -f "$ROOT/docs/LINUX_PACKAGING.md" ]] && install -m 0644 "$ROOT/docs/LINUX_PACKAGING.md" "$STAGE/usr/share/doc/axiom/"

# Modes: nothing group/world-writable, directories 0755, files 0644, executables 0755. The
# daemon tree is audited again by --install-service after it is copied to /usr/libexec/axiom.
find "$STAGE" -type d -exec chmod 0755 {} +
find "$STAGE" -type f -exec chmod 0644 {} +
chmod 0755 "$STAGE/opt/axiom/Axiom" "$STAGE/opt/axiom/axiomd/axiomd"
[[ -f "$STAGE/opt/axiom/axiomd/bpf/axiom-bpf-events" ]] && chmod 0755 "$STAGE/opt/axiom/axiomd/bpf/axiom-bpf-events"
find "$STAGE/opt/axiom" -type f \( -name 'createdump' -o -name '*.so' -o -name '*.so.*' \) -exec chmod 0755 {} +

# ---------------------------------------------------------------------------------------------
# 4. Dependencies: dpkg-shlibdeps for everything in NEEDED; libraries the runtime and Avalonia
#    dlopen at run time (ICU, OpenSSL, X11, fontconfig) are listed by hand.
# ---------------------------------------------------------------------------------------------
DLOPEN_DEPENDS='libicu76 | libicu74 | libicu72 | libicu70, libssl3t64 | libssl3, zlib1g, libx11-6, libxext6, libxrender1, libxi6, libxcursor1, libxrandr2, libice6, libsm6, libfontconfig1, libfreetype6'
SHLIBS_DEPENDS=""
if command -v dpkg-shlibdeps >/dev/null 2>&1; then
  SHLIBDEPS_DIR=$(mktemp -d "${TMPDIR:-/tmp}/axiom-shlibdeps.XXXXXX")
  mkdir -p "$SHLIBDEPS_DIR/debian"
  printf 'Source: axiom\n\nPackage: axiom\nArchitecture: %s\n' "$DEB_ARCH" >"$SHLIBDEPS_DIR/debian/control"
  # Every dynamic ELF object (the BPF object is ELF too but has no dynamic section).
  mapfile -t ELF_FILES < <(find "$STAGE/opt/axiom" -type f -not -name '*.bpf.o' -exec sh -c 'head -c 4 "$1" | grep -q "^.ELF" && echo "$1"' _ {} \;)
  SHLIBS_DEPENDS=$(cd "$SHLIBDEPS_DIR" && dpkg-shlibdeps -O --ignore-missing-info --warnings=0 \
      -l"$STAGE/opt/axiom" -l"$STAGE/opt/axiom/axiomd" "${ELF_FILES[@]}" 2>/dev/null | sed -n 's/^shlibs:Depends=//p') || true
  rm -rf "$SHLIBDEPS_DIR"
fi
if [[ -z "$SHLIBS_DEPENDS" ]]; then
  log "dpkg-shlibdeps unavailable or empty; using the static dependency list"
  SHLIBS_DEPENDS='libc6 (>= 2.34), libgcc-s1, libstdc++6'
fi
# Merge, drop duplicate package names (the versioned shlibdeps entry wins) and keep a stable order.
DEPENDS=$(printf '%s, %s' "$SHLIBS_DEPENDS" "$DLOPEN_DEPENDS" | tr ',' '\n' | sed 's/^ *//;s/ *$//' | awk 'NF && !seen[$1]++' | paste -sd ',' - | sed 's/,/, /g')
log "Depends (shared libraries): $DEPENDS"

# ---------------------------------------------------------------------------------------------
# 5. .deb
# ---------------------------------------------------------------------------------------------
build_deb() {
  log "assembling DEBIAN/ control, md5sums, maintainer scripts"
  mkdir -p "$STAGE/DEBIAN"
  local installed_size
  installed_size=$(du -sk --exclude=DEBIAN "$STAGE" | cut -f1)
  sed -e "s#@VERSION@#$VERSION#" -e "s#@ARCH@#$DEB_ARCH#" -e "s#@INSTALLED_SIZE@#$installed_size#" \
      -e "s#@SHLIBS_DEPENDS@#$DEPENDS#" "$PKG/debian/control.in" >"$STAGE/DEBIAN/control"
  for script in postinst prerm postrm; do
    bash -n "$PKG/debian/$script"
    install -m 0755 "$PKG/debian/$script" "$STAGE/DEBIAN/$script"
  done
  (cd "$STAGE" && find . -type f -not -path './DEBIAN/*' -printf '%P\n' | sort | xargs -d '\n' md5sum >DEBIAN/md5sums)
  chmod 0644 "$STAGE/DEBIAN/control" "$STAGE/DEBIAN/md5sums"
  chmod 0755 "$STAGE/DEBIAN"

  rm -f "$DEB"
  if command -v fakeroot >/dev/null 2>&1; then
    log "fakeroot dpkg-deb --build -> $DEB"
    fakeroot dpkg-deb --build -Zxz "$STAGE" "$DEB"
  else
    log "dpkg-deb --root-owner-group --build -> $DEB"
    dpkg-deb --root-owner-group --build -Zxz "$STAGE" "$DEB"
  fi
  if command -v lintian >/dev/null 2>&1; then
    log "lintian"
    lintian --no-tag-display-limit "$DEB" || true
  else
    log "lintian not installed; skipped"
  fi
}

# ---------------------------------------------------------------------------------------------
# 6. .rpm via nfpm (same root, RPM maintainer scripts under packaging/linux/rpm/)
# ---------------------------------------------------------------------------------------------
build_rpm() {
  if ! command -v nfpm >/dev/null 2>&1; then
    log "nfpm not on PATH: .rpm skipped (docs/LINUX_PACKAGING.md §7 has the control mapping)"
    return 0
  fi
  local cfg="$OUT/nfpm.yaml" bpf_line='s| *# @IF_BPF@$||'
  # The libbpf.so.1 requirement only exists when the BPF helper is shipped.
  [[ -f "$STAGE/opt/axiom/axiomd/bpf/axiom-bpf-events" ]] || bpf_line='/@IF_BPF@/d'
  sed -e "s|@VERSION@|${VERSION//\~/_}|" -e "s|@ARCH@|$DEB_ARCH|" -e "s|@STAGE@|$STAGE|" -e "s|@PKG@|$PKG|" \
      -e "$bpf_line" "$PKG/nfpm.yaml.in" >"$cfg"
  for script in postinstall preremove postremove; do bash -n "$PKG/rpm/$script"; done
  log "nfpm package -p rpm -> $OUT"
  nfpm package -f "$cfg" -p rpm -t "$OUT/"
}

case "$FORMATS" in
  deb) build_deb ;;
  rpm) build_rpm ;;
  all) build_deb; build_rpm ;;
esac

log "artifacts:"
ls -l "$OUT"/axiom_*.deb "$OUT"/axiom-*.rpm 2>/dev/null >&2 || true
[[ -f "$DEB" ]] && dpkg-deb -I "$DEB" >&2
exit 0
