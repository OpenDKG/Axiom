#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Assemble Axiom.app for macOS (docs/MACOS_ARCHITECTURE.md §1 and §4):
#
#   Axiom.app/Contents/Info.plist
#   Axiom.app/Contents/MacOS/Axiom (+ the self-contained .NET/Avalonia publish output)
#   Axiom.app/Contents/MacOS/axiom-sysext                               (when macos/build has it)
#   Axiom.app/Contents/MacOS/libAxiomSysext.dylib                       (when macos/build has it)
#   Axiom.app/Contents/Resources/service/axiomd (+ its publish output)
#   Axiom.app/Contents/Resources/Axiom.icns                              (when sips/iconutil exist)
#   Axiom.app/Contents/Library/SystemExtensions/com.axiom.firewall.filter.systemextension
#
# Usage:
#   scripts/macos/package-app.sh [osx-x64|osx-arm64] [--skip-publish] [--no-sign] [--build-filter]
#
#   Linux (or any host with the .NET SDK): publishes both .NET parts and assembles an UNSIGNED
#     bundle in build/macos/<rid>/Axiom.app. Code signing and the Swift filter need macOS.
#   macOS ("on-mac" mode, automatic when uname is Darwin): additionally copies the filter artifacts
#     from macos/build (building them with macos/build.sh when --build-filter is given and they are
#     missing), creates the icon and signs inside-out (ad hoc, or AXIOM_SIGN_IDENTITY).
#
#   Typical VM loop (the VM has no .NET SDK):
#     linux$ scripts/macos/package-app.sh osx-x64                 # publish + unsigned bundle
#     linux$ tar cf - build/macos/osx-x64/publish scripts/macos macos src/Axiom.UI.Avalonia/Assets \
#              Directory.Build.props | ssh mac 'mkdir -p ~/axiom && tar xf - -C ~/axiom'
#     mac$   ~/axiom/scripts/macos/package-app.sh osx-x64 --skip-publish --build-filter
#     mac$   sudo rm -rf /Applications/Axiom.app && sudo ditto ~/axiom/build/macos/osx-x64/Axiom.app /Applications/Axiom.app
#
# Environment:
#   AXIOM_SIGN_IDENTITY   codesign identity (Developer ID); unset = ad hoc ("-")
#   AXIOM_INSTALLER_IDENTITY  "Developer ID Installer: …" for Axiom.pkg; unset = unsigned .pkg
#   AXIOM_TEAM_ID         team id for the app group (default: "(TEAMID)" suffix of the identity)
#   AXIOM_APP_PROFILE     provisioning profile embedded as Contents/embedded.provisionprofile
#   AXIOM_BUILD           CFBundleVersion (default 1)
#   AXIOM_SERVICE_PROJECT path of Axiom.Service.csproj to publish (default: this repository's)
#   DOTNET                dotnet executable (default: dotnet on PATH, then ~/.dotnet/dotnet)
#   DOTNET_WRAPPER        command prefix for dotnet publish (e.g. a flock wrapper)
set -euo pipefail

cd "$(dirname "$0")/../.."
ROOT=$(pwd)

RID=osx-x64
SKIP_PUBLISH=0
NO_SIGN=0
BUILD_FILTER=0
for argument in "$@"; do
  case "$argument" in
    osx-x64|osx-arm64) RID=$argument ;;
    --skip-publish) SKIP_PUBLISH=1 ;;
    --no-sign) NO_SIGN=1 ;;
    --build-filter) BUILD_FILTER=1 ;;
    -h|--help) sed -n '3,40p' "$0"; exit 0 ;;
    *) printf 'package-app.sh: unknown argument %s\n' "$argument" >&2; exit 64 ;;
  esac
done

log() { printf '==> %s\n' "$*" >&2; }
die() { printf 'package-app.sh: %s\n' "$*" >&2; exit 1; }

APP_ID=com.axiom.firewall
EXT_ID=com.axiom.firewall.filter
MIN_OS=13.0
OUT="$ROOT/build/macos/$RID"
PUBLISH="$OUT/publish"
APP="$OUT/Axiom.app"
FILTER_BUILD="$ROOT/macos/build"
ON_MAC=0
[[ "$(uname -s)" == Darwin ]] && ON_MAC=1

VERSION=$(sed -n 's:.*<Version>\(.*\)</Version>.*:\1:p' "$ROOT/Directory.Build.props" | head -n 1)
VERSION=${VERSION:-0.0.0}
BUILD=${AXIOM_BUILD:-1}

# ---------------------------------------------------------------------------------------------
# 1. Publish (.NET SDK host: Linux, Windows or a Mac with the SDK)
# ---------------------------------------------------------------------------------------------
if [[ $SKIP_PUBLISH -eq 0 ]]; then
  DOTNET=${DOTNET:-$(command -v dotnet || echo "$HOME/.dotnet/dotnet")}
  [[ -x "$DOTNET" ]] || die "dotnet not found (set DOTNET or use --skip-publish with an existing $PUBLISH)"
  SERVICE_PROJECT=${AXIOM_SERVICE_PROJECT:-$ROOT/src/Axiom.Service/Axiom.Service.csproj}
  # Split the optional wrapper into an array only when it is set: `read -a` on empty input leaves
  # an empty array, and macOS's bash 3.2 aborts on "${WRAP[@]}" under set -u.
  [[ -n "${DOTNET_WRAPPER:-}" ]] && read -r -a WRAP <<<"$DOTNET_WRAPPER"
  rm -rf "$PUBLISH"
  log "dotnet publish Axiom.Desktop.Avalonia.MacOS ($RID)"
  ${WRAP[@]+"${WRAP[@]}"} "$DOTNET" publish "$ROOT/src/Axiom.Desktop.Avalonia.MacOS/Axiom.Desktop.Avalonia.MacOS.csproj" \
    -c Release -r "$RID" --self-contained true -m:2 -nologo -v:q \
    -p:UseAppHost=true -p:PublishSingleFile=false -o "$PUBLISH/app"
  log "dotnet publish Axiom.Service -> axiomd ($RID)"
  ${WRAP[@]+"${WRAP[@]}"} "$DOTNET" publish "$SERVICE_PROJECT" \
    -f net10.0 -c Release -r "$RID" --self-contained true -m:2 -nologo -v:q \
    -p:UseAppHost=true -o "$PUBLISH/service"
  "$DOTNET" build-server shutdown >/dev/null 2>&1 || true
  # A RID-specific restore appends "net10.0/osx-*" sections to packages.lock.json; like the
  # Windows release scripts, those are build artefacts and are not committed.
  log "note: publish adds RID sections to packages.lock.json; discard them with: git checkout -- '*.lock.json'"
fi

[[ -x "$PUBLISH/app/Axiom" ]] || die "missing $PUBLISH/app/Axiom (publish first)"
[[ -x "$PUBLISH/service/axiomd" ]] || die "missing $PUBLISH/service/axiomd (publish first)"

# ---------------------------------------------------------------------------------------------
# 2. Bundle layout
# ---------------------------------------------------------------------------------------------
log "assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/service"
cp -R "$PUBLISH/app/." "$APP/Contents/MacOS/"
cp -R "$PUBLISH/service/." "$APP/Contents/Resources/service/"
# Debug symbols are not shipped.
find "$APP/Contents" -name '*.pdb' -delete

ICON_KEY=""
ICON_PNG="$ROOT/src/Axiom.UI.Avalonia/Assets/axiom-icon.png"
if [[ -f "$ICON_PNG" ]] && command -v sips >/dev/null && command -v iconutil >/dev/null; then
  ICONSET="$OUT/Axiom.iconset"
  rm -rf "$ICONSET"; mkdir -p "$ICONSET"
  for size in 16 32 128 256 512; do
    sips -z $size $size "$ICON_PNG" --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
    double=$((size * 2))
    sips -z $double $double "$ICON_PNG" --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
  done
  iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/Axiom.icns"
  rm -rf "$ICONSET"
  ICON_KEY="<key>CFBundleIconFile</key><string>Axiom</string>"
elif command -v png2icns >/dev/null && [[ -f "$ICON_PNG" ]]; then
  png2icns "$APP/Contents/Resources/Axiom.icns" "$ICON_PNG" >/dev/null && \
    ICON_KEY="<key>CFBundleIconFile</key><string>Axiom</string>"
else
  log "no icon tools (sips/iconutil or png2icns): bundle has no icon"
fi

cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>$APP_ID</string>
  <key>CFBundleExecutable</key><string>Axiom</string>
  <key>CFBundleName</key><string>Axiom</string>
  <key>CFBundleDisplayName</key><string>Axiom</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$BUILD</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>LSMinimumSystemVersion</key><string>$MIN_OS</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSHumanReadableCopyright</key><string>Copyright (C) 2026 The Axiom contributors. GPL-3.0-or-later.</string>
  $ICON_KEY
</dict>
</plist>
EOF

# ---------------------------------------------------------------------------------------------
# 3. Filter system extension + helper (Swift; built on macOS only)
# ---------------------------------------------------------------------------------------------
# Always rebuild when asked (a stale macos/build would silently ship old filter code); the version
# contract is macos/README.md "Versioning": the extension carries the product version and build.
if [[ $ON_MAC -eq 1 && $BUILD_FILTER -eq 1 ]]; then
  arch=x86_64; [[ "$RID" == osx-arm64 ]] && arch=arm64
  log "building the filter extension (macos/build.sh, ARCH=$arch, version $VERSION build $BUILD)"
  AXIOM_VERSION="$VERSION" AXIOM_BUILD="$BUILD" ARCH=$arch "$ROOT/macos/build.sh"
fi

HAS_FILTER=0
HAS_SYSEXT_LIB=0
if [[ -d "$FILTER_BUILD/$EXT_ID.systemextension" && -f "$FILTER_BUILD/axiom-sysext" ]]; then
  log "adding the filter extension and axiom-sysext from macos/build"
  mkdir -p "$APP/Contents/Library/SystemExtensions"
  cp -R "$FILTER_BUILD/$EXT_ID.systemextension" "$APP/Contents/Library/SystemExtensions/"
  cp "$FILTER_BUILD/axiom-sysext" "$APP/Contents/MacOS/axiom-sysext"
  HAS_FILTER=1
  # In-process activation path (review #4): the main executable P/Invokes this dylib; the helper
  # stays as the fallback and the diagnostics CLI. Only shipped when build.sh produced it.
  if [[ -f "$FILTER_BUILD/libAxiomSysext.dylib" ]]; then
    cp "$FILTER_BUILD/libAxiomSysext.dylib" "$APP/Contents/MacOS/libAxiomSysext.dylib"
    HAS_SYSEXT_LIB=1
    log "adding libAxiomSysext.dylib (in-process activation)"
  fi
else
  log "no prebuilt filter in macos/build (run macos/build.sh on a Mac): bundle has no network filter"
fi

if [[ -n "${AXIOM_APP_PROFILE:-}" ]]; then
  cp "$AXIOM_APP_PROFILE" "$APP/Contents/embedded.provisionprofile"
fi

# ---------------------------------------------------------------------------------------------
# 4. Sign inside-out (macOS only)
# ---------------------------------------------------------------------------------------------
if [[ $ON_MAC -eq 0 || $NO_SIGN -eq 1 ]]; then
  log "unsigned bundle: $APP"
  [[ $ON_MAC -eq 0 ]] && log "finish on a Mac: copy this tree and run scripts/macos/package-app.sh $RID --skip-publish"
  exit 0
fi

IDENTITY=${AXIOM_SIGN_IDENTITY:-}
if [[ -n "$IDENTITY" ]]; then
  TEAM_ID=${AXIOM_TEAM_ID:-$(sed -n 's/.*(\([A-Z0-9]\{10\}\)).*/\1/p' <<<"$IDENTITY")}
  [[ -n "$TEAM_ID" ]] || die "set AXIOM_TEAM_ID (could not derive it from AXIOM_SIGN_IDENTITY)"
  APP_GROUP="$TEAM_ID.$APP_ID"
  # A secure timestamp only exists for a real identity; ad hoc signatures have none.
  SIGN_ARGS=(--sign "$IDENTITY" --options runtime --timestamp)
else
  APP_GROUP="group.$APP_ID"
  SIGN_ARGS=(--sign - --options runtime)
fi

# dSYMs (Developer ID only): the Swift filter extension and helper carry DWARF that dsymutil can
# extract; the .NET parts have no dSYM (portable .pdb is the managed equivalent and is produced
# by publish; it is stripped from the bundle above, keep build/macos/<rid>/publish for symbolication).
if [[ -n "$IDENTITY" && $HAS_FILTER -eq 1 ]] && command -v dsymutil >/dev/null; then
  DSYMS="$OUT/dSYMs"; rm -rf "$DSYMS"; mkdir -p "$DSYMS"
  for bin in "$APP/Contents/Library/SystemExtensions/$EXT_ID.systemextension/Contents/MacOS/$EXT_ID" \
             "$APP/Contents/MacOS/axiom-sysext" "$APP/Contents/MacOS/libAxiomSysext.dylib"; do
    [[ -f "$bin" ]] && dsymutil "$bin" -o "$DSYMS/$(basename "$bin").dSYM" 2>/dev/null \
      && log "dSYM: $DSYMS/$(basename "$bin").dSYM" || log "no DWARF for $(basename "$bin") (n/a)"
  done
fi

ENTITLEMENTS="$OUT/Axiom.entitlements"
sed -e "s|@APP_GROUP@|$APP_GROUP|g" "$ROOT/scripts/macos/Axiom.entitlements" > "$ENTITLEMENTS"
plutil -lint -s "$ENTITLEMENTS"

is_macho() { # Mach-O or fat magic: feedface/feedfacf (thin), cefaedfe/cffaedfe (swapped), cafebabe (fat)
  local magic
  magic=$(od -An -N4 -tx1 "$1" 2>/dev/null | tr -d ' \n')
  case "$magic" in
    feedface|feedfacf|cefaedfe|cffaedfe|cafebabe) return 0 ;;
    *) return 1 ;;
  esac
}

sign_tree() { # sign_tree <dir> <macho|all> <skip-name...>: deepest first (review #16)
  # "macho": only Mach-O files; everything else (managed .dll, .json, .plist) is sealed by the
  # bundle signature as a resource. "all": every regular file — codesign treats Contents/MacOS as
  # code, not resources, so a non-Mach-O file there must carry its own signature or
  # `--verify --deep --strict` fails with "code object is not signed at all".
  local dir=$1 mode=$2; shift 2
  local skip=("$@")
  local signed=0 skipped=0
  while IFS= read -r -d '' file; do
    local name; name=$(basename "$file")
    local wanted=1
    for s in "${skip[@]}"; do [[ "$name" == "$s" ]] && wanted=0; done
    if [[ $wanted -eq 1 ]]; then
      if [[ $mode == all ]] || is_macho "$file"; then
        codesign --force "${SIGN_ARGS[@]}" "$file" 2>&1 | grep -v 'replacing existing signature' || true
        signed=$((signed + 1))
      else skipped=$((skipped + 1)); fi
    fi
  done < <(find "$dir" -type f -print0 | sort -z -r)
  log "  signed $signed files, left $skipped non-Mach-O files to the bundle seal"
}

log "codesign axiomd and its runtime (Contents/Resources/service)"
sign_tree "$APP/Contents/Resources/service" macho axiomd
codesign --force "${SIGN_ARGS[@]}" --identifier com.axiom.service \
  --entitlements "$ROOT/scripts/macos/axiomd.entitlements" "$APP/Contents/Resources/service/axiomd"

log "codesign the .NET runtime and libraries (Contents/MacOS)"
# axiom-sysext keeps the signature and entitlements from macos/build.sh; Axiom is signed with the bundle.
# libAxiomSysext.dylib is a Mach-O in Contents/MacOS and is (re)signed here with the same identity
# as the runtime libraries, keeping build.sh's identifier (a library carries no entitlements).
sign_tree "$APP/Contents/MacOS" all Axiom axiom-sysext libAxiomSysext.dylib
if [[ $HAS_SYSEXT_LIB -eq 1 ]]; then
  codesign --force "${SIGN_ARGS[@]}" --identifier com.axiom.firewall.sysextlib "$APP/Contents/MacOS/libAxiomSysext.dylib" \
    2>&1 | grep -v 'replacing existing signature' || true
fi

if [[ $HAS_FILTER -eq 1 ]]; then
  codesign --verify --strict "$APP/Contents/Library/SystemExtensions/$EXT_ID.systemextension"
  codesign --verify --strict "$APP/Contents/MacOS/axiom-sysext"
fi
if [[ $HAS_SYSEXT_LIB -eq 1 ]]; then
  codesign --verify --strict "$APP/Contents/MacOS/libAxiomSysext.dylib"
fi

log "codesign Axiom.app (${IDENTITY:-ad hoc}, app group $APP_GROUP)"
codesign --force "${SIGN_ARGS[@]}" --entitlements "$ENTITLEMENTS" "$APP"
codesign --verify --deep --strict "$APP"
log "signed bundle: $APP"

# ---------------------------------------------------------------------------------------------
# 5. Installer package: /Applications/Axiom.app + postinstall that installs the daemon
# ---------------------------------------------------------------------------------------------
if command -v pkgbuild >/dev/null; then
  PKGROOT="$OUT/pkgroot"; SCRIPTS="$OUT/pkgscripts"
  rm -rf "$PKGROOT" "$SCRIPTS"; mkdir -p "$PKGROOT/Applications" "$SCRIPTS"
  ditto "$APP" "$PKGROOT/Applications/Axiom.app"
  cat > "$SCRIPTS/postinstall" <<'EOF'
#!/bin/sh
# Installs the root daemon (launchd plist, root-owned helper copy, newsyslog rotation); idempotent.
# Installer scripts get $2 = installation destination and $3 = target volume mountpoint; with
# --install-location / and a root-relative payload both are the volume root, so the daemon path
# is <destination>/Applications/Axiom.app.
TARGET="${2:-/}"
"$TARGET/Applications/Axiom.app/Contents/Resources/service/axiomd" --install-service || exit 1
exit 0
EOF
  chmod 755 "$SCRIPTS/postinstall"
  PKG="$OUT/Axiom.pkg"
  PKG_SIGN=()
  [[ -n "${AXIOM_INSTALLER_IDENTITY:-}" ]] && PKG_SIGN=(--sign "$AXIOM_INSTALLER_IDENTITY" --timestamp)
  pkgbuild --root "$PKGROOT" --identifier "$APP_ID.pkg" --version "$VERSION" --install-location / \
    --scripts "$SCRIPTS" ${PKG_SIGN[@]+"${PKG_SIGN[@]}"} "$PKG" >/dev/null
  # The postinstall runs "$2/Applications/Axiom.app/...": fail the package if the payload does not
  # place the app there, instead of shipping an installer that cannot start the daemon.
  pkgutil --payload-files "$PKG" > "$OUT/pkg-payload-files.txt"
  grep -qx './Applications/Axiom.app' "$OUT/pkg-payload-files.txt" \
    || die "the payload does not install Applications/Axiom.app, but postinstall expects it there"
  log "installer: $PKG (unsigned unless AXIOM_INSTALLER_IDENTITY=\"Developer ID Installer: …\")"
fi
log "install (bundle only): sudo rm -rf /Applications/Axiom.app && sudo ditto '$APP' /Applications/Axiom.app"
