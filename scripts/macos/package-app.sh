#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Assemble Axiom.app (UI) and AxiomFilterHost.app (activation host) for macOS
# (docs/MACOS_ARCHITECTURE.md §1 and §4):
#
#   Axiom.app/Contents/Info.plist
#   Axiom.app/Contents/MacOS/Axiom (+ the self-contained .NET/Avalonia publish output)
#   Axiom.app/Contents/Resources/service/axiomd (+ its publish output)
#   Axiom.app/Contents/Resources/Axiom.icns                              (when sips/iconutil exist)
#   AxiomFilterHost.app/                                                 (when macos/build has it)
#     Contents/MacOS/axiom-sysext                                        (activation host/CLI)
#     Contents/Library/SystemExtensions/com.axiom.firewall.filter.systemextension
#
# The activation host is a separate top-level app in /Applications (not nested in Axiom.app):
# macOS activates an extension only when the requesting app is in an Applications directory and
# the extension is in that app's Contents/Library/SystemExtensions. The host owns the restricted
# entitlements and provisioning profile; the JIT UI claims none of them.
#
# Usage:
#   scripts/macos/package-app.sh [osx-x64|osx-arm64] [--skip-publish] [--no-sign] [--build-filter]
#
#   Linux (or any host with the .NET SDK): publishes both .NET parts and assembles an UNSIGNED
#     bundle in build/macos/<rid>/Axiom.app. Code signing and the Swift filter need macOS.
#   macOS ("on-mac" mode, automatic when uname is Darwin): additionally copies the filter host
#     from macos/build (building it with macos/build.sh when --build-filter is given), creates the
#     icon and signs inside-out (ad hoc, or AXIOM_SIGN_IDENTITY).
#
#   Typical VM loop (the VM has no .NET SDK):
#     linux$ scripts/macos/package-app.sh osx-x64                 # publish + unsigned bundle
#     linux$ tar cf - build/macos/osx-x64/publish scripts/macos macos src/Axiom.UI.Avalonia/Assets \
#              Directory.Build.props | ssh mac 'mkdir -p ~/axiom && tar xf - -C ~/axiom'
#     mac$   ~/axiom/scripts/macos/package-app.sh osx-x64 --skip-publish --build-filter
#     mac$   sudo rm -rf /Applications/Axiom.app /Applications/AxiomFilterHost.app
#     mac$   sudo ditto ~/axiom/build/macos/osx-x64/Axiom.app /Applications/Axiom.app
#     mac$   sudo ditto ~/axiom/build/macos/osx-x64/AxiomFilterHost.app /Applications/AxiomFilterHost.app
#
# Environment:
#   AXIOM_SIGN_IDENTITY   codesign identity (Developer ID); unset = ad hoc ("-")
#   AXIOM_INSTALLER_IDENTITY  "Developer ID Installer: …" for Axiom.pkg; unset = unsigned .pkg
#   AXIOM_TEAM_ID         team id for the app group (default: "(TEAMID)" suffix of the identity)
#   AXIOM_HOST_PROFILE    provisioning profile for AxiomFilterHost.app (required when signed)
#   AXIOM_FILTER_PROFILE  provisioning profile for com.axiom.firewall.filter (required when signed)
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
    -h|--help) sed -n '3,48p' "$0"; exit 0 ;;
    *) printf 'package-app.sh: unknown argument %s\n' "$argument" >&2; exit 64 ;;
  esac
done

log() { printf '==> %s\n' "$*" >&2; }
die() { printf 'package-app.sh: %s\n' "$*" >&2; exit 1; }

APP_ID=com.axiom.firewall
HOST_ID=com.axiom.firewall.host
EXT_ID=com.axiom.firewall.filter
MIN_OS=13.0
OUT="$ROOT/build/macos/$RID"
PUBLISH="$OUT/publish"
APP="$OUT/Axiom.app"
HOST_APP="$OUT/AxiomFilterHost.app"
FILTER_BUILD="$ROOT/macos/build"
FILTER_HOST="$FILTER_BUILD/AxiomFilterHost.app"
ON_MAC=0
[[ "$(uname -s)" == Darwin ]] && ON_MAC=1

VERSION=$(sed -n 's:.*<Version>\(.*\)</Version>.*:\1:p' "$ROOT/Directory.Build.props" | head -n 1)
VERSION=${VERSION:-0.0.0}
BUILD=${AXIOM_BUILD:-1}

# Signing configuration is decided before the Swift build so a signed release never even builds
# an ad hoc host or a host without an authorising profile.
SIGNING=0
IDENTITY=${AXIOM_SIGN_IDENTITY:-}
if [[ $ON_MAC -eq 1 && $NO_SIGN -eq 0 && -n "$IDENTITY" ]]; then
  SIGNING=1
  TEAM_ID=${AXIOM_TEAM_ID:-$(sed -n 's/.*(\([A-Z0-9]\{10\}\)).*/\1/p' <<<"$IDENTITY")}
  [[ -n "$TEAM_ID" ]] || die "set AXIOM_TEAM_ID (could not derive it from AXIOM_SIGN_IDENTITY)"
  APP_GROUP="$TEAM_ID.$APP_ID"
  # A secure timestamp only exists for a real identity; ad hoc signatures have none.
  SIGN_ARGS=(--sign "$IDENTITY" --options runtime --timestamp)
  [[ -n "${AXIOM_HOST_PROFILE:-}" && -f "${AXIOM_HOST_PROFILE:-}" ]] \
    || die "AXIOM_HOST_PROFILE must point to the provisioning profile for AxiomFilterHost.app ($HOST_ID)"
  [[ -n "${AXIOM_FILTER_PROFILE:-}" && -f "${AXIOM_FILTER_PROFILE:-}" ]] \
    || die "AXIOM_FILTER_PROFILE must point to the provisioning profile for $EXT_ID"
else
  APP_GROUP="group.$APP_ID"
  SIGN_ARGS=(--sign - --options runtime)
fi

# PlistBuddy handles entitlement keys that contain dots (plutil -extract treats dots as a
# keypath). PLISTBUDDY is overridable so the packaging tests can run without macOS's tool.
PLISTBUDDY=${PLISTBUDDY:-/usr/libexec/PlistBuddy}
profile_value() { # plist key
  "$PLISTBUDDY" -c "Print :Entitlements:$2" "$1" 2>/dev/null
}

# validate_profile <profile> <expected-app-id> <label>: the profile must authorise this Team ID
# and application identifier, otherwise macOS would reject the signed host at runtime.
validate_profile() {
  local profile=$1 expected_app_id=$2 label=$3 plist app_id team_id
  plist=$(mktemp "${TMPDIR:-/tmp}/axiom-profile.XXXXXX") || die "cannot create a temporary file"
  security cms -D -i "$profile" > "$plist" 2>/dev/null \
    || die "$label profile '$profile' is not a valid provisioning profile"
  app_id=$(profile_value "$plist" com.apple.application-identifier || true)
  team_id=$(profile_value "$plist" com.apple.developer.team-identifier || true)
  [[ "$app_id" == "$expected_app_id" ]] \
    || die "$label profile authorises '$app_id', expected '$expected_app_id' (Team ID/profile mismatch)"
  [[ "$team_id" == "$TEAM_ID" ]] \
    || die "$label profile belongs to team '$team_id', expected '$TEAM_ID' (Team ID/profile mismatch)"
  rm -f "$plist"
}

require_profile_entitlement() { # profile key label
  local plist
  plist=$(mktemp "${TMPDIR:-/tmp}/axiom-profile.XXXXXX") || die "cannot create a temporary file"
  security cms -D -i "$1" > "$plist" 2>/dev/null || die "$3 profile is not a valid provisioning profile"
  profile_value "$plist" "$2" >/dev/null \
    || die "$3 profile does not authorise $2"
  rm -f "$plist"
}

if [[ $SIGNING -eq 1 ]]; then
  validate_profile "$AXIOM_HOST_PROFILE" "$TEAM_ID.$HOST_ID" "host"
  validate_profile "$AXIOM_FILTER_PROFILE" "$TEAM_ID.$EXT_ID" "filter extension"
  require_profile_entitlement "$AXIOM_HOST_PROFILE" "com.apple.developer.system-extension.install" "host"
  require_profile_entitlement "$AXIOM_HOST_PROFILE" "com.apple.developer.networking.networkextension" "host"
  require_profile_entitlement "$AXIOM_HOST_PROFILE" "com.apple.security.application-groups" "host"
  require_profile_entitlement "$AXIOM_FILTER_PROFILE" "com.apple.developer.networking.networkextension" "filter extension"
  require_profile_entitlement "$AXIOM_FILTER_PROFILE" "com.apple.security.application-groups" "filter extension"
fi

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
# 3. Activation host + filter system extension (Swift; built on macOS only)
# ---------------------------------------------------------------------------------------------
# Always rebuild when asked (a stale macos/build would silently ship old filter code); the version
# contract is macos/README.md "Versioning": the extension carries the product version and build.
if [[ $BUILD_FILTER -eq 1 ]]; then
  [[ $ON_MAC -eq 1 ]] || die "--build-filter requires macOS (swiftc/codesign)"
  arch=x86_64; [[ "$RID" == osx-arm64 ]] && arch=arm64
  log "building the activation host (macos/build.sh, ARCH=$arch, version $VERSION build $BUILD)"
  AXIOM_VERSION="$VERSION" AXIOM_BUILD="$BUILD" ARCH=$arch "$ROOT/macos/build.sh"
fi

HAS_FILTER=0
rm -rf "$HOST_APP"
if [[ -d "$FILTER_HOST" ]]; then
  log "adding AxiomFilterHost.app from macos/build"
  cp -R "$FILTER_HOST" "$HOST_APP"
  [[ -d "$HOST_APP/Contents/Library/SystemExtensions/$EXT_ID.systemextension" ]] \
    || die "AxiomFilterHost.app does not contain $EXT_ID.systemextension"
  [[ -f "$HOST_APP/Contents/embedded.provisionprofile" || $SIGNING -eq 0 ]] \
    || die "AxiomFilterHost.app has no embedded provisioning profile; rebuild it with AXIOM_HOST_PROFILE"
  [[ -f "$HOST_APP/Contents/Library/SystemExtensions/$EXT_ID.systemextension/Contents/embedded.provisionprofile" || $SIGNING -eq 0 ]] \
    || die "$EXT_ID.systemextension has no embedded provisioning profile; rebuild it with AXIOM_FILTER_PROFILE"
  HAS_FILTER=1
elif [[ $BUILD_FILTER -eq 1 ]]; then
  die "macos/build.sh did not produce AxiomFilterHost.app"
else
  log "no prebuilt activation host in macos/build (run macos/build.sh on a Mac): bundle has no network filter"
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

# dSYMs (Developer ID only): the Swift host and filter extension carry DWARF that dsymutil can
# extract; the .NET parts have no dSYM (portable .pdb is the managed equivalent and is produced
# by publish; it is stripped from the bundle above, keep build/macos/<rid>/publish for symbolication).
if [[ -n "$IDENTITY" && $HAS_FILTER -eq 1 ]] && command -v dsymutil >/dev/null; then
  DSYMS="$OUT/dSYMs"; rm -rf "$DSYMS"; mkdir -p "$DSYMS"
  for bin in "$HOST_APP/Contents/Library/SystemExtensions/$EXT_ID.systemextension/Contents/MacOS/$EXT_ID" \
             "$HOST_APP/Contents/MacOS/axiom-sysext"; do
    [[ -f "$bin" ]] && dsymutil "$bin" -o "$DSYMS/$(basename "$bin").dSYM" 2>/dev/null \
      && log "dSYM: $DSYMS/$(basename "$bin").dSYM" || log "no DWARF for $(basename "$bin") (n/a)"
  done
fi

# The UI has no restricted entitlements in either mode. The host app was signed by build.sh with
# its own profile and entitlements; a signed package must not carry a stale/ad hoc host.
ENTITLEMENTS="$OUT/Axiom.entitlements"
sed -e "s|@APP_GROUP@|$APP_GROUP|g" "$ROOT/scripts/macos/Axiom.entitlements" > "$ENTITLEMENTS"
plutil -lint -s "$ENTITLEMENTS"

if [[ $HAS_FILTER -eq 1 ]]; then
  if [[ $SIGNING -eq 1 ]]; then
    host_authority=$(codesign -dv --verbose=2 "$HOST_APP" 2>&1 | sed -n 's/^Authority=//p' | head -n 1)
    [[ "$host_authority" == "$IDENTITY" ]] \
      || die "AxiomFilterHost.app is signed as '${host_authority:-unknown}', not '$IDENTITY'; rebuild with --build-filter"
    host_team=$(codesign -dv --verbose=2 "$HOST_APP" 2>&1 | sed -n 's/^TeamIdentifier=//p' | head -n 1)
    [[ "$host_team" == "$TEAM_ID" ]] \
      || die "AxiomFilterHost.app belongs to team '${host_team:-unknown}', expected '$TEAM_ID'"
  fi
  codesign --verify --deep --strict "$HOST_APP" || die "AxiomFilterHost.app signature is invalid"
fi

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
# The activation host keeps the signature/entitlements/profile from macos/build.sh; only the UI
# runtime files inside Axiom.app are (re)signed here.
sign_tree "$APP/Contents/MacOS" all Axiom

if [[ $HAS_FILTER -eq 1 ]]; then
  codesign --verify --strict "$HOST_APP/Contents/Library/SystemExtensions/$EXT_ID.systemextension"
  codesign --verify --strict "$HOST_APP/Contents/MacOS/axiom-sysext"
fi

log "codesign Axiom.app (${IDENTITY:-ad hoc}, no restricted entitlements)"
codesign --force "${SIGN_ARGS[@]}" --entitlements "$ENTITLEMENTS" "$APP"
codesign --verify --deep --strict "$APP"
if [[ $HAS_FILTER -eq 1 ]]; then
  log "signed bundles: $APP and $HOST_APP"
else
  log "signed bundle: $APP"
fi

# ---------------------------------------------------------------------------------------------
# 5. Installer package: /Applications/Axiom.app + AxiomFilterHost.app + daemon postinstall
# ---------------------------------------------------------------------------------------------
if command -v pkgbuild >/dev/null; then
  PKGROOT="$OUT/pkgroot"; SCRIPTS="$OUT/pkgscripts"
  rm -rf "$PKGROOT" "$SCRIPTS"; mkdir -p "$PKGROOT/Applications" "$SCRIPTS"
  ditto "$APP" "$PKGROOT/Applications/Axiom.app"
  if [[ $HAS_FILTER -eq 1 ]]; then
    ditto "$HOST_APP" "$PKGROOT/Applications/AxiomFilterHost.app"
  fi
  cat > "$SCRIPTS/postinstall" <<'EOF'
#!/bin/sh
# Installs the root daemon (launchd plist, root-owned helper copy, newsyslog rotation); idempotent.
# Installer scripts get $2 = installation destination and $3 = target volume mountpoint. Only the
# running system's /Applications is supported: an offline-volume install would start a live-root
# daemon while the payload went to another volume. Refuse that before changing the system.
TARGET_VOLUME="${3:-${2:-/}}"
case "$TARGET_VOLUME" in
  ""|"/") ;;
  *) echo "Axiom: installing to a non-startup volume ('$TARGET_VOLUME') is not supported." >&2; exit 1 ;;
esac
/Applications/Axiom.app/Contents/Resources/service/axiomd --install-service || exit 1
exit 0
EOF
  chmod 755 "$SCRIPTS/postinstall"
  PKG="$OUT/Axiom.pkg"
  PKG_SIGN=()
  [[ -n "${AXIOM_INSTALLER_IDENTITY:-}" ]] && PKG_SIGN=(--sign "$AXIOM_INSTALLER_IDENTITY" --timestamp)
  pkgbuild --root "$PKGROOT" --identifier "$APP_ID.pkg" --version "$VERSION" --install-location / \
    --scripts "$SCRIPTS" ${PKG_SIGN[@]+"${PKG_SIGN[@]}"} "$PKG" >/dev/null
  # The postinstall runs /Applications/Axiom.app/...: fail the package if the payload does not
  # place the app there, instead of shipping an installer that cannot start the daemon.
  pkgutil --payload-files "$PKG" > "$OUT/pkg-payload-files.txt"
  grep -qx './Applications/Axiom.app' "$OUT/pkg-payload-files.txt" \
    || die "the payload does not install Applications/Axiom.app, but postinstall expects it there"
  if [[ $HAS_FILTER -eq 1 ]]; then
    grep -qx './Applications/AxiomFilterHost.app' "$OUT/pkg-payload-files.txt" \
      || die "the payload does not install Applications/AxiomFilterHost.app"
  fi
  log "installer: $PKG (unsigned unless AXIOM_INSTALLER_IDENTITY=\"Developer ID Installer: …\")"
fi
log "install (bundles only): sudo rm -rf /Applications/Axiom.app /Applications/AxiomFilterHost.app"
log "  sudo ditto '$APP' /Applications/Axiom.app"
if [[ $HAS_FILTER -eq 1 ]]; then
  log "  sudo ditto '$HOST_APP' /Applications/AxiomFilterHost.app"
fi
