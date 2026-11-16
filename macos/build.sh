#!/usr/bin/env bash
# Build the Axiom macOS filter system extension inside its app-like activation host with the
# Xcode Command Line Tools only (swiftc + codesign + lipo; no Xcode project).
#
#   macos/build.sh            build the artifacts:
#                               macos/build/AxiomFilterHost.app
#                                 Contents/MacOS/axiom-sysext      (activation host / CLI)
#                                 Contents/Library/SystemExtensions/
#                                   com.axiom.firewall.filter.systemextension
#   macos/build.sh test       compile and run the filter unit tests (no signing)
#   macos/build.sh clean      remove macos/build
#
# Environment:
#   ARCH=x86_64|arm64|universal   target architecture(s) (default: this Mac's arch)
#   AXIOM_SIGN_IDENTITY           codesign identity (e.g. "Developer ID Application: Name (TEAMID)");
#                                 unset = ad hoc signature (activation then reports that the
#                                 signed package is required; no restricted entitlements are claimed)
#   AXIOM_TEAM_ID                 Apple team id; defaults to the "(TEAMID)" suffix of AXIOM_SIGN_IDENTITY.
#                                 Used for the app group "<TEAMID>.com.axiom.firewall"
#                                 (ad hoc builds use "group.com.axiom.firewall").
#   AXIOM_HOST_PROFILE            provisioning profile for AxiomFilterHost.app (required when signed)
#   AXIOM_FILTER_PROFILE          provisioning profile embedded into the extension (required when signed)
#   AXIOM_VERSION / AXIOM_BUILD   CFBundleShortVersionString / CFBundleVersion of the extension and host.
#                                 Release mode (AXIOM_SIGN_IDENTITY set): AXIOM_VERSION is REQUIRED
#                                 (the build fails without it); AXIOM_BUILD defaults to the git commit
#                                 count. Dev mode: AXIOM_VERSION defaults to 0.0.<commit count> and
#                                 AXIOM_BUILD to <commit count>.<build timestamp>, so every build
#                                 differs and `activate` replaces the installed extension.
#                                 The packaging script must pass the product version through
#                                 these two variables (see macos/README.md "Versioning").
set -euo pipefail

cd "$(dirname "$0")"
MACOS_DIR=$(pwd)
OUT="$MACOS_DIR/build"
OBJ="$OUT/obj"

APP_ID=com.axiom.firewall
HOST_ID=com.axiom.firewall.host
EXT_ID=com.axiom.firewall.filter
EXT_BUNDLE="$OUT/$EXT_ID.systemextension"
HOST_APP="$OUT/AxiomFilterHost.app"
MIN_OS=13.0
ARCH=${ARCH:-$(uname -m)}
IDENTITY=${AXIOM_SIGN_IDENTITY:-}

log() { printf '==> %s\n' "$*" >&2; }
die() { printf 'build.sh: %s\n' "$*" >&2; exit 1; }

# Version/build (review #5): a release build must carry the product version; a dev build gets a
# version and build number that change with every commit and every build.
GIT_COUNT=$(git rev-list --count HEAD 2>/dev/null || echo 0)
GIT_REV=$(git describe --always --dirty 2>/dev/null || echo unknown)
if [[ -n "$IDENTITY" ]]; then
  [[ -n "${AXIOM_VERSION:-}" ]] || die "AXIOM_VERSION must be set for a signed (release) build; pass the product version"
  VERSION=$AXIOM_VERSION
  BUILD=${AXIOM_BUILD:-$GIT_COUNT}
else
  VERSION=${AXIOM_VERSION:-0.0.$GIT_COUNT}
  BUILD=${AXIOM_BUILD:-$GIT_COUNT.$(date -u +%Y%m%d%H%M%S)}
fi
[[ "$VERSION" =~ ^[0-9]+(\.[0-9]+)*([-+][A-Za-z0-9.+-]*)?$ ]] || die "AXIOM_VERSION '$VERSION' is not a version string (e.g. 1.2.3)"
[[ "$BUILD" =~ ^[0-9]+(\.[0-9]+){0,2}$ ]] || die "AXIOM_BUILD '$BUILD' must be 1-3 dot-separated integers (CFBundleVersion)"

command -v swiftc >/dev/null || die "swiftc not found: install the Xcode Command Line Tools (xcode-select --install)"
SDK=$(xcrun --sdk macosx --show-sdk-path)

case "$ARCH" in
  x86_64|arm64) ARCHS=("$ARCH") ;;
  universal) ARCHS=(x86_64 arm64) ;;
  *) die "ARCH must be x86_64, arm64 or universal (got '$ARCH')" ;;
esac

if [[ -n "$IDENTITY" ]]; then
  TEAM_ID=${AXIOM_TEAM_ID:-$(sed -n 's/.*(\([A-Z0-9]\{10\}\)).*/\1/p' <<<"$IDENTITY")}
  [[ -n "$TEAM_ID" ]] || die "set AXIOM_TEAM_ID (could not derive it from AXIOM_SIGN_IDENTITY)"
  [[ -n "${AXIOM_HOST_PROFILE:-}" && -f "${AXIOM_HOST_PROFILE:-}" ]] \
    || die "AXIOM_HOST_PROFILE must point to the provisioning profile for AxiomFilterHost.app ($HOST_ID)"
  [[ -n "${AXIOM_FILTER_PROFILE:-}" && -f "${AXIOM_FILTER_PROFILE:-}" ]] \
    || die "AXIOM_FILTER_PROFILE must point to the provisioning profile for $EXT_ID"
  APP_GROUP="$TEAM_ID.$APP_ID"
  SIGN_ARGS=(--sign "$IDENTITY" --options runtime --timestamp)
else
  APP_GROUP="group.$APP_ID"
  SIGN_ARGS=(--sign - --options runtime)
fi

# substitute <template> <output>: fills @VERSION@ @BUILD@ @GIT@ @APP_GROUP@
substitute() {
  sed -e "s|@VERSION@|$VERSION|g" -e "s|@BUILD@|$BUILD|g" -e "s|@GIT@|$GIT_REV|g" -e "s|@APP_GROUP@|$APP_GROUP|g" "$1" > "$2"
}

# Warnings are errors: the macOS 13/14 code paths wrap deprecated APIs in helpers that are
# themselves marked deprecated, so a clean build has no deprecation warnings on the macOS 15 SDK.
SWIFT_FLAGS=(-O -whole-module-optimization -swift-version 5 -warnings-as-errors -sdk "$SDK")

# compile <module> <output> <sources...>: one slice per arch, lipo'd when universal
compile() {
  local module=$1 output=$2; shift 2
  local slices=()
  for arch in "${ARCHS[@]}"; do
    local slice="$OBJ/$module-$arch"
    log "swiftc $module ($arch)"
    swiftc "${SWIFT_FLAGS[@]}" -target "$arch-apple-macos$MIN_OS" -module-name "$module" -o "$slice" "$@"
    slices+=("$slice")
  done
  if (( ${#slices[@]} > 1 )); then
    lipo -create -output "$output" "${slices[@]}"
  else
    cp "${slices[0]}" "$output"
  fi
}

build_extension() {
  rm -rf "$EXT_BUNDLE"
  mkdir -p "$EXT_BUNDLE/Contents/MacOS"
  compile AxiomFilter "$EXT_BUNDLE/Contents/MacOS/$EXT_ID" \
    AxiomFilter/main.swift AxiomFilter/FilterDataProvider.swift AxiomFilter/RuleTable.swift \
    AxiomFilter/RuleStore.swift AxiomFilter/EventSink.swift AxiomFilter/FlowInspector.swift
  substitute AxiomFilter/Info.plist "$EXT_BUNDLE/Contents/Info.plist"
  plutil -lint -s "$EXT_BUNDLE/Contents/Info.plist"
  if [[ -n "${AXIOM_FILTER_PROFILE:-}" ]]; then
    cp "$AXIOM_FILTER_PROFILE" "$EXT_BUNDLE/Contents/embedded.provisionprofile"
  fi
  substitute AxiomFilter/AxiomFilter.entitlements "$OUT/AxiomFilter.entitlements"
  log "codesign $EXT_ID.systemextension"
  codesign --force "${SIGN_ARGS[@]}" --entitlements "$OUT/AxiomFilter.entitlements" "$EXT_BUNDLE"
}

# The app-like activation host: a real app bundle whose main executable is the native CLI and
# whose profile (signed builds) authorises the restricted entitlements. The extension lives in
# this bundle, so OSSystemExtensionRequest finds it through Bundle.main.
build_host() {
  rm -rf "$HOST_APP"
  mkdir -p "$HOST_APP/Contents/MacOS" "$HOST_APP/Contents/Library/SystemExtensions"
  compile AxiomSysext "$HOST_APP/Contents/MacOS/axiom-sysext" \
    AxiomSysext/main.swift AxiomSysext/SysextCore.swift AxiomSysext/FilterRefreshPolicy.swift
  substitute AxiomSysext/Info.plist "$HOST_APP/Contents/Info.plist"
  plutil -lint -s "$HOST_APP/Contents/Info.plist"
  cp -R "$EXT_BUNDLE" "$HOST_APP/Contents/Library/SystemExtensions/"
  if [[ -n "$IDENTITY" ]]; then
    cp "$AXIOM_HOST_PROFILE" "$HOST_APP/Contents/embedded.provisionprofile"
    substitute AxiomSysext/axiom-sysext.entitlements "$OUT/axiom-sysext.entitlements"
    local entitlements="$OUT/axiom-sysext.entitlements"
  else
    # Ad hoc cannot authorise restricted entitlements; claim none so the host can run and
    # report a clear "signed package required" answer instead of being killed at exec.
    cp AxiomSysext/axiom-sysext-adhoc.entitlements "$OUT/axiom-sysext-adhoc.entitlements"
    local entitlements="$OUT/axiom-sysext-adhoc.entitlements"
  fi
  log "codesign AxiomFilterHost.app"
  codesign --force "${SIGN_ARGS[@]}" --identifier "$HOST_ID" --entitlements "$entitlements" "$HOST_APP"
  codesign --verify --deep --strict "$HOST_APP"
}

run_tests() {
  mkdir -p "$OBJ"
  log "swiftc filter unit tests"
  swiftc -swift-version 5 -warnings-as-errors -sdk "$SDK" -target "$(uname -m)-apple-macos$MIN_OS" \
    -module-name FilterTests -o "$OBJ/filter-tests" \
    AxiomFilter/RuleTable.swift AxiomFilter/RuleStore.swift AxiomFilter/EventSink.swift \
    AxiomSysext/FilterRefreshPolicy.swift Tests/main.swift
  AXIOM_RULE_FIXTURES="$MACOS_DIR/Tests/fixtures/rules-cases.json" "$OBJ/filter-tests"
}

case "${1:-build}" in
  clean) rm -rf "$OUT"; exit 0 ;;
  test) run_tests; exit 0 ;;
  build) ;;
  *) die "usage: build.sh [build|test|clean]" ;;
esac

mkdir -p "$OBJ"
log "version $VERSION build $BUILD ($GIT_REV)"
build_extension
build_host
codesign --verify --strict "$EXT_BUNDLE"
log "built ($ARCH, ${IDENTITY:-ad hoc}, app group $APP_GROUP, version $VERSION build $BUILD):"
log "  $HOST_APP"
log "    Contents/Library/SystemExtensions/$EXT_ID.systemextension"
