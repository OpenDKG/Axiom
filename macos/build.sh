#!/usr/bin/env bash
# Build the Axiom macOS filter system extension and its activation helper with the
# Xcode Command Line Tools only (swiftc + codesign + lipo; no Xcode project).
#
#   macos/build.sh            build the artifacts:
#                               macos/build/com.axiom.firewall.filter.systemextension
#                               macos/build/axiom-sysext            (activation helper CLI)
#                               macos/build/libAxiomSysext.dylib    (same, as P/Invoke entry points)
#   macos/build.sh testapp    also assemble a minimal host app, macos/build/Axiom.app
#                             (axiom-sysext as CFBundleExecutable) for development testing
#   macos/build.sh test       compile and run the filter unit tests (no signing)
#   macos/build.sh clean      remove macos/build
#
# Environment:
#   ARCH=x86_64|arm64|universal   target architecture(s) (default: this Mac's arch)
#   AXIOM_SIGN_IDENTITY           codesign identity (e.g. "Developer ID Application: Name (TEAMID)");
#                                 unset = ad hoc signature (needs SIP off + systemextensionsctl developer on)
#   AXIOM_TEAM_ID                 Apple team id; defaults to the "(TEAMID)" suffix of AXIOM_SIGN_IDENTITY.
#                                 Used for the app group "<TEAMID>.com.axiom.firewall"
#                                 (ad hoc builds use "group.com.axiom.firewall").
#   AXIOM_FILTER_PROFILE          provisioning profile embedded into the extension (Developer ID builds)
#   AXIOM_APP_PROFILE             provisioning profile embedded into the test app (Developer ID builds)
#   AXIOM_VERSION / AXIOM_BUILD   CFBundleShortVersionString / CFBundleVersion of the extension.
#                                 Release mode (AXIOM_SIGN_IDENTITY set): AXIOM_VERSION is REQUIRED
#                                 (the build fails without it); AXIOM_BUILD defaults to the git commit
#                                 count. Dev mode: AXIOM_VERSION defaults to 0.0.<commit count> and
#                                 AXIOM_BUILD to <commit count>.<build timestamp>, so every build
#                                 differs and `activate` replaces the installed extension.
#                                 The packaging script must pass the product version through
#                                 these two variables (see macos/README.md "Versioning").
#   AXIOM_TESTAPP_LAYOUT=helper   testapp variant whose main executable is a stub "Axiom" and
#                                 axiom-sysext is a secondary executable, like the real product
set -euo pipefail

cd "$(dirname "$0")"
MACOS_DIR=$(pwd)
OUT="$MACOS_DIR/build"
OBJ="$OUT/obj"

APP_ID=com.axiom.firewall
EXT_ID=com.axiom.firewall.filter
EXT_BUNDLE="$OUT/$EXT_ID.systemextension"
HELPER="$OUT/axiom-sysext"
LIBRARY="$OUT/libAxiomSysext.dylib"
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

build_helper() {
  compile AxiomSysext "$HELPER" AxiomSysext/main.swift AxiomSysext/SysextCore.swift
  substitute AxiomSysext/axiom-sysext.entitlements "$OUT/axiom-sysext.entitlements"
  log "codesign axiom-sysext"
  # Identifier = the app's bundle id: restricted entitlements of an executable inside
  # Axiom.app are validated against the app's provisioning profile (Developer ID builds).
  codesign --force "${SIGN_ARGS[@]}" --identifier "$APP_ID" \
    --entitlements "$OUT/axiom-sysext.entitlements" "$HELPER"
}

# Same operations as a dylib with C entry points (axiom_sysext_activate, ...) for the .NET host.
# No entitlements on the library: the calling executable (Axiom) must carry them.
build_library() {
  compile AxiomSysextLib "$LIBRARY" -emit-library \
    -Xlinker -install_name -Xlinker "@executable_path/libAxiomSysext.dylib" \
    AxiomSysext/SysextCore.swift AxiomSysextLib/Exports.swift
  log "codesign libAxiomSysext.dylib"
  codesign --force "${SIGN_ARGS[@]}" --identifier "$APP_ID.sysextlib" "$LIBRARY"
}

# Minimal host app for development: /Applications/Axiom.app with the helper and the extension.
build_testapp() {
  local app="$OUT/Axiom.app" layout=${AXIOM_TESTAPP_LAYOUT:-main} main_exe
  rm -rf "$app"
  mkdir -p "$app/Contents/MacOS" "$app/Contents/Library/SystemExtensions"
  cp -R "$EXT_BUNDLE" "$app/Contents/Library/SystemExtensions/"
  cp "$HELPER" "$app/Contents/MacOS/axiom-sysext"
  if [[ "$layout" == helper ]]; then
    # Product-like layout: a stub main executable; axiom-sysext is a secondary executable.
    main_exe=Axiom
    printf 'import Foundation\nprint("Axiom test host stub; use Contents/MacOS/axiom-sysext")\n' > "$OBJ/stub.swift"
    compile AxiomStub "$app/Contents/MacOS/Axiom" "$OBJ/stub.swift"
    # The helper keeps its own signature/entitlements (signed in build_helper).
  else
    main_exe=axiom-sysext
  fi
  cat > "$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>$APP_ID</string>
  <key>CFBundleExecutable</key><string>$main_exe</string>
  <key>CFBundleName</key><string>Axiom</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$BUILD</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>LSMinimumSystemVersion</key><string>$MIN_OS</string>
  <key>LSUIElement</key><true/>
</dict></plist>
EOF
  if [[ -n "${AXIOM_APP_PROFILE:-}" ]]; then
    cp "$AXIOM_APP_PROFILE" "$app/Contents/embedded.provisionprofile"
  fi
  log "codesign Axiom.app (layout: $layout)"
  # Signing the bundle signs its main executable with these entitlements and seals the
  # already-signed nested code (extension, helper).
  codesign --force "${SIGN_ARGS[@]}" --entitlements "$OUT/axiom-sysext.entitlements" "$app"
  codesign --verify --deep --strict "$app"
  log "test app: $app (copy to /Applications, then run /Applications/Axiom.app/Contents/MacOS/axiom-sysext activate)"
}

run_tests() {
  mkdir -p "$OBJ"
  log "swiftc filter unit tests"
  swiftc -swift-version 5 -warnings-as-errors -sdk "$SDK" -target "$(uname -m)-apple-macos$MIN_OS" \
    -module-name FilterTests -o "$OBJ/filter-tests" \
    AxiomFilter/RuleTable.swift AxiomFilter/RuleStore.swift AxiomFilter/EventSink.swift Tests/main.swift
  AXIOM_RULE_FIXTURES="$MACOS_DIR/Tests/fixtures/rules-cases.json" "$OBJ/filter-tests"
}

case "${1:-build}" in
  clean) rm -rf "$OUT"; exit 0 ;;
  test) run_tests; exit 0 ;;
  build|testapp) ;;
  *) die "usage: build.sh [build|testapp|test|clean]" ;;
esac

mkdir -p "$OBJ"
log "version $VERSION build $BUILD ($GIT_REV)"
build_extension
build_helper
build_library
codesign --verify --strict "$EXT_BUNDLE"
codesign --verify --strict "$HELPER"
codesign --verify --strict "$LIBRARY"
[[ "${1:-build}" == testapp ]] && build_testapp
log "built ($ARCH, ${IDENTITY:-ad hoc}, app group $APP_GROUP, version $VERSION build $BUILD):"
log "  $EXT_BUNDLE"
log "  $HELPER"
log "  $LIBRARY"
