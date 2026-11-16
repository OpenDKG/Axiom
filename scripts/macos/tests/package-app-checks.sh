#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Checks the packaging script without publishing, signing, installing or touching a real system:
# fake toolchain in a temp "repo", stub dotnet/pkgbuild/codesign/security/plutil/ditto, real cp/sh.
#
#   scripts/macos/tests/package-app-checks.sh            # from anywhere, bash 3.2 or newer
#
# Covers: DOTNET_WRAPPER unset/empty/populated, unsigned vs signed .pkg arguments, host/profile
# wiring, missing/mismatched profiles, the generated postinstall (syntax, alternate target volume
# refusal), payload ownership of the extension, and unknown-argument refusal.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
SRC=$(cd "$HERE/../../.." && pwd)
TEMP=$(mktemp -d "${TMPDIR:-/tmp}/package-app-checks.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT INT TERM

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS: %s\n' "$*"; }
assert_file_has() { # file pattern description
  grep -q -- "$2" "$1" || fail "$3 (missing '$2' in $1)"
}

# --- fake repo -------------------------------------------------------------------------------
REPO="$TEMP/repo"
mkdir -p "$REPO/scripts/macos" "$REPO/macos" "$REPO/src/Axiom.UI.Avalonia/Assets" \
         "$REPO/build/macos/osx-arm64/publish/app" "$REPO/build/macos/osx-arm64/publish/service" \
         "$REPO/macos/build/AxiomFilterHost.app/Contents/MacOS" \
         "$REPO/macos/build/AxiomFilterHost.app/Contents/Library/SystemExtensions/com.axiom.firewall.filter.systemextension/Contents"
cp "$SRC/scripts/macos/package-app.sh" "$REPO/scripts/macos/"
cp "$SRC/scripts/macos/Axiom.entitlements" "$SRC/scripts/macos/axiomd.entitlements" "$REPO/scripts/macos/"
cp "$SRC/macos/AxiomSysext/axiom-sysext.entitlements" \
   "$SRC/macos/AxiomSysext/axiom-sysext-adhoc.entitlements" "$REPO/macos/"
cp "$SRC/Directory.Build.props" "$REPO/"
printf '#!/bin/sh\nexit 0\n' > "$REPO/build/macos/osx-arm64/publish/app/Axiom"
printf '#!/bin/sh\nexit 0\n' > "$REPO/build/macos/osx-arm64/publish/service/axiomd"
printf '#!/bin/sh\n' > "$REPO/macos/build/AxiomFilterHost.app/Contents/MacOS/axiom-sysext"
printf 'fake host profile\n' > "$REPO/macos/build/AxiomFilterHost.app/Contents/embedded.provisionprofile"
printf 'fake filter profile\n' > "$REPO/macos/build/AxiomFilterHost.app/Contents/Library/SystemExtensions/com.axiom.firewall.filter.systemextension/Contents/embedded.provisionprofile"
printf '#!/bin/sh\n' > "$REPO/macos/build/AxiomFilterHost.app/Contents/Library/SystemExtensions/com.axiom.firewall.filter.systemextension/axiom-filter"
cat > "$REPO/macos/build/AxiomFilterHost.app/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.axiom.firewall.host</string>
  <key>CFBundleExecutable</key><string>axiom-sysext</string>
</dict></plist>
EOF
chmod +x "$REPO/build/macos/osx-arm64/publish/app/Axiom" \
         "$REPO/build/macos/osx-arm64/publish/service/axiomd" \
         "$REPO/macos/build/AxiomFilterHost.app/Contents/MacOS/axiom-sysext"

# --- fake toolchain --------------------------------------------------------------------------
BIN="$TEMP/bin"
mkdir -p "$BIN"
cat > "$BIN/uname" <<'EOF'
#!/bin/sh
[ "$1" = "-s" ] && { echo Darwin; exit 0; }
exec /usr/bin/uname "$@"
EOF
cat > "$BIN/plutil" <<'EOF'
#!/bin/sh
# Enough of plutil for profile validation and lint.
if [ "$1" = "-extract" ]; then
  key=$2
  file=
  for argument; do file=$argument; done
  case "$key" in
    Entitlements.com.apple.application-identifier)
      if grep -q host "$file" 2>/dev/null; then
        printf '%s\n' "${EXPECTED_HOST_APP_ID:-ABCDE12345.com.axiom.firewall.host}"
      elif grep -q filter "$file" 2>/dev/null; then
        printf '%s\n' "${EXPECTED_FILTER_APP_ID:-ABCDE12345.com.axiom.firewall.filter}"
      else
        printf 'WRONG\n'
      fi
      ;;
    Entitlements.com.apple.developer.team-identifier) printf '%s\n' "${EXPECTED_TEAM_ID:-ABCDE12345}" ;;
    *) printf '1\n' ;;
  esac
  exit 0
fi
exit 0
EOF
cat > "$BIN/PlistBuddy" <<'EOF'
#!/bin/sh
# PlistBuddy -c "Print :Entitlements:<key>" <plist>
# Linux stand-in for macOS's tool: profiles in these tests are small XML plists.
key=${2#Print :Entitlements:}
file=
for argument; do file=$argument; done
keyline=$(grep "<key>$key</key>" "$file" 2>/dev/null | head -1)
[ -n "$keyline" ] || exit 1
case "$keyline" in
  *'<array>'*)
    printf 'Array {\n'
    sed -n "/<key>$key<\/key>/,/<\/array>/p" "$file" \
      | sed -n 's:.*<string>\([^<]*\)</string>.*:    \1:p'
    printf '}\n'
    ;;
  *'<string>'*)
    printf '%s\n' "$keyline" | sed -n 's:.*<string>\([^<]*\)</string>.*:\1:p'
    ;;
  *) exit 1 ;;
esac
EOF
cat > "$BIN/security" <<'EOF'
#!/bin/sh
# security cms -D -i <profile>: the fake profile is already a plist.
for argument; do profile=$argument; done
cat "$profile"
EOF
cat > "$BIN/codesign" <<'EOF'
#!/bin/sh
if [ "$1" = "-dv" ]; then
  printf 'Authority=%s\n' "${AXIOM_SIGN_IDENTITY:-adhoc}"
  printf 'TeamIdentifier=%s\n' "${EXPECTED_TEAM_ID:-ABCDE12345}"
  exit 0
fi
exit 0
EOF
cat > "$BIN/ditto" <<'EOF'
#!/bin/sh
cp -R "$1" "$2"
EOF
cat > "$BIN/pkgbuild" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$PKG_ARGS"
for last; do :; done
: > "$last"
EOF
cat > "$BIN/pkgutil" <<'EOF'
#!/bin/sh
printf './Applications/Axiom.app\n./Applications/Axiom.app/Contents/MacOS/Axiom\n'
printf './Applications/Axiom.app/Contents/Resources/service/axiomd\n'
printf './Applications/AxiomFilterHost.app\n'
printf './Applications/AxiomFilterHost.app/Contents/MacOS/axiom-sysext\n'
printf './Applications/AxiomFilterHost.app/Contents/Library/SystemExtensions/com.axiom.firewall.filter.systemextension\n'
EOF
# dotnet creates the two publish outputs its -o argument names; records every publish call.
cat > "$BIN/dotnet" <<'EOF'
#!/bin/sh
[ "$1" = "build-server" ] && exit 0
printf 'publish\n' >> "$DOTNET_CALLS"
out=
prev=
for argument; do
  if [ "$prev" = "-o" ]; then out=$argument; fi
  prev=$argument
done
[ -n "$out" ] || exit 1
mkdir -p "$out"
case $out in
  */app) printf '#!/bin/sh\nexit 0\n' > "$out/Axiom" ;;
  */service) printf '#!/bin/sh\nexit 0\n' > "$out/axiomd" ;;
  *) exit 1 ;;
esac
chmod +x "$out"/Axiom "$out"/axiomd 2>/dev/null || true
EOF
cat > "$TEMP/wrap.sh" <<'EOF'
#!/bin/sh
printf 'wrapped %s\n' "$1" >> "$WRAP_LOG"
exec "$@"
EOF
chmod +x "$BIN"/* "$TEMP/wrap.sh"
export PATH="$BIN:$PATH"
if [ -x /usr/libexec/PlistBuddy ]; then
  unset PLISTBUDDY || true
else
  export PLISTBUDDY="$BIN/PlistBuddy"
fi
export PKG_ARGS="$TEMP/pkgbuild.args" DOTNET_CALLS="$TEMP/dotnet.calls" WRAP_LOG="$TEMP/wrap.log"
: > "$PKG_ARGS"; : > "$DOTNET_CALLS"; : > "$WRAP_LOG"

HOST_PROFILE="$TEMP/host.provisionprofile"
FILTER_PROFILE="$TEMP/filter.provisionprofile"
cat > "$HOST_PROFILE" <<'PROFILE'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Entitlements</key><dict>
<key>com.apple.application-identifier</key><string>ABCDE12345.com.axiom.firewall.host</string>
<key>com.apple.developer.team-identifier</key><string>ABCDE12345</string>
<key>com.apple.developer.system-extension.install</key><true/>
<key>com.apple.developer.networking.networkextension</key><array>
<string>content-filter-provider-systemextension</string>
</array>
<key>com.apple.security.application-groups</key><array>
<string>ABCDE12345.com.axiom.firewall</string>
</array>
</dict></dict></plist>
PROFILE
cat > "$FILTER_PROFILE" <<'PROFILE'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Entitlements</key><dict>
<key>com.apple.application-identifier</key><string>ABCDE12345.com.axiom.firewall.filter</string>
<key>com.apple.developer.team-identifier</key><string>ABCDE12345</string>
<key>com.apple.developer.networking.networkextension</key><array>
<string>content-filter-provider-systemextension</string>
</array>
<key>com.apple.security.application-groups</key><array>
<string>ABCDE12345.com.axiom.firewall</string>
</array>
</dict></dict></plist>
PROFILE

run() { # run the packager with the fake toolchain
  bash "$REPO/scripts/macos/package-app.sh" osx-arm64 "$@"
}

# --- 1. unset DOTNET_WRAPPER, unsigned package ----------------------------------------------
unset DOTNET_WRAPPER || true
run >/dev/null 2>&1 || fail "packaging failed with DOTNET_WRAPPER unset"
[ "$(wc -l < "$DOTNET_CALLS" | tr -d ' ')" = "2" ] || fail "expected two publish calls"
assert_file_has "$PKG_ARGS" "install-location /" "pkgbuild payload location"
grep -q -- "--sign" "$PKG_ARGS" && fail "unsigned build passed --sign to pkgbuild"
ENT="$REPO/build/macos/osx-arm64/Axiom.entitlements"
assert_file_has "$ENT" "allow-jit" "UI keeps the runtime relaxations"
grep -q "<key>com.apple.developer" "$ENT" && fail "UI must not claim restricted entitlements"
[ -d "$REPO/build/macos/osx-arm64/AxiomFilterHost.app" ] || fail "host app was not packaged"
[ -d "$REPO/build/macos/osx-arm64/Axiom.app/Contents/Library/SystemExtensions" ] \
  && fail "extension must live in AxiomFilterHost.app, not Axiom.app"
pass "DOTNET_WRAPPER unset: publishes twice, unsigned pkg, UI has no restricted entitlements"

# --- 2. empty DOTNET_WRAPPER (bash 3.2 must not abort on ${WRAP[@]} under set -u) -----------
DOTNET_WRAPPER="" run >/dev/null 2>&1 || fail "packaging failed with DOTNET_WRAPPER empty"
pass "DOTNET_WRAPPER empty: packaging succeeds"

# --- 3. populated DOTNET_WRAPPER runs both publishes through it ------------------------------
: > "$DOTNET_CALLS"; : > "$WRAP_LOG"
DOTNET_WRAPPER="$TEMP/wrap.sh" run >/dev/null 2>&1 || fail "packaging failed with DOTNET_WRAPPER set"
[ "$(wc -l < "$WRAP_LOG" | tr -d ' ')" = "2" ] || fail "wrapper did not prefix both publishes"
pass "DOTNET_WRAPPER populated: both publishes run through the wrapper"

# --- 4. signed packaging requires both profiles ---------------------------------------------
set +e
AXIOM_SIGN_IDENTITY="Developer ID Application: Test (ABCDE12345)" run >/dev/null 2>&1
code=$?
set -e
[ "$code" != "0" ] || fail "signed packaging succeeded without profiles"
pass "signed packaging without profiles fails clearly"

sed 's/ABCDE12345.com.axiom.firewall.host/WRONG.com.axiom.firewall.host/' \
  "$HOST_PROFILE" > "$TEMP/host-wrong-appid.provisionprofile"
AXIOM_SIGN_IDENTITY="Developer ID Application: Test (ABCDE12345)" \
AXIOM_HOST_PROFILE="$TEMP/host-wrong-appid.provisionprofile" AXIOM_FILTER_PROFILE="$FILTER_PROFILE" \
  run >/dev/null 2>&1 && fail "mismatched profile was accepted"
pass "mismatched profile bundle id is refused"

sed 's/content-filter-provider-systemextension/packet-tunnel-provider/' \
  "$HOST_PROFILE" > "$TEMP/host-wrong-ne.provisionprofile"
AXIOM_SIGN_IDENTITY="Developer ID Application: Test (ABCDE12345)" \
AXIOM_HOST_PROFILE="$TEMP/host-wrong-ne.provisionprofile" AXIOM_FILTER_PROFILE="$FILTER_PROFILE" \
  run >/dev/null 2>&1 && fail "wrong host network-extension value was accepted"
pass "wrong host network-extension value is refused"

sed 's/ABCDE12345.com.axiom.firewall/ABCDE12345.com.other/' \
  "$FILTER_PROFILE" > "$TEMP/filter-wrong-group.provisionprofile"
AXIOM_SIGN_IDENTITY="Developer ID Application: Test (ABCDE12345)" \
AXIOM_HOST_PROFILE="$HOST_PROFILE" AXIOM_FILTER_PROFILE="$TEMP/filter-wrong-group.provisionprofile" \
  run >/dev/null 2>&1 && fail "wrong filter app-group was accepted"
pass "wrong filter application-group is refused"

sed 's|<key>com.apple.developer.system-extension.install</key><true/>|<key>com.apple.developer.system-extension.install</key><false/>|' \
  "$HOST_PROFILE" > "$TEMP/host-false-install.provisionprofile"
AXIOM_SIGN_IDENTITY="Developer ID Application: Test (ABCDE12345)" \
AXIOM_HOST_PROFILE="$TEMP/host-false-install.provisionprofile" AXIOM_FILTER_PROFILE="$FILTER_PROFILE" \
  run >/dev/null 2>&1 && fail "non-true system-extension.install was accepted"
pass "non-true system-extension.install is refused"

# --- 5. real identities sign the UI and the package; the host keeps its own profile ----------
: > "$PKG_ARGS"
AXIOM_SIGN_IDENTITY="Developer ID Application: Test (ABCDE12345)" \
AXIOM_INSTALLER_IDENTITY="Developer ID Installer: Test (ABCDE12345)" \
AXIOM_HOST_PROFILE="$HOST_PROFILE" AXIOM_FILTER_PROFILE="$FILTER_PROFILE" \
  run >/dev/null 2>&1 || fail "packaging failed with signing identities and profiles"
assert_file_has "$PKG_ARGS" -- "--sign Developer ID Installer: Test (ABCDE12345)" "pkg signature"
assert_file_has "$PKG_ARGS" -- "--timestamp" "pkg signature timestamp"
ENT="$REPO/build/macos/osx-arm64/Axiom.entitlements"
assert_file_has "$ENT" "allow-jit" "signed UI keeps the runtime relaxations"
grep -q "<key>com.apple.developer" "$ENT" && fail "signed UI must not claim restricted entitlements"
[ -f "$REPO/build/macos/osx-arm64/AxiomFilterHost.app/Contents/embedded.provisionprofile" ] \
  || fail "host profile was not shipped"
[ -d "$REPO/build/macos/osx-arm64/AxiomFilterHost.app/Contents/Library/SystemExtensions" ] \
  || fail "host does not own the extension"
pass "identities: pkg signed/timestamped; UI unprivileged; host owns extension/profile"

# --- 6. the ad hoc host claims no restricted entitlements -----------------------------------
ADHOC="$SRC/macos/AxiomSysext/axiom-sysext-adhoc.entitlements"
grep -q "<key>com.apple.developer" "$ADHOC" && fail "ad hoc host must not claim restricted entitlements"
grep -q "<key>com.apple.developer.system-extension.install</key>" \
  "$SRC/macos/AxiomSysext/axiom-sysext.entitlements" || fail "signed host lost system-extension.install"
pass "ad hoc host is unprivileged; signed host carries the restricted entitlement"

# --- 7. generated postinstall refuses an offline target volume -------------------------------
SCRIPTS="$REPO/build/macos/osx-arm64/pkgscripts"
POSTINSTALL="$SCRIPTS/postinstall"
[ -f "$POSTINSTALL" ] || fail "postinstall was not generated"
sh -n "$POSTINSTALL" || fail "postinstall is not valid /bin/sh"
assert_file_has "$POSTINSTALL" "/Applications/Axiom.app/Contents/Resources/service/axiomd" \
  "postinstall runs the installed daemon"
CALLS="$TEMP/daemon.calls"
for volume in "$TEMP/vol-a" "$TEMP/vol-b"; do
  mkdir -p "$volume/Applications/Axiom.app/Contents/Resources/service"
  printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s"\n' "$CALLS" \
    > "$volume/Applications/Axiom.app/Contents/Resources/service/axiomd"
  chmod +x "$volume/Applications/Axiom.app/Contents/Resources/service/axiomd"
done
: > "$CALLS"
set +e
sh "$POSTINSTALL" /tmp/Axiom.pkg /Applications "$TEMP/vol-a" >/dev/null 2>&1
code=$?
set -e
[ "$code" != "0" ] || fail "postinstall accepted an alternate target volume"
[ ! -s "$CALLS" ] || fail "postinstall started a live daemon for an offline volume"
pass "postinstall: alternate volume is refused before the daemon runs"

# --- 8. unknown argument is refused ----------------------------------------------------------
set +e
run --not-an-option >/dev/null 2>&1
code=$?
set -e
[ "$code" = "64" ] || fail "unknown argument exited $code, expected 64"
pass "unknown argument refused with exit 64"
