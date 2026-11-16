#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Checks the packaging script without publishing, signing, installing or touching a real system:
# fake toolchain in a temp "repo", stub dotnet/pkgbuild/codesign/ditto, real cp/sh.
#
#   scripts/macos/tests/package-app-checks.sh            # from anywhere, bash 3.2 or newer
#
# Covers: DOTNET_WRAPPER unset/empty/populated, unsigned vs signed .pkg arguments, the generated
# postinstall (syntax, alternate target volume, $2 fallback), and unknown-argument refusal.
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
         "$REPO/build/macos/osx-arm64/publish/app" "$REPO/build/macos/osx-arm64/publish/service"
cp "$SRC/scripts/macos/package-app.sh" "$REPO/scripts/macos/"
cp "$SRC/scripts/macos/Axiom.entitlements" "$SRC/scripts/macos/axiomd.entitlements" "$REPO/scripts/macos/"
cp "$SRC/Directory.Build.props" "$REPO/"
printf '#!/bin/sh\nexit 0\n' > "$REPO/build/macos/osx-arm64/publish/app/Axiom"
printf '#!/bin/sh\nexit 0\n' > "$REPO/build/macos/osx-arm64/publish/service/axiomd"
chmod +x "$REPO/build/macos/osx-arm64/publish/app/Axiom" "$REPO/build/macos/osx-arm64/publish/service/axiomd"

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
exit 0
EOF
cat > "$BIN/codesign" <<'EOF'
#!/bin/sh
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
export PKG_ARGS="$TEMP/pkgbuild.args" DOTNET_CALLS="$TEMP/dotnet.calls" WRAP_LOG="$TEMP/wrap.log"
: > "$PKG_ARGS"; : > "$DOTNET_CALLS"; : > "$WRAP_LOG"

run() { # run the packager with the fake toolchain
  bash "$REPO/scripts/macos/package-app.sh" osx-arm64 "$@"
}

# --- 1. unset DOTNET_WRAPPER, unsigned package ----------------------------------------------
unset DOTNET_WRAPPER || true
run >/dev/null 2>&1 || fail "packaging failed with DOTNET_WRAPPER unset"
[ "$(wc -l < "$DOTNET_CALLS" | tr -d ' ')" = "2" ] || fail "expected two publish calls"
assert_file_has "$PKG_ARGS" "install-location /" "pkgbuild payload location"
grep -q -- "--sign" "$PKG_ARGS" && fail "unsigned build passed --sign to pkgbuild"
pass "DOTNET_WRAPPER unset: publishes twice, builds an unsigned pkg"

# --- 2. empty DOTNET_WRAPPER (bash 3.2 must not abort on ${WRAP[@]} under set -u) -----------
DOTNET_WRAPPER="" run >/dev/null 2>&1 || fail "packaging failed with DOTNET_WRAPPER empty"
pass "DOTNET_WRAPPER empty: packaging succeeds"

# --- 3. populated DOTNET_WRAPPER runs both publishes through it ------------------------------
: > "$DOTNET_CALLS"; : > "$WRAP_LOG"
DOTNET_WRAPPER="$TEMP/wrap.sh" run >/dev/null 2>&1 || fail "packaging failed with DOTNET_WRAPPER set"
[ "$(wc -l < "$WRAP_LOG" | tr -d ' ')" = "2" ] || fail "wrapper did not prefix both publishes"
pass "DOTNET_WRAPPER populated: both publishes run through the wrapper"

# --- 4. installer identity signs the package -------------------------------------------------
: > "$PKG_ARGS"
AXIOM_INSTALLER_IDENTITY="Developer ID Installer: Test (ABCDE12345)" run >/dev/null 2>&1 \
  || fail "packaging failed with an installer identity"
assert_file_has "$PKG_ARGS" -- "--sign Developer ID Installer: Test (ABCDE12345)" "pkg signature"
assert_file_has "$PKG_ARGS" -- "--timestamp" "pkg signature timestamp"
pass "AXIOM_INSTALLER_IDENTITY: pkgbuild signs and timestamps"

# --- 5. generated postinstall resolves the daemon on the target volume -----------------------
SCRIPTS="$REPO/build/macos/osx-arm64/pkgscripts"
POSTINSTALL="$SCRIPTS/postinstall"
[ -f "$POSTINSTALL" ] || fail "postinstall was not generated"
sh -n "$POSTINSTALL" || fail "postinstall is not valid /bin/sh"
CALLS="$TEMP/daemon.calls"
for volume in "$TEMP/vol-a" "$TEMP/vol-b"; do
  mkdir -p "$volume/Applications/Axiom.app/Contents/Resources/service"
  printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s"\n' "$CALLS" \
    > "$volume/Applications/Axiom.app/Contents/Resources/service/axiomd"
  chmod +x "$volume/Applications/Axiom.app/Contents/Resources/service/axiomd"
done
: > "$CALLS"
# $2 = installation destination, $3 = target volume: the volume must win.
sh "$POSTINSTALL" /tmp/Axiom.pkg /Applications "$TEMP/vol-a" || fail "postinstall failed for a volume"
[ "$(cat "$CALLS")" = "--install-service" ] || fail "postinstall did not run the daemon with --install-service"
# Only $2 present (older callers): fall back to the destination.
sh "$POSTINSTALL" /tmp/Axiom.pkg "$TEMP/vol-b" || fail "postinstall failed with only \$2"
[ "$(wc -l < "$CALLS" | tr -d ' ')" = "2" ] || fail "postinstall did not fall back to \$2"
pass "postinstall: uses \$3 volume, falls back to \$2, passes --install-service"

# --- 6. unknown argument is refused ----------------------------------------------------------
set +e
run --not-an-option >/dev/null 2>&1
code=$?
set -e
[ "$code" = "64" ] || fail "unknown argument exited $code, expected 64"
pass "unknown argument refused with exit 64"
