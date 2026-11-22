#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

release_url='https://github.com/OpenDKG/Axiom/releases/latest/download'
scratch=''
package=''
complete=false
blackbox_revision='6df9193f8ba1d0a7adb39701d67c59b560408f8d' # blackbox-v1.5.0

fail() {
    printf 'Axiom installer: %s\n' "$*" >&2
    exit 1
}

install_agent_modules() (
    local desktop=$1 capability=$2 runtime parent lock checkout python stage='' launcher='' graph_status=''
    [[ -r $capability && $(<"$capability") == 1 ]] ||
        fail 'Complete setup requires a newer Axiom package. Update Axiom first.'
    [[ $EUID -ne 0 ]] || fail 'Run Complete setup as your desktop user.'
    runtime=$("$desktop" --axiom-unix-agent-setup path) ||
        fail 'Could not locate the Axiom agent runtime directory.'
    [[ $runtime = /* && ! -L $runtime ]] ||
        fail 'The Axiom agent runtime directory is invalid.'
    parent=${runtime%/*}
    mkdir -p -- "$parent"
    lock="$parent/.axiom-complete.lock"
    mkdir "$lock" ||
        fail "Complete setup is already running. If it was interrupted, remove the empty lock directory at $lock and retry."
    trap '[[ -z $stage ]] || rm -rf -- "$stage"; [[ -z $launcher ]] || rm -f -- "$launcher"; rmdir -- "$lock"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    graph_status=$(curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:9700/api/graph-status 2>/dev/null) || graph_status=''
    if [[ -x $runtime/axiom-blackbox-python ]] &&
        "$runtime/axiom-blackbox-python" -c 'import json, sys; from plugins.blackbox.guard import hooks; sys.exit(json.load(sys.stdin).get("node_reachable") is not True)' \
            <<< "$graph_status" >/dev/null 2>&1; then
        printf 'Using the existing Axiom-managed Blackbox runtime.\n'
    else
        command -v git >/dev/null || fail 'Install Git, then rerun Complete setup.'
        if [[ -e $runtime ]]; then
            [[ -d $runtime/.git && $(git -C "$runtime" rev-parse HEAD) == "$blackbox_revision" ]] ||
                fail 'An existing runtime has a different revision. Its Blackbox checkout was preserved.'
        else
            if [[ -n $graph_status || -x $HOME/.local/bin/blackbox ]] || command -v blackbox >/dev/null; then
                fail 'Another Blackbox installation was found and preserved. Complete setup only manages its own runtime.'
            fi
            stage=$(mktemp -d "$parent/.axiom-blackbox.XXXXXX")
        fi
        if [[ -n $stage ]]; then
            checkout="$stage/agent-blackbox"
            git init -q "$checkout"
            git -C "$checkout" fetch -q --depth 1 https://github.com/umanitek/agent-blackbox.git "$blackbox_revision"
            git -C "$checkout" checkout -q --detach FETCH_HEAD
            [[ $(git -C "$checkout" rev-parse HEAD) == "$blackbox_revision" ]] ||
                fail 'Blackbox checkout did not match the pinned revision.'
            mv -n "$checkout" "$parent/"
            [[ ! -e $checkout ]] || fail 'Another Blackbox installation started. Retry Complete setup.'
        fi
        (
            cd "$runtime"
            BLACKBOX_SETUP_ONLY=false BLACKBOX_USE_EXISTING_HERMES=0 BLACKBOX_MODE=block \
                BLACKBOX_HERMES_SETUP=never BLACKBOX_SYNC_MODE=wait \
                bash scripts/blackbox-install.sh --store oxigraph
        ) || fail 'Core Axiom is installed. Blackbox/DKG setup did not finish. Fix the error above and rerun --complete.'

        python=$("$runtime/scripts/run-in-hermes-env" python3 -c \
            'import sys; from plugins.blackbox.guard import hooks; print(sys.executable)' | tail -n 1) ||
            fail 'Blackbox was installed, but its Python guard could not be loaded.'
        [[ $python = /* && -x $python ]] || fail 'Blackbox did not report a usable Python interpreter.'
        launcher=$(mktemp "$runtime/.axiom-python.XXXXXX")
        # Pin the interpreter selected by Hermes at setup time so a tool call does not trigger an env sync.
        printf '#!/bin/bash\nexport HERMES_HOME=%q\nexec %q "$@"\n' "${HERMES_HOME:-$HOME/.hermes}" "$python" > "$launcher"
        chmod 0700 "$launcher"
        [[ ! -d $runtime/axiom-blackbox-python ]] || fail 'The Blackbox interpreter launcher path is occupied.'
        mv -f "$launcher" "$runtime/axiom-blackbox-python"
        launcher=''
    fi
    "$desktop" --axiom-unix-agent-setup refresh ||
        fail 'Blackbox/DKG setup finished, but Axiom could not refresh its agent hooks.'
    printf 'Blackbox/DKG setup complete. Axiom checked hooks for detected agents. Review each agent status in Axiom.\n'
)

download_package() {
    local pattern=$1 sha_command=$2 directory=${3:-${TMPDIR:-/tmp}}
    local actual expected entry name='' checksum
    scratch=$(mktemp -d "$directory/.axiom-install.XXXXXX")
    trap 'rm -rf -- "$scratch"' EXIT
    # Releases publish one SHA256SUMS.txt for every platform. Lines for other platforms do not
    # match the pattern below; the file may have CRLF line endings.
    curl -fsSL "$release_url/SHA256SUMS.txt" -o "$scratch/SHA256SUMS.txt" ||
        fail 'Could not download SHA256SUMS.txt from the latest release.'
    while read -r checksum entry; do
        entry=${entry%$'\r'}
        entry=${entry#\*}
        if [[ $checksum =~ ^[[:xdigit:]]{64}$ && $entry =~ $pattern ]]; then
            [[ -z $name ]] || fail 'Multiple preview packages match this platform.'
            name=$entry
            expected=$(printf '%s' "$checksum" | tr '[:upper:]' '[:lower:]')
        fi
    done < "$scratch/SHA256SUMS.txt"
    [[ -n $name ]] || fail 'The latest release has no verified preview for this platform.'
    package="$scratch/$name"
    curl -fsSL "$release_url/$name" -o "$package"
    if [[ $sha_command == shasum ]]; then
        actual=$(shasum -a 256 "$package")
    else
        actual=$(sha256sum "$package")
    fi
    [[ ${actual%% *} == "$expected" ]] || fail 'Package SHA-256 verification failed.'
}

install_linux() {
    [[ -r /etc/os-release ]] || fail 'The Linux preview requires Ubuntu 24.04 amd64.'
    # This file describes the installed OS.
    source /etc/os-release
    [[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 && $(uname -m) == x86_64 ]] ||
        fail 'The Linux preview requires Ubuntu 24.04 amd64.'
    [[ $EUID -ne 0 ]] || fail 'Run this as your desktop user. The installer calls sudo for APT.'
    download_package '^axiom-firewall_[0-9]+\.[0-9]+\.[0-9]+\+linux\.preview[0-9]+_amd64\.deb$' sha256sum
    chmod a+rx "$scratch"
    chmod a+r "$package"
    sudo apt-get install -y "$package"
    [[ -x /usr/bin/axiom-firewall ]] || fail 'The Axiom desktop launcher is missing.'
    if $complete; then
        install_agent_modules /usr/bin/axiom-firewall /usr/lib/axiom-firewall/axiom-unix-agent-setup
    fi
    nohup /usr/bin/axiom-firewall </dev/null >/dev/null 2>&1 &
}

install_macos() {
    [[ $(uname -m) == x86_64 ]] || fail 'The published macOS preview is for Intel x64.'
    # The system extension only activates from /Applications (see macos/README.md).
    local applications_dir='/Applications'
    local application="$applications_dir/Axiom.app"
    if [[ -d $application ]]; then
        printf 'Opening the existing Axiom installation in /Applications.\n'
    else
        [[ -w $applications_dir ]] ||
            fail 'This account cannot write to /Applications. Run the installer as an administrator account.'
        download_package '^Axiom-[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-osx-x64-adhoc\.zip$' shasum "$applications_dir"
        ditto -x -k "$package" "$scratch/unpacked"
        local bundle="$scratch/unpacked/Axiom.app"
        [[ -x $bundle/Contents/MacOS/Axiom ]] || fail 'The downloaded app bundle is incomplete.'
        codesign --verify --deep --strict "$bundle"
        # Unpacking on the destination filesystem makes the final move an atomic rename.
        mv -n "$bundle" "$applications_dir/"
        [[ ! -e $bundle ]] || fail 'The destination already exists.'
    fi
    if $complete; then
        install_agent_modules "$application/Contents/MacOS/Axiom" "$application/Contents/Resources/axiom-unix-agent-setup"
    fi
    open "$application"
}

case "${1:-}" in
    '') ;;
    --complete) complete=true ;;
    -h|--help)
        printf '%s\n' 'Usage: install-from-github.sh [--complete]' \
            'By default install Axiom. --complete also installs the Umanitek Blackbox runtime and its local DKG node.'
        exit 0
        ;;
    *) fail 'Usage: install-from-github.sh [--complete]' ;;
esac
[[ $# -le 1 ]] || fail 'Usage: install-from-github.sh [--complete]'

case "$(uname -s)" in
    Linux) install_linux ;;
    Darwin) install_macos ;;
    *) fail 'Use the Windows PowerShell command on Windows.' ;;
esac
