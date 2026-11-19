#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

release_url='https://github.com/OpenDKG/Axiom/releases/download'
scratch=''

fail() {
    printf 'Axiom installer: %s\n' "$*" >&2
    exit 1
}

download_package() {
    local tag=$1 name=$2 expected=$3 sha_command=$4 directory=${5:-${TMPDIR:-/tmp}} actual
    scratch=$(mktemp -d "$directory/.axiom-install.XXXXXX")
    trap 'rm -rf -- "$scratch"' EXIT
    curl -fsSL "$release_url/$tag/$name" -o "$scratch/$name"
    if [[ $sha_command == shasum ]]; then
        actual=$(shasum -a 256 "$scratch/$name")
    else
        actual=$(sha256sum "$scratch/$name")
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
    local name='axiom-firewall_1.3.0+linux.preview2_amd64.deb'
    download_package 'v1.3.0-linux-preview.2' "$name" \
        '44d9e8435a996f2d1ff9d364b85dc4662fc0dfbe5d1e7a4ea4d5386be74bb0a6' sha256sum
    chmod a+rx "$scratch"
    chmod a+r "$scratch/$name"
    sudo apt-get install -y "$scratch/$name"
    [[ -x /usr/bin/axiom-firewall ]] || fail 'The Axiom desktop launcher is missing.'
    nohup /usr/bin/axiom-firewall </dev/null >/dev/null 2>&1 &
}

install_macos() {
    [[ $(uname -m) == x86_64 ]] || fail 'The published macOS preview is for Intel x64.'
    local application="$HOME/Applications/Axiom.app"
    if [[ -d $application ]]; then
        printf 'Opening the existing Axiom installation in ~/Applications.\n'
    else
        local name='Axiom-1.3.0-19-osx-x64-adhoc.zip'
        mkdir -p "$HOME/Applications"
        download_package 'v1.3.0-macos-preview.2' "$name" \
            '74568194086be232e1fffbd0eaf1e92575f2cf78c741e653d41be34170f0efd9' shasum "$HOME/Applications"
        ditto -x -k "$scratch/$name" "$scratch/unpacked"
        local bundle="$scratch/unpacked/Axiom.app"
        [[ -x $bundle/Contents/MacOS/Axiom ]] || fail 'The downloaded app bundle is incomplete.'
        codesign --verify --deep --strict "$bundle"
        [[ ! -e $application ]] || fail 'The destination already exists.'
        mv "$bundle" "$application"
    fi
    open "$application"
}

case "$(uname -s)" in
    Linux) install_linux ;;
    Darwin) install_macos ;;
    *) fail 'Use the Windows PowerShell command on Windows.' ;;
esac
