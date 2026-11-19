#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

release_url='https://github.com/OpenDKG/Axiom/releases/latest/download'
scratch=''
package=''

fail() {
    printf 'Axiom installer: %s\n' "$*" >&2
    exit 1
}

download_package() {
    local pattern=$1 sha_command=$2 directory=${3:-${TMPDIR:-/tmp}}
    local actual expected entry name='' checksum
    scratch=$(mktemp -d "$directory/.axiom-install.XXXXXX")
    trap 'rm -rf -- "$scratch"' EXIT
    curl -fsSL "$release_url/SHA256SUMS-previews.txt" -o "$scratch/SHA256SUMS-previews.txt"
    while read -r checksum entry; do
        entry=${entry%$'\r'}
        entry=${entry#\*}
        if [[ $checksum =~ ^[[:xdigit:]]{64}$ && $entry =~ $pattern ]]; then
            [[ -z $name ]] || fail 'Multiple preview packages match this platform.'
            name=$entry
            expected=$(printf '%s' "$checksum" | tr '[:upper:]' '[:lower:]')
        fi
    done < "$scratch/SHA256SUMS-previews.txt"
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
    nohup /usr/bin/axiom-firewall </dev/null >/dev/null 2>&1 &
}

install_macos() {
    [[ $(uname -m) == x86_64 ]] || fail 'The published macOS preview is for Intel x64.'
    local application="$HOME/Applications/Axiom.app"
    if [[ -d $application ]]; then
        printf 'Opening the existing Axiom installation in ~/Applications.\n'
    else
        mkdir -p "$HOME/Applications"
        download_package '^Axiom-[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-osx-x64-adhoc\.zip$' shasum "$HOME/Applications"
        ditto -x -k "$package" "$scratch/unpacked"
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
