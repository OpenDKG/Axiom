#!/usr/bin/env bash
# Sync the Linux-published bundle to the VM, embed filter + sign there, install into /Applications.
set -euo pipefail
cd /home/buba/projects/Axiom-mac-desktop
S=/home/buba/vms/macos-dev/ssh-mac
$S 'rm -rf ~/axiom/build/macos ~/axiom/scripts ~/axiom/src && mkdir -p ~/axiom'
tar cf - --exclude=macos/build build/macos/osx-x64/publish scripts/macos macos src/Axiom.UI.Avalonia/Assets Directory.Build.props \
  | $S 'tar xf - -C ~/axiom'
$S "cd ~/axiom && AXIOM_BUILD=${AXIOM_BUILD:-10} scripts/macos/package-app.sh osx-x64 --skip-publish --build-filter 2>&1 | tail -15"
if [[ "${INSTALL:-1}" == 1 ]]; then
  $S 'osascript -e "quit app \"Axiom\"" 2>/dev/null; sleep 2; sudo -n rm -rf /Applications/Axiom.app && sudo -n ditto ~/axiom/build/macos/osx-x64/Axiom.app /Applications/Axiom.app && codesign --verify --deep --strict /Applications/Axiom.app && echo INSTALLED'
fi
