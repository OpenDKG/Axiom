#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Builds and tests the Linux-compatible projects. The WPF/Windows projects are not part of this
# filter; they are built by the Windows toolchain (see docs/LINUX.md).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dotnet="${DOTNET:-dotnet}"
configuration="${CONFIGURATION:-Release}"

cd "$root"

"$dotnet" restore Axiom.Linux.slnf
"$dotnet" build Axiom.Linux.slnf -c "$configuration" --no-restore
"$dotnet" test Axiom.Linux.slnf -c "$configuration" --no-build

echo "Linux build and tests passed."
