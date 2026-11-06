#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Publishes the Linux service, UI and MCP server into artifacts/publish/linux.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dotnet="${DOTNET:-dotnet}"
configuration="${CONFIGURATION:-Release}"
self_contained="${SELF_CONTAINED:-1}"
out="$root/artifacts/publish/linux"
publish_args=()
if [[ "$self_contained" == "1" ]]; then
  publish_args=(-r linux-x64 --self-contained true)
fi

cd "$root"
rm -rf "$out"
mkdir -p "$out"

"$dotnet" publish src/Axiom.Service/Axiom.Service.csproj -c "$configuration" "${publish_args[@]}" -o "$out/service"
"$dotnet" publish src/Axiom.Desktop.Linux/Axiom.Desktop.Linux.csproj -c "$configuration" "${publish_args[@]}" -o "$out/ui"
"$dotnet" publish src/Axiom.McpServer/Axiom.McpServer.csproj -c "$configuration" "${publish_args[@]}" -o "$out/mcp"

echo "Published to $out"
