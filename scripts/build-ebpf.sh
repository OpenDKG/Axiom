#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Rebuilds the embedded per-executable firewall object from source.
#
# Requires: bpftool, clang with the BPF target, kernel BTF at /sys/kernel/btf/vmlinux.
# The generated vmlinux.h is not committed; the CO-RE object is, so normal builds do not need
# clang. Re-run this after editing axiom_fw.bpf.c and record the tool versions in the PR.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bpf="$root/src/Axiom.Infrastructure.Linux/Firewall/bpf"
arch="${ARCH:-$(uname -m)}"

case "$arch" in
  x86_64|amd64) target="x86" ;;
  aarch64|arm64) target="arm64" ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac

command -v bpftool >/dev/null || { echo "bpftool is required" >&2; exit 1; }
command -v clang >/dev/null || { echo "clang is required" >&2; exit 1; }
[[ -r /sys/kernel/btf/vmlinux ]] || { echo "kernel BTF is required" >&2; exit 1; }

bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$bpf/vmlinux.h"
clang -O2 -g -target bpf -D__TARGET_ARCH_"$target" -I "$bpf" -c "$bpf/axiom_fw.bpf.c" -o "$bpf/axiom_fw.bpf.o"
echo "rebuilt $bpf/axiom_fw.bpf.o"
