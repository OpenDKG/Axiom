#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Shared by the Debian prerm and the RPM %preun (sourced, not executed).
#
# Removes Axiom's own BPF pins only after the kernel confirms that no Axiom program is
# attached at the cgroup root. A missing bpftool, an unreadable or malformed `cgroup show`,
# or a remaining attachment is "unknown": the pins are kept for recovery and the caller
# fails the package operation. Unlinking pins while programs are attached would not detach
# anything; it would only remove the handles a later detach needs.

# Usage: axiom_bpf_pins_remove <pin-dir> <cgroup-root>
axiom_bpf_pins_remove() {
    pin_dir=$1
    cgroup_root=$2
    [ -d "$pin_dir" ] || return 0

    if ! command -v bpftool >/dev/null 2>&1; then
        echo "axiom: bpftool is unavailable; cannot confirm the BPF layer is detached (keeping $pin_dir)" >&2
        return 1
    fi

    # 1. Detach by pinned path; a stale pin (already detached) fails here and is proven absent below.
    for hook in connect4 connect6 sendmsg4 sendmsg6; do
        pin="$pin_dir/axiom_$hook"
        [ -e "$pin" ] || continue
        bpftool cgroup detach "$cgroup_root" "$hook" pinned "$pin" >/dev/null 2>&1 || true
    done

    # 2. Read the kernel's list back. Only a JSON array is a readable answer.
    if ! show=$(bpftool -j cgroup show "$cgroup_root" 2>/dev/null); then
        echo "axiom: cannot read cgroup BPF attachments; keeping $pin_dir" >&2
        return 1
    fi
    trimmed=$(printf '%s' "$show" | tr -d '[:space:]')
    case "$trimmed" in
        \[*\]) ;;
        *)
            echo "axiom: unreadable cgroup BPF attachment list; keeping $pin_dir" >&2
            return 1
            ;;
    esac

    attached=$(printf '%s' "$trimmed" | tr '}' '\n' |
        grep -oE '"name":"axiom_(connect4|connect6|sendmsg4|sendmsg6)"' || true)
    if [ -n "$attached" ]; then
        echo "axiom: Axiom BPF programs are still attached ($attached); keeping $pin_dir" >&2
        return 1
    fi

    # 3. Confirmed absent. Only Axiom's own pin directory is touched.
    rm -rf "$pin_dir"
    return 0
}
