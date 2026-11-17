#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Shared by the Debian prerm and the RPM %preun (sourced, not executed).
#
# Removes Axiom's own BPF pins only after the kernel confirms that no Axiom program is
# attached at the cgroup root. A missing bpftool, an unreadable or malformed `cgroup show`,
# or a remaining attachment is "unknown": the pins are kept for recovery and the caller
# fails the package operation. Unlinking pins while programs are attached would not detach
# anything; it would only remove the handles a later detach needs.
#
# Runtime: /bin/sh, bpftool and POSIX awk. Debian/Ubuntu ship mawk (Priority: required) and
# Fedora ships gawk in its core group, so this adds no package dependency; python and jq are
# deliberately not used. If awk is missing the pins are kept and removal fails safely.
#
# `bpftool -j cgroup show` prints nothing (exit 0) or `[]` when no program is attached. Anything
# else must be a JSON array of objects whose "id" is a non-zero uint32 and whose "name" is a
# decoded string: a malformed document, a non-array, a non-object element, a missing/duplicate
# field, a wrong type or an invalid id keeps the pins. Escaped names are decoded before the
# Axiom program names are matched, so "axiom_connect\u0034" is still an attachment.

# A daemon that starts while a previous daemon's programs are attached stages its new set in
# "<pin-dir>.next" (make-before-break, docs/LINUX_EBPF.md section 12); a crash during that start can
# leave it behind, so both trees are detached and removed together.
#
# Usage: axiom_bpf_pins_remove <pin-dir> <cgroup-root>
axiom_bpf_pins_remove() {
    pin_dir=$1
    cgroup_root=$2
    [ -d "$pin_dir" ] || [ -d "$pin_dir.next" ] || return 0

    if ! command -v bpftool >/dev/null 2>&1; then
        echo "axiom: bpftool is unavailable; cannot confirm the BPF layer is detached (keeping $pin_dir)" >&2
        return 1
    fi
    if ! command -v awk >/dev/null 2>&1; then
        echo "axiom: awk is unavailable; cannot parse the BPF attachment list (keeping $pin_dir)" >&2
        return 1
    fi

    # 1. Detach by pinned path; a stale pin (already detached) fails here and is proven absent below.
    for tree in "$pin_dir" "$pin_dir.next"; do
        for hook in connect4 connect6 sendmsg4 sendmsg6; do
            pin="$tree/axiom_$hook"
            [ -e "$pin" ] || continue
            bpftool cgroup detach "$cgroup_root" "$hook" pinned "$pin" >/dev/null 2>&1 || true
        done
    done

    # 2. Read the kernel's list back. Only a readable JSON array is an answer.
    if ! show=$(bpftool -j cgroup show "$cgroup_root" 2>/dev/null); then
        echo "axiom: cannot read cgroup BPF attachments; keeping $pin_dir" >&2
        return 1
    fi
    # bpftool prints no output at all when the cgroup has no attached program.
    case "$show" in
        *[![:space:]]*) ;;
        *)
            rm -rf "$pin_dir" "$pin_dir.next"
            return 0
            ;;
    esac

    if ! printf '%s' "$show" | awk '
        BEGIN { ctrl = ""; for (i = 1; i < 32; i++) ctrl = ctrl sprintf("%c", i) }
        { doc = doc $0 "\n" }
        END {
            s = doc; n = length(s); p = 1; err = ""; axiom = 0
            skipws()
            if (substr(s, p, 1) != "[") bad("top-level value is not an array")
            if (err == "") parse_array(0)
            if (err == "") {
                skipws()
                if (p <= n) bad("trailing data after the array")
            }
            if (err != "") {
                print "axiom: unreadable cgroup BPF attachment list: " err > "/dev/stderr"
                exit 2
            }
            if (axiom) {
                print "axiom: an Axiom BPF program is still attached at the cgroup root" > "/dev/stderr"
                exit 3
            }
            exit 0
        }
        function bad(msg) { if (err == "") err = msg }
        function skipws(  c) {
            while (p <= n) {
                c = substr(s, p, 1)
                if (c == " " || c == "\t" || c == "\n" || c == "\r") p++
                else break
            }
        }
        function hex4(at,  i, ch, v, d) {
            if (at + 3 > n) return -1
            v = 0
            for (i = 0; i < 4; i++) {
                ch = tolower(substr(s, at + i, 1))
                d = index("0123456789abcdef", ch)
                if (d == 0) return -1
                v = v * 16 + d - 1
            }
            return v
        }
        function parse_string(  c, e, u, lo) {
            p++; str = ""
            while (p <= n) {
                c = substr(s, p, 1)
                if (c == "\"") { p++; return 1 }
                if (c == "\\") {
                    p++
                    if (p > n) { bad("unterminated escape"); return 0 }
                    e = substr(s, p, 1)
                    if (e == "\"" || e == "\\" || e == "/") { str = str e; p++ }
                    else if (e == "b") { str = str "\b"; p++ }
                    else if (e == "f") { str = str "\f"; p++ }
                    else if (e == "n") { str = str "\n"; p++ }
                    else if (e == "r") { str = str "\r"; p++ }
                    else if (e == "t") { str = str "\t"; p++ }
                    else if (e == "u") {
                        u = hex4(p + 1)
                        if (u < 0) { bad("invalid \\u escape"); return 0 }
                        p += 5
                        if (u >= 55296 && u <= 56319) {
                            if (substr(s, p, 2) != "\\u") { bad("unpaired surrogate"); return 0 }
                            lo = hex4(p + 2)
                            if (lo < 56320 || lo > 57343) { bad("unpaired surrogate"); return 0 }
                            p += 6; str = str "#"
                        } else if (u >= 56320 && u <= 57343) {
                            bad("unpaired surrogate"); return 0
                        } else if (u >= 32 && u < 127) {
                            str = str sprintf("%c", u)
                        } else {
                            str = str "#"
                        }
                    } else { bad("invalid escape"); return 0 }
                } else {
                    if (index(ctrl, c) > 0) { bad("raw control character in string"); return 0 }
                    str = str c; p++
                }
            }
            bad("unterminated string"); return 0
        }
        function parse_number(  c, start) {
            start = p
            if (substr(s, p, 1) == "-") p++
            c = substr(s, p, 1)
            if (c == "0") p++
            else if (c ~ /[1-9]/) { while (p <= n && substr(s, p, 1) ~ /[0-9]/) p++ }
            else { bad("invalid number"); return 0 }
            if (substr(s, p, 1) == ".") {
                p++
                if (substr(s, p, 1) !~ /[0-9]/) { bad("invalid fraction"); return 0 }
                while (p <= n && substr(s, p, 1) ~ /[0-9]/) p++
            }
            if (substr(s, p, 1) == "e" || substr(s, p, 1) == "E") {
                p++
                if (substr(s, p, 1) == "+" || substr(s, p, 1) == "-") p++
                if (substr(s, p, 1) !~ /[0-9]/) { bad("invalid exponent"); return 0 }
                while (p <= n && substr(s, p, 1) ~ /[0-9]/) p++
            }
            numraw = substr(s, start, p - start)
            return 1
        }
        function parse_value(depth,  c) {
            skipws()
            if (p > n) { bad("unexpected end of input"); return 0 }
            c = substr(s, p, 1)
            if (c == "{") return parse_object(depth)
            if (c == "[") return parse_array(depth)
            if (c == "\"") return parse_string()
            if (c == "-" || c ~ /[0-9]/) return parse_number()
            if (substr(s, p, 4) == "true") { p += 4; return 1 }
            if (substr(s, p, 5) == "false") { p += 5; return 1 }
            if (substr(s, p, 4) == "null") { p += 4; return 1 }
            bad("unexpected character"); return 0
        }
        function parse_object(depth,  c, key) {
            p++; skipws()
            if (substr(s, p, 1) == "}") { p++; return 1 }
            while (1) {
                skipws()
                if (substr(s, p, 1) != "\"") { bad("object key is not a string"); return 0 }
                if (!parse_string()) return 0
                key = str
                skipws()
                if (substr(s, p, 1) != ":") { bad("expected colon"); return 0 }
                p++; skipws()
                if (depth == 1 && key == "id") {
                    if (ehasid) { bad("duplicate id"); return 0 }
                    if (!parse_number()) return 0
                    if (numraw !~ /^[0-9]+$/ || numraw == "0" || (length(numraw) > 1 && substr(numraw, 1, 1) == "0")) {
                        bad("id is not a non-zero unsigned integer"); return 0
                    }
                    if (length(numraw) > 10 || numraw + 0 > 4294967295) { bad("id is out of range"); return 0 }
                    ehasid = 1
                } else if (depth == 1 && key == "name") {
                    if (ehasname) { bad("duplicate name"); return 0 }
                    if (substr(s, p, 1) != "\"") { bad("name is not a string"); return 0 }
                    if (!parse_string()) return 0
                    ename = str; ehasname = 1
                } else {
                    if (!parse_value(depth + 1)) return 0
                }
                skipws()
                c = substr(s, p, 1)
                if (c == ",") { p++; continue }
                if (c == "}") { p++; return 1 }
                bad("expected comma or closing brace"); return 0
            }
        }
        function parse_array(depth,  c) {
            p++; skipws()
            if (substr(s, p, 1) == "]") { p++; return 1 }
            while (1) {
                if (depth == 0) {
                    skipws()
                    if (substr(s, p, 1) != "{") { bad("array element is not an object"); return 0 }
                    ehasid = 0; ehasname = 0; eidraw = ""; ename = ""
                }
                if (!parse_value(depth + 1)) return 0
                if (depth == 0) {
                    if (!ehasid) { bad("array element has no id"); return 0 }
                    if (!ehasname) { bad("array element has no name"); return 0 }
                    if (ename == "axiom_connect4" || ename == "axiom_connect6" ||
                        ename == "axiom_sendmsg4" || ename == "axiom_sendmsg6") axiom = 1
                }
                skipws()
                c = substr(s, p, 1)
                if (c == ",") { p++; continue }
                if (c == "]") { p++; return 1 }
                bad("expected comma or closing bracket"); return 0
            }
        }
    ' >/dev/null; then
        echo "axiom: cannot confirm that Axiom BPF programs are detached; keeping $pin_dir" >&2
        return 1
    fi

    # 3. Confirmed absent. Only Axiom's own pin directory is touched.
    rm -rf "$pin_dir" "$pin_dir.next"
    return 0
}
