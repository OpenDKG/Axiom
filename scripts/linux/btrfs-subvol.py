#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Print the btrfs subvolume id (root objectid) of each path, from both user-space sources the
daemon uses (docs/LINUX_EBPF.md §2.1): statx(STATX_SUBVOL) -> stx_subvol and
BTRFS_IOC_INO_LOOKUP(treeid=0, objectid=256) -> treeid. Non-btrfs files print 0 for the ioctl
(ENOTTY) and "-" for statx when the kernel does not fill STATX_SUBVOL.

Usage: btrfs-subvol.py [--key] PATH...
  --key  print only the ABI 2 exe-key subvolume (statx, else ioctl, else 0), for shell scripts.
Run with python3 -I.
"""
import ctypes
import fcntl
import os
import struct
import sys

AT_FDCWD = -100
STATX_INO = 0x100
STATX_SUBVOL = 0x8000
BTRFS_IOC_INO_LOOKUP = 0xD0009412
BTRFS_FIRST_FREE_OBJECTID = 256


def from_statx(path):
    libc = ctypes.CDLL(None, use_errno=True)
    buf = ctypes.create_string_buffer(256)
    if libc.statx(AT_FDCWD, os.fsencode(path), 0, STATX_INO | STATX_SUBVOL, buf) != 0:
        return None
    mask = struct.unpack_from("<I", buf.raw, 0)[0]
    return struct.unpack_from("<Q", buf.raw, 160)[0] if mask & STATX_SUBVOL else None


def from_ioctl(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        args = bytearray(4096)
        struct.pack_into("<QQ", args, 0, 0, BTRFS_FIRST_FREE_OBJECTID)
        try:
            fcntl.ioctl(fd, BTRFS_IOC_INO_LOOKUP, args, True)
        except OSError:
            return None
        return struct.unpack_from("<Q", args, 0)[0]
    finally:
        os.close(fd)


def main(argv):
    key_only = bool(argv) and argv[0] == "--key"
    paths = argv[1:] if key_only else argv
    if not paths:
        print((__doc__ or "").strip(), file=sys.stderr)
        return 2
    for path in paths:
        sx, io = from_statx(path), from_ioctl(path)
        if key_only:
            print(sx if sx is not None else (io if io is not None else 0))
        else:
            agree = "agree" if sx is not None and io is not None and sx == io else "n/a" if sx is None or io is None else "DISAGREE"
            print(f"{path}: statx={sx if sx is not None else '-'} ioctl={io if io is not None else '-'} ({agree}) ino={os.stat(path).st_ino}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
