// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * Shared layout of the Axiom BPF verdict maps and ring-buffer events
 * (docs/LINUX_EBPF.md §2). Included by the BPF program (axiom_connect.bpf.c),
 * the user-space event helper (axiom-bpf-events.c) and mirrored byte for byte
 * by Bpf/BpfLayout.cs on the .NET side, which writes map entries through
 * `bpftool map update … key hex … value hex …`. Every field is explicitly
 * sized and the structs are packed so the hex encoding is identical on both
 * sides; bump AXIOM_BPF_ABI when anything here changes.
 */
#ifndef AXIOM_BPF_H
#define AXIOM_BPF_H

#define AXIOM_BPF_ABI 2

/* Pin layout under /sys/fs/bpf/axiom (BpfEnginePaths mirrors these). */
#define AXIOM_BPF_PIN_DIR "/sys/fs/bpf/axiom"
#define AXIOM_BPF_MAP_DIR "/sys/fs/bpf/axiom/maps"
#define AXIOM_BPF_EVENTS_MAP "axiom_events"
#define AXIOM_BPF_EXE_MAP "axiom_exe_verdicts"
#define AXIOM_BPF_CGROUP_MAP "axiom_cgroup_verdicts"
#define AXIOM_BPF_STATS_MAP "axiom_stats"
#define AXIOM_BPF_SELFCHECK_MAP "axiom_selfcheck"

/* axiom_verdict.action */
#define AXIOM_ACTION_ALLOW 1u
#define AXIOM_ACTION_BLOCK 2u

/* axiom_verdict.proto_mask bits (connect() protocol of the socket). */
#define AXIOM_PROTO_TCP 1u
#define AXIOM_PROTO_UDP 2u
#define AXIOM_PROTO_OTHER 4u
#define AXIOM_PROTO_ANY (AXIOM_PROTO_TCP | AXIOM_PROTO_UDP | AXIOM_PROTO_OTHER)

/* axiom_event.source: which map produced the verdict. */
#define AXIOM_SOURCE_CGROUP 1u
#define AXIOM_SOURCE_EXE 2u

/* axiom_stats indices. */
#define AXIOM_STAT_LOOKUPS 0
#define AXIOM_STAT_BLOCKED 1
#define AXIOM_STAT_EVENTS_DROPPED 2
#define AXIOM_STAT_ALLOWED_LOOPBACK 3
#define AXIOM_STAT_COUNT 4

/* Key of axiom_exe_verdicts (ABI 2): the executable's inode identity.
 * dev_major/minor are the kernel's MAJOR()/MINOR() of inode->i_sb->s_dev (the
 * superblock device: mountinfo field 3, NOT stat's st_dev on btrfs), ino is
 * inode->i_ino, subvol is the btrfs subvolume (root objectid,
 * BTRFS_I(inode)->root->root_key.objectid; statx STATX_SUBVOL in user space) and
 * 0 on every other filesystem. btrfs inode numbers are unique per subvolume
 * only, so without subvol two binaries could share a key. 24 bytes, naturally
 * aligned (packed changes nothing). ABI 1 had no subvol (16 bytes). */
struct axiom_exe_key {
    __u32 dev_major;
    __u32 dev_minor;
    __u64 ino;
    __u64 subvol;
} __attribute__((packed));

/* axiom_selfcheck.flags */
#define AXIOM_SELFCHECK_BTRFS_CORE 1u  /* btrfs_inode/btrfs_root relocated (btrfs BTF present at load) */
#define AXIOM_SELFCHECK_EXE_BTRFS 2u   /* the recorded exe lives on btrfs (s_magic) */

/* Value of axiom_selfcheck[0] (ARRAY, one entry). The daemon writes its tgid,
 * makes one connect(), reads back the key the program computed for its own
 * exe and compares it with the user-space key; then writes 0 to stop
 * recording. 40 bytes. */
struct axiom_selfcheck {
    __u32 target_tgid;
    __u32 hits;
    struct axiom_exe_key key;
    __u32 flags;
    __u32 reserved;
} __attribute__((packed));

/* Value of both verdict maps. rule_id is the .NET Guid's ToByteArray() order
 * (mixed-endian), carried opaquely so events can name the rule without a
 * second lookup. 24 bytes. */
struct axiom_verdict {
    __u8 action;
    __u8 proto_mask;
    __u16 reserved;
    __u32 rule_generation;
    __u8 rule_id[16];
} __attribute__((packed));

/* Ring-buffer record for every verdict that came from a map entry (blocked, or
 * allowed by an explicit allow entry). Connections without an entry pass
 * through silently: they are not Axiom's to report and cost two hash lookups.
 * 72 bytes. */
struct axiom_event {
    __u64 ts_ns;          /* bpf_ktime_get_ns(), monotonic */
    __u64 cgroup_id;      /* bpf_get_current_cgroup_id() */
    __u64 ino;            /* exe inode, 0 when the task has no mm (kernel thread) */
    __u32 pid;            /* tgid */
    __u32 dev_major;
    __u32 dev_minor;
    __u32 rule_generation;
    __u16 family;         /* AF_INET / AF_INET6 */
    __u16 dport;          /* host order */
    __u8 proto;           /* IPPROTO_* */
    __u8 verdict;         /* AXIOM_ACTION_* */
    __u8 source;          /* AXIOM_SOURCE_* */
    __u8 hook;            /* 1 connect, 2 sendmsg */
    __u8 daddr[16];       /* network order; IPv4 in the first 4 bytes */
    __u8 rule_id[16];
} __attribute__((packed));

#endif /* AXIOM_BPF_H */
