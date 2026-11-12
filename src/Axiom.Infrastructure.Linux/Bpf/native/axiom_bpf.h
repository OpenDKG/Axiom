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

#define AXIOM_BPF_ABI 1

/* Pin layout under /sys/fs/bpf/axiom (BpfEnginePaths mirrors these). */
#define AXIOM_BPF_PIN_DIR "/sys/fs/bpf/axiom"
#define AXIOM_BPF_MAP_DIR "/sys/fs/bpf/axiom/maps"
#define AXIOM_BPF_EVENTS_MAP "axiom_events"
#define AXIOM_BPF_EXE_MAP "axiom_exe_verdicts"
#define AXIOM_BPF_CGROUP_MAP "axiom_cgroup_verdicts"
#define AXIOM_BPF_STATS_MAP "axiom_stats"

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

/* Key of axiom_exe_verdicts: the executable's inode identity. dev_major/minor
 * are the kernel's MAJOR()/MINOR() of inode->i_sb->s_dev (what `stat -c '%Hd %Ld'`
 * prints for the file), ino is inode->i_ino. 16 bytes. */
struct axiom_exe_key {
    __u32 dev_major;
    __u32 dev_minor;
    __u64 ino;
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
