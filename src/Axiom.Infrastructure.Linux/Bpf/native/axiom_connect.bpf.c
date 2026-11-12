// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * Axiom connect-time verdict programs (docs/LINUX_EBPF.md).
 *
 * Attached at the cgroup root with BPF_F_ALLOW_MULTI on cgroup/connect4,
 * cgroup/connect6 (TCP connect + connected UDP) and cgroup/sendmsg4,
 * cgroup/sendmsg6 (unconnected UDP sendto). They close the exec-time race of
 * the nftables engine: nft keys on the socket's cgroup, and a process is only
 * herded into its app cgroup by the daemon's 1 s poll; here the verdict is
 * taken synchronously inside connect() from two keys that need no herding:
 *
 *   1. the task's cgroup id          -> axiom_cgroup_verdicts   (herded apps)
 *   2. the task's exe inode (dev,ino) -> axiom_exe_verdicts     (any process of
 *      the binary, from its very first syscall — this is what closes the race)
 *
 * A hit with action BLOCK returns 0: the kernel fails connect()/sendmsg() with
 * EPERM immediately, no packet leaves. Everything else returns 1 (allow) and the
 * nftables table remains the primary boundary. Loopback destinations are exempt
 * exactly like the nft chains (MACOS_ARCHITECTURE §3.1, review #13).
 *
 * Every verdict that came from a map entry is reported on the axiom_events ring
 * buffer; connections without an entry produce no event (cost: two hash
 * lookups, no user-space wakeup).
 *
 * Built with `clang -O2 -g -target bpf` against the running kernel's BTF
 * (vmlinux.h from `bpftool btf dump`); the exe lookup uses CO-RE reads of
 * task->mm->exe_file->f_inode so the object is portable across kernels that
 * ship BTF. Loaded, pinned and attached by the daemon through bpftool.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "axiom_bpf.h"

char LICENSE[] SEC("license") = "GPL";

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#define AXIOM_HOOK_CONNECT 1u
#define AXIOM_HOOK_SENDMSG 2u

#define AXIOM_VERDICT_MAP_ENTRIES 4096
#define AXIOM_EVENTS_BYTES (256 * 1024)

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, AXIOM_VERDICT_MAP_ENTRIES);
    __type(key, __u64);
    __type(value, struct axiom_verdict);
} axiom_cgroup_verdicts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, AXIOM_VERDICT_MAP_ENTRIES);
    __type(key, struct axiom_exe_key);
    __type(value, struct axiom_verdict);
} axiom_exe_verdicts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, AXIOM_EVENTS_BYTES);
} axiom_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, AXIOM_STAT_COUNT);
    __type(key, __u32);
    __type(value, __u64);
} axiom_stats SEC(".maps");

static __always_inline void stat_inc(__u32 index)
{
    __u64 *counter = bpf_map_lookup_elem(&axiom_stats, &index);
    if (counter)
        __sync_fetch_and_add(counter, 1);
}

static __always_inline __u8 proto_bit(__u32 protocol)
{
    if (protocol == IPPROTO_TCP)
        return AXIOM_PROTO_TCP;
    if (protocol == IPPROTO_UDP)
        return AXIOM_PROTO_UDP;
    return AXIOM_PROTO_OTHER;
}

/*
 * 127.0.0.0/8, ::1 and ::ffff:127.0.0.0/8 are never filtered (parity with the nft chains).
 * The verifier only allows user_ip4 in the *4 programs and user_ip6 in the *6 programs
 * ("invalid bpf_context access" otherwise), so the family is a compile-time parameter
 * (`is6`) and every helper below is inlined into a program of exactly one family.
 */
static __always_inline bool is_loopback(struct bpf_sock_addr *ctx, const bool is6)
{
    if (!is6)
        return (ctx->user_ip4 & 0xffu) == 127u; /* network order: first octet is the low byte */

    if (ctx->user_ip6[0] == 0 && ctx->user_ip6[1] == 0) {
        if (ctx->user_ip6[2] == 0 && ctx->user_ip6[3] == bpf_htonl(1))
            return true; /* ::1 */
        if (ctx->user_ip6[2] == bpf_htonl(0x0000ffffu) && (ctx->user_ip6[3] & 0xffu) == 127u)
            return true; /* ::ffff:127.x.x.x */
    }

    return false;
}

/* Fills the exe identity of the current task; false for kernel threads (no mm). */
static __always_inline bool current_exe(struct axiom_exe_key *key)
{
    struct task_struct *task = bpf_get_current_task_btf();
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm)
        return false;

    struct file *exe = BPF_CORE_READ(mm, exe_file);
    if (!exe)
        return false;

    struct inode *inode = BPF_CORE_READ(exe, f_inode);
    if (!inode)
        return false;

    dev_t dev = BPF_CORE_READ(inode, i_sb, s_dev);
    key->dev_major = dev >> 20;        /* kernel MAJOR() */
    key->dev_minor = dev & 0xfffffu;   /* kernel MINOR() */
    key->ino = BPF_CORE_READ(inode, i_ino);
    return true;
}

static __always_inline void emit_event(struct bpf_sock_addr *ctx, __u64 cgroup_id, const struct axiom_exe_key *exe,
                                       const struct axiom_verdict *verdict, __u8 source, __u8 hook, const bool is6)
{
    struct axiom_event *event = bpf_ringbuf_reserve(&axiom_events, sizeof(*event), 0);
    if (!event) {
        stat_inc(AXIOM_STAT_EVENTS_DROPPED);
        return;
    }

    event->ts_ns = bpf_ktime_get_ns();
    event->cgroup_id = cgroup_id;
    event->ino = exe->ino;
    event->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    event->dev_major = exe->dev_major;
    event->dev_minor = exe->dev_minor;
    event->rule_generation = verdict->rule_generation;
    event->family = is6 ? AF_INET6 : AF_INET;
    event->dport = bpf_ntohs((__u16)ctx->user_port);
    event->proto = (__u8)ctx->protocol;
    event->verdict = verdict->action;
    event->source = source;
    event->hook = hook;
    __builtin_memset(event->daddr, 0, sizeof(event->daddr));
    if (!is6) {
        __u32 ip4 = ctx->user_ip4;
        __builtin_memcpy(event->daddr, &ip4, 4);
    } else {
        __u32 ip6[4] = { ctx->user_ip6[0], ctx->user_ip6[1], ctx->user_ip6[2], ctx->user_ip6[3] };
        __builtin_memcpy(event->daddr, ip6, 16);
    }

    __builtin_memcpy(event->rule_id, verdict->rule_id, sizeof(event->rule_id));
    bpf_ringbuf_submit(event, 0);
}

/* Returns 1 (allow) or 0 (block → EPERM to the caller). */
static __always_inline int decide(struct bpf_sock_addr *ctx, __u8 hook, const bool is6)
{
    stat_inc(AXIOM_STAT_LOOKUPS);
    if (is_loopback(ctx, is6)) {
        stat_inc(AXIOM_STAT_ALLOWED_LOOPBACK);
        return 1;
    }

    const __u8 proto = proto_bit(ctx->protocol);
    struct axiom_exe_key exe = {};
    const bool have_exe = current_exe(&exe);
    const __u64 cgroup_id = bpf_get_current_cgroup_id();

    /* Block wins over allow, as in the nft chain order (block rules are emitted first). */
    const struct axiom_verdict *hit = NULL;
    __u8 source = 0;
    const struct axiom_verdict *by_cgroup = bpf_map_lookup_elem(&axiom_cgroup_verdicts, &cgroup_id);
    if (by_cgroup && (by_cgroup->proto_mask & proto)) {
        hit = by_cgroup;
        source = AXIOM_SOURCE_CGROUP;
    }

    if (have_exe && (!hit || hit->action != AXIOM_ACTION_BLOCK)) {
        const struct axiom_verdict *by_exe = bpf_map_lookup_elem(&axiom_exe_verdicts, &exe);
        if (by_exe && (by_exe->proto_mask & proto) && (!hit || by_exe->action == AXIOM_ACTION_BLOCK)) {
            hit = by_exe;
            source = AXIOM_SOURCE_EXE;
        }
    }

    if (!hit)
        return 1;

    emit_event(ctx, cgroup_id, &exe, hit, source, hook, is6);
    if (hit->action == AXIOM_ACTION_BLOCK) {
        stat_inc(AXIOM_STAT_BLOCKED);
        return 0;
    }

    return 1;
}

SEC("cgroup/connect4")
int axiom_connect4(struct bpf_sock_addr *ctx)
{
    return decide(ctx, AXIOM_HOOK_CONNECT, false);
}

SEC("cgroup/connect6")
int axiom_connect6(struct bpf_sock_addr *ctx)
{
    return decide(ctx, AXIOM_HOOK_CONNECT, true);
}

SEC("cgroup/sendmsg4")
int axiom_sendmsg4(struct bpf_sock_addr *ctx)
{
    return decide(ctx, AXIOM_HOOK_SENDMSG, false);
}

SEC("cgroup/sendmsg6")
int axiom_sendmsg6(struct bpf_sock_addr *ctx)
{
    return decide(ctx, AXIOM_HOOK_SENDMSG, true);
}
