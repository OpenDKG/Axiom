// SPDX-License-Identifier: GPL-3.0-or-later
// Axiom per-executable firewall policy for Linux.
//
// Enforcement point: cgroup v2 socket-address hooks. The program matches the executable of the
// calling task by a 128-bit hash of its filesystem-internal path (dentry chain, namespace
// independent) and compares the requested peer/local address, port and protocol against the rules
// userspace wrote into the policy maps. No UID, port-global or cgroup-global rule is used.
//
// Return value 0 from a connect/sendmsg hook => EPERM for the caller. Return value 0 from a bind
// hook => the bind fails. Every "no rule matched" path returns 1 unless the executable is in
// allow-list mode for that direction.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define NP_MAX_RULES 16
#define NP_MAX_COMPONENTS 8
#define NP_MAX_NAME 64

#define NP_DIR_IN 0
#define NP_DIR_OUT 1

#define NP_ACTION_BLOCK 0
#define NP_ACTION_ALLOW 1

#define NP_PROTO_ANY 0
#define NP_PROTO_TCP 6
#define NP_PROTO_UDP 17

struct np_config {
    __u32 enabled;
    __u32 generation;
};

struct np_exe_key {
    __u64 hi;
    __u64 lo;
};

struct np_exe_val {
    __u8 allow_out;
    __u8 allow_in;
    __u16 pad;
    __u32 rule_count;
};

struct np_rule_key {
    __u64 hi;
    __u64 lo;
    __u32 index;
    __u32 pad;
};

struct np_rule_val {
    __u8 action;
    __u8 protocol;
    __u8 family; // 0 any, 4 IPv4, 6 IPv6
    __u8 prefix;
    __u16 port_min;
    __u16 port_max;
    __u8 addr[16]; // network byte order, already masked
    __u8 direction;
    __u8 enabled;
    __u8 pad[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct np_config);
} np_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct np_exe_key);
    __type(value, struct np_exe_val);
} np_exes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct np_rule_key);
    __type(value, struct np_rule_val);
} np_rules SEC(".maps");

struct np_scratch {
    __u8 bytes[NP_MAX_NAME];
};

// Per-CPU scratch keeps the 64-byte name buffer off the 512-byte BPF stack.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct np_scratch);
} np_name_scratch SEC(".maps");

static __always_inline void np_mix(__u64 *h, __u64 value)
{
    *h ^= value;
    *h *= 1099511628211ULL;
}

static __always_inline void np_mix_second(__u64 *h, __u64 value)
{
    *h = (*h ^ value) * 1099511628211ULL;
    *h = (*h << 7) | (*h >> 57);
}

// s_dev is encoded as (major << 20) | minor for the common 32-bit dev_t layout. Userspace derives
// the same numbers from the major:minor field of /proc/self/mountinfo, so two filesystems that
// happen to expose the same internal path do not share an executable identity.
static __always_inline int np_path_hash(struct dentry *start, __u64 *hi, __u64 *lo)
{
    __u64 h1 = 14695981039346656037ULL;
    __u64 h2 = 1099511628211ULL;
    struct dentry *current = start;

    struct super_block *super = BPF_CORE_READ(start, d_sb);
    if (!super)
        return -1;

    __u32 dev = BPF_CORE_READ(super, s_dev);
    __u32 dev_major = dev >> 20;
    __u32 dev_minor = dev & 0xfffff;
    np_mix(&h1, dev_major);
    np_mix(&h1, dev_minor);
    np_mix_second(&h2, dev_major);
    np_mix_second(&h2, dev_minor);

    for (int depth = 0; depth < NP_MAX_COMPONENTS; depth++) {
        struct qstr name = {};
        if (BPF_CORE_READ_INTO(&name, current, d_name) != 0)
            return -1;

        // Masking gives the verifier a bounded length; a name longer than the mask is refused
        // before this point, so the masked value is the real length.
        __u32 raw_len = name.len;
        if (raw_len == 0 || raw_len >= NP_MAX_NAME)
            return -1;
        __u32 len = raw_len & (NP_MAX_NAME - 1);
        if (len == 0)
            return -1;

        __u32 scratch_key = 0;
        struct np_scratch *scratch = bpf_map_lookup_elem(&np_name_scratch, &scratch_key);
        if (!scratch)
            return -1;
        __builtin_memset(scratch->bytes, 0, NP_MAX_NAME);
        if (bpf_probe_read_kernel(scratch->bytes, len, name.name) != 0)
            return -1;

        np_mix(&h1, len);
        // Hash the fixed-size buffer so the verifier sees a static loop; userspace pads the same
        // way. The length was checked above, so padding bytes are always zero for both sides.
        for (int i = 0; i < NP_MAX_NAME; i++) {
            np_mix(&h1, (__u8)scratch->bytes[i]);
            h2 = (h2 ^ (__u8)scratch->bytes[i]) * 1099511628211ULL;
            h2 = (h2 << 7) | (h2 >> 57);
        }

        struct dentry *parent = BPF_CORE_READ(current, d_parent);
        if (!parent || parent == current)
            break;

        if (depth == NP_MAX_COMPONENTS - 1)
            return -1; // Deeper than the documented limit: refuse instead of hashing a prefix.

        current = parent;
    }

    *hi = h1;
    *lo = h2 ^ (h1 >> 17);
    return 0;
}

static __always_inline int np_prefix_match(const __u8 *addr, const __u8 *rule_addr, __u8 prefix, __u8 family)
{
    if (prefix == 0)
        return 1;

    int bytes = family == 4 ? 4 : 16;
    for (int i = 0; i < 16; i++) {
        if (i >= bytes)
            break;
        __u8 remaining = prefix > (__u8)(i * 8) ? (__u8)(prefix - i * 8) : 0;
        if (remaining == 0)
            break;
        __u8 mask = remaining >= 8 ? 0xff : (__u8)(0xff << (8 - remaining));
        if ((addr[i] & mask) != (rule_addr[i] & mask))
            return 0;
    }

    return 1;
}

static __always_inline int np_rule_matches(
    const struct np_rule_val *rule,
    __u8 direction,
    __u8 protocol,
    __u8 family,
    __u16 port,
    const __u8 *addr)
{
    if (!rule->enabled || rule->direction != direction)
        return 0;

    if (rule->protocol != NP_PROTO_ANY && protocol != NP_PROTO_ANY && rule->protocol != protocol)
        return 0;

    if (rule->family != 0) {
        if (rule->family != family)
            return 0;
        if (!np_prefix_match(addr, rule->addr, rule->prefix, family))
            return 0;
    }

    if (rule->port_min != 0) {
        if (port < rule->port_min || port > rule->port_max)
            return 0;
    }

    return 1;
}

static __always_inline int np_evaluate(
    struct bpf_sock_addr *ctx,
    __u8 direction,
    __u8 protocol,
    __u8 family)
{
    __u32 zero = 0;
    struct np_config *config = bpf_map_lookup_elem(&np_config, &zero);
    if (!config || !config->enabled)
        return 1;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct file *exe = BPF_CORE_READ(task, mm, exe_file);
    if (!exe)
        return 1;

    struct dentry *dentry = BPF_CORE_READ(exe, f_path.dentry);
    struct np_exe_key exe_key = {};
    if (np_path_hash(dentry, &exe_key.hi, &exe_key.lo) != 0)
        return 1;

    struct np_exe_val *exe_val = bpf_map_lookup_elem(&np_exes, &exe_key);
    if (!exe_val)
        return 1;

    __u8 addr[16] = {};
    if (family == 4) {
        // bpf_sock_addr is a virtual context: these fields must be read with a direct context
        // load so the verifier translates them. bpf_probe_read_kernel would read the backing
        // kernel object instead of the requested address.
        __u32 ip = ctx->user_ip4;
        __builtin_memcpy(addr, &ip, 4);
    } else {
        // Constant offsets: the verifier rejects a context read through a modified pointer.
        __u32 v6[4] = {};
        v6[0] = ctx->user_ip6[0];
        v6[1] = ctx->user_ip6[1];
        v6[2] = ctx->user_ip6[2];
        v6[3] = ctx->user_ip6[3];
        __builtin_memcpy(addr, v6, 16);
    }

    __u16 port = __builtin_bswap16(ctx->user_port);

    int allowed = 0;
    __u32 count = exe_val->rule_count;
    if (count > NP_MAX_RULES)
        count = NP_MAX_RULES;

    for (int index = 0; index < NP_MAX_RULES; index++) {
        if (index >= (int)count)
            break;

        struct np_rule_key key = {
            .hi = exe_key.hi,
            .lo = exe_key.lo,
            .index = index,
        };

        struct np_rule_val *rule = bpf_map_lookup_elem(&np_rules, &key);
        if (!rule)
            continue;

        if (!np_rule_matches(rule, direction, protocol, family, port, addr))
            continue;

        if (rule->action == NP_ACTION_BLOCK)
            return 0;

        allowed = 1;
    }

    int allow_list = direction == NP_DIR_OUT ? exe_val->allow_out : exe_val->allow_in;
    if (allow_list && !allowed)
        return 0;

    return 1;
}

SEC("cgroup/connect4")
int np_connect4(struct bpf_sock_addr *ctx)
{
    __u8 protocol = ctx->type == 1 ? NP_PROTO_TCP : (ctx->type == 2 ? NP_PROTO_UDP : NP_PROTO_ANY);
    return np_evaluate(ctx, NP_DIR_OUT, protocol, 4);
}

SEC("cgroup/connect6")
int np_connect6(struct bpf_sock_addr *ctx)
{
    __u8 protocol = ctx->type == 1 ? NP_PROTO_TCP : (ctx->type == 2 ? NP_PROTO_UDP : NP_PROTO_ANY);
    return np_evaluate(ctx, NP_DIR_OUT, protocol, 6);
}

SEC("cgroup/sendmsg4")
int np_udp4_sendmsg(struct bpf_sock_addr *ctx)
{
    return np_evaluate(ctx, NP_DIR_OUT, NP_PROTO_UDP, 4);
}

SEC("cgroup/sendmsg6")
int np_udp6_sendmsg(struct bpf_sock_addr *ctx)
{
    return np_evaluate(ctx, NP_DIR_OUT, NP_PROTO_UDP, 6);
}

SEC("cgroup/bind4")
int np_bind4(struct bpf_sock_addr *ctx)
{
    __u8 protocol = ctx->type == 1 ? NP_PROTO_TCP : (ctx->type == 2 ? NP_PROTO_UDP : NP_PROTO_ANY);
    return np_evaluate(ctx, NP_DIR_IN, protocol, 4);
}

SEC("cgroup/bind6")
int np_bind6(struct bpf_sock_addr *ctx)
{
    __u8 protocol = ctx->type == 1 ? NP_PROTO_TCP : (ctx->type == 2 ? NP_PROTO_UDP : NP_PROTO_ANY);
    return np_evaluate(ctx, NP_DIR_IN, protocol, 6);
}

char _license[] SEC("license") = "GPL";
