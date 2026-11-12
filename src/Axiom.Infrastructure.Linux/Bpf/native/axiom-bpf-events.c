// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * axiom-bpf-events: drains the pinned axiom_events ring buffer and prints one
 * NDJSON object per record on stdout (docs/LINUX_EBPF.md §4). The daemon runs
 * it as a long-lived child exactly like `nft monitor trace` (BpfEventMonitor
 * mirrors NftTraceMonitor) and turns each line into the flow.open/flow.close
 * contract. No arguments: it reads AXIOM_BPF_MAP_DIR/axiom_events, or the path
 * given as the first argument (tests, e2e). Exits 0 on SIGINT/SIGTERM/EOF,
 * 2 when the map cannot be opened, 3 when libbpf fails.
 *
 * Build: cc -O2 -Wall -o axiom-bpf-events axiom-bpf-events.c -lbpf (libbpf ≥ 1.0).
 */
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
#include "axiom_bpf.h"

static volatile sig_atomic_t stopping;

static void on_signal(int signo)
{
    (void)signo;
    stopping = 1;
}

static const char *verdict_name(__u8 verdict)
{
    return verdict == AXIOM_ACTION_BLOCK ? "block" : "allow";
}

static const char *source_name(__u8 source)
{
    return source == AXIOM_SOURCE_EXE ? "exe" : "cgroup";
}

static int on_event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size < sizeof(struct axiom_event))
        return 0;

    const struct axiom_event *event = data;
    char daddr[INET6_ADDRSTRLEN] = "";
    if (event->family == AF_INET)
        inet_ntop(AF_INET, event->daddr, daddr, sizeof daddr);
    else
        inet_ntop(AF_INET6, event->daddr, daddr, sizeof daddr);

    char rule_id[33];
    for (int i = 0; i < 16; i++)
        snprintf(rule_id + i * 2, 3, "%02x", event->rule_id[i]);

    printf("{\"abi\":%d,\"ts\":%llu,\"pid\":%u,\"cgroup\":%llu,\"devMajor\":%u,\"devMinor\":%u,\"ino\":%llu,"
           "\"family\":%u,\"proto\":%u,\"daddr\":\"%s\",\"dport\":%u,\"verdict\":\"%s\",\"source\":\"%s\","
           "\"hook\":\"%s\",\"generation\":%u,\"ruleId\":\"%s\"}\n",
           AXIOM_BPF_ABI,
           (unsigned long long)event->ts_ns,
           event->pid,
           (unsigned long long)event->cgroup_id,
           event->dev_major,
           event->dev_minor,
           (unsigned long long)event->ino,
           event->family,
           event->proto,
           daddr,
           event->dport,
           verdict_name(event->verdict),
           source_name(event->source),
           event->hook == 2 ? "sendmsg" : "connect",
           event->rule_generation,
           rule_id);
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : AXIOM_BPF_MAP_DIR "/" AXIOM_BPF_EVENTS_MAP;
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, on_signal);
    libbpf_set_print(NULL);

    int fd = bpf_obj_get(path);
    if (fd < 0) {
        fprintf(stderr, "axiom-bpf-events: cannot open %s: %s\n", path, strerror(errno));
        return 2;
    }

    struct ring_buffer *rb = ring_buffer__new(fd, on_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "axiom-bpf-events: ring_buffer__new failed: %s\n", strerror(errno));
        close(fd);
        return 3;
    }

    printf("{\"abi\":%d,\"type\":\"hello\",\"map\":\"%s\"}\n", AXIOM_BPF_ABI, path);
    fflush(stdout);
    while (!stopping) {
        int polled = ring_buffer__poll(rb, 250);
        if (polled < 0 && polled != -EINTR) {
            fprintf(stderr, "axiom-bpf-events: poll failed: %s\n", strerror(-polled));
            break;
        }
    }

    ring_buffer__free(rb);
    close(fd);
    return 0;
}
