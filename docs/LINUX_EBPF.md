# Linux enforcement: the connect-time BPF layer (P2b)

Status: designed, implemented (C sources, bpftool-driven .NET engine, daemon wiring, 13 unit tests,
e2e script) on branch `buba/linux-enforce`, 2026-11-12. **Not yet compiled or proven live**: the
evidence box has `bpftool` 7.x and kernel BTF but **no `clang` and no `libbpf-dev`** (only the
`libbpf1` runtime), and the brief forbids installing packages. `make -C src/Axiom.Infrastructure.Linux/Bpf/native`
reports exactly what is missing; once `apt install clang libbpf-dev` is done,
`scripts/linux/bpf/e2e.sh` runs the proof described in §7 unchanged.

Companion documents: `LINUX_ENFORCEMENT.md` (the nftables engine this layer sits on top of),
`LINUX_ARCHITECTURE.md` §10 (daemon wiring), `LINUX_TEST_REPORT.md` (evidence).

## 1. Why: the exec-time race

The nftables engine keys rules on **cgroups**: `socket cgroupv2 level 2 "axiom.slice/a-<hash>"`. A
process is only in that cgroup once the daemon's 1 s attribution poll has read `/proc/<pid>/exe` and
written the pid to `cgroup.procs`. nft evaluates the socket's cgroup, so a one-shot tool that
`exec`s and `connect`s inside the same second (`curl https://…`) is not matched; `LINUX_ENFORCEMENT.md`
§5 step 4 shows the lost race. Children of herded processes inherit the cgroup, long-lived apps are
covered from their first poll on — the gap is the first second of every fresh process.

Closing it without polling needs a decision taken **inside `connect()`** from facts that are true at
exec time, not after herding. Two such facts exist: the task's cgroup id (herded apps) and the task's
executable inode (any process of the binary, from its first syscall). Both are readable from a
`cgroup/connect*` BPF program; neither needs user space on the hot path.

## 2. Programs, maps, verdict

Sources: `src/Axiom.Infrastructure.Linux/Bpf/native/` (`axiom_bpf.h` shared layout,
`axiom_connect.bpf.c` programs, `axiom-bpf-events.c` ring-buffer helper, `Makefile`).

| Program | Section | Hook | Covers |
|---|---|---|---|
| `axiom_connect4` | `cgroup/connect4` | `connect()` AF_INET | TCP connect, connected UDP |
| `axiom_connect6` | `cgroup/connect6` | `connect()` AF_INET6 | same, v6 and v4-mapped |
| `axiom_sendmsg4` | `cgroup/sendmsg4` | `sendmsg()`/`sendto()` on unconnected UDP v4 | DNS-style datagrams |
| `axiom_sendmsg6` | `cgroup/sendmsg6` | same, v6 | |

All four are attached at the **cgroup root** (`/sys/fs/cgroup`) with `BPF_F_ALLOW_MULTI`
(`bpftool cgroup attach / connect4 pinned … multi`), so systemd's per-service
`cgroup_inet_egress`/`cgroup_device` programs and Docker's keep working (`bpftool cgroup tree` on
the box lists 20+ of them, all `multi`). With `multi`, every program on the path runs and **any 0
wins** — Axiom can only add blocks, never override another program's block.

Decision (`decide()` in the C file), per call:

1. Loopback destinations (`127.0.0.0/8`, `::1`, `::ffff:127.0.0.0/8`) → allow, counted
   (`axiom_stats[3]`). Parity with the nft chains' loopback exemption.
2. `cgroup_id = bpf_get_current_cgroup_id()` → `axiom_cgroup_verdicts[cgroup_id]`.
3. `exe = task->mm->exe_file->f_inode` via `bpf_get_current_task_btf()` + `BPF_CORE_READ`
   (CO-RE against the running kernel's BTF): key `{MAJOR(i_sb->s_dev), MINOR(i_sb->s_dev), i_ino}`
   → `axiom_exe_verdicts[key]`. Kernel threads (no `mm`) skip this.
4. A hit whose `proto_mask` contains the socket's protocol bit (TCP/UDP/other) is the verdict;
   **block wins over allow** when both maps hit (nft chain order: block rules first).
5. Hit → ring-buffer event; `action == BLOCK` → `return 0` (the kernel fails the syscall with
   `EPERM`, no packet leaves, `curl` reports `(7) Couldn't connect to server` after 0 ms);
   otherwise `return 1`.
6. No hit → `return 1`, no event. nftables remains the primary boundary for everything else.

Maps (pinned under `/sys/fs/bpf/axiom/maps/`):

| Map | Type | Key | Value | Filled from |
|---|---|---|---|---|
| `axiom_exe_verdicts` | hash, 4096 | `struct axiom_exe_key {u32 dev_major; u32 dev_minor; u64 ino}` (16 B) | `struct axiom_verdict` | `stat -L -c '%Hd %Ld %i' <realpath(appPath)>` |
| `axiom_cgroup_verdicts` | hash, 4096 | `u64 cgroup_id` | `struct axiom_verdict` | inode number of `/sys/fs/cgroup/axiom.slice/a-<hash>` (cgroup v2 id == directory inode) |
| `axiom_events` | ringbuf, 256 KiB | — | `struct axiom_event` (72 B) | the programs |
| `axiom_stats` | array, 4 | index | `u64` | lookups, blocked, events dropped, loopback allowed |

`struct axiom_verdict` (24 B, packed): `u8 action` (1 allow, 2 block), `u8 proto_mask` (1 TCP,
2 UDP, 4 other), `u16 reserved`, `u32 rule_generation`, `u8 rule_id[16]` (the .NET `Guid` byte order,
carried opaquely so events name the rule without a second lookup). `BpfLayout.cs` mirrors every
offset; `BpfLayerTests.Layout_encodes_keys_and_verdicts_little_endian_and_round_trips_rule_ids` pins
the encoding; `AXIOM_BPF_ABI`/`BpfLayout.Abi` (1) is printed by the helper and checked by the parser.

Why dev **major/minor** and not raw `s_dev`: the kernel's `dev_t` is `MKDEV(ma, mi) = ma<<20 | mi`,
glibc's `st_dev` packs differently; splitting removes the ambiguity (`stat` prints `%Hd %Ld`).
Known caveat: on btrfs, user-space `st_dev` is the per-subvolume anonymous device while
`i_sb->s_dev` is the real superblock's — the exe key would miss there (the cgroup key still works).
Fix when needed: let the daemon learn the kernel-side dev by reading one event, or key on `ino` +
filesystem id. Evidence box root is ext4 (`/usr/bin/curl` = `8:2 ino 51643045`).

## 3. What the daemon writes into the maps (`BpfVerdictPlanner`)

Only rules the layer can express **without widening** become entries:

- `Enabled`, `Action = Block`, `Direction = Outbound`, no remote address scope (`*`/empty/`0.0.0.0/0`/`::/0`
  only), no port scope. `Protocol` sets the mask (`Any` → TCP|UDP|other).
- Several block rules of one app merge their masks under the first rule's id.
- Everything else is reported as *uncovered* with a reason (scoped block rules, allow rules, inbound,
  unreachable appPath, directory rules — the latter keep the cgroup entry only) and stays with nftables,
  so for those the ~1 s window remains. Allow rules never need an entry: no entry ⇒ allow.

Per app: one `axiom_exe_verdicts` entry (exe identity of `realpath(appPath)`) **and**, when the app
cgroup exists, one `axiom_cgroup_verdicts` entry (covers a binary replaced on disk after exec, and
herded processes whose `exe` no longer resolves). Both carry the nft **generation** so an event can be
matched to the table that was in force.

Sync is a reconciliation in memory: entries the previous sync wrote but the new plan does not want are
`bpftool map delete`d, every desired entry is `bpftool map update … any`-ed (idempotent). After a fresh
`loadall` the maps are empty, so the in-memory set is authoritative. Cost: one `bpftool` process per
entry change — a handful per publish, never on the hot path.

Events: only verdicts that came from a map entry are reported, and the planner only writes block
entries, so the ring buffer carries **blocked attempts** (both hooks, both families). Allowed-without-
rule connections cost two hash lookups and produce nothing; sampling them was considered and rejected
for v1 — `/proc/net` polling already lists live sockets and the trace stream already carries nft blocks.

## 4. Events: the same NDJSON contract

`axiom-bpf-events [map-pin]` (C, libbpf `ring_buffer__poll`) prints one line per record:

```
{"abi":1,"type":"hello","map":"/sys/fs/bpf/axiom/maps/axiom_events"}
{"abi":1,"ts":…,"pid":4242,"cgroup":93,"devMajor":8,"devMinor":2,"ino":51643045,"family":2,"proto":6,"daddr":"93.184.216.34","dport":443,"verdict":"block","source":"exe","hook":"connect","generation":7,"ruleId":"<32 hex>"}
```

`BpfEventProcessSource` runs it exactly like `NftTraceProcessSource` runs `nft monitor trace`
(long-lived child, `NOTIFY_SOCKET` stripped, restarted by the engine after exit).
`BpfEventMonitor.Publish` emits `FilterEventFormatter.FlowOpen` + `FlowClose` with
`id = "bpf-N"`, `verdict`, `ruleId`, exact `pid` (the hook runs in the caller's context — no
`/proc/net` inode hunt), `path` from `/proc/<pid>/exe` while the process lives else the rule's app
path, local endpoint `0.0.0.0:0`/`[::]:0` (not bound yet at connect time). The `bpf-` id prefix is the
**verdict source marker** in the flow table/snapshot; nft traces keep `nft-<trace>-N`.

## 5. Build and ship

```
make -C src/Axiom.Infrastructure.Linux/Bpf/native          # clang -O2 -g -target bpf, llvm-strip -g (BTF kept), cc … -lbpf
make -C src/Axiom.Infrastructure.Linux/Bpf/native install  # → build/linux/axiomd/bpf/{axiom_connect.bpf.o,axiom-bpf-events}
```

`vmlinux.h` is generated from `/sys/kernel/btf/vmlinux` with `bpftool btf dump … format c`
(ignored by git, as is `out/`). The csproj picks `Bpf/native/out/*` up as `bpf/…` content when it
exists, so a normal `dotnet publish` after `make` ships them and `axiomd --install-service` copies them
to `/usr/libexec/axiom/bpf/` with the rest of the protected image. Without them the build is unchanged
and the daemon is nft-only.

Toolchain needed on the build box: `clang` (≥ 14), `llvm-strip`, `bpftool`, `libbpf-dev` (≥ 1.0,
headers; the runtime `libbpf.so.1` is already on Ubuntu 24.04), kernel BTF. Not needed in .NET: no
libbpf binding — load/attach/pin/map writes go through `bpftool`, the ring buffer through the C helper.

## 6. Daemon integration (`BpfEngine : IEnforcementLayer`)

- `LinuxEnforcement.CreateBpfEngine(adapter, sink)` builds the engine over `ProcessRunner`,
  `StatInodeReader`, the adapter's `AppCgroupManager`, `BpfEventProcessSource`, and sets
  `adapter.VerdictLayer = engine`. DI registers it as a singleton; `NftEnforcementWorker` hands it to
  `NftEnforcementSupervisor`.
- Supervisor order: publish table → `layer.StartAsync` (probe, stale-pin cleanup, `prog loadall`,
  4 × `cgroup attach … multi`; any failure rolls back and leaves the layer inactive with the reason)
  → `adapter.ResyncLayerAsync` (maps from the stored rules) → loops (attribution, watcher, trace
  monitor, **events helper**) → on stop `layer.StopAsync` (4 × `cgroup detach`, `rm -r /sys/fs/bpf/axiom`)
  before the nft teardown. `--uninstall-service` stops the unit, which runs the same stop path.
- `NftFirewallPolicyAdapter.PublishAsync` calls `layer.SyncAsync(rules, generation)` after every
  **successful** nft apply (upsert, remove, recovery removal, republish by the watcher). A refused
  batch never touches the maps; a map write failure is logged and never fails the publish.
- Pins survive a daemon crash/restart; `StartAsync` detects `/sys/fs/bpf/axiom`, detaches and removes
  it, then loads fresh (deterministic; the maps are rebuilt from `managed-rules.json` anyway).

Degradation (`BpfCapabilityProbe`, in this order, each a journal line `BPF layer inactive: …`):
not root → objects not shipped → `bpftool` missing → no kernel BTF → bpffs not mounted; then runtime
failures (`loadall`, `attach`) with bpftool's stderr. Surfaces:

- `capabilities` → `firewall.reason`: `Connect-time BPF layer inactive: <why>; a process that connects
  within ~1 s of exec is not blocked until herded.` (status stays `Available` — nftables enforces).
- `snapshot.limitations` gets the same line (`LinuxConnectionSource` extra limitations).
- `axiomd --doctor` check `bpf layer`: WARN (never FAIL) when bpftool/BTF/object are missing; as root
  PASS when the daemon is active and all four programs are pinned, WARN when active without pins
  (`journalctl -u axiomd | grep 'BPF layer'` has the reason) or when pins remain after a stop.

Unit (`SystemdUnit`): `CapabilityBoundingSet` += `CAP_BPF CAP_PERFMON` (`bpf()` load and map ops;
`bpf_get_current_task_btf`/`bpf_probe_read_kernel` used by the CO-RE exe lookup are gated on
`perfmon_capable()`; attaching at the cgroup root needs `CAP_SYS_ADMIN`, already granted for
`cgroup.procs`), `ReadWritePaths` += `/sys/fs/bpf` (pins under `ProtectSystem=strict`).
`ProtectKernelTunables` had to become `no`: with `yes`, systemd 255 mounts `/sys/fs/bpf` read-only and
neither `ReadWritePaths` nor `BindPaths` can override it (`bpftool prog loadall failed: libbpf: failed
to mkdir /sys/fs/bpf/axiom/axiom_connect4: -EROFS`, found live). The unit lists the same paths
read-only by hand (`ReadOnlyPaths=-/proc/sys -/proc/sysrq-trigger … -/sys/kernel -/sys/devices …`)
and adds `ProtectKernelLogs=yes`; `NoNewPrivileges`, `RestrictAddressFamilies` are unchanged —
`bpf()` is a syscall, not a socket family.

## 7. Proof plan (`scripts/linux/bpf/e2e.sh`)

Part A, engine alone (no daemon, pin dir `/sys/fs/bpf/axiom-e2e` so it never collides with the
daemon's), as root via `sudo -n`:

1. `make` (as the developer), control `curl -m 8 https://example.com` → 200.
2. `bpftool prog loadall … pinmaps …`, 4 × `cgroup attach / … multi`; `bpftool cgroup tree /` shows
   the four `axiom_*` programs at `/sys/fs/cgroup` next to systemd's.
3. `stat -L -c '%Hd %Ld %i' /usr/bin/curl` → `python3 -I` packs `<IIQ` key and `<BBHI16s` value →
   `bpftool map update pinned …/axiom_exe_verdicts key hex … value hex … any`. **Only** curl's inode
   is ever written (never a shell, never a system cgroup).
4. `axiom-bpf-events` started on the pinned ring buffer; **bare** `curl -sS -m 8 https://example.com`
   immediately (no slow transfer, no herding) → must be `rc=7`, `Couldn't connect to server` after
   0 ms (EPERM from connect); the helper prints a `"verdict":"block","source":"exe"` line with curl's
   pid; `axiom_stats` shows blocked ≥ 1.
5. `bpftool map delete … key hex …` → curl 200 again.
6. 4 × `cgroup detach`, `rm -r /sys/fs/bpf/axiom-e2e`; `bpftool prog list` and `bpftool cgroup tree`
   contain no `axiom_*`, the pin dir is gone.

Part B (`--daemon`), the full path: `make install`, publish `axiomd`, `sudo -n build/linux/axiomd/axiomd
--install-service` (upgrade in place), `axipc.py protection.enable {"defaultPolicy":"ask"}`,
`rule.apply` block `/usr/bin/curl` → bare curl `rc=7` immediately, `snapshot` lists the blocked flow
with an `id` starting `bpf-` (verdict source), `rule.remove` → 200, `journalctl -u axiomd` shows
`BPF layer attached: connect4/connect6/sendmsg4/sendmsg6 at /sys/fs/cgroup (multi)` and
`BPF verdicts generation N: 1 exe, 1 cgroup entries`, `protection.disable`, daemon left installed with
no rules.

Safety in both parts: entries only for `/usr/bin/curl`'s inode; no cgroup ids of system services; no
process killed except the helper the script started; every object the script created is removed.

## 8. Residual gaps after P2b

- Scoped block rules (addresses/ports) and inbound rules: nft only, so the ~1 s window remains for
  them. Next step if wanted: carry `daddr`/`dport` sets in the verdict value (LPM trie per app) —
  the hook already sees both.
- Allowed flows produce no BPF events (by design, §3); flow visibility of allowed traffic stays with
  `/proc/net` polling.
- Kernels without BTF (some distro kernels, older LTS) and non-root test runs: nft-only, reported.
- btrfs exe-key caveat (§2).
- `bpftool` must exist on the target (Ubuntu: `linux-tools-$(uname -r)`); packaging must list it as a
  recommends and the probe reports its absence.

## 9. As built and proven (2026-11-12, kernel 7.0.0-42, clang 18, libbpf 1.3, bpftool 7.7)

- `make -C src/Axiom.Infrastructure.Linux/Bpf/native` compiles the object and the events helper with
  the installed toolchain (only `vmlinux.h` redefinition warnings from the generated header).
- First load failed in the verifier: `invalid bpf_context access off=8 size=4` in `axiom_connect4` —
  a `connect4` program may not touch `user_ip6` even on a dead branch behind `user_family`. The loopback
  check and the event copy now take the family as a compile-time constant (`is6`), so each of the four
  programs reads only its own fields. No other verifier complaint; the CO-RE exe lookup
  (`bpf_get_current_task_btf` → `mm->exe_file->f_inode`) is accepted under `cgroup/connect4,6` and
  `sendmsg4,6`.
- `bpftool prog loadall` pin names match `BpfLayout` as written (section = program name); no change.
- `scripts/linux/bpf/e2e.sh` part A **PASS** (bpftool only, with a live daemon also attached): control
  curl 200 → load/pin/attach 4 programs (ids listed) → exe verdict for `/usr/bin/curl` (dev 8:2 ino
  51643045) → bare `curl -m 8 https://example.com` **rc=7 after 0 ms** → 8 block events from
  `axiom-bpf-events` (v4+v6, udp+tcp, `source:"exe"`, `hook:"connect"`) → delete entry → 200 →
  detach/unload → none of our ids loaded or attached, `/sys/fs/bpf/axiom-e2e` gone.
- Live daemon (`LINUX_TEST_REPORT.md`, "Security parity + BPF" rows): `BPF layer attached …`,
  `BPF verdicts generation 16: 1 exe, 1 cgroup entries; 0 rule(s) left to nftables.`, bare curl rc=7 in
  8 ms, `--limit-rate 400k` rc=7, still rc=7 while `table inet axiom` was deleted, `--doctor` `PASS bpf
  layer: bpftool v7.7.0; 4 programs pinned at /sys/fs/bpf/axiom`.
- Residual: §8 unchanged (scoped/inbound rules nft-only, allowed flows not evented, BTF-less kernels).
