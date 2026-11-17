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
   (CO-RE against the running kernel's BTF): key `{MAJOR(i_sb->s_dev), MINOR(i_sb->s_dev), i_ino,
   subvol}` → `axiom_exe_verdicts[key]`; `subvol` is the btrfs subvolume id
   (`BTRFS_I(inode)->root->root_key.objectid`) when `i_sb->s_magic == BTRFS_SUPER_MAGIC`, else 0 (ABI 2,
   §2.1). Kernel threads (no `mm`) skip this. Before step 1 the programs record the key of the daemon's
   own exe in `axiom_selfcheck` while the daemon has armed it (§2.1, self-check).
4. A hit whose `proto_mask` contains the socket's protocol bit (TCP/UDP/other) is the verdict;
   **block wins over allow** when both maps hit (nft chain order: block rules first).
5. Hit → ring-buffer event; `action == BLOCK` → `return 0` (the kernel fails the syscall with
   `EPERM`, no packet leaves, `curl` reports `(7) Couldn't connect to server` after 0 ms);
   otherwise `return 1`.
6. No hit → `return 1`, no event. nftables remains the primary boundary for everything else.

Maps (pinned under `/sys/fs/bpf/axiom/maps/`):

| Map | Type | Key | Value | Filled from |
|---|---|---|---|---|
| `axiom_exe_verdicts` | hash, 4096 | `struct axiom_exe_key {u32 dev_major; u32 dev_minor; u64 ino; u64 subvol}` (24 B, ABI 2) | `struct axiom_verdict` | dev: `/proc/self/mountinfo` field 3 of the mount holding `realpath(appPath)`; ino: `stat -L -c %i`; subvol: `statx(STATX_SUBVOL)` / `BTRFS_IOC_INO_LOOKUP` on btrfs, 0 elsewhere (§2.1) |
| `axiom_selfcheck` | array, 1 | `u32 0` | `struct axiom_selfcheck {u32 target_tgid; u32 hits; axiom_exe_key key; u32 flags; u32 reserved}` (40 B) | the daemon arms it with its tgid; the programs record its exe key and flags (1 btrfs CO-RE relocated, 2 exe on btrfs) |
| `axiom_cgroup_verdicts` | hash, 4096 | `u64 cgroup_id` | `struct axiom_verdict` | inode number of `/sys/fs/cgroup/axiom.slice/a-<hash>` (cgroup v2 id == directory inode) |
| `axiom_events` | ringbuf, 256 KiB | — | `struct axiom_event` (72 B) | the programs |
| `axiom_stats` | array, 4 | index | `u64` | lookups, blocked, events dropped, loopback allowed |

`struct axiom_verdict` (24 B, packed): `u8 action` (1 allow, 2 block), `u8 proto_mask` (1 TCP,
2 UDP, 4 other), `u16 reserved`, `u32 rule_generation`, `u8 rule_id[16]` (the .NET `Guid` byte order,
carried opaquely so events name the rule without a second lookup). `BpfLayout.cs` mirrors every
offset; `BpfLayerTests.Layout_encodes_keys_and_verdicts_little_endian_and_round_trips_rule_ids` pins
the encoding; `AXIOM_BPF_ABI`/`BpfLayout.Abi` (2 since the subvolume field; 1 had the 16-byte key) is
printed by the helper and checked by the parser. After `prog loadall` the engine reads
`bpftool -j map show pinned …/axiom_exe_verdicts` and refuses (detach + unpin, layer `inactive: object key
layout mismatch: … key is 16 bytes, this daemon writes 24 (ABI 2)`) an object built for another layout;
pins are never reused across daemon starts anyway (startup always detaches and unpins, then loads fresh).

Why dev **major/minor** and not raw `s_dev`: the kernel's `dev_t` is `MKDEV(ma, mi) = ma<<20 | mi`,
glibc's `st_dev` packs differently; splitting removes the ambiguity (`stat` prints `%Hd %Ld`).

### 2.1 Exe key derivation (`BpfExeKey`, `MountInfoTable`, `BtrfsSubvolumeReader`, self-check)

The kernel side reads `MAJOR/MINOR(exe_file->f_inode->i_sb->s_dev)`, `i_ino` and, on btrfs, the
subvolume id. User space must produce the same numbers, and `stat`'s `st_dev` is **not** always the
superblock device: btrfs reports a per-subvolume anonymous device (Fedora 45: `/usr/bin/curl` → `stat`
`0 35 3056`, `findmnt -T` → `0:33`). The first implementation keyed on `st_dev`, so on btrfs the exe map
never matched while `rule.verify` claimed "BPF-backed … read back verified" (LINUX_TEST_REPORT.md F-8).

User-space derivation (`BpfExeKey.Resolve`):

- **dev** = `MAJ:MIN` (field 3) of the `/proc/self/mountinfo` entry whose mount point is the longest
  whole-component prefix of `realpath -e <appPath>`; among identical mount points the *last* line wins
  (it is mounted on top). Field 3 is `sb->s_dev` by definition (`show_mountinfo()`), so it is exactly
  what the BPF program reads, for bind mounts too (a bind mount shares the superblock; field 4 `root`
  differs, the device does not). Octal escapes (`\040` space, `\011`, `\012`, `\134`) are decoded.
  The daemon runs as a system service in the host mount namespace; systemd's `ProtectSystem=`
  sandboxing only adds read-only re-mounts of the same superblocks.
- **ino** = `stat -L -c %i` (equals `i_ino` on ext4, xfs, btrfs, tmpfs, squashfs, NFS/FUSE on 64-bit).
- **subvol** = 0 unless the mount is btrfs. On btrfs: `statx(path, STATX_SUBVOL)` → `stx_subvol`
  (Linux 6.10+, mask `0x8000`, offset 160) and `BTRFS_IOC_INO_LOOKUP` (`0xD0009412`, `treeid=0`,
  `objectid=256`) → `treeid`, which the kernel answers for the fd's own subvolume without
  `CAP_SYS_ADMIN`. statx is preferred, the ioctl is the fallback, and when both answer they must agree
  (`BtrfsSubvolumeReader.Combine`); disagreement or no answer → not provable.
  `scripts/linux/btrfs-subvol.py` prints both for any path (used by `e2e.sh` and the VM proof).
- **cross-check**: `st_dev` must equal the mountinfo dev; the only accepted difference is btrfs (subvolume
  device by design). Anything else is "not provable".

Kernel side (`axiom_connect.bpf.c`, `btrfs_subvol()`): when `inode->i_sb->s_magic == 0x9123683E`, the
program does `container_of(inode, struct btrfs_inode, vfs_inode)->root->root_key.objectid` with local
CO-RE flavours (`struct btrfs_inode___axiom { struct btrfs_root___axiom *root; struct inode vfs_inode; }`,
`btrfs_root___axiom { btrfs_key___axiom root_key; }`, `btrfs_key___axiom { u64 objectid; }`, all
`preserve_access_index`). The `vfs_inode` offset comes from `bpf_core_field_offset`, so the layout is
the running kernel's, not the build host's. Every access is behind `bpf_core_type_exists` /
`bpf_core_field_exists`: libbpf resolves them against vmlinux BTF (Fedora builds btrfs in) or
`/sys/kernel/btf/btrfs` (module, when loaded); without btrfs BTF (Ubuntu ext4 host: btrfs is an unloaded
module) the guards relocate to 0, the branch is dead code the verifier never walks, and subvol stays 0.
Checked against Fedora 45 / 7.2.11 BTF: `struct btrfs_inode { struct btrfs_root *root; … struct inode
vfs_inode; }`, `struct btrfs_root { … struct btrfs_key root_key; … }`, `btrfs_key` packed
`{u64 objectid; u8 type; u64 offset}`.

**Self-check (kernel vs user space, every attach).** After attaching, `BpfEngine` writes its tgid into
`axiom_selfcheck[0]`, makes one UDP `connect()` to `127.0.0.1:9` (runs `connect4`, sends nothing; the
record is taken before the loopback exemption), reads the record back and disarms it (target 0, record
kept for the doctor). The recorded key of `/proc/<pid>/exe` (= `/usr/libexec/axiom/axiomd`) is compared
with the user-space key of the same file (`BpfKernelKeyCheck.Compare`):

| Result | Effect |
|---|---|
| `verified`, flag 1 (btrfs CO-RE relocated) | btrfs exe rules get `{s_dev, ino, subvol}` keys → connect-time proven again; ext4/xfs as before |
| `verified`, no flag 1 | ext4/xfs keys as before; btrfs exe rules stay nft-only (`… the loaded BPF program's btrfs subvolume id is not confirmed (no btrfs BTF at load …)`) |
| `unverified` (old object without the map, no record, own key not provable) | ext4/xfs keys as before; btrfs exe rules nft-only with the reason |
| `mismatch` | **no** exe key at all (`kernel/userspace exe key mismatch for …: kernel dev … ino … subvol …, user space …`); cgroup keys stay; this also hardens ext4/xfs |

The journal logs `BPF exe key self-check verified: kernel and user space agree for /usr/libexec/axiom/axiomd:
dev 0:33 ino 34192 subvol 256 (btrfs); btrfs subvolume read relocated (CO-RE).` (Fedora) or `… dev 8:2 ino
4194354 subvol 0; no btrfs BTF at load …` (Ubuntu host).

**btrfs (history and current state).** Inode numbers are unique per *subvolume*, not per superblock, and
every subvolume shares the superblock `s_dev`, so the ABI 1 key `{0:33, ino}` matched that inode number in
**every** subvolume (proven on the Fedora 45 VM, §11.1: two fresh subvolumes give their first file inode
257, and the key written for one blocked a *different* executable in the other). From `c60fc36` to ABI 2
btrfs exe rules were therefore nft-only (`exe key ambiguous on btrfs subvolumes`, ~50/50 fresh-process
slips on Fedora). With ABI 2 the subvolume id separates them: on the VM a rule on `subA/tool` (ino 257,
subvol 260) blocks it 0/10 while `subB/tool` (ino 257, subvol 261) connects 10/10, and the reverse; the
canary is 0/50 on Fedora's btrfs root (§11.1, §11.2). The old reason is kept, extended with *why* the
subvolume id is not usable, whenever the self-check did not confirm the kernel side or user space cannot
read the id; the safe direction is still to under-claim rather than block unrelated binaries.

When the key is not provable the rule is reported **uncovered** (`exe key not provable for <app>: …`),
never "BPF-backed": no mountinfo entry / unreadable mountinfo, `realpath` failure, overlayfs (and
`fuse-overlayfs`/aufs) — there `exe_file->f_inode` is the overlay inode, whose device and inode number
user-space `stat` does not report reliably (`xino`, samefs vs. multi-layer) — an unexplained
`st_dev` ≠ `s_dev`, an unconfirmed/unreadable btrfs subvolume id, or a self-check mismatch. The app's
cgroup key is still written (herded processes stay blocked at connect time), but
`LayerSyncResult.CoveredRules` excludes every uncovered rule, so `rule.verify` says `nft-only: … the ~1 s
exec window applies` instead of claiming a connect-time verdict. Directory rules are reported the same way.

Containers: a process inside an overlay rootfs has an overlay exe inode, so host-path rules do not
exe-match it (the cgroup key does if it is herded); this is the same behaviour nftables' cgroup rules
have. Overlay paths are nft-only and reported so (§11.1).

Every planned exe entry carries its derivation (format from `BpfVerdictPlanner`; the subA example is
assembled from the VM values, not a captured journal line):
`exe /srv/axbt/subA/tool dev 0:33 ino 257 subvol 260 proto 0x7 (dev 0:33 from mountinfo (btrfs at / [root /root]; stat 0:68 is the subvolume device), subvol 260 from statx STATX_SUBVOL (BTRFS_IOC_INO_LOOKUP agrees))`.

`axiomd --doctor` has a **`bpf exe key`** check: it derives the key of `/usr/bin/env` the same way, prints
the source, the filesystem, the subvolume id and its source, and re-checks the running daemon's
`axiom_selfcheck` record against the user-space key of the installed image (root):
`PASS bpf exe key: /usr/bin/env: key dev 0:33 ino 3102 subvol 256, source mountinfo superblock dev (btrfs at /, /dev/vda3) + btrfs subvolume id 256 (statx STATX_SUBVOL (BTRFS_IOC_INO_LOOKUP agrees)); stat st_dev 0:35 is a btrfs subvolume device and is NOT used. Kernel self-check verified: …`.
`SKIP` on btrfs when the subvolume id is not confirmed (documented boundary), `WARN` on a self-check
mismatch or an unprovable key.

Tests: `BpfExeKeyTests` (mountinfo parser: btrfs subvolumes, ext4, xfs, overlay, bind mounts, escapes,
longest component prefix, overmounts, garbage lines; planner with a Fedora btrfs fixture; symlink
resolution; not-provable cases → uncovered; doctor; bpftool hint per distribution) and
`BtrfsSubvolumeKeyTests` (ABI 2 layout, subvolume-keyed btrfs plan, same ino in two subvolumes → two keys,
non-btrfs subvol 0 without asking, unprovable subvolume, unconfirmed kernel side, mismatch drops every exe
key, self-check record round trip/compare, engine self-check pass and mismatch over the fake bpftool,
ABI 1 object refused and unpinned, statx/ioctl combination, doctor `live enforcement` WARN when neutralised).

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
  batch never touches the maps. Since the PR #276 review (LNX-1) the sync returns a `LayerSyncResult`
  that the adapter folds into the rule result, the enforcement report and the capabilities (§10); the
  nft batch itself is never rolled back for a map failure.
- Pins survive a daemon crash/restart and, since §12, a `systemctl restart` or package upgrade too. A
  start that finds a previous daemon's set attached replaces it **make-before-break** (§12): the new set
  is attached next to it and the old one is detached by id only after the new maps are populated and
  read back. Nothing attached: clean leftovers by pin **and** by id (`bpftool -j cgroup show`), then load.

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
3. `findmnt -no MAJ:MIN -T` (superblock dev) + `stat -L -c %i /usr/bin/curl` → `python3 -I` packs `<IIQ` key and `<BBHI16s` value →
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
- btrfs: exe keys carry the subvolume id since ABI 2 and are used once the self-check confirms the kernel side (§2.1); before that (from `c60fc36`) they were nft-only; overlayfs exe
  paths stay nft-only (+ cgroup key).
- `bpftool` must exist on the target; the probe and the doctor print a distribution-aware hint from
  `/etc/os-release` `ID`/`ID_LIKE` (`BpftoolHint`): Ubuntu & derivatives `apt install linux-tools-common
  linux-tools-$(uname -r)`, Debian `apt install bpftool`, Fedora/RHEL family `dnf install bpftool`, SUSE
  `zypper install bpftool`, otherwise generic.

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

## 10. Effective state: sync result, reconciliation, neutralisation (PR #276 review, LNX-1)

Before the review, a failed `bpftool map delete` was only logged: the adapter reported a removed rule as
`Desired`/verified while the stale exe/cgroup verdict kept blocking at connect time. Now the BPF maps
are an enforcement layer of their own and a rule is only "removed" when every attached layer stopped
enforcing it.

**`IVerdictLayer.SyncAsync` → `Task<LayerSyncResult>`** (Linux-only interface):
`Generation`, `Attached` (the layer's programs enforce after the sync), `Pinned`, `Applied` (every desired
entry written, every stale entry deleted), `Verified` (a `bpftool -j map dump` read-back matched the plan),
`Neutralised`, `Attempts`, `FailedUpdates[]`, `FailedDeletes[]` (`{operation, map, keyHex, ruleId,
describe, error}`), `CoveredRules[]`, `Uncovered[]` (rule id + reason), `Status`;
`StaleEntriesCanBlock = Attached && FailedDeletes.Count > 0`.

**Bounded reconciliation** (`BpfEngine.SyncAsync`, `ReconcileAttempts = 3`, backoff 250 ms → 500 ms):

1. write pass: delete keys the plan no longer wants, update every wanted key;
2. read back both verdict maps and repair against the plan: unknown keys (a crashed daemon's leftovers,
   a delete that lied) are deleted, missing or different entries rewritten;
3. repeat while anything failed, at most 3 passes.

A missing map pin is not "key already gone": the ENOENT of `bpf obj get` is told apart from the ENOENT
of a missing key, so a renamed/removed pin fails the delete instead of passing it. A missing/unrunnable
`bpftool` is a failed result (exit 127, `bpftool could not be run`), never an exception.

**Neutralisation.** When a stale entry still cannot be deleted after the passes, the only safe move is
to stop the layer from enforcing anything: the engine detaches **only Axiom's four programs** (by pin,
then by id for any `axiom_*` program `bpftool cgroup show` lists — third-party programs are never
selected), removes `/sys/fs/bpf/axiom`, and reports `Neutralised` (status `degraded: detached after …;
nftables only until re-attached`). nftables keeps enforcing every rule. The supervisor's watch tick
re-attaches the layer (one attempt per tick: `StartAsync` + resync from `managed-rules.json`). If the
detach fails too, the result says so (`StaleEntriesCanBlock`): the engine stays `degraded: … could not be
detached` and nothing claims success. Programs detached by another tool are detected after each sync
(fewer than 4 `axiom_*` at the root) and handled as neutralised (re-attached by the watcher).

**Fail-safe direction, explicitly.** A stale *block* verdict errs towards blocking (connectivity loss
for one app); the engine trades that for nft-only enforcement (security unchanged for every rule nft
expresses — all of them — only the ~1 s exec window reopens) and says so in every surface.

**What the adapter reports** (`NftFirewallPolicyAdapter`):

| Situation | `rule.remove` | `rule.apply` | enforcement / capabilities | `rule.verify` |
|---|---|---|---|---|
| sync applied + read back | `Success`, `Desired`, `verifiedUtc` set | `Applied` | `Verified` / `Available` | `BPF-backed: … read back verified` or `nft-only: <reason>` |
| delete failed → neutralised | `Success=false`, `Pending`, `bpf.delete_failed`, "detached its own BPF programs … retry rule.remove" | — | `Degraded`, reason "BPF layer neutralised" | not verified, note |
| delete and detach failed | `Success=false`, `Pending`, `bpf.stale_entry`, "may still be blocked … restart axiomd or bpftool map delete" | — | `Degraded`, "stale entries … removed rules may still block" | `EnforcementVerified=false`, "still in an attached map" |
| update failed (partial) | verified only if the rule's own state is clean; message names the failed updates | `Pending`, `bpf.update_failed` | `Pending`, limitation "BPF map sync failed …" | "connect-time verdict … not written" |
| read-back unavailable | `Success`, not verified, "connect-time state is unconfirmed" | `Applied` | `Verified` (nft) | "read-back unavailable" |
| layer never attached (no BTF/bpftool/root) | nft decides | `Applied` (nft) | `Available` + "BPF layer inactive" | "BPF layer inactive … nftables alone" |

`managed-rules.json` keeps the generation; the engine's applied set is in memory only and starts empty
after every attach, and the first read-back after a (re)start deletes whatever a previous instance left in
the maps — so generation/epoch is coherent across restarts by rebuilding, not by trusting old pins.
Every operation is idempotent: re-applying the same rule writes the same keys (`any`), re-removing a
removed rule republishes and resyncs without it.

Tests: `BpfEffectiveStateTests` (red tests of the review, green now), `LinuxFaultMatrixTests` (16), over
`FakeBpftool`, which models map contents, attachments, transient (`FailTimes`) and persistent
(`FailPrefixes`) faults, EPERM text and a missing binary.

## 11. Coverage labelling, identity boundary and live canary (PR #276 round 3)

Commits on `buba/linux`: red `9dc4ec4` → fix `1c71a01` (#290, restart-while-pending, coverage fields);
UI red `4599e8b` → `5a3f3ad`; red `794e226` → `c60fc36` (btrfs, executable replacement); `4d14f80`
`scripts/linux/canary.sh`; red `0c65629` → `b06adb8` (externally detached programs). Evidence rows:
`LINUX_TEST_REPORT.md` "PR #276 round 3".

**Two claims, kept apart.** `EnforcementVerified` keeps its meaning (the OS rule is installed and read
back). New, additive and `null` on Windows/macOS:

| Field | Meaning |
|---|---|
| `EffectiveRuleReport.NftRuleReadBack` | the nft rule of this managed rule was listed back from `table inet axiom` |
| `EffectiveRuleReport.ConnectTimeBlockingProven` (+ `ManagedRule`, `RuleApplyResult`) | the BPF layer is attached, not neutralised, maps read back, and this rule's exe key is written and provable: a *new* process is refused at `connect()` |
| `EffectiveRuleReport.CoverageReason` | why not, verbatim: scoped/inbound rule, layer inactive/neutralised, `exe key ambiguous on btrfs subvolumes`, overlay, executable replaced, … always ending with `nft rule installed/read back, not race-free: a newly launched process can connect during the ~1 s cgroup attribution window before it is herded` |
| `FirewallCapabilityReport.ConnectTimeLayer` | `state`, `healthy`, `attached`, `generation`, `mapsVerified`, `connectTimeProvenRules[]`, `nftOnlyRules[]`, `pendingRemovals[]`, `failedDeletes[]` |

The Avalonia UI (Firewall/Apps clause, header connection line, status bar, owned-rule state, apply
result) reads "installed/read back, not race-free" for nft-only rules on Linux; Windows/macOS strings are
byte-identical because the fields are null there (`ConnectTimeCoverageWordingTests`).

**#290 doctor.** While `axiomd` is active, the `bpf layer` and the new `live enforcement` checks query the
daemon over IPC (`rules.query` → capability + `ConnectTimeLayer`); pin files alone never give PASS; IPC
unavailable is `WARN cannot confirm live state`. A neutralised/degraded layer or a non-empty
`pendingRemovals` is WARN and `Result: 1 problem(s)` (live: §11.3).

**Restart while a removal is pending.** Not present in the pushed `97d2719`: there was no pending-removal
concept, and `BpfEngine.StartAsync` ignored a failed detach of the previous instance's programs, unlinked
its pins and loaded a second program set, so the old stale verdicts kept blocking while the new instance
reported clean. Since `1c71a01`: `managed-rules.json` persists `pendingRemovals` (cleared only by an
attached, written and read-back sync); `StartAsync` refuses to load a second set while a previous daemon's
programs are still attached and keeps the pins; the enforcement report is Degraded while anything is
pending; the watch tick retries. Unit-tested (`LiveStateAndCoverageTests`); the guest wrapper repro of
#290 (failing `bpftool map delete`/`cgroup detach` + restart) was not re-run live.

**Externally detached programs (`b06adb8`).** `IVerdictLayer.CheckAttached` runs on every supervisor
watch tick and on every `rule.verify`: fewer than 4 `axiom_*` programs at the cgroup root marks the layer
neutralised immediately (`only 0 of 4 Axiom BPF programs are attached (detached by another tool)`), every
rule drops to `connectTimeBlockingProven=false`, and the same tick re-attaches and resyncs. Before the
fix the canary measured 99/100 fresh-process slips while the daemon still claimed connect-time coverage.

### 11.1 Executable identity boundary (validation matrix)

| Case | Where | Result | Decision |
|---|---|---|---|
| two btrfs subvolumes, same ino 257, **identical** copies; rule on `subA/tool` | Fedora 45 VM | `connectTimeBlockingProven=False`, reason `exe key ambiguous on btrfs subvolumes`; fresh connects slipped subA 20/20, subB 20/20 (nft-only window) | no exe key on btrfs (`c60fc36`) |
| same, the pre-fix key `{0:33, 257}` written by hand | Fedora 45 VM | subA 0/10 slipped, **unrelated** subB 0/10 slipped (over-block proven); deleted → subB 5/5 | collision is real in the kernel |
| subvolumes subC/subD, ino 257, **different** executables (sha256 `8f9b3657…` vs `13d0b4f7…`) with the key `{0:33, 257}` | Fedora 45 VM | subC 0/10, different exe subD **0/10** slipped; deleted → subD 5/5 | unrelated binaries can be blocked → downgrade, never claim |
| overlayfs (`lowerdir/upperdir` mount) | Fedora 45 VM | nft-only, reason `… is on overlay …`; fresh connects slipped 20/20 (19/20 at `c60fc36`) | nft-only + cgroup key |
| mount namespace: `unshare -m` + bind mount of the blocked exe | Ubuntu host, ext4 | same ino 30933725 in the new ns; 0/20 slipped | inode-keyed: the path does not matter |
| hard link at another path | Ubuntu host, ext4 | 0/20 slipped | same |
| executable replaced by `rename(2)` (new inode) | Ubuntu host, ext4 | `rule.verify` immediately `connectTimeBlockingProven=False` (`the executable at this path was replaced (new inode)…`); fresh connects slipped 3/3 per probe round for ~7 s wall clock (05:25:53 → 05:26:00), then 0/3 after the watch tick re-resolved (`BPF exe key(s) re-resolved`) | re-resolve on the watch tick; window documented |
| tmpfs copy (provable key) | Fedora VM and host | `connectTimeBlockingProven=True`, 0/20 slipped | proven |
| **ABI 2** (`788c709`): subA/subB, ino 257 both, **different** executables (sha256 `8f9b3657…` / `b23fe00f…`, subvol 260 / 261, statx = ioctl); rule on `subA/tool` | Fedora 45 VM | `connectTimeBlockingProven=True`, map key `dev 0:33 ino 257 subvol 260`; slipped subA **0/10**, unrelated subB **10/10**, system python3 5/5 | subvolume id separates the keys |
| ABI 2, reverse: rule on `subB/tool` | Fedora 45 VM | key `… ino 257 subvol 261`; subB **0/10**, subA **10/10** | same |
| ABI 2, `unshare -m` + bind mount of `subA/tool` (btrfs) | Fedora 45 VM | 0/10 slipped | inode + subvolume keyed: the path does not matter |
| ABI 2, `subA/tool` replaced by `rename(2)` | Fedora 45 VM | `rule.verify` at once `connectTimeBlockingProven=False` (`the executable at this path was replaced (new inode)…`); after the watch tick key `ino 258 subvol 260`, proven=True, 0/10 | window reported, then re-keyed |
| ABI 2, overlayfs | Fedora 45 VM | still nft-only, `… is on overlay at /srv/axov/merged …` | unchanged |

### 11.2 Live negative canary (`scripts/linux/canary.sh`)

```
host netns                                   netns axcanary
axc0  10.231.0.1/30   fd00:a51:a51::1/64 <-veth-> axc1  10.231.0.2/30  fd00:a51:a51::2/64
                                                  listener [::]:18080 (dual stack, HTTP 204)
```

Loopback is exempt in the nft chains and the BPF programs, so a loopback target would prove nothing; the
veth peer forces the normal output path and gives real IPv6 traffic without an IPv6 default route.
Probes are copies under `/opt/axiom-canary` (`curl -g --connect-timeout 2`, `python3 -I` with
`socket.create_connection`), each run = 50 fresh processes per probe and family, connecting right after
exec. `sudo scripts/linux/canary.sh --cleanup` removes the netns, the veth and the copies.

| Run | curl v4 | curl v6 | python v4 | python v6 | Claimed |
|---|---|---|---|---|---|
| Ubuntu ext4, BPF attached, unscoped rules (`c60fc36` and again `b06adb8`) | 0/50 | 0/50 | 0/50 | 0/50 | proven=True |
| Ubuntu, scoped to port 18080 (nft-only by design) | 50/50 | 50/50 | 50/50 | 49/50 | proven=False |
| Ubuntu, unscoped, Axiom's programs detached (nft only) | 50/50 | 50/50 | 49/50 | 49/50 | before `b06adb8`: still proven=True (bug); now False |
| Fedora 45 btrfs, unscoped (`b06adb8`) | 49/50 | 50/50 | 49/50 | 49/50 | proven=False (btrfs) |
| Fedora 45 btrfs, scoped (`b06adb8`) | 50/50 | 49/50 | 49/50 | 50/50 | proven=False |
| **Fedora 45 btrfs, unscoped, ABI 2 (`788c709`)** | **0/50** | **0/50** | **0/50** | **0/50** | proven=True (subvol 256) |
| Ubuntu ext4, unscoped, ABI 2 (`788c709`) | 0/50 | 0/50 | 0/50 | 0/50 | proven=True (subvol 0) |

Numbers are slipped/attempts (a connect that completed although the rule blocks the executable). The
nft-only window lets almost every immediate connect through; only the connect-time layer closes it, and
every surface now says which of the two a rule has.

### 11.3 Externally detached programs, live (`b06adb8`)

Fedora VM and Ubuntu host, rule on a tmpfs copy of python3: proven, 0/20 slipped → `bpftool cgroup
detach` of the 4 programs → `rule.verify` at once `connectTimeBlockingProven=False` (`the BPF layer is
neutralised …`), doctor `WARN bpf layer: … live layer neutralised …`, `Result: 1 problem(s)`; 10/10 slipped
→ re-attached by the watch tick after 2.8 s (VM) / 7.2 s (host), 4 programs, proven again, 0/20 slipped.
Note: the doctor's `live enforcement` line stays PASS in that state (nft is verified) and carries the
degraded BPF text; the WARN comes from `bpf layer`.

### 11.4 "table inet axiom is missing" during neutralisation (`70c7ee8`)

The R4-H4 doctor run showed `table inet axiom is missing` while the layer was neutralised. Polling
every ~110 ms (nft, `rules.query`, a fresh canary curl) through `bpftool cgroup detach` of the 4
programs and through the map-fault neutralisation found **0 samples without the table** (≥ 7 rules
throughout); the text came from the capability reason, whose `Degraded` fallback named the table for
every degradation, including the BPF-only ones folded in by LNX-1. nft enforcement was never lost; what
was lost while the layer was detached is the connect-time layer (fresh-process slips until the watch
tick re-attaches, 18/18 → 0 after ~2 s at `fb8f04f`). Since `70c7ee8` the reason says the table is
present and that the BPF layer degrades enforcement. Neutralisation and re-attach never write nft (unit
test: no `delete table inet axiom` call). The same run found a real gap: `nft flush table inet axiom`
keeps the table and its generation comment, so the watcher reported `verified` with 0 rules for as
long as it lasted; the watcher now compares the owned rule comments and republishes. External
`nft delete table inet axiom` / `nft flush ruleset`: degraded at once with `nft table inet axiom
missing (removed externally …)`, restored by the next watch tick; the BPF layer stays attached
meanwhile, so unscoped block rules kept blocking (0 slips). Evidence: `LINUX_TEST_REPORT.md` R5-*.

## 12. Startup ordering: make-before-break hand-over (recon80 enforcement gap)

**Gap (0.64.0 … 0.80.0).** `BpfEngine.StartAsync` called `DetachAndUnpin()` on whatever a previous
daemon left attached **before** loading, attaching and populating its own set, and
`NftEnforcementSupervisor.TeardownAsync` detached the layer on every stop, `systemctl restart` included.
Each start after a crash or restart therefore had a window in which a fresh exec of a program blocked
by a connect-time-proven rule connected, while IPC and `--doctor` already said `active`/`verified`.

**Ordering now.**

1. Stop. A plain `systemctl stop` / `disable --now` / shutdown detaches and unpins as before. A
   restart hands the layer over and leaves programs and pinned maps attached. Restarts are detected
   by `SystemdStopIntent`: a `restart`/`start` job for `axiomd.service` in
   `systemctl list-jobs --no-legend --plain --full axiomd.service`, or the installer's one-shot marker
   `/run/axiom/bpf-handover`, which `--install-service` writes before its upgrade stop. A loop fault
   (systemd restarts the unit) also hands over, and so does a `list-jobs` answer that cannot be read
   (fail closed). `packaging/linux/bpf-pins.sh` (prerm remove/purge) still detaches everything.
2. Start, previous set attached (read from `bpftool -j cgroup show`). `prog loadall` stages the new
   object in `/sys/fs/bpf/axiom-next` (new maps; no map reuse, so an upgrade with a changed object is
   handled the same way). The four programs are attached with `multi` next to the old ones (8 attached),
   and the layer reports **`pending`**: connect-time layer state `pending`, filter enforcement
   `Pending`, no rule connect-time proven, and `--doctor` "live enforcement" WARN.
3. First sync (`managed-rules.json` → maps, read back). Only if it is verified are the old programs
   detached by id. `/sys/fs/bpf/axiom` is then replaced by a rename of `axiom-next`. The layer goes
   `active`.
4. Failure paths, all fail closed:
   - New set cannot be loaded or attached, or its maps cannot be populated: the new set is rolled
     back and the old set keeps enforcing. It is reported `stale_programs` (degraded, removals
     pending) and retried on the watch tick.
   - Old programs refuse to detach: the new set stays and the leftovers are reported stale. Only
     their detach is retried; no further load.
   - Unreadable `bpftool` output at start: unchanged (`unknown`, pins kept, nothing loaded or
     detached).
   - `bpftool` unusable while a previous set is pinned: `unknown`/stale and retried, never a plain
     `inactive`.
   - More than one set already attached at start: the old detach-then-load path, so never a third
     set.

**Kernel/tool behaviour this relies on, checked in the VM** (Ubuntu 24.04, kernel 6.8.0-147, bpftool
7.4.0 / libbpf 1.4, systemd 255):
- legacy `bpftool cgroup attach … multi` (BPF_F_ALLOW_MULTI) runs two Axiom sets side by side: 8
  attached, the old set's deny keeps refusing;
- `bpftool cgroup detach … id N` removes one program;
- `rename(2)` of a bpffs directory works and the pins keep their objects;
- bpffs refuses `.` in any name it creates (`bpf_lookup` → EPERM: "libbpf: failed to mkdir
  /sys/fs/bpf/axiom.next/axiom_connect4: Operation not permitted"), hence `axiom-next`;
- the stopping daemon can run `systemctl list-jobs` under the unit's sandbox and sees `restart`.

**Measured** (VM, `recon80-gap/guest/g.sh`):
- probes: 3 loops of fresh execs of a copied `curl` under an unscoped block rule, about 60 probes/s;
- control: an allowed `python3` connect every 50 ms;
- program count: sampled every 20 ms.

| scenario | before (0.80.0 @ 9067a6c) | after (fixed) |
|---|---|---|
| SIGKILL + auto-restart (×4) | 14–20 probes connected per run, over 0.2–0.4 s, ~3 s after the kill | 0 of 2,582 |
| `systemctl restart` (×4) | 65–68 per run, over 1.3–2.4 s from the restart | 0 of 2,392 |
| reinstall/upgrade same build | 134 over 2.6 s | 0 of 2,978 |
| upgrade 0.80.0 (pre-fix) → fixed | — | 126 over 2.2 s (the old daemon detaches on stop) |
| upgrade 0.64.0 → fixed | — | 136 over 2.2 s (same reason) |

After the fix, the attached count peaks at 7–8 (old + new) for about 0.2 s and settles at 4. The
allowed control connected throughout (0 failures in any run). IPC during startup: no reply → `pending`
/ enforcement `pending` / 0 proven for about 0.45 s → `active` / `verified`.

**Limits.**
- An upgrade **from** a package without this change still opens the window once: its daemon
  detaches on the upgrade stop. Upgrades from this build on are covered.
- The nft table and `axiom.slice` cgroups are still removed on every stop. Rules that are nft-only
  (scoped, inbound, allow) are therefore not enforced while the daemon is down; that window is
  unchanged, and only connect-time-proven rules are covered.
- While a handed-over set enforces without a daemon (crash loop, `start-limit-hit`), it enforces
  the verdicts it had. A rule removed in that state keeps blocking until a daemon runs again;
  `systemctl stop` or package removal detaches it.
- Live `--doctor` takes about 2 s and did not catch the ~0.5 s `pending` window. Its wording is
  covered by unit tests only.
