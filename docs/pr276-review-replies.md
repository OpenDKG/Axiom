# PR #276 — replies to the maintainer review (draft, NOT posted)

Review `5874574074` (REQUEST_CHANGES) on `62b6406`. Branch `buba/linux`, commits on top of `62b6406`:
`4ff73d5` red tests · `983ef21` LNX-1 · `bd33548` LNX-2 · `f2063fa` hardening + fault matrix · `d8949e9` CA1873 · docs commit.
All evidence below is the author's, on one Ubuntu 24.04 x86_64 box; no independent CI.

## Summary

Both blockers are fixed and covered by tests that were red before the fix (7 failed / 83 passed at `4ff73d5`,
106/106 now). A failed BPF map delete or update can no longer produce a verified removal or an applied rule:
the BPF layer's sync result is part of the effective state, reconciled with bounded retries and a read-back,
and when a stale entry cannot be removed the daemon detaches only its own programs and reports `Degraded`
until it re-attaches. The supervisor tears down in `finally` with bounded, independent steps and reconciles
orphaned Axiom state at start. Proven live through the packaged daemon (fault injection, SIGKILL, stop/start,
upgrade, third-party table retention). Platform claims are reduced to what was run (Ubuntu 24.04 x64); RPM is
built but not install-tested; Debian/Fedora/Wayland/KDE/arm64 and live IPv6 traffic are untested. The PR
stays Draft.

## LNX-1 — removed rule can remain active in the eBPF map

Fixed in `983ef21` + `f2063fa`. `IVerdictLayer.SyncAsync` returns `LayerSyncResult` (generation, applied,
verified, attached, pinned, neutralised, attempts, failedUpdates[], failedDeletes[], covered/uncovered rules).
`BpfEngine` writes, reads both maps back (`bpftool -j map dump`), repairs unknown/missing/different keys, retries
3 passes with 250/500 ms backoff. Persistent stale entry → detach only `axiom_*` programs (by pin and by id from
`bpftool cgroup show`), `Neutralised`; detach failure → `StaleEntriesCanBlock`, never success.
`RemoveOwnedRuleAsync` → `Success=false`, `Pending`, `bpf.delete_failed` / `bpf.stale_entry` with the failed
operations and what to do; `UpsertOwnedRuleAsync` → `Pending` `bpf.update_failed`; enforcement report
`Degraded`/`Pending`; `VerifyAsync` never verifies while the layer disagrees and says `BPF-backed` vs `nft-only`
per rule; capabilities carry the reason/limitation. Missing pins, a missing bpftool and externally detached
programs are handled explicitly. Tests: every minimum bullet (LINUX_TEST_REPORT.md fault matrix), all with a
pre-seeded third-party program and an nft call audit. Live: renamed map pin → `rule.remove` `success:false`
`bpf.delete_failed`, re-attached 1 s later, retry verified, curl 200. Design: LINUX_EBPF.md §10.

## LNX-2 — unexpected supervisor failure can bypass teardown

Fixed in `bd33548` (+ `d8949e9`). `RunAsync` = `try { reconcile orphans; publish; start layer; loops } finally
{ teardown }`; the first faulted loop cancels the others, is logged first and rethrown after the teardown, and
the worker exits 70 so `Restart=on-failure` restarts the daemon. Teardown steps (BPF detach/unpin, `delete table
inet axiom`, cgroup release) each run under an 8 s bound regardless of the others; errors are aggregated. A
failed `nft delete` is now an error rather than a silent success. Tests: a fault in each of the four loops, a
throwing / hanging / failing teardown step, rapid stop/start, crash + new instance. Live: SIGKILL → restart
reconciled (4 programs, not 8; journal `Startup reconciliation …`), `systemctl stop` → no table, no `axiom_*`
attachment, no `axiom.slice`, no pins; start republished. Known limit: a process herded by a killed instance
is released to its parent's cgroup or the root (origin not persisted) — documented in LINUX_ENFORCEMENT.md §8.

## Platform and security requirements

- systemd/capabilities: every capability justified in LINUX_ARCHITECTURE.md (table); `CAP_NET_RAW` flagged as a
  removal candidate pending an audit. Unit unchanged otherwise.
- nftables: one atomic batch per generation for `table inet axiom` only, no `flush ruleset`; a third-party
  `inet` table was byte-identical through publish/stop/teardown live. IPv6: structural evidence only (no v6
  route on the box).
- eBPF: requirements and degradation in LINUX_EBPF.md §6/§10; coverage is advertised only for unscoped outbound
  block rules; the ~1 s window of nft-only rules is stated per rule and in the capability limitations.
- Privacy/IPC, DNS recovery: unchanged by this round; not re-tested beyond the DNS baseline diff (unchanged).

## Integration and packaging evidence

- `.deb` rebuilt and upgraded in place on the live box (LINUX_TEST_REPORT.md L-1…L-9).
- `.rpm`: built only; Fedora/SELinux install/upgrade/remove **pending**.
- Debian, Fedora, Wayland, KDE, arm64, BTF variants: **untested**; no compatibility is claimed.
- Windows: shared contracts untouched by this round (the changed interfaces are Linux-only); the solution builds
  0/0 with `EnableWindowsTargeting`; Windows test suites were not run on Windows.

## Shared-contract changes in this round

None in `Axiom.Contracts`/`Axiom.Core`. `Axiom.Service`: only the Linux-only `Platform/NftEnforcementWorker.cs` (exit code 70 on a supervisor fault). Linux-only: `IVerdictLayer.SyncAsync` returns `Task<LayerSyncResult>`
(+ default `Neutralised`), new records `LayerSyncResult`/`LayerSyncFailure`/`LayerUncoveredRule`, `BpfMapDump`,
`AppCgroupManager.ListSliceCgroups`, adapter `DeleteTableAsync`/`ReleaseCgroups`/`ForgetPublished`/
`ReconcileCgroups`/`LayerSync`, supervisor `TeardownErrors`/`LastFault`/`OrphansReconciled`/`LayerReattachments`.
New error codes (strings in the existing `ErrorCode`): `bpf.delete_failed`, `bpf.stale_entry`,
`bpf.update_failed`, `bpf.neutralised`.
