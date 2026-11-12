# Linux enforcement: nftables per-app engine (P2)

Status: built and proven end to end on the evidence box (Ubuntu 24.04.5, kernel 7.0.0-42-generic,
nftables 1.0.9, systemd 255, cgroup2fs), 2026-11-12. Branch `buba/linux-enforce`.
Plan: `docs/LINUX_PORT_PLAN.md` §3 (decision a: nft `socket cgroupv2`), spike in the plan's `spike/`.

Component: `src/Axiom.Infrastructure.Linux/Nft/` (`Axiom.Infrastructure.Linux.Nft.csproj`, references
`Axiom.Core` + `Axiom.Contracts` only). Tests: `tests/Axiom.Infrastructure.Linux.Nft.Tests/` (52 xUnit
tests against a fake `nft` runner and a fake cgroup/proc fs; the same exe is the root e2e harness).
E2E: `scripts/linux/nft/e2e.sh`.

## 1. What a rule becomes

`NftRuleCompiler.Compile(specs, generation, cgroups)` turns the enabled `RuleSpec`s into **one** `nft -f`
batch for `table inet axiom` and a report (`Applied`, `Rejected[{ruleId, reason}]`):

```
add table inet axiom
delete table inet axiom              # delete + re-add in one batch = atomic replace (nft idiom)
table inet axiom {
	comment "axiom generation 42"       # read back with `nft -j list table inet axiom`
	chain axiom_out {
		type filter hook output priority filter; policy accept;
		<loopback parts of rules that name 127.0.0.0/8 or ::1>
		ip daddr 127.0.0.0/8 accept      # loopback exempt (MACOS_ARCHITECTURE §3.1, review #13)
		ip6 daddr ::1 accept
		meta l4proto tcp socket cgroupv2 level 2 "axiom.slice/a-f0da955d46aa49e3" counter meta nftrace set 1 reject with tcp reset comment "axiom:<ruleId>:1"
		meta l4proto udp socket cgroupv2 level 2 "axiom.slice/a-f0da955d46aa49e3" counter meta nftrace set 1 drop comment "axiom:<ruleId>:2"
		meta l4proto != { tcp, udp } socket cgroupv2 level 2 "axiom.slice/a-f0da955d46aa49e3" counter meta nftrace set 1 drop comment "axiom:<ruleId>:3"
		meta l4proto tcp socket cgroupv2 level 2 "axiom.slice/a-…" ip daddr { 1.2.3.4, 10.0.0.0/8, 1.2.3.4-1.2.3.9 } tcp dport { 443, 8000-8100 } counter accept comment "axiom:<ruleId>:1"
	}
	chain axiom_in {
		type filter hook input priority filter; policy accept;
		ip saddr 127.0.0.0/8 accept
		ip6 saddr ::1 accept
		meta l4proto tcp socket cgroupv2 level 2 "axiom.slice/a-…" ip saddr { 10.0.0.0/8 } tcp sport { 1024-65535 } counter meta nftrace set 1 reject with tcp reset comment "axiom:<ruleId>:1"
	}
}
```

| Spec field | nft | Notes |
|---|---|---|
| `AppPath` | `socket cgroupv2 level N "axiom.slice/a-<16 hex>"` | N = path depth (2). One cgroup **per app** (sha256 of the realpath), shared by every rule of that app: a pid can only be in one cgroup. |
| `Direction` | chain `axiom_out` (hook output, `daddr`/`dport`) / `axiom_in` (hook input, `saddr`/`sport`) | Inbound loopback is not filtered (as on macOS). |
| `Action` Block | TCP `reject with tcp reset`, UDP/other `drop` | Immediate `ECONNREFUSED` for TCP clients (macOS drops the SYN → connect timeout; Windows also silently drops). `drop` stays available by editing one line if parity is preferred. |
| `Action` Allow | `accept` | Block rules are emitted **before** allow rules, so a matching block always wins (Windows semantics); no match ⇒ chain policy accept. |
| `Protocol` Any/Tcp/Udp | one nft rule per (family, protocol); Any + ports ⇒ tcp + udp; Any without ports ⇒ tcp + udp + `meta l4proto != { tcp, udp }` | |
| `RemoteAddresses` | anonymous sets `{ ip, cidr, a-b }` split into `ip daddr` / `ip6 daddr`; `*`/empty = any | Strict `inet_pton`-like IPv4 (`1.2.3` rejected, as the macOS filter does), host bits masked, IPv4-mapped v6 folded. `0.0.0.0/0`, `::/0` do not count as naming loopback. |
| `RemotePorts` | `tcp dport { 80, 443, 1000-2000 }` | |
| `Profiles` | ignored (Linux has no network profiles); `None` ⇒ rejected | |
| `Enabled = false` | skipped (stored, not emitted) | |

**Rejected, never widened** (reason strings are what the UI shows under "not enforced by the filter"):
hostnames, Windows address keywords (`LocalSubnet`, `DNS`, …), bad CIDR/range/port (`RPC`, `70000`,
`90-80`), relative or `*` appPath, `Profiles=None`, **unreachable appPath** (`appPath is not reachable on
this system: …`; re-evaluated at every publish, so installing the app later makes the rule live),
cgroup creation failure, and a **live process of the app that could not be moved** into its cgroup
(`live process pid N (…) could not be moved into …: Permission denied`).

Verified on nft 1.0.9: every construct above parses (`nft -c -f`, syntax errors are reported before
the netlink cache error as a user), `nft describe cgroupsv2` ⇒ `datatype cgroupsv2 (cgroupsv2 path)
(basetype integer), 64 bits`, so `set … { type cgroupsv2; }` **is** available — but it is not used: the
spike showed nft resolves a cgroup path to its numeric id at insert time (ENOENT if absent, rule dies
with the cgroup), so the engine keys rules on cgroups **it owns** and whose lifetime it controls
(`axiom.slice/a-…`, created before the batch, removed only after the table is gone). A set would only
help when keying on foreign cgroups (systemd scopes), which the herding design below avoids.

## 2. Attribution: processes → app cgroups (`AppCgroupManager`)

- Match: realpath of `/proc/<pid>/exe` (the kernel resolves symlinks; ` (deleted)` suffix stripped) equals the
  canonical appPath (realpath; `/bin/curl` and `/usr/bin/curl` agree) or lies inside it when appPath is a
  directory. **Case-sensitive** (Linux file systems are). Longest prefix wins.
- Herding policy (plan §9 question, decided): **always move** a matching pid into its app cgroup by writing
  `cgroup.procs` (root; needs `CAP_SYS_ADMIN` under a hardened unit), because the spike proved an
  already-running process is only matched once it sits in the keyed cgroup. The source cgroup is
  classified — `AppScope` (`app-*.scope`, `vte-spawn-*.scope`, `run-*.scope`, anything under `app.slice`),
  `UserSessionLeaf` (`session-N.scope`, other user units), `SystemService` (`system.slice/*`, `init.scope`),
  `Other` — and **system-service moves are reported** (`CgroupPlacement.Reportable`) so the daemon can log
  "pid N of X moved out of cron.service". Unmovable pids are reported and reject the rule (above).
  Test: `AppCgroupManagerTests.Attribute_moves_every_matching_pid_classifies_the_source_and_reports_system_services`.
- The origin cgroup of every moved pid is remembered; when an app loses its last rule, on teardown and
  on daemon stop, its processes are **returned** (origin → else the parent process's cgroup → else the
  cgroup root) before the cgroup is removed. Verified live: four foreign `dash` processes herded by an
  early e2e revision (rule on `/usr/bin/dash`) were returned to `system.slice/pm2-buba.service` and
  `…/hermes-gateway.service` via the parent heuristic after a daemon restart lost the origin map.
- Loop: the daemon calls `NftFirewallPolicyAdapter.Attribute()` every 1 s (one `readlink` per pid; ~3 000
  pids ≈ ms). The exec-time race (a process that connects before the next poll) is real: the e2e's
  step 4 shows `curl` started in a fresh scope connecting before a 50 ms poll caught it. Children forked
  by a herded process inherit the cgroup (step 3 proves it), so long-lived apps are covered from their
  first poll on; one-shot CLI tools are the gap. **P2b closes it** with the connect-time BPF layer
  (`docs/LINUX_EBPF.md`): `cgroup/connect4,6` + `sendmsg4,6` programs at the cgroup root decide inside
  `connect()` from the task's exe inode and cgroup id (both true at exec time, no herding needed) and
  fail the syscall with `EPERM` for unscoped outbound block rules — the same rules nft keys on the
  cgroup. Residual window after P2b: address/port-scoped block rules and inbound rules stay nft-only
  (still ≤ 1 s), and the layer is off (nft-only, reported in `capabilities`, `snapshot.limitations`
  and `--doctor`) on kernels without BTF or boxes without `bpftool`. The layer is implemented and
  unit-tested but **not yet compiled/proven live** (the evidence box lacks `clang`/`libbpf-dev`).
- Containers/sandboxes: Flatpak and Snap apps run in their own mount namespace; `/proc/<pid>/exe` shows
  the path inside it (`/app/bin/foo`, `/snap/foo/123/bin/foo`), AppImages run from a FUSE mount
  (`/tmp/.mount_fooXXXX/usr/bin/foo`). A rule must name that path (directory rules — `/snap/foo`,
  `/app` — match by prefix); mapping `.flatpak-info`/`.desktop` ids to rules is the identity resolver's
  job (P3). Flatpak's bwrap already places the app in its own `app-flatpak-….scope`; herding out of it
  works (cgroup v2, no delegation to the sandbox).

## 3. Events: the macOS NDJSON contract, reused unchanged

`FilterEventFormatter` emits `docs/MACOS_ARCHITECTURE.md` §3.2 lines on an `IFilterEventSink`:

- `filter.hello {version:"nft-1", generation, dropped:0}` + `filter.rules {generation, applied, rejected:[{id,reason}], error}`
  after every publish (`error` = nft's stderr when the batch was refused; the previous generation stays
  in force, as a rejected `rules.json` does on macOS).
- Block verdicts: block rules carry `meta nftrace set 1`; `NftTraceMonitor` runs `nft monitor trace`
  and `NftTraceParser` joins the `packet:` and `rule … (verdict drop)` records by trace id into
  `flow.open {verdict:"block", ruleId, protocol, local/remote address+port}` + `flow.close {0,0}`.
  The pid comes from `ProcNetSocketLookup` (local port → inode → `/proc/*/fd`) when the socket still
  exists; a rejected SYN closes within microseconds, so in practice the fallback supplies the rule's
  app path and a pid from its cgroup (`NftFirewallPolicyAdapter.DescribeRuleApp`). Allow rules are not
  traced (tracing every packet of allowed flows would be far too expensive); they only have counters.
- Counters: `NftTable.ReadCountersAsync` parses `nft -j list table inet axiom` (per-rule `packets`/`bytes`
  by comment); `rule.verify` reports "N nft rule(s), M packet(s) matched". Counters reset with every
  generation (the table is recreated), which is why the trace stream is the durable source.
- Why not nflog/NFQUEUE: nflog needs libnetfilter_log bindings (none for .NET) and still lacks pid; NFQUEUE
  puts every connection on a user-space round trip. `nft monitor trace` costs nothing until a block
  rule matches and already carries the rule comment. Full flow events (allowed flows, bytes, stats) come
  from `ProcNetConnectionSource` (P3 poll) and finally from the BPF helper (P2b), which speaks the same
  NDJSON so `FilterEventServer`/`FlowTable`/`FilterStatus` need no change.

## 4. Adapter (`NftFirewallPolicyAdapter`: `IFirewallPolicyAdapter` + `IOwnedRuleRecoveryAdapter`)

Mirrors `MacFirewallPolicyAdapter`: `managed-rules.json` (0600, schema 1, same record shape) persisted
**before** the nft apply (a crash leaves a republishable record, never unknown rules in the kernel),
`rules.nft` (0644) kept for `--doctor`, generation = max(state, table comment) + 1. `GetCapabilities`
→ `Available` (table present, generation matches), `Degraded` (nft refused a batch, or the table is
**missing** — someone ran `nft flush ruleset`; the daemon-side watcher should call `PublishAsync()`
to re-apply), `Unavailable` (state dir not writable). `FilterEnforcement` is the same
`{generation, appliedRuleCount, rejectedRules, fileError}` the Firewall page already renders.
`Upsert` returns `Success=true, State=Pending, ErrorCode=nft.rule_rejected` for a stored-but-rejected
rule (visible in the UI), `nft.apply_failed` when the batch was refused. `Verify` reads the table and
counters back. Recovery removal needs root/the daemon and re-checks ownership (`OwnedRuleOwnership`).
`TeardownAsync` deletes **only** `table inet axiom`, returns herded pids and removes `axiom.slice`.
Writes go through the same `FirewallWriteGate`.

## 5. E2E evidence (`scripts/linux/nft/e2e.sh`, run as root via `sudo -n`, 2026-11-12)

```
## host: Ubuntu 24.04.5 LTS kernel 7.0.0-42-generic nftables v1.0.9 (Old Doc Yak #3) cgroup cgroup2fs
## 1 control
200 rc=0
PASS control: curl reaches http://example.com
## 2 apply
rule.apply: success=True state=Applied
rule.apply(bad): success=True state=Pending error=nft.rule_rejected invalid address '1.2.3' (IP, CIDR or a-b range expected; hostnames are not supported)
rule.apply(extra): <private copy of dash> success=True state=Applied
enforcement: generation=3 applied=2 rejected=1 fileError=
cgroup: /usr/bin/curl -> /sys/fs/cgroup/axiom.slice/a-f0da955d46aa49e3
PASS rules applied through the engine (2 applied, 1 rejected)
  nft: meta l4proto tcp socket cgroupv2 level 2 "axiom.slice/a-f0da955d46aa49e3" counter packets 0 bytes 0 meta nftrace set 1 reject with tcp reset comment "axiom:0f8fad5b-d9cb-469f-a165-70867728950e:1"
## 3 already-running shell in its own scope, herded while it sleeps; its curl child inherits the cgroup
placement: pid 994771 (…/dash) moved from SystemService cgroup system.slice/axiom-e2e-994717.scope into axiom.slice/a-…
curl: (7) Failed to connect to example.com port 80 after 0 ms: Couldn't connect to server
000 rc=7
PASS herded shell: curl blocked (rc=7, connection refused)
## 4 curl started after the rule, caught by the 50 ms attribution poll (race: reported, not asserted)
200 rc=0
INFO exec-time race lost: curl connected before the poll caught it (expected sometimes; P2b closes it)
## 5 trace events + counters
event {"type":"flow.open","id":"nft-839228e1-1","ts":"2026-11-12T02:23:35.812Z","pid":2291,"path":"/usr/bin/dash","direction":"outbound","protocol":"tcp","localAddress":"192.168.70.4","localPort":39148,"remoteAddress":"104.20.23.154","remotePort":80,"remoteHost":null,"verdict":"block","ruleId":"c7d05fe4-ae68-59b7-90f4-eed017f7aab3","responsiblePid":null,"responsiblePath":null}
event {"type":"flow.close","id":"nft-839228e1-1","ts":"2026-11-12T02:23:35.812Z","bytesIn":0,"bytesOut":0}
PASS trace monitor emitted flow.open verdict=block with a rule id
counters: meta l4proto tcp socket cgroupv2 level 2 "axiom.slice/a-6bfb5004339731b0" counter packets 37 bytes 2220 meta nftrace set 1 reject with tcp reset comment "axiom:c7d05fe4-…:1"
rule.verify: present=True matches=True effective=Block rejection=
PASS rule.verify: present, effective action block
## 6 remove
rule.remove: success=True bad=True all=True
200 rc=0
PASS after remove: curl reaches http://example.com again
## 7 teardown
teardown: tableGone=True sliceGone=True
PASS table inet axiom removed
PASS axiom.slice removed
## RESULT: PASS
```

(Run 4 of the script; that revision keyed the shell rule on the system `/usr/bin/dash`, which is why 37
packets of unrelated shells were blocked during the 12 s window — the shipped script uses a private
copy of the shell. Rule-removal restored them, teardown returned their pids.)

## 6. What the daemon side (P3) must wire

1. Construct `NftFirewallPolicyAdapter(new NftEnginePaths("/var/lib/axiom/filter"), new NftTable(new NftProcessRunner()), new AppCgroupManager(new ProcCgroupFs()), sink)` and register it as `IFirewallPolicyAdapter` + `IOwnedRuleRecoveryAdapter` (replacing the `LinuxFirewallPolicyAdapter` stub).
2. On start: `PublishAsync()`; on stop/uninstall: `TeardownAsync()`.
3. A 1 s loop calling `Attribute()` (log `Reportable` placements).
4. `NftTraceMonitor(new NftTraceProcessSource(), new ProcNetSocketLookup(), adapter.DescribeRuleApp, sink, TimeProvider.System).RunAsync(ct)` with restart on exit.
5. The sink: feed lines into the existing `FilterEventServer.ConsumeAsync`/`FlowEventParser` + `FilterStatus` (in-process pipe) so `capabilities.filterEnforcement`, the Connections page and the "not enforced" block work as on macOS; `adapter.Enforcement` can be used directly where `FilterStatus.Rules` was.
6. A ruleset watcher (`nft monitor` or a 10 s `ReadGenerationAsync` poll) that republishes when the table disappears; `--doctor` FAIL on the same condition.
7. Unit: `CapabilityBoundingSet` needs `CAP_NET_ADMIN` (nft) and `CAP_SYS_ADMIN` (`cgroup.procs` of foreign cgroups), `ReadWritePaths=/sys/fs/cgroup`.
8. P2b: `LinuxEnforcement.CreateBpfEngine(adapter, sink)` → `adapter.VerdictLayer`; the supervisor takes it as
   its `IEnforcementLayer` (start after the first publish, resync, events loop, stop before teardown); every
   successful publish calls `layer.SyncAsync(rules, generation)`. Unit adds `CAP_BPF CAP_PERFMON` and
   `ReadWritePaths` `/sys/fs/bpf`. Details and the proof plan: `docs/LINUX_EBPF.md`.
