# Linux compatibility: implementation plan (completion pass)

Status: implemented and re-based on the renamed upstream; independent review in progress.
Baseline revision: `3d58baa94940d9dc6a5d4764071f4c8ce2e91b9b` (`main` of `a-51-50/Axiom` 0.5.2, which
was renamed from `a-51-50/Netpetra`; GitHub redirects the old URL). Fork `brxtrac/Axiom`,
branch `feature/linux-compatibility`, PR #174 (draft), enforcement gap #175, umbrella #150.
Linux first; macOS is a later phase and is not claimed here.

The previous revision (`ec0f62f`) was based on `6991fb9`, before upstream renamed every project,
namespace and product string to Axiom. It is no longer authoritative and PR #174 was conflicting.
This pass first synchronized: fetched upstream and fork, preserved the interrupted uncommitted
work as `wip/linux-interrupted-20261106` (`75dfd6a`), re-applied the whole Linux delta onto
`73c6c3e` with the Netpetra→Axiom path/identifier mapping, merged upstream's nine rename-era
commits, and was re-based once more onto `3d58baa` when three further commits landed (ZCode and
DeepSeek agent protection, test-count docs, 0.5.2 release). Windows-only legacy names remain only
in `LegacyIdentity`/installer migration code.

Verified on this host (Ubuntu 24.04.4, x64, kernel 7.0.0, root in a container with
`CAP_BPF`/`CAP_SYS_ADMIN`/`CAP_NET_ADMIN`, cgroup v2, `libbpf` 1.3, clang 18, BTF available):

- `dotnet test Axiom.Linux.slnf`: **305 passed, 0 failed, 0 skipped**
  (Contracts 67, Core 66, Persistence 23, Service 16, Dns 11, MCP 35, Infrastructure.Linux 87).
- Windows compile-only regression is part of the previous run and is re-run at the end.
- Existing work preserved (do not regress): `/proc` inventory, authenticated Unix socket
  (`SO_PEERCRED`, 0600/0700, no unlink of a healthy endpoint), shared IPC dispatcher, systemd
  user/system lifecycle, loopback browser UI with per-run token, DNS proxy with validated
  loopback upstreams (no public fallback), case-sensitive Linux app identity, quarantine of
  invalid-header databases and sidecars, bounded IPC writes, DNS admission/drain, platform-neutral
  MCP/mapped IPv4, no chmod of populated shared directories.

## Goal

Close the remaining Linux feature-parity and reliability limitations with real Linux mechanisms,
or state an exact unresolved limitation with evidence. No wording-only closures, no global
port/UID substitutions labelled as per-executable, no Windows/WSL/macOS results invented on this
host. Windows behaviour and gates stay unchanged. The desktop browser UI remains the supported
Linux UI; MSIX/Store mechanics are not ported literally (no Store on Linux) and have a documented
Linux equivalent.

## Capability matrix (target state after this pass)

| Windows capability | Real Linux equivalent | Target status | Evidence |
|---|---|---|---|
| Socket inventory TCP/UDP v4/v6, PID/path attribution | `/proc/net/*` + inode map + `/proc/<pid>/{fd,exe,stat}` | Complete (already) | 30 Linux tests, live capture |
| Per-flow byte counters | none in `/proc`; needs eBPF/tcp_info | Unresolved, reported (same truthfulness as Windows) | limitation string |
| SQLite history, search, retention, corruption recovery | SQLite + quarantine | Complete; valid-header page corruption evidence fix added | M2 tests |
| History CSV export | desktop HTTP endpoint using the shared export formatter | Complete | M3 tests |
| Service lifecycle | systemd system/user unit | Complete (already) | lifecycle run |
| IPC | Unix socket, `SO_PEERCRED`, 0600, private dir | Complete; init-failure ownership cleanup hardened | M2 tests |
| Firewall read/list/verify/apply/remove, per-application | **eBPF cgroup hooks** (`connect4/6`, `sendmsg4/6`, `bind4/6`) with executable path identity | Complete for outbound and bind-scoped inbound; inbound allow-with-remote-scope stays unsupported (exact code) | 6 live tests, 3 compiler/identity suites, service smoke |
| Privacy Shield DNS | loopback filter in `Axiom.Dns` | Complete (already); drain fix | M2 tests |
| External reputation / feed / local scan | hash-only VirusTotal endpoint + `ICredentialStore` (Secret Service, else refuse) | Contract and refusal path complete; the Linux UI has no VirusTotal key field, and no live provider key was exercised | M3 tests |
| AI analyst | portable HTTP client + Linux settings/credential storage + UI action | Implemented (settings, key store, analyze endpoint, UI panel); no provider round-trip executed | M3 tests, docs |
| Agent hook adapters (Claude, Codex, Cline, Cursor, Copilot, Gemini, Windsurf, OpenCode) | hook payload depends on the Blackbox Python module, which ships only as a pinned Windows installer | **Unresolved** (exact blocker). Linux hook installer is not shipped because it would install hooks that fail open | matrix + PR |
| Optional Blackbox | Windows-only vendor installer | Unresolved (no Linux build to pin/verify) | docs |
| Optional DKG | npm package, platform-neutral | Documented only: no Linux probe or status surface; no silent download | docs |
| Tray icon/status/notifications | no tray without a shell extension; no notification backend shipped on Linux | Unresolved: neither tray nor desktop notifications are implemented; the browser UI is the surface | docs |
| UI autostart | `~/.config/autostart/*.desktop` (XDG) | Complete | M3 tests |
| Desktop UI | loopback browser UI | Complete (already) | UI run |
| CLI/MCP | Unix socket transport | Complete (already) | 35 MCP tests |
| Install/update/uninstall | POSIX scripts + tarball | Complete; add `.deb` packaging and upgrade/uninstall checks | M4 |
| MSIX/Store | n/a on Linux | Not applicable | docs |
| WSL/container | detection + explicit supported boundaries | Complete as reporting, not as a claim of exercised support | M3 tests |
| AppArmor/SELinux confinement | detection + explicit limitation | Reporting complete; confined runtime not exercised on this host | M3 tests |

## Milestone 1: per-executable Linux firewall (closes #175)

### Mechanism

`BPF_PROG_TYPE_CGROUP_SOCK_ADDR` programs attached to the cgroup v2 root (or
`AXIOM_FIREWALL_CGROUP` for isolated tests) at `cgroup/connect4`, `cgroup/connect6`,
`cgroup/udp4_sendmsg`, `cgroup/udp6_sendmsg`, and `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` bind hooks
`cgroup/bind4`, `cgroup/bind6`. nftables cannot match an executable path; UID-only and global port
rules are explicitly rejected.

### Identity

The kernel derives a 128-bit FNV-1a hash from the executable's **filesystem device**
(`d_sb->s_dev`, mixed as major/minor first) and its **filesystem-internal path** by walking
`task->mm->exe_file->f_path.dentry` and its parents (bounded to 7 non-root components, 64 bytes
each; component names are read with `bpf_probe_read_kernel`). Userspace derives the same hash from
the canonical executable path, the `major:minor` field of `/proc/self/mountinfo` and the mount root.
Two filesystems exposing the same internal path therefore get different identities. This identity
is stable across PID reuse, restarts, bind mounts and mount namespaces; a replacement binary at the
same path inherits the rule, and an already running deleted binary keeps matching until it exits
while the adapter refuses to manage or remove that rule. Path length/depth beyond the documented
bounds is refused with an explicit error rather than truncated.

### Policy model

Per executable (max 256 executables, max 16 rules each):

- `action` block/allow, `protocol` any/TCP/UDP, optional port range, optional IPv4/IPv6 CIDR;
- block wins; an executable with at least one **allow** rule for a direction is in allow-list
  mode: unmatched traffic for that executable/direction is denied (this is the opt-in
  default-closed semantic and is documented as stricter than Windows' profile default);
- otherwise unmatched traffic is allowed, so installing Axiom never silently blocks unrelated
  traffic;
- outbound rules apply to `connect` (TCP and connected UDP) and `sendto` (UDP);
- inbound rules apply to `bind`/`listen` (new binds only; a socket bound before the rule is not
  torn down). Inbound allow rules, inbound remote-address scope and inbound remote-port scope are
  refused with `rule.scope.unsupported_platform` because a bind hook cannot see the future peer
  and `RuleSpec.RemotePorts` names the peer port; an accepted inbound block covers every new bind
  of that executable.

### Write gate, trust boundary, rollback

- Writes require `AXIOM_ENABLE_FIREWALL_WRITES=1` **and**
  `AXIOM_FIREWALL_WRITE_CONFIRM=yes`, same gate as Windows. Reads never change state.
- `RuleSpecValidator` runs before any map write. Additionally: absolute regular file, resolves to
  an existing executable, no directory, path/depth bounds, ports only with a concrete protocol,
  CIDR parse checked again at the adapter boundary.
- Apply is transactional: snapshot the executable's previous slots, write, read back from the
  kernel maps, compare to the spec; on mismatch restore the snapshot and fail with
  `rule.verify_failed`. Remove clears only the owned slots and verifies the clear.
- No bpffs pins: links are owned by the service process and disappear if it dies. Shutdown detaches
  every hook and closes the object. Tests never attach to a shared cgroup without an isolated
  child cgroup, and never modify host firewall/DNS.

### Loader

Embedded CO-RE object compiled from `firewall.bpf.c` by `scripts/build-ebpf.sh` (source, object,
libbpf version and kernel prerequisites recorded). Loading uses `libbpf.so.1` through a narrow
P/Invoke surface (`bpf_object__open_mem`, `bpf_object__load`, program/map lookup,
`bpf_prog_attach`/`bpf_prog_detach2`, `bpf_map_update_elem`/`bpf_map_lookup_elem`). Missing
libbpf, BTF, cgroup v2 or capability is a truthful `Unavailable` capability with a specific
reason; it is not a crash and not a silent no-op.

### Acceptance tests

1. Pure policy tests: CIDR parsing/matching, port ranges, path hash parity between the userspace
   and a reference implementation, bounds, invalid specs refused.
2. Map round-trip without BPF: apply/list/verify/remove; block-wins; allow-list mode; rollback on
   simulated verification failure.
3. Live integration (skipped with a printed reason when capability is absent): create a private
   child cgroup, attach the real object, run a spawned client in that cgroup:
   - TCP connect to an allowed port succeeds, to a blocked port fails with EPERM;
   - UDP `sendto` to a blocked port fails with EPERM, allowed port succeeds;
   - an inbound block makes a new bind of the executable fail; removal allows it again;
   - a different executable is unaffected;
   - allow-list executable denies an unlisted port and allows a listed one;
   - remove restores connectivity; detach on dispose leaves no attached program;
   - IPv6 variants where the host has `::1`.
4. No traffic is altered outside the test cgroup; the test client is a test-only console project.

## Milestone 2: recovery and reliability gaps

1. **Valid-header SQLite page corruption.** Before any read-write SQLite open, when `-wal`/`-shm`
   or a `-journal` exists (unclean shutdown), copy DB + WAL + SHM into
   `<data>/quarantine/preopen-<utc>/` so evidence is preserved before SQLite can checkpoint or
   delete it. Then probe the main DB with a read-only, immutable connection and
   `PRAGMA quick_check`; on SQLITE_CORRUPT/SQLITE_NOTADB move the originals and sidecars to the
   normal corrupt backup and start fresh. Healthy databases (including a healthy WAL) are never
   quarantined; a locked/busy database is reported, not quarantined.
2. **Blocked-writer deadlines.** Every response write (success, error, oversized-request error,
   rate-limit error) is bounded by a dedicated linked token with `RequestTimeout`; the oversized
   error path no longer inherits a possibly expired idle token. Independent re-review of the
   `ec0f62f` oversized fix and a regression test with a client that never reads.
3. **DNS handler drain/cancellation.** Shutdown stops accepting, drains in-flight UDP/TCP handlers
   with a bounded grace period while sockets remain usable, then cancels and disposes; no handler
   observes a disposed socket before its deadline. Tests cover dispose with an in-flight query and
   with a stalled TCP client.
4. **Socket ownership cleanup on initialization failure.** If directory preparation or bind fails
   after the instance created/changed a path, the instance removes only what it owns and leaves a
   live endpoint untouched; tests cover stale socket, symlink, refused second instance and bind
   failure.

## Milestone 3: parity features

- **CSV export** of history in the Linux browser UI (`/api/history.csv`) using one shared formatter
  with RFC 4180 quoting and spreadsheet-injection neutralisation (leading `= + - @ TAB CR`), UTF-8
  BOM, `Content-Disposition`; tests assert escaping and injection safety.
- **Credential storage** (`ICredentialStore`): Windows keeps DPAPI; Linux uses Secret Service via
  `secret-tool` when a session bus is available; otherwise saving a key is refused with an explicit
  error and no plaintext file is written. AI analyst and reputation settings use it. Tests cover
  round-trip with a fake store, refusal when no backend exists, and that no key appears on disk.
- **AI analyst**: portable request/response client (no WPF types), service-side invocation from the
  Linux UI, provider settings and credential flow documented; unavailable provider is a visible
  error, not a silent no-op.
- **Autostart**: XDG desktop entry (`~/.config/autostart/axiom-ui.desktop`) with absolute exec
  path, validated by `desktop-file-validate`; enable/disable/status; no registry emulation.
- **Notifications**: not implemented on Linux (no `notify-send` path); the browser UI is the
  status surface. Tray icon and desktop notifications remain an explicit non-claim.
- **Optional modules**: DKG documented for Linux only (`npm` package, user-scope prefix, no silent
  install, no status probe); Blackbox reported unavailable on Linux with the exact
  vendor-installer reason.
- **Platform reporting**: WSL (`/proc/version` microsoft), container (`/.dockerenv`,
  `container=` env, cgroup), AppArmor/SELinux (`/sys/kernel/security/lsm`,
  `/proc/self/attr/current`), systemd user bus availability. These produce explicit limitation
  strings and never claim a tested confined/WSL/container run.

## Milestone 4: packaging and lifecycle

- `.deb` build (self-contained publish, `/opt/axiom`, systemd unit, desktop entry, uninstall
  preserves user data); `dpkg-deb --info`/`--contents` smoke; install/upgrade/uninstall in an
  isolated prefix without touching the host firewall, DNS or proxy.
- Installer safety re-checked: root-owned immutable payload, symlink/setuid rejection, absolute
  desktop exec path, no remote downloads.
- User/system state preservation verified across upgrade and uninstall.

## Milestone 5: live testing, soak, review

- Real non-root client and cross-user service/IPC; service restart; MCP over the real socket; UI
  auth/Host/CSP/CSRF/limits; DNS UDP/TCP with blocked upstream and no public fallback; adapter
  script execution in isolated profiles; credential refusal path; package smoke.
- Bounded soak (e.g. 10 minutes / fixed iteration count) with measured RSS, CPU, handle and map
  counts while capture, history writes, IPC reads and UI requests run concurrently. Exact numbers
  and host recorded; no extrapolation to Windows/macOS.
- Windows compile-only regression (`EnableWindowsTargeting=true`) and Linux full suite with exact
  counts.
- Independent review of the real diff and connected code (separate OpenCode review session), then a
  re-review of the final substantive fixes. Findings fixed in Build or documented as spec errors.

## Milestone 6: docs, GitHub, deliverable

- Update `docs/LINUX.md`, `docs/TEST_MATRIX.md`, `docs/PRIVACY_SHIELD.md`, compatibility matrix,
  install docs; add the firewall prerequisites/semantics and the exact unresolved list.
- Duplicate-check issues; file confirmed bugs with revision/path/trigger/reproduction/impact; push
  reviewed commits to `feature/linux-compatibility`; update PR #174 evidence and keep it draft
  unless every claimed item meets acceptance; comment on #175/#150. Do not merge.
- Record installation cleanup state and remove test cgroups/processes/data created by this pass.

## Security decisions (delta)

- The firewall never substitutes UID, port-global or cgroup-global blocking for executable scope.
  A rule that cannot be expressed with the executable identity is refused, not broadened.
- The BPF program is fail-open only in the sense of "no rule match → no change to the host"; a
  configured block/allow-list decision is fail-closed (connect/bind error). A failed load/attach
  disables the feature and reports `Unavailable`; it never reports rules as applied.
- Policy updates are read back from the kernel maps; the SQLite audit trail still records
  pending/applied/failed, and removal failure remains audited (prior fix preserved).
- Credentials: no plaintext fallback. The Linux backend refuses when Secret Service is absent.
- Tests that need privileges create a private child cgroup and disposable processes; they never
  attach enforcement to the shared root cgroup, never change host firewall/DNS/proxy.

## Explicitly unresolved after this pass (candidates; final list in the PR)

- Agent hook installers on Linux: the hook payload requires the Blackbox Python module, shipped
  only as a pinned Windows installer; installing a fail-open hook would be worse than reporting the
  gap. Exact blocker, not a wording change.
- Blackbox module installation on Linux: no verified Linux artifact to pin.
- Inbound allow-with-remote-scope on Linux: a bind hook cannot see the future peer; refused with a
  specific error.
- Tray icon: no cross-desktop tray without a shell extension; notifications + autostart are the
  supported equivalent.
- WSL/container/SELinux/AppArmor confined runtime: detection and documented boundaries only unless
  a disposable environment is available and exercised.
- macOS: not included; seams recorded (`/proc` → `libproc`, `SO_PEERCRED` → `getpeereid`, systemd →
  `launchd`, eBPF cgroup → `pf` anchor/Network Extension decision).

## Acceptance criteria (definition of done for this pass)

1. M1 and M2 acceptance tests pass on Linux; live firewall tests pass where capability exists and
   skip with a printed reason otherwise.
2. Full Linux suite passes with exact counts; Windows compile checks pass; no skipped test without
   a platform reason recorded.
3. Every row of the matrix is either Complete with evidence, Partial with the documented delta, or
   Unresolved with an exact blocker; no claim of a runtime environment not exercised.
4. Independent review completed on the final substantive diff; last fix re-reviewed; no unreviewed
   security change.
5. PR #174 updated with evidence, prerequisites, soak numbers, cleanup state and remaining
   blockers; issue #175 either closed as fixed (if live enforcement verified) or updated with the
   exact remaining blocker.

## Results (completion pass)

- Baseline was 233 tests at `ec0f62f`; after the Axiom re-base and the upstream merge the suite is
  **305/305 passed, 0 skipped** in `dotnet test Axiom.Linux.slnf`
  (Contracts 67, Core 66, Persistence 23, Dns 11, Service 16, MCP 35, Infrastructure.Linux 87),
  run twice on the final tree. Windows compile: `OS=Windows_NT dotnet build Axiom.sln -c Release
  -p:EnableWindowsTargeting=true` -> 0 errors.
- Firewall: the eBPF backend is real and exercised live in a disposable cgroup (TCP block, UDP
  sendmsg block, bind block, allow-list, another executable unaffected, remove restores, verify/list
  Applied). The service smoke reported `available` with the write gate closed. No host firewall/DNS
  change was made and nothing was attached to the shared root cgroup during tests.
- Recovery: valid-header page corruption is detected with a read-only `quick_check` and the DB,
  WAL, SHM and journal are copied into `quarantine/preopen-*` before SQLite can mutate them; healthy
  WAL databases are not quarantined. Oversized-request errors now have a dedicated write deadline
  (test with a blocked writer). DNS dispose drains in-flight queries. Init failure removes only what
  the instance created.
- Parity shipped: CSV export (escaping + formula neutralisation), Secret Service credential store
  (no plaintext fallback), Linux AI settings/analyze and VirusTotal hash endpoints (UI panel), XDG
  autostart, host environment limitations (WSL/container/LSM/SELinux/AppArmor), `.deb` packaging
  with an opt-in firewall drop-in, and a soak script.
- Soak (90 s, published payload, isolated data/socket): 7 070 requests, 0 HTTP errors, service RSS
  69 872 -> 266 436 KiB, UI RSS 67 156 -> 332 708 KiB, service CPU 81 s, threads 20/23, 4 057 sockets
  and 6 536 history rows at the end; socket cleanup and data preservation `ok`.
- Package smoke: `dpkg-deb --info/--contents`, extraction, `desktop-file-validate`, extracted
  service + UI self-check + MCP start, clean stop, data preserved.
- Outstanding, stated rather than hidden: agent hook installers (Blackbox Windows-only payload),
  Blackbox install, AI provider/keyring live round-trip, tray icon, Windows runtime tests (compile
  only), WSL/container/SELinux/AppArmor confined runtime, 24 h soak/reboot, macOS.

### Synchronization record (this pass)

| Step | Value |
|---|---|
| Starting branch/commit | `feature/linux-compatibility` at `ec0f62f` (fork), base `6991fb9` |
| Interrupted work preserved | branch/tag `wip/linux-interrupted-20261106` = `75dfd6a` (51 files, +5 435/-388) |
| Upstream default HEAD | `a-51-50/Axiom` `main` = `3d58baa94940d9dc6a5d4764071f4c8ce2e91b9b` (0.5.2) |
| Fork default HEAD | `brxtrac/Axiom` `main` = `6991fb919ac1decb267f7164b2a6650d5b7f8d02` |
| Re-base | Linux delta re-applied onto `3d58baa` after the Netpetra→Axiom rename; twelve upstream commits reconciled |
| Port verification | Linux build 0 errors; 305/305 tests twice; Windows compile and locked restore 0 errors |
| Runtime re-check | service, socket 0600, UI 401/400/200 + CSP, CSV, MCP `initialize`/`tools/list`/`axiom_get_status` over the real socket, system install/uninstall with data kept, `.deb` build + `desktop-file-validate` |
| Not re-run | DNS live forwarding (covered by the real-socket Dns tests), 24 h soak/reboot, Windows runtime, WSL/containers/SELinux/AppArmor confined runtime |

### Independent review

An independent read-only review (`reviewer` agent, separate OpenCode run) covered the branch
diff against the then-current main, the connected callers, tests, units and install/package scripts. Findings and
their disposition:

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `RestoreAsync` wrote maps without loading/attaching the object, so restart lost enforcement | Fixed: restore reuses the compile/load/attach/write/read-back path; live test restarts the adapter and proves the block still applies |
| 2 | high | `BPF_CORE_READ(ctx, user_ip4/user_ip6)` reads the virtual context through a helper; CIDR rules would miss | Fixed: direct constant-offset context loads; new live IPv4 `/32` and IPv6 `/128` block tests (and a negative address) |
| 3 | high | Identity hashed only the internal path, so two filesystems collided | Fixed: `d_sb->s_dev` (major/minor) mixed first in the kernel and from `mountinfo` in userspace; test proves different devices differ; docs corrected |
| 4 | high | Failed removal dropped the desired entry while kernel slots stayed | Fixed: resolve before mutating; failure keeps the rule listed; live delete/rename test |
| 5 | high | Inbound `RemotePorts` was silently interpreted as the local bind port | Fixed: refused with `rule.scope.unsupported_platform`; inbound block now covers every new bind; live test |
| 6 | high | A pre-existing user-owned `/opt/axiom` was not re-owned before copying a root-executed payload | Fixed: system install creates the prefix root-owned and verifies it; re-tested with a 0777 uid-1000 prefix |
| 7 | medium | Verify could attribute an old block to a rejected replacement with the same id | Fixed: verification compiles the supplied spec in place of the stored one; live test |
| 8 | medium | Credential deletion faked success without a backend or on a failed clear | Fixed: unavailable/failed deletes throw; UI returns 409/400; tests |
| 9 | medium | `.deb` instructions started the service with `AXIOM_ALLOWED_UID=0` so the desktop user could not connect | Fixed: post-install message writes the allowed-uid drop-in before enabling; docs |
| 10 | medium | Loopback HTTP AI endpoint saved as the default provider and then failed validation | Fixed: loopback HTTP is accepted regardless of the provider label; contract test |
| 11 | medium | Settings/autostart saves shared one `.tmp` path | Fixed: unique temporary file per save plus cleanup; concurrency test |
| 12 | medium | First-seen cache keyed without the socket inode and pruned behind a size threshold | Fixed: inode in the key, unconditional expiry of absent sockets; test |
| 13 | medium | Linux-generated lock graphs broke the documented Windows `--locked-mode` restore | Fixed: the two OS-conditional projects no longer use a lock file (central pins still apply); Windows locked restore re-verified; docs note |

A second review pass over the fix delta found three remaining defects, all fixed:

- restore aborted every executable when one persisted rule was no longer expressible: restore now
  runs per executable and records rejected groups, with a live legacy-rule + valid-block test;
- removal could still drop the desired entry when compilation threw after the entry was removed:
  every failing exit now restores it, with a live sibling-spec test;
- the inode regression test changed ownership rather than the table inode, and pruning had no
  test: both were corrected, and the first-seen retention is injectable for the expiry test.

The second review also corrected documentation drift (device identity, seven components, inbound
remote-port refusal, unlocked OS-conditional projects). It confirmed the socket peer check, write
gate, unsupported-scope refusals, kernel/userspace hash order, no plaintext credential fallback, no
public DNS fallback, token/Host handling, and unchanged private-cgroup test isolation.

Final verification after these fixes: **305/305** tests twice, Windows compile and locked restore
0 errors.

## Deployment pass (persistent install on this host)

Authorized by the user after the audit pass: keep a real Linux deployment running on this server,
isolated from other workloads and from the existing user settings. This pass did not re-plan and
did not change the product scope above.

### Synchronization

| Step | Value |
|---|---|
| Upstream | `a-51-50/Axiom` `main` advanced `3d58baa` -> `7431612` (README only); fetched and merged, conflict in `README.md` resolved keeping upstream text |
| Branch | `feature/linux-compatibility`, merge commit on top of `a869be2` |
| Preserved work | `wip/linux-interrupted-20261106` (`75dfd6a`) untouched; no reset, no stash drop |
| Fork/PR | `brxtrac/Axiom`, PR #174 (draft) reused, not duplicated |

### Verification on the merged tree

- `dotnet restore Axiom.Linux.slnf --locked-mode` 0 errors; `dotnet build -c Release` 0 warnings,
  0 errors; `dotnet test Axiom.Linux.slnf -c Release` **312 passed, 0 failed, 0 skipped**
  (Contracts 72, Core 66, Persistence 23, Service 18, Dns 11, MCP 35, Infrastructure.Linux 87,
  including the 12 live eBPF tests against a disposable child cgroup). Windows compile
  (`EnableWindowsTargeting=true`) 0 errors. Upstream `696e4d4` merged; its file-lock privacy test
  cannot fail on Unix (rename over a locked file succeeds), so the Linux-safe `FailingSettingsStore`
  variant was restored while keeping upstream's other change.
- `scripts/publish-linux.sh` self-contained x64 payload; `.deb` built, `dpkg-deb --info/--contents`,
  extraction, `desktop-file-validate`, isolated payload start/self-check/MCP and clean stop.

### Review remediation (this pass)

The independent reviewer rejected the first deployment delta and then the fix delta; findings and
dispositions:

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | A pre-existing `install-manifest.sha256` symlink in an adopted `/opt/axiom` would be followed by the root redirect | Fixed: the installer unlinks the manifest before writing it |
| 2 | high | Failed removal persisted `Failed`, so the still-enforced kernel rule was dropped by the next restart | Fixed: failed removal keeps the stored state (normally `Applied`), records `last_error` and the failed audit row |
| 3 | high | Failed update of an `Applied` rule persisted the failed replacement, losing the previous policy on restart | Fixed: the coordinator reads the previous record inside its gate and persists the previous `Applied` spec for returned failures and exceptions; the failed attempt is still audited |
| 4 | medium | Failed-update audit row showed the retained policy instead of the attempted replacement | Fixed: `SaveFirewallRuleAsync` takes an optional audited spec; both failure paths pass the attempted spec, covered by two tests |
| 5 | medium | Rollback ignored native map results and never verified the snapshot | Fixed: every rollback operation is checked (ENOENT treated as empty), the maps are re-read and compared, and a failed rollback is reported in the returned error |
| 6 | medium | Kestrel configuration could add a non-loopback endpoint | Fixed: startup refuses a non-loopback configured `Kestrel:Endpoints` URL and refuses to serve if any bound address is not loopback; manually exercised by disposable execution |
| 7 | medium | Headless unit example stored settings on a read-only mount | Fixed: `StateDirectory=axiom-ui` plus XDG variables in the documented unit; applied to the running unit |
| 8 | medium | Capability claims exceeded the Linux implementation (DKG probe, notify-send, reputation key field) | Docs and matrix corrected to the implemented surface |
| 9 | medium | Token passed to `xdg-open` is visible in process arguments | Not fixed; documented as a limitation. The deployed unit uses `--no-browser` |
| 10 | medium | No injected-fault tests for rollback and no automated HTTP boundary tests | Explicitly outstanding; the Kestrel rejection was verified manually. Carried only because enforcement stays disabled and the PR stays draft |

Review outcome: the last round approved this delta for the draft, monitoring-only branch (its only
nit, the exception-path audit assertion, was added); enforcement/release approval is still withheld.

### Installed deployment

- System scope: `/opt/axiom` (root-owned payload + `install-manifest.sha256`), unit
  `/etc/systemd/system/axiom.service`, data `/var/lib/axiom` (0700 root; the pre-existing
  `privacy-shield-blocked.jsonl` was kept, hash unchanged across restart/reinstall), socket
  `/run/axiom/service.sock` (0600, owned by the allowed uid, directory 0711).
- Dedicated unprivileged account `axiom-ui` (uid 997) is the only uid `AXIOM_ALLOWED_UID` accepts.
  A site-local `axiom-ui.service` runs the loopback UI as that account on `127.0.0.1:5600`
  (`--no-browser`), enabled at boot; the unit content is documented in `docs/LINUX.md`.
- Enforcement and DNS stay off: `/api/firewall` reports `available` with `writesEnabled: false`,
  `/api/privacy` reports `Disabled` with no listener; no iptables/nft rules name Axiom and
  `/etc/resolv.conf` was not touched.

### Runtime checks

- HTTP: `/api/status` 401 without token, 200 with token and `Cache-Control: no-store`; CSP,
  `X-Frame-Options: DENY`, `nosniff`, `no-referrer`; `Host: attacker.example` -> 400; no CORS
  allow headers; `/` and `/app.js`/`/style.css` render; `/api/history.csv` UTF-8 BOM, RFC 4180,
  `Content-Disposition`.
- IPC authorization: uid 0 connects and is rejected from `SO_PEERCRED` (logged), uid 1000 gets
  `EACCES` at the socket, uid 997 connects and is served. MCP over the deployed socket
  (`initialize`, `tools/list` = 9 tools, `axiom_get_status`) as uid 997.
- Capture: a spawned client's TCP listen/established rows and its bound UDP socket appeared with
  the right PID and executable path, disappeared from the snapshot after exit, and the flow
  remained in history (`/api/history?search=<port>` returned it).
- Lifecycle: restart and stop/start keep the unit and data; with the service stopped the UI returns
  `503 service_unavailable` instead of crashing; reinstall over the running install preserved data
  and the allowed-uid unit setting.
- Soak (300 s, isolated data/socket, published payload): 16 120 HTTP requests, 0 HTTP errors,
  service RSS 67 232 -> 264 376 KiB, UI RSS 67 376 -> 371 160 KiB, service CPU 318 s, 20/24
  threads, 2 822 sockets and 13 965 history rows at the end, socket cleanup and data preservation
  `ok`. RSS rises during warm-up and had levelled off by the end of the window; this is a 5 minute
  bound, not a 24 hour one.
- Not exercised, stated instead of claimed: real reboot (units are enabled and restart-tested
  only), 24 h soak, Windows runtime, agent hooks/Blackbox install (still blocked on the Windows-only
  Blackbox payload), tray icon, AI provider/keyring live round-trip, WSL/container/SELinux/AppArmor
  confined runtime, macOS.
