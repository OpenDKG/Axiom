# Windows differential: S1b (shared portable platform seams)

## Split8 recut (current): `split8/s1b-service-seams`, stacked on S1a `a1ad18b` (main `da1987a`, v1.1.0)

**Status: Windows round W1 (2026-11-18) run on `5095719`, results below.** This branch is a new focused cut of S1b from the S1a head
`a1ad18b` (which already contains `main` `da1987a`, v1.1.0). S1a (#325) is not merged yet, so S1b is
stacked on it and will be recut onto `main` once S1a merges. The old branch
`feature/macos-s1b-service-seams` (`0330e4a`) is the source; the rounds below were run on that old
branch and are **historical evidence on older SHAs**, not results for this branch.

Differences from the old branch that matter when reading the historical rounds:

- Left out of this cut (later slices): `FilterEnforcementReport` / `FirewallCapabilityReport.FilterEnforcement`
  (`b0a5767`), the Unix IPC endpoint, `EffectiveRuleReport.EnforcementVerified/FilterRejectionReason`,
  `LiveConnection.RemoteHost` and `ProtectionSettings.AllowedUid/AllowAdminGroupWrites` (`e1d0524`),
  `ToolProcess` (`6917053`) and Pending-not-Applied in `FirewallRuleCoordinator` (`ec8b18d`).
  The historical service differential's 6 expected differences (`remoteHost`, `filterEnforcement`,
  `filterRejectionReason`, `enforcementVerified`) therefore **must not appear** on this branch; only the
  new `Axiom.Service.Hosting` files in the publish output may differ.
- Added: off-Windows rejection of Windows-style executable paths (`rule.path.windows_style`; Windows
  unchanged) and tests for adapter DNS error propagation, failed-start and service-start DNS recovery
  through `IPrivacyDnsPlatform`, and owner-only file modes on Unix.

What the Windows round for this branch must record (see the PR text for the full list):
lock files and locked restore per project vs `da1987a`/`a1ad18b`; Release build; every suite by
failing name vs `a1ad18b`; service start/restart and IPC connect (named pipe, allowed SID log line
`Pipe ... allows SID ...`); Privacy Shield on/off, DoH default upstream, unreachable DoH gives SERVFAIL
with no plaintext fallback, adapter DNS pointed and restored, adapter DNS error shown in the status,
restart with the shield on, disable restores adapter DNS; offline network recovery command.

Host (Linux) results for this branch are in the PR text (`pr-body`), not here.


## Round W1 (2026-11-18): S1b `5095719` vs S1a `a1ad18b` vs `main` `da1987a` on Windows 11

Author-run on the project's Windows 11 test VM (not CI). Tested SHAs: S1b `50957193ea7a`, S1a
`a1ad18b673f4`, `main` `da1987a18962`, each as a fresh `git archive` expanded into an empty directory.

| Item | Value |
|---|---|
| Guest | Windows 11, build 10.0.26300.9457, QEMU/KVM, 4 vCPU, 3 GB, restored from the clean snapshot before the round |
| SDK | .NET SDK 10.0.403 (zip, sha512 checked against the official value) |
| Package cache | a fresh, empty `NUGET_PACKAGES` per tree; no warm cache |
| Logon | build/test/service steps in an elevated Interactive scheduled task as the install owner; NETWORK probe over SSH |
| Deviation | Defender real-time scanning made the fresh guest CPU-bound, so Defender path/process exclusions were added in the guest for `C:\src`, `C:\nugetclean`, `C:\dotnet*`, `C:\logs`, `C:\axiom-pub-*` and `dotnet`/`MSBuild`/`testhost` (the same for all three trees; undone by the snapshot restore) |

### W1.1 Lock files

`dotnet restore Axiom.sln --force-evaluate` on Windows, compared with the committed lock files as JSON per TFM
and package (not by bytes):

| Tree | Entries that differ | Kind |
|---|---|---|
| S1b `5095719` (22 lock files) | 15 | all in-repo project version-range refresh (`[0.x.0, )` -> `[1.1.0, )`) |
| `main` `da1987a` (21 lock files) | 38 | the same range refresh |

No package entry is added, removed or changed on S1b, so **no lock-file commit**. (S1b's only build-file change
against S1a is a comment in `Axiom.Service.Hosting.csproj`.)

### W1.2 Locked restore, build, CI gates

Each tree with an empty package folder, the steps of `windows-ci.yml`:

| Step | S1b | S1a | main |
|---|---|---|---|
| `restore Axiom.Portable.slnx --locked-mode` | exit 0 | exit 0 | exit 0 |
| `restore Axiom.sln --locked-mode` | exit 0 | exit 0 | exit 0 |
| per project `--locked-mode` (projects with a lock file) | 22/22 pass | 22/22 pass | 21/21 pass |
| `build Axiom.sln -c Release --no-restore` | 0 W / 0 E | 0 W / 0 E | 0 W / 0 E |
| `list package --vulnerable --include-transitive` | none | none | none |
| legal files / community feed | present / 1 entry | present / 1 entry | present / 1 entry |
| `scripts/publish-setup.ps1` | exit 0, 95,991,167 B | exit 0, 95,973,141 B | exit 0, 95,948,457 B |
| `Axiom.Setup.exe --silent` (non-admin CLI check) | exit 2 | exit 2 | exit 2 |

### W1.3 Suites (`dotnet test Axiom.sln -c Release --no-build -m:1`, trx counters, passed/executed)

| Suite | S1b `5095719` | S1a `a1ad18b` | main `da1987a` |
|---|---|---|---|
| Axiom.Contracts.Tests | 180/180, skip 0 | 170/170, skip 0 | 170/170, skip 0 |
| Axiom.Core.Tests | 191/191, skip 0 | 184/184, skip 0 | 184/184, skip 0 |
| Axiom.Infrastructure.Windows.Tests | 169/170, skip 0 | 153/153, skip 0 | 86/86, skip 0 |
| Axiom.McpServer.Tests | 34/34, skip 0 | 34/34, skip 0 | 34/34, skip 0 |
| Axiom.Persistence.Tests | 22/22, skip 0 | 21/21, skip 0 | 21/21, skip 0 |
| Axiom.Presentation.Tests | 316/316, skip 0 | 315/315, skip 0 | 315/315, skip 0 |
| Axiom.Service.Tests | 128/128, skip 0 | 101/101, skip 0 | 101/101, skip 0 |
| Axiom.UI.Avalonia.Tests | 66/66, skip 0 | 66/66, skip 0 | 66/66, skip 0 |
| Axiom.UI.Tests | 197/201, skip 0 | 197/201, skip 0 | 197/201, skip 0 |
| **total** | **1303/1308, skip 0** | **1241/1245, skip 0** | **1174/1178, skip 0** |

Failing names:

- All three trees: the 4 `Axiom.UI.Tests.AgentHookScriptTests` that need a Python interpreter (the guest has
  only the Store alias: `Apply_patch_path_extraction_and_host_deny_shapes_match_each_host`,
  `Guard_helpers_block_vectors_in_a_real_python_run`, `Lifecycle_bridge_is_valid_python_when_python_is_available`,
  `OpenCode_bridge_compiles_when_python_is_available`).
- S1b gate run only: `WindowsFirewallPolicyAdapterTests.Owned_rules_all_follow_the_naming_contract`
  (`InvalidComObjectException`, RCW separated): the known COM flake. Flake runs on the same builds, alternating
  S1b/S1a: full `Axiom.Infrastructure.Windows.Tests` assembly S1b 1/3 failed (`Capabilities_are_available`),
  S1a 1/3 failed (`Owned_rules_all_follow_the_naming_contract`); the class alone 0/5 on each, plus 0/3 on each
  in the gate. With the gate run counted, assembly runs fail 2/4 on S1b and 1/4 on S1a; the flake hits S1a too and
  moves between tests of the class, so it is not attributed to S1b (sample too small to compare rates).
- **No test that passes on S1a fails on S1b apart from that flake; no S1a test is missing on S1b; 0 skipped on every
  tree.** S1b adds 63 results (Contracts +10, Core +7, Infrastructure.Windows +17, Persistence +1, Presentation +1,
  Service +27), all passed.

### W1.4 Runtime differential, S1b vs S1a

Same VM state for both builds: publish `Axiom.Service` single-file from the gate tree, install with
`--install-service --allowed-sid <owner>`, run the same scripts, then uninstall and delete
`C:\ProgramData\Axiom`, the SYSTEM profile's `Axiom` folder and `C:\Program Files\Axiom` (asserted absent before
the next install). Installed exe = published exe (SHA-256 S1b `0B8B3AFD…`, S1a `763D4337…`). The check lines are
compared after normalising ids, timestamps and uptime.

**164 checks per build: 151 identical after normalisation; the 13 others differ only in live values**
(connection and socket counts in `serviceHealth`/`snapshot`/`pending`, capture times in the recovery text, one
Windows telemetry lookup (`svchost` -> `v20.events.data.microsoft.com`, blocked by a starter rule) that reached
the resolver right after the restart on S1b only, and 5 s vs 2 s until the start-time DNS restore was seen).
**JSON key paths of all 62 IPC replies are identical** except where an array was empty on one build (the
telemetry entry above, same record shape as S1a's `blockedHistory` entries): **no new reply field.**

(a) Service and IPC

| Check | S1b = S1a |
|---|---|
| install, alive, health at 60 s / 180 s, restart (`Restart-Service`) alive, `--uninstall-service` exit 0, service absent, 0 Axiom firewall rules left | yes |
| event 2001 (service environment `Logging__EventLog__LogLevel__Default=Information` set for this check only; at the default level no Information event reaches the Application log on either build) | yes: provider `Axiom.Service`, id 2001, `Pipe Axiom.Service.v1 allows SID <install owner SID>` |
| owner: `protection.enable` (write gate open), `rule.apply` block `curl.exe` -> 1 rule `Outbound/Block`, curl rc 7; `rule.verify` `presentInOs`/`matchesSpec`/`effectiveAction:block`; `rule.remove` -> 0 rules, curl 200; `protection.disable`; bad enum -> `invalid_request` | yes |
| `enforcement.status`/`evaluate`/`receipts` with the gate closed and open; `enforcement-policy.json` written by the first status call | yes |
| NETWORK logon (SSH): 10 commands (public, private reads, writes) | `CONNECT_FAIL Access to the path is denied` for all 10 |
| second local user: temporary standard account (random password generated in the guest, not in Administrators), `Start-Process -Credential` | `CONNECT_FAIL Access to the path is denied` for all 10; account, profile and staged secret removed and checked |

(b) Privacy Shield

| Check | S1b = S1a |
|---|---|
| enable (`1.1.1.1, 9.9.9.9`, DoH on, auto-point on): `Active`, bind `127.0.0.1, ::1` :53, upstream `https://1.1.1.1/dns-query (DoH), https://9.9.9.9/dns-query (DoH)`; adapter `127.0.0.1,10.0.2.3`; DNS backup written; listeners on loopback only | yes |
| allowed names resolve; custom blocked name and subdomain NXDOMAIN; counters `queries=5 allowed=3 blocked=2 errors=0` | yes |
| attribution: blocked name queried by `nslookup.exe` -> `recentBlocked` `appName nslookup.exe`, `appPath C:\Windows\System32\nslookup.exe`; queried by `curl.exe` through the system resolver -> `svchost.exe` (DNS Client service) | yes |
| automatic upstream (`upstreamDns:""`) -> DoH 1.1.1.1 + 9.9.9.9, resolves | yes |
| unreachable DoH (`https://192.0.2.1/dns-query`): stays `Active`, upstream unchanged, lookups `DNS server failure` (SERVFAIL), error counter rises, no plaintext answer; blocked name still NXDOMAIN | yes |
| `1.1.1.1` with DoH off -> still `https://1.1.1.1/dns-query (DoH)` | yes |
| adapter DNS error: IPv4 default route removed, enable -> `lastError` `No active default-route network adapter was found for automatic 127.0.0.1 DNS setup.` in the configure reply and in `privacy.status`, state `Active` | yes |
| route restored: the worker re-points the adapter (`127.0.0.1,10.0.2.3`) and resolution works, but `lastError` still holds the adapter message after 75 s | yes (same on S1a, so not from S1b) |
| service restart with the shield on: `Active`, same settings and DoH upstream, adapter still pointed, allowed resolves, blocked NXDOMAIN | yes |
| `privacy.sources.update` (`windowsspyblocker`, `blocklistproject-ads`): 236,174 rules, no source error, listed names NXDOMAIN | yes |
| disable: adapter back to `10.0.2.3`, equal to the value before enabling; system resolution works | yes |
| service start with the shield off, adapter left on `127.0.0.1,10.0.2.3` with a machine backup: adapter restored to `10.0.2.3` (= baseline) within the first poll after start; state `Disabled` | yes |
| guest adapter DNS at the end of every phase equals the baseline; no safety reset was needed | yes |

(c) Offline recovery (`Axiom.Service.exe --recover-network`, elevated)

| Check | S1b = S1a |
|---|---|
| no snapshot: exit 2, "No saved network state is available" | yes |
| `networkRecovery.capture` over IPC: `succeeded`, 1 adapter, `network-recovery.txt` written | yes |
| dry run: exit 1, plan printed (`Adapter Ethernet: IPv4 static 10.0.2.3, IPv6 automatic (DHCP)`), "Dry run: no change was made" | yes |
| `--apply` with the service running: exit 6, refused | yes |
| `--apply` with the service stopped: exit 5, `Result: Failed; verified: no`, `dns_verify_missing: Adapter 'Ethernet' is no longer present after the DNS restore`; adapter DNS afterwards `10.0.2.3`, service starts again | yes (same failure on S1a, so not from S1b; cause not investigated in this round) |

### W1.5 The places where Windows could differ (PR text, plus the two "known differences" of its compatibility table)

| # | Point | Result |
|---|---|---|
| 1 | `DnsProxyServer.ResolveApp` through `IDnsAppAttributor` | checked identical (nslookup.exe name + path, svchost.exe for system-resolver queries). The exception-to-`Unknown` path was not exercised |
| 2 | `UpstreamFailureStreak` / `UpdateTargets` | checked identical as far as observable: an unreachable DoH upstream keeps the configured upstream, SERVFAIL, no swap and no plaintext fallback; the streak itself is not visible over IPC |
| 3 | start warning combined with `OnResolverStarted` | checked identical for the null-warning case (all status/configure replies and `detail` texts equal); the NoUpstream warning case was not exercised |
| 4 | endpoint log line from parts, event 2001 | checked identical: `Pipe Axiom.Service.v1 allows SID <sid>`, provider `Axiom.Service`, id 2001 (template name not visible in the event) |
| 5 | `RuleSpecValidator` UNC/absolute order | runtime not exercised with a UNC path; the valid path and the bad-enum payload behave identically, and `RuleSpecValidatorTests` pass on Windows |
| 6 | DI registration order; `ProtectionController` reads `FirewallWriteGate.IsOpen` | checked identical (`protection.*`, `writeGateOpen`, rule apply/verify/remove, event ids at start) |
| 7 | `EnforcementController` optional in the transport | checked identical (`enforcement.status`/`evaluate`/`receipts`, gate closed and open; no `not_supported`) |

### W1.6 Not run, limits

- The 4 Python-dependent tests cannot pass on this guest (no interpreter); CI has Python.
- The stored second test account `tester` does not exist in the clean snapshot, so the second-user probe used a
  temporary standard account (same probe script).
- Desktop UI, installer upgrade path and MSIX were not run. Event 2001 needed a test-only log level (see (a)).
- Not CI: a self-hosted CI run on this head does not exist yet.

---

# Historical rounds (old branch, older SHAs)

# Windows differential test: `main` `1cd0b79` vs S1b `d5cd91c` (service seams, Privacy Shield DNS behind `IPrivacyDnsPlatform`)

**Author-run on the project's Windows 11 test VM. This is not CI.** Run on 2026-11-15 (round 3).

S1b sits on S1a. It adds the service seams (`IIpcTransport`, `ServicePlatform`), shared contract
additions, `AxiomPaths`, and Pending-not-Applied in `FirewallRuleCoordinator`. It also moves the Privacy
Shield DNS proxy (with upstream's DoH from v0.21.0 / v0.24.0) into `Axiom.Service.Hosting`, behind
`IPrivacyDnsPlatform`. The Windows adapter handling (`PreferredAdapterAlias` / `AutoPointAdapterDns`,
v0.23.3) moved unchanged into `WindowsPrivacyDnsPlatform`. This run checks that a Windows user sees the
same behaviour as on `main`, including Privacy Shield.

| | Commit |
|---|---|
| main | `1cd0b79a82bf9469cea804a91ac029b8b369e631` |
| S1a (base of S1b) | `7ee1527` (lock files regenerated on Windows; see `docs/WINDOWS_DIFFERENTIAL_S1A.md`, round 3) |
| S1b tested | **`d5cd91c`** = S1b's 12 commits on S1a + merge of S1a `7ee1527`. Later commits on the branch change docs only. |

Environment, scripts and method are those of `docs/WINDOWS_DIFFERENTIAL_S1A.md`: SDK 10.0.403, a
`git archive` per tree in an empty directory, an empty `NUGET_PACKAGES` per tree, and tests and probes
run from Interactive scheduled tasks. The probes talk only to `\\.\pipe\Axiom.Service.v1`, the local
firewall, `curl.exe`, and DNS queries against `127.0.0.1` and the VM's own resolver `10.0.2.3`.

## 1. Lock files

S1b changes no package or project reference. It only adds a comment to `Axiom.Service.Hosting.csproj`.
A `--force-evaluate` regeneration on the VM gives the same content as the committed files for every lock
file that involves `Axiom.Service.Hosting`. The remaining differences are upstream's project-range drift,
which S1a does not take either. So S1b needs no lock-file commit of its own.

Locked restore, per project, on a fresh copy of `d5cd91c`: **the same result as S1a `7ee1527`.** The
win-x64 projects Contracts, Core, Desktop, Infrastructure.Windows, Persistence, Presentation, Service,
Service.Hosting, Setup and UI pass. Desktop.Avalonia.Windows and the 12 plain-shape projects fail, as
on `main`. **No project that passes on `main` fails on S1b.**

## 2. Clean restore, build and suites

| Step | main `1cd0b79` | S1b `d5cd91c` |
|---|---|---|
| clean `dotnet restore Axiom.sln --no-http-cache` | exit 0, 88 packages | exit 0, 88 packages |
| `dotnet build Axiom.sln -c Release --no-restore` | 0 warnings, 0 errors | 0 warnings, 0 errors |
| Axiom.Contracts.Tests | 148 / 148 | 157 / 157 |
| Axiom.Core.Tests | 151 / 151 | 151 / 151 |
| Axiom.Infrastructure.Windows.Tests | 75 / 75 | 141 / 142 (COM flake) |
| Axiom.McpServer.Tests | 33 / 33 | 33 / 33 |
| Axiom.Persistence.Tests | 21 / 21 | 21 / 21 |
| Axiom.Presentation.Tests | 196 / 196 | 196 / 196 |
| Axiom.Service.Tests | 91 / 91 | 110 / 110 |
| Axiom.UI.Avalonia.Tests | 37 / 37 | 37 / 37 |
| Axiom.UI.Tests | 171 / 174 | 171 / 174 |

- **No test that passes on `main` is missing or failing on S1b**, apart from the COM flake below.
- 95 new results, all passed. Among them: `WindowsPrivacyDnsPlatformTests` (16), `UpstreamRediscoveryTests`
  (14, including the no-plaintext-downgrade case), `AxiomPathsTests` (9), the IPC access tests from S1a,
  and the 3 `IpcCallerEntryPointTests`.
- **`FirewallRuleCoordinatorTests.Apply_pending_is_stored_as_pending_not_applied` passes on Windows.**
  It cannot pass on a Linux host.
- Axiom.UI.Tests: the same 3 `AgentHookScriptTests` fail on both trees (no Python on the VM).
- Axiom.Infrastructure.Windows.Tests: `WindowsFirewallPolicyAdapterTests.Capabilities_are_available`
  failed in the full-suite run with `InvalidComObjectException`. Over 9 runs of the suite per tree
  (1 full-suite run + 8 more), it failed in 2 of 9 on `main`, 3 of 9 on S1a and **5 of 9 on S1b**. Every
  failure is in `WindowsFirewallPolicyAdapterTests` (`Capabilities_are_available`,
  `Owned_rules_all_follow_the_naming_contract`, `Unknown_rule_is_reported_as_absent`), with the same
  exception. Neither the adapter nor that test class is changed by S1a or S1b (`git diff 1cd0b79 d5cd91c`
  on both is empty). S1b runs more test classes in that assembly, and xUnit runs them in parallel. The
  higher rate is recorded here, not explained. The sample is small.

## 3. Service differential (same script as for S1a)

The installed `Axiom.Service.exe` has the same SHA-256 as the published one: `main` `1696CC17…`, S1b
`E7647C8B…`.

**175 checks per build: 167 identical after normalisation, 2 with the same shape and different live
values (the `pending` ask list), 6 different.** Every difference:

| Check | Difference | Explanation |
|---|---|---|
| `publish_files` | S1b adds `Axiom.Service.Hosting.pdb` | new assembly (S1a) |
| `snapshot` | each connection has an extra `"remoteHost":""` | S1b contract addition, empty on Windows |
| `rules.query` (twice) | `capability` has an extra `"filterEnforcement":null` | S1b contract addition, null on Windows |
| `rule.verify` (twice: open gate, and after the restart) | extra `"filterRejectionReason":null`, `"enforcementVerified":null` | S1b contract additions, null on Windows |

These are additive fields with empty or null values. No existing key or value changed. Block and unblock,
restart persistence, `enforcement.*`, error paths, oversized and invalid payloads, the unknown command,
the connection matrix and the access probes are identical to `main`. The Privacy Shield phase of this run
was identical too.

## 4. Privacy Shield and DoH, `main` vs S1b

What upstream intends: v0.21.0 adds RFC 8484 DoH with strict no-plaintext-downgrade, and well-known
public resolvers are upgraded to DoH. v0.23.3 adds `PreferredAdapterAlias` / `AutoPointAdapterDns`, which
keep `127.0.0.1` + the previous servers on the adapter, persisted across restarts. v0.24.0 adds
`EncryptDnsViaDoh` (default on) and makes the automatic upstream DoH 1.1.1.1 + 9.9.9.9, never plain DNS
to the LAN resolver.

A dedicated pass with a fresh install per build (same script, same order, reset between builds). The VM
has outbound network: DoH to 1.1.1.1 / 9.9.9.9 on port 443 and the list downloads worked.
**61 / 61 checks identical after normalisation, `main` vs S1b** (and `main` vs S1a). Results, the same
on both builds:

| Step | Result (main = S1b) |
|---|---|
| status before enabling | `state:"Disabled"`, `bindAddress:"not listening"`, upstream `encrypted DoH (1.1.1.1, 9.9.9.9)`, 24 built-in rules; adapter DNS `Ethernet 10.0.2.3`; no DNS backup file |
| `privacy.configure` enable (`upstreamDns:"1.1.1.1, 9.9.9.9"`, `encryptDnsViaDoh:true`, `autoPointAdapterDns:true`, `preferredAdapterAlias:""`, one custom blocked domain) | `state:"Active"`, `running:true`, bind `127.0.0.1, ::1` port 53, upstream `https://1.1.1.1/dns-query (DoH), https://9.9.9.9/dns-query (DoH)`, 25 rules |
| adapter DNS while enabled | `Ethernet 127.0.0.1,10.0.2.3` (the active default-route adapter, previous server kept as fallback); `C:\ProgramData\Axiom\privacy-shield-dns-backup.json` written; UDP+TCP 53 listening on `127.0.0.1` and `::1` only |
| allowed names via `127.0.0.1` (`example.com`, `www.wikipedia.org`) | resolve (public A records) |
| blocked custom name and a subdomain of it | `DNS name does not exist` (NXDOMAIN) on both; recorded in `recentBlocked` with category `custom` |
| counters after these queries | `queries=5 allowed=3 blocked=2 errors=0` |
| automatic upstream (`upstreamDns:""`, DoH on) | upstream reported as `https://1.1.1.1/dns-query (DoH), https://9.9.9.9/dns-query (DoH)`: encrypted by default, not the LAN resolver |
| unreachable DoH upstream (`https://192.0.2.1/dns-query`, DoH on) | still `Active`; queries get `DNS server failure` (SERVFAIL) after about 3 s; the error counter rises; **no answer through any plaintext fallback**; blocked names are still NXDOMAIN |
| `1.1.1.1` with `encryptDnsViaDoh:false` | still upgraded: `https://1.1.1.1/dns-query (DoH)` (v0.21.0 upgrade of known public resolvers) |
| service restart with the shield on | `Active`, enabled, same settings and upstream; adapter DNS still `127.0.0.1,10.0.2.3`; allowed resolves, blocked NXDOMAIN |
| `privacy.sources.update` with `windowsspyblocker` + `blocklistproject-ads` enabled | `ok:true`, 236,174 rules; `windowsspyblocker` 347 entries, `blocklistproject-ads` 235,821, others 0 (not enabled), no source error. These counts are network-dependent; both builds fetched the same lists minutes apart and got the same numbers |
| after the update | `doubleclick.net`, `vortex.data.microsoft.com`, `ads.yahoo.com`, `watson.telemetry.microsoft.com` NXDOMAIN; `example.com` resolves |
| `privacy.history.clear` | `ok:true` |
| disable | `state:"Disabled"`, `running:false`; adapter DNS back to `Ethernet 10.0.2.3`, **equal to the value before enabling**; system resolution works |

Raw request and reply lines are in the run logs (`pv-<sha>.log`, `diff-<sha>.log`), one `CHECK` line
per probe.

Not covered: a named `PreferredAdapterAlias` (the VM has a single adapter, so the alias path and the
auto path pick the same adapter); IPv6 adapter DNS (the VM has no IPv6 DNS servers); DoT/DoQ; the
desktop UI.

## 5. Cleanup and credential handling

The service was uninstalled through the product after each build, and the data roots were removed and
checked absent. 0 Axiom firewall rules remain, and the adapter DNS is back to `10.0.2.3`. The `tester`
credential file was copied to the guest only for the access probes, removed right after each use, and
checked absent each time.


# Round 4 (2026-11-15): `main` `d0991bd` vs S1b `f67b6c2`

**Author-run on the project's Windows 11 test VM. This is not CI; no GitHub-hosted run exists for this
revision.** Same VM, SDK 10.0.403 (pinned by `global.json`), scripts and method as above. Every tree is a
fresh `git archive` with its own empty package folder. S1a's document, round 4, has the IPC and
lock-file detail.

| | Commit |
|---|---|
| main (pinned for this round) | `d0991bdcef4913bd626700e007bf814b2854b249` |
| S1a | `d207ba7` (main `d0991bd` merged + lock files regenerated on Windows) |
| **S1b tested** | **`f67b6c2483b09984d491680b47c46009844ab92`** = `382fc30` + `Merge S1a (main d0991bd + lock files) into S1b`. The commits after it change docs only. |

## R4.1 Reconciliation with `main` `d0991bd`

Git merged every file automatically. **No file was resolved by hand.** What `main` changed in the area
S1b moves behind seams, and where it lands:

| `main` change since `1cd0b79` | File | In S1b |
|---|---|---|
| fallback candidates from saved / current / gateway+DHCP servers; virtual adapters ordered last; netsh wait 45 s (`f5420ab`) | `PrivacyDnsFailSafe.cs` | unchanged file. S1b calls it through the delegates of `WindowsPrivacyDnsPlatform` (`ServicePlatform.Windows.cs`), so the Windows adapter code is `main`'s |
| `ShouldAutoPointAdapterDns`; the worker re-points adapter DNS every 30 s and restarts a stopped resolver; source-sync signal | `PrivacyShieldController.cs`, `PrivacyShieldWorker.cs` | merged as written. The worker calls `controller.EnsureConfiguredAdapterDns()`, which S1b forwards to `WindowsPrivacyDnsPlatform.EnsureConfiguredAdapterDns`. `main`'s body of that method is unchanged since `1cd0b79`, so the moved copy is still current |
| Phishing category; policy and source classification | `Axiom.Contracts/Privacy/*`, controller | merged as written |
| process-spawn audit worker | `Program.cs` (+1 line) | merged as written |

The DNS proxy, `DnsUpstream` (DoH upstream selection, no plaintext downgrade) and `SystemDnsResolver` are
not changed by `main` since `1cd0b79`. So S1b's moved copies needed no update. Lock files: S1b changes no
dependency over S1a. A `--force-evaluate` regeneration of `f67b6c2` on the VM gave files that are
JSON-identical to the committed ones for all 7 `Axiom.Service.Hosting` graph files (14 identical in all). The
other 8 differ only by NuGet's project-range refresh, so S1b has no lock-file commit.

## R4.2 Restore, build and suites

| Step | main `d0991bd` | S1b `f67b6c2` |
|---|---|---|
| `--locked-mode`: `Axiom.Portable.slnx` / `Axiom.sln` / per project | exit 0 / exit 0 / 22 of 22 | exit 0 / exit 0 / 23 of 23 |
| clean restore `--no-http-cache` | exit 0, 88 packages | same |
| `dotnet build Axiom.sln -c Release --no-restore` | 0 warnings, 0 errors | 0 warnings, 0 errors |
| Contracts / Core / Infrastructure.Windows | 152 / 184 / 86 | 161 / 184 / 153 |
| McpServer / Persistence / Presentation | 34 / 21 / 275 | 34 / 21 / 275 |
| Service / UI.Avalonia / UI.Tests | 98 / 56 / 179 of 183 | 117 / 56 / 179 of 183 |

Every count above is passed = total, except UI.Tests. **No test that passes on `main` is missing or
failing on S1b.** The extra tests (Contracts +9, Infrastructure.Windows +67, Service +19) all pass.
UI.Tests: the same 4 `AgentHookScriptTests` fail on both trees (no Python on the VM).
`WindowsFirewallPolicyAdapterTests` COM / RCW flake: the full-suite runs passed. In 4 more runs, it failed
once on each tree (`main` 1 / 4, S1a 1 / 4, S1b 1 / 4).

## R4.3 Service differential

The installed exe matches the published one: `main` `F4E01EAF…`, S1b `A9A3CC22…`. **168 checks per
build: 160 identical after normalisation, 2 with the same shape and live values (the remote IP of the
pending `curl.exe` ask), 6 different.** Every difference is additive, with an empty or null value:

| Check | Difference |
|---|---|
| `publish_files` | `+Axiom.Service.Hosting.pdb` |
| `snapshot` | each connection has `"remoteHost":""` |
| `rules.query` (gate closed, gate open) | `capability.filterEnforcement: null` |
| `rule.verify` (gate open; after the restart) | `enforcementVerified: null`, `filterRejectionReason: null` |

No existing key or value changed. Block, unblock and persistence across a restart, `enforcement.*` (receipt
results byte-identical), error paths and the connection matrix are identical to `main`. Access: the
NETWORK logon and a **temporary standard local account** (created in the guest, random password never on
the host, deleted with its profile afterwards) are denied at connect for all 10 probed commands, private
reads and writes included. `axiom` (S4U and Interactive) is answered. This is identical to `main`.

## R4.4 Privacy Shield and DoH, `main` vs S1b

This ran in the same pass as R4.3, with a fresh install per build. **All 54 Privacy Shield checks (raw
reply lines included) are identical after normalisation, `main` vs S1b and `main` vs S1a.** The results, the same on all
three builds:

| Step | Result |
|---|---|
| before enabling | adapter DNS `Ethernet 10.0.2.3`; no DNS backup file; system resolution works |
| enable (`upstreamDns:"1.1.1.1, 9.9.9.9"`, DoH on, `autoPointAdapterDns:true`, one custom blocked domain) | `Active`, running, bind `127.0.0.1, ::1` port 53, upstream `https://1.1.1.1/dns-query (DoH), https://9.9.9.9/dns-query (DoH)`; UDP+TCP 53 on loopback only |
| adapter DNS while enabled | `127.0.0.1,10.0.2.3` (previous server kept); DNS backup file written |
| allowed lookups (`example.com`, `www.wikipedia.org`, a default name) | resolve |
| blocked custom name and its subdomain | `DNS name does not exist`; both listed in `recentBlocked` as `custom`; counters `queries=5 allowed=3 blocked=2 errors=0` |
| automatic upstream (`upstreamDns:""`) | DoH 1.1.1.1 + 9.9.9.9, not the LAN resolver; resolves |
| **unavailable encrypted upstream** (`https://192.0.2.1/dns-query`, DoH on) | stays `Active`, upstream still the DoH URL; lookups get `DNS server failure` (twice); error counter rises; **no answer through a plaintext fallback**; blocked names still NXDOMAIN |
| `1.1.1.1` with `encryptDnsViaDoh:false` | still `https://1.1.1.1/dns-query (DoH)` (upgrade of well-known public resolvers) |
| service restart with the shield on | `Active`, same settings and DoH upstream, adapter DNS still `127.0.0.1,10.0.2.3`; allowed resolves, blocked NXDOMAIN |
| `privacy.sources.update` (`windowsspyblocker` + `blocklistproject-ads`) | `ok`, 236,174 rules, no source error; listed names NXDOMAIN, `example.com` resolves |
| **disable** | `Disabled`; adapter DNS back to `Ethernet 10.0.2.3`, **equal to the value before enabling**; system resolution works |

The `privacy.status` counters right after the restart depend on background lookups. In the discarded
first pass (see R4.5), Windows telemetry (`svchost` looking up `v20.events.data.microsoft.com`) reached the
resolver in that window on one build. In the re-run the counters were equal on all three builds.

## R4.5 Not tested in this round

- An explicit LAN or local resolver as upstream with DoH off (only the public `1.1.1.1` case ran live), a
  named `PreferredAdapterAlias` (the VM has one adapter), IPv6 adapter DNS, DoT/DoQ.
- Desktop UI, installer, and any GitHub-hosted run.
- A first differential pass was discarded: a second script reinstalled the service while it was running.
  The results above come from the sequential re-run.

## R4.6 Cleanup

After each build: product uninstall, data roots removed and checked absent. At the end: no Axiom service,
process or firewall rule; no temporary account, profile or staged secret; no `Ax*` scheduled task; adapter
DNS `10.0.2.3`. The VM was shut down.

# Round 5 (2026-11-16): `main` `25bfcc1` vs S1b `e4eb91a`

**Author-run on the project's Windows 11 test VM. This is not CI.** Same VM, SDK 10.0.403 and method as
round 4. S1a's document, round 5, has the IPC-area analysis and the lock-file detail.

| | Commit |
|---|---|
| main (pinned for this round) | `25bfcc176dbb40c63b34f225d31cffb254732587` (v0.64.0) |
| S1a | `ab7df89` (main `25bfcc1` merged, no conflicts) |
| **S1b tested** | **`e4eb91a536b07a2f8b4162481461ce81b946387a`** = `b32e7a8` + `Merge S1a (main 25bfcc1, v0.64.0) into S1b`. Later commits change docs only. |

## R5.1 Reconciliation with `main` `25bfcc1`

`main` changed four files S1b also changes: `PrivacyShieldController.cs`, `PrivacyShieldRuleStore.cs`,
`PrivacyShieldWorker.cs` and `DnsProxyTests.cs`. Two needed a hand resolution:

- `PrivacyShieldController.EnsureConfiguredAdapterDns`: since v0.64.0 upstream copies
  `PrivacyDnsFailSafe.LastError` into the status error after pointing the adapter, if no other error is set.
  S1b has this method body behind `IPrivacyDnsPlatform`. The seam member now returns the adapter error
  (default `null`, so other platforms still never change system DNS). `WindowsPrivacyDnsPlatform` returns
  `PrivacyDnsFailSafe.LastError` (a new optional delegate, wired in `ServicePlatform.Windows`) from the
  pointing branch only, and the controller applies it as upstream does. New test:
  `WindowsPrivacyDnsPlatformTests.Adapter_error_is_returned_only_after_pointing_the_adapter`.
- `PrivacyShieldController.EnsureRulesLoadedAsync`: upstream's new body and signature (load once, adopt,
  compact) are taken; S1b's upstream-watch helpers next to it are kept.
- `PrivacyShieldRuleStore.Save`: upstream's streamed serialisation is taken; S1b's
  `ServiceFiles.SetOwnerOnly` on the temporary file is kept, after the stream is closed.

The worker's new 3-second first re-point and `PrivacyDnsFailSafe`'s netsh fallback merged automatically and
are used unchanged on Windows.

## R5.2 Restore, build and suites

`--locked-mode` for `Axiom.Portable.slnx`, `Axiom.sln` and per project: pass, 22 / 22 (main 21 / 21). No lock
file changed. Clean restore: 88 packages. Release build: 0 warnings, 0 errors. Suites, `main` → S1b:
Contracts 160 → 169, Infrastructure.Windows 86 → 154, Service 101 → 120; all other suites equal. **No test
that passes on `main` fails or is missing**; all 96 added tests pass. The same 4 Python `AgentHookScriptTests`
fail on both trees. `WindowsFirewallPolicyAdapterTests` flake: 1 of 3 extra runs on each tree.

## R5.3 Privacy Shield and DoH, `main` vs S1b

`main` changed the DNS / Privacy Shield service code in this range, so the R4.4 pass was repeated with the
same script, a fresh install per build and a reset between them. Each installed `Axiom.Service.exe` has the
SHA-256 of its publish output (main `3A2D23BA…`, S1b `5C2699C0…`). **All 54 Privacy Shield checks, raw reply
lines included, are identical after normalisation.** The only other difference of the 63 checks is
`publish_files` (S1b adds `Axiom.Service.Hosting.pdb`). The results match R4.4: adapter DNS
`127.0.0.1,10.0.2.3` while on, with a backup file; allowed names resolve; blocked custom names and their
subdomains get NXDOMAIN; the automatic upstream is DoH 1.1.1.1 + 9.9.9.9; with an unreachable DoH upstream the
shield stays `Active`, lookups get SERVFAIL with no plaintext fallback and blocked names stay NXDOMAIN;
`1.1.1.1` with DoH off is still DoH; settings, upstream and adapter DNS survive a service restart; the source
update gives 236,174 rules; disabling restores adapter DNS to exactly `10.0.2.3`. `lastError` is empty in
every step on both builds, so the new adapter-error path did not fire on this VM.

## R5.4 Not repeated or not tested in this round

- The service differential and access probes of R4.3 (`main` did not change the dispatcher, caller
  authorization or the write gate). No second account was created and the `tester` credential was not used.
- A failing adapter-DNS setup live (the adapter-error path is covered by the unit test only), an explicit LAN
  upstream with DoH off, a named `PreferredAdapterAlias`, IPv6 adapter DNS, desktop UI (including the new
  Privacy Overview page), installer.

## R5.5 Cleanup

After each build: product uninstall, data roots removed and checked absent. At the end: no Axiom service,
process or firewall rule, no staged secret, no `Ax*` scheduled task, adapter DNS `10.0.2.3`. The VM was
powered off.
