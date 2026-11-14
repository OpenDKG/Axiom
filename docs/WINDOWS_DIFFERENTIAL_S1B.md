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
