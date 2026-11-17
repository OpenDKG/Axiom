# Windows differential test: `main` `16229f4` vs S1a `1784a51` (shared IPC dispatcher)

**Author-run on a project-controlled Windows 11 VM. This is not GitHub CI.** Run on 2026-11-14.

S1a moves the request loop of `PipeServer.cs` into the portable `IpcRequestDispatcher`
(`Axiom.Service.Hosting`), moves the firewall write gate to `Axiom.Core`, and classifies every IPC
command, including the three `enforcement.*` commands. On Windows `PipeServer` passes
`IpcCaller.FullAccess`, so no access class narrows a Windows caller. This run checks that a Windows
user sees the same behaviour as on `main`.

| | Commit |
|---|---|
| main | `16229f4c74f715c3c17433c118be320be63501b9` |
| S1a | `1784a51f036e86ffbcc19f091255f8576fa6c714` (six commits on `16229f4`) |
| full S1 (suites only, section 5) | `f574e0e52c0ef55b1bb07a42f262d7a37c7c3ef8` |

`docs/WINDOWS_IPC_DIFFERENTIAL_A.md` is the earlier run on the previous base `77cc50a`; it does not
cover the `enforcement.*` commands. This document replaces it for the current base.

## 1. Environment

- Windows 11 VM (QEMU/KVM, 3 GB RAM, 4 vCPU). .NET SDK 10.0.403 (win-x64), as pinned by `global.json`.
- Each tree is a `git archive` of its commit, expanded into an empty directory (`C:\src\<sha>`). The
  guest has no git checkout, so no `bin`/`obj` directory existed before the restore.
- The `axiom` admin user is logged on at the console. Tests and probes run from scheduled tasks with
  an Interactive logon, because the pipe DACL denies NETWORK logons such as an SSH session. A second
  local user (`tester`) is used only for the access probes.
- The probe script talks only to `\\.\pipe\Axiom.Service.v1`, the local Windows Firewall
  (`Get-NetFirewallRule`) and `curl.exe https://example.com`.

## 2. Clean restore and build

Commands, identical for both trees, each with its own empty package folder:

```
set NUGET_PACKAGES=C:\nugetclean\<sha>          (did not exist before)
dotnet restore Axiom.sln --no-http-cache -m:2 -nr:false
dotnet build Axiom.sln -c Release -m:2 -nr:false --no-restore
```

| Step | main `16229f4` | S1a `1784a51` |
|---|---|---|
| `dotnet restore Axiom.sln` | exit 0, 88 packages downloaded | exit 0, 88 packages downloaded |
| `System.CodeDom` resolved | `10.0.14` | `10.0.14` |
| `dotnet build Axiom.sln -c Release` | 0 warnings, 0 errors | 0 warnings, 0 errors |

**Restore finding.** On a Linux host a pristine checkout of `main` once failed to restore
`Axiom.Desktop` (WPF) with `NU1102: Unable to find package System.CodeDom with version (>= 10.0.14)`.
That error does not occur on Windows: a clean restore from an empty package folder, without the HTTP
cache, succeeds for `main` and for S1a, and both resolve `System.CodeDom` 10.0.14. No workaround was
used for either tree. The same holds for the full S1 head (section 5).

## 3. Test suites

Command per test project, from an Interactive scheduled task:
`dotnet test <project> -c Release --no-build --logger trx`. Passed / total:

| Suite | main `16229f4` | S1a `1784a51` |
|---|---|---|
| Axiom.Contracts.Tests | 143 / 143 | 143 / 143 |
| Axiom.Core.Tests | 151 / 151 | 151 / 151 |
| Axiom.Infrastructure.Windows.Tests | 70 / 70 | 117 / 118 first run, 118 / 118 on re-run |
| Axiom.McpServer.Tests | 33 / 33 | 33 / 33 |
| Axiom.Persistence.Tests | 21 / 21 | 21 / 21 |
| Axiom.Presentation.Tests | 105 / 105 | 105 / 105 |
| Axiom.Service.Tests | 87 / 87 | 87 / 87 |
| Axiom.UI.Avalonia.Tests | 37 / 37 | 37 / 37 |
| Axiom.UI.Tests | 144 / 146 | 144 / 146 |

Failing test names were compared per suite from the trx files (`failset.py`). Every difference:

- **Axiom.UI.Tests**: the same two tests fail on both trees,
  `AgentHookScriptTests.Apply_patch_path_extraction_and_host_deny_shapes_match_each_host` and
  `AgentHookScriptTests.Lifecycle_bridge_is_valid_python_when_python_is_available`. The VM has no
  Python, only the Microsoft Store alias (`Python was not found`, exit 9009). Environment, not code.
- **Axiom.Infrastructure.Windows.Tests**, first run of S1a:
  `WindowsFirewallPolicyAdapterTests.Owned_rules_all_follow_the_naming_contract` failed with
  `InvalidComObjectException: COM object that has been separated from its underlying RCW cannot be
  used`. It passed on the re-run (118 / 118). The same exception hit `main` on its own re-run, in
  `WindowsFirewallPolicyAdapterTests.Unknown_rule_is_reported_as_absent` (69 / 70). Three further runs
  of the suite per tree all passed (`main` 70 / 70 ×3, S1a 118 / 118 ×3). So this test class failed 1
  run in 5 on each tree with the same COM exception; S1a does not touch those tests. It is a flake
  that exists on `main`.
- **New in S1a**: 48 test results in Infrastructure.Windows.Tests, all in `IpcCommandAccessTests`, 48
  passed in every run. No test of `main` is missing from S1a.

No other failing name on either tree.

## 4. Service differential

One script, the same order for both builds. Before each build the machine was reset to the same state:
product uninstall, then `C:\ProgramData\Axiom`, the LocalSystem profile's `AppData\Local\Axiom` and
`C:\Program Files\Axiom` removed; the script records that the service, the three directories and all
Axiom firewall rules are absent before it installs.

Per build: `dotnet publish src\Axiom.Service -c Release -f net10.0-windows -r win-x64
--self-contained -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true`, then
`Axiom.Service.exe --install-service --allowed-sid <axiom SID>` (runs as LocalSystem). The SHA-256 of
the installed `Axiom.Service.exe` equals that of the published file on each build (`24A11CEA…` for
`main`, `A960270E…` for S1a), so each set of answers comes from the intended build.

Replies were compared after replacing envelope ids, timestamps, GUIDs, hashes, uptime and live
connection/process counts.

### Result

**140 checks per build. 136 are identical. 3 have the same JSON shape and differ only in live
traffic. 1 differs, as expected.**

| Difference | main | S1a | Explanation |
|---|---|---|---|
| `publish_files` | 7 files | 8 files, adds `Axiom.Service.Hosting.pdb` | S1a adds the `Axiom.Service.Hosting` assembly. Expected, not behaviour. |
| `snapshot` | 54 connections, 7 app-traffic rows | 50 connections, 4 rows | Live traffic at that moment. Same keys and types. |
| `protection.enable` (`pending` list) | 4 entries | 2 entries | Ask queue: which apps had traffic. Same keys and types. |
| `protection.status` after restart (`pending` list) | 4 entries | 2 entries | Same as above. |

### What the 140 checks cover

| Group | Checks | Result on both builds |
|---|---|---|
| Clean start, publish, install, health at 60 s and 180 s uptime | 10 | service alive 1 s after install; image `C:\Program Files\Axiom\Service\Axiom.Service.exe` |
| `serviceHealth`, `capabilities`, `snapshot`, `protection.status`, `rules.query` | 5 | `ok:true`; capabilities list is the same 23 commands, `firewallWrites:false`, `Axiom 0.17.0` |
| `enforcement.*` with the write gate closed | 20 | see below |
| `enforcement.*` with the write gate open, and a real block and unblock | 19 | see below |
| Malformed JSON, empty line, invalid UTF-8, 11 envelope shapes, 70 KiB and 2 MiB requests | 22 | `invalid_request` "Malformed JSON envelope."; `null` gives "Empty envelope."; `version:2` gives "Unsupported protocol version 2."; 2 MiB gives "Pipe is broken" on write; service alive after each group |
| Unknown command, invalid rule payloads, write gate closed | 9 | `unknown_command` "Unknown command 'bogus.command'."; `rule.apply` / `rule.remove` give `not_supported` "Firewall writes are disabled on this service." before the payload is validated; 0 firewall rules |
| Idle client, disconnect mid-request, 20 concurrent clients, 200 rapid connects, stop with a client connected, start | 7 | idle client closed after about 30 s; 4 of 20 concurrent clients connect, 16 time out |
| Restart persistence | 13 | see below |
| `enforcement.*`, `capabilities`, `serviceHealth` after two service restarts | 5 | receipts are empty again (they are kept in memory on both builds) |
| Access probes: NETWORK logon, second user `tester`, `axiom` in a limited S4U task (5 commands each) | 15 | NETWORK and `tester`: "Access to the path is denied" at connect for all 5 commands; limited `axiom`: all 5 answered, `rule.apply` `not_supported` (gate closed) |
| Uninstall and leftovers | 11 | `--uninstall-service` exit 0, service absent, no process, 0 firewall rules, same data files left |
| Firewall rule counters and gate reset between phases | 4 | 0 rules; gate closed |

### The `enforcement.*` commands

No policy file was installed, so agent enforcement is in its default off state on both builds.

| Request | Reply on `main` and on S1a |
|---|---|
| `enforcement.status` | `ok:true`, `{"enabled":false,"revision":"0","agentCount":0,"ruleCount":0,"protectedResourceCount":0,"error":null,"receiptCount":0,"hostDenySentCount":0,"hostDenyVerifiedCount":0,"guardUnavailableCount":0,"failedOpenCount":0,"chainValid":true}` |
| `enforcement.receipts` | `ok:true`, `{"chainValid":true,"total":0,"receipts":[]}` |
| `enforcement.evaluate`, valid (`kind:"readFile"`) | `ok:true`, `{"requestId":"s7-req-0001","decision":"unavailable","ruleId":"policy:disabled","reasonCode":"ENF-DISABLED","availableStrength":"observation","requireUserApproval":false,"canEnforce":false,"blackboxSignalId":null,"evaluatedUtc":"2026-11-14T12:00:00+00:00","policyRevision":null,"receiptResult":"GUARD_UNAVAILABLE"}` |
| `enforcement.evaluate`, unknown kind (`teleport`, and `runCommand`) | `ok:true`, `decision:"unavailable"`, `ruleId:"policy:invalid-request"`, `reasonCode:"ENF-INVALID-REQUEST"` |
| `enforcement.evaluate`, empty `requestId` | `ok:true`, `requestId:"invalid"`, `reasonCode:"ENF-INVALID-REQUEST"` |
| `enforcement.evaluate`, same `requestId` with another target | `ok:true`, `reasonCode:"ENF-DISABLED"`, no additional receipt |
| `enforcement.evaluate` with no payload, `null`, a string, `{}`, a missing `kind`, a bad timestamp, a wrong field type (7 checks) | `ok:false`, `invalid_request`, "An enforcement evaluate payload is required." |
| `enforcement.status` and `enforcement.receipts` with an unexpected payload | payload ignored, normal reply |
| `enforcement.status` after these | `receiptCount:4`, `guardUnavailableCount:4`, `chainValid:true` |
| `enforcement.receipts` after these | 4 receipts (5 after one more valid evaluate with the gate open) |

The receipt lists are equal on both builds without any normalisation: the same `eventId`,
`indicatorRef`, `previousHash` and `integrityHash` values (first `integrityHash`
`6a990aa275bcf472a95e9e14a23de4747562e14c272e3afeed83a1826dd79143` on both). The request carries a
fixed `utcTime`, so the hash chain is deterministic.

S1a classifies `enforcement.evaluate` as a Write. That class is not the firewall write gate:
`evaluate` answers the same with the gate closed and open, on both builds. Neither build lists the
`enforcement.*` commands in `capabilities`.

Not covered: an enabled enforcement policy. Every valid `evaluate` here ends in `ENF-DISABLED`.

### Block and unblock

| Step | main | S1a |
|---|---|---|
| `curl https://example.com` before | exit 0, HTTP 200 | exit 0, HTTP 200 |
| `protection.enable` | `writeGateOpen:true`; capabilities add `rule.apply`, `rule.remove`, `firewallWrites:true` | same |
| `rule.apply` (block `curl.exe` outbound) | `state:"applied"`, `osRuleName:"Axiom::<id>::OUT"` | same |
| Windows Firewall | 1 rule: enabled, Outbound, Block, `C:\Windows\System32\curl.exe` | same |
| `curl` while blocked | exit 7, no HTTP status | exit 7, no HTTP status |
| `rule.verify` | `presentInOs:true`, `matchesSpec:true`, `effectiveAction:"block"` | same |
| `rule.apply` with a bad enum, gate open | `invalid_request` "Rule apply payload is invalid." | same |
| `rule.remove` | `success:true`, `state:"desired"`; 0 firewall rules | same |
| `curl` after remove | exit 0, HTTP 200 | exit 0, HTTP 200 |

### Restart persistence

A second rule was applied (curl exit 7), then the service was restarted. After the restart on both
builds: `protection.status` still enabled with the gate open, `rule.verify` `presentInOs:true`
`effectiveAction:"block"`, 1 firewall rule, curl exit 7. After `rule.remove`: curl exit 0, HTTP 200.
After `protection.disable`: 0 firewall rules.

### Behaviour that `main` already has (identical on S1a, not changed by this slice)

- 4 pipe instances: 16 of 20 simultaneous clients time out in connect.
- An envelope without `id` is accepted; so is `version:"1"` as a string.
- An idle client is closed after about 30 s.
- `--uninstall-service` leaves `C:\Program Files\Axiom\Service\Axiom.Service.exe`, `axiom.db`,
  `network-recovery.txt`, `protection.json` and `threat-share.json` behind.
- Enforcement receipts do not survive a service restart.

## 5. Full S1 head `f574e0e`: suites only

Same restore, build and test commands. No service differential was run for this head.

| Step | main `16229f4` | S1 `f574e0e` |
|---|---|---|
| Clean restore | exit 0 | exit 0, `System.CodeDom` 10.0.14 |
| `dotnet build Axiom.sln -c Release` | 0 warnings, 0 errors | 0 warnings, 0 errors |
| Axiom.Contracts.Tests | 143 / 143 | 152 / 152 (+9 new) |
| Axiom.Core.Tests | 151 / 151 | 151 / 151 |
| Axiom.Infrastructure.Windows.Tests | 70 / 70 | 118 / 118 (+48 new) |
| Axiom.McpServer.Tests | 33 / 33 | 33 / 33 |
| Axiom.Persistence.Tests | 21 / 21 | 21 / 21 |
| Axiom.Presentation.Tests | 105 / 105 | 105 / 105 |
| Axiom.Service.Tests | 87 / 87 | 96 / 96 (+9 new) |
| Axiom.UI.Avalonia.Tests | 37 / 37 | 37 / 37 |
| Axiom.UI.Tests | 144 / 146 | 144 / 146 (the same two `AgentHookScriptTests`) |

Failing names are identical to `main` in every suite. No test of `main` is missing.
`FirewallRuleCoordinatorTests.Apply_pending_is_stored_as_pending_not_applied`, which cannot pass on
Linux, **passes on Windows**.

## 6. Cleanup

Service uninstalled through the product, data directories, published output, source trees and package
folders removed from the VM, 0 Axiom firewall rules, no scheduled task left. The `tester` password
file was copied to the guest only for the two access probes and deleted right after each; a separate
check found no copy afterwards.

## 7. Not covered

- An enabled enforcement policy (allow / block / ask decisions, host deny).
- The desktop UI against either build.
- The installer (`Axiom.Setup`); the service was installed with `--install-service`.
- A service differential of the full S1 head `f574e0e`.
- GitHub CI: none of this ran there.


---

# Round 3 (2026-11-15): `main` `1cd0b79` vs S1a `7ee1527`, lock files regenerated on Windows

**Author-run on the project's Windows 11 test VM. This is not CI.** Same VM, SDK 10.0.403, scripts and
method as in sections 1 to 6. Every tree is a `git archive` of its commit expanded into an empty directory,
each with its own empty `NUGET_PACKAGES` folder.

| | Commit |
|---|---|
| main | `1cd0b79a82bf9469cea804a91ac029b8b369e631` (after `419e9e9`: the self-test fix `a57ebbe`, the 0.25.0 release commit and its revert, merges #328 / #329) |
| S1a before the lock-file fix | `8e087b2` = published `6a5073a` + merge of `main` `419e9e9` + the reviewer nit (`7880c55`) + `Merge main (1cd0b79) into S1a` (clean) |
| S1a tested | **`7ee1527d2003399761495fb0c1d79eec8285e093`** = `8e087b2` + the lock-file commit. Later commits on the branch change docs only. |

## R3.1 Locked restore and the lock-file fix

A reviewer found that `dotnet restore --locked-mode` fails with `NU1004` on S1a. The cause: S1a adds the
project `Axiom.Service.Hosting` and references it from `Axiom.Infrastructure.Windows` and
`Axiom.Service`, but the lock files were not regenerated.

Upstream's lock files have two shapes. 13 lock files have a `<tfm>/win-x64` section: the projects in the
closure of the win-x64 published apps. The other 9 have no RID section. A plain `--locked-mode` restore
(without `-r`) fails with `NU1004` ("runtime identifiers have changed") for **every** project of pristine
`main` on Windows. So each project was restored in the mode that matches its own lock file: `-r win-x64`
for the RID-shaped ones and plain for the others. An error counts for a project only when the NuGet error
line names that project's `.csproj`.

**Fix (`7ee1527`).** Run on the VM: `dotnet restore <project> --force-evaluate` per project, in the shape
of its lock file (plain projects first, RID projects last). The new `Axiom.Service.Hosting` lock file gets
the `win-x64` shape, like `Axiom.Contracts` and `Axiom.Core`. Review of the regenerated files against the
committed ones:

- **No NuGet package entry changed in any of the 22 files.** So there is no package version drift.
- Every regenerated file refreshes the in-repo project reference ranges, for example
  `"Axiom.Contracts": "[0.13.0, )"` becomes `"[0.24.0, )"`. NuGet records the current project versions
  when it regenerates a file. `Axiom.UI.Avalonia` would also gain a `win-x64` section, through the
  `-r win-x64` graph of `Axiom.Desktop.Avalonia.Windows`.
- **Only the 7 files whose graph contains `Axiom.Service.Hosting` are taken:** `Axiom.Desktop`,
  `Axiom.Desktop.Avalonia.Windows`, `Axiom.Infrastructure.Windows`, `Axiom.Service`,
  `Axiom.Service.Hosting` (adds an empty `net10.0/win-x64` section), `Axiom.Infrastructure.Windows.Tests`
  and `Axiom.Service.Tests`. The diff adds the `axiom.service.hosting` project entry and refreshes the
  project ranges. The other 15 files are as on `main`. Line endings are LF, as in the repository.

Proof on a **fresh** copy of each committed tree (`--locked-mode` per project, in its matching mode):

| Project | Lock shape | main `1cd0b79` | S1a before (`8e087b2`) | S1a `7ee1527` |
|---|---|---|---|---|
| Axiom.Contracts, Core, Persistence, Presentation, Setup, UI | win-x64 | pass | pass | pass |
| Axiom.Desktop, Axiom.Infrastructure.Windows, Axiom.Service | win-x64 | pass | **fail** `NU1004` "A new project reference to Axiom.Service.Hosting was found" | pass |
| Axiom.Service.Hosting (new) | win-x64 | — | fail | pass |
| Axiom.Desktop.Avalonia.Windows | win-x64 | fail | fail | fail |
| Axiom.McpServer, Axiom.UI.Avalonia, the 10 test projects | plain | fail | fail | fail |

**No project that passes locked restore on `main` fails on S1a.** The rows that fail on S1a also fail on
pristine `main`, with the same `NU1004` runtime-identifier message. The plain-shape projects reference
projects whose lock files carry `win-x64`, so neither mode matches them. The slice does not change those
files.

## R3.2 Clean restore, build and suites

| Step | main `1cd0b79` | S1a `7ee1527` |
|---|---|---|
| `dotnet restore Axiom.sln --no-http-cache` (empty package folder) | exit 0, 88 packages, `System.CodeDom` 10.0.14 | same |
| `dotnet build Axiom.sln -c Release --no-restore` | 0 warnings, 0 errors | 0 warnings, 0 errors |
| Axiom.Contracts.Tests | 148 / 148 | 148 / 148 |
| Axiom.Core.Tests | 151 / 151 | 151 / 151 |
| Axiom.Infrastructure.Windows.Tests | 75 / 75 | 125 / 126 (COM flake, see below) |
| Axiom.McpServer.Tests | 33 / 33 | 33 / 33 |
| Axiom.Persistence.Tests | 21 / 21 | 21 / 21 |
| Axiom.Presentation.Tests | 196 / 196 | 196 / 196 |
| Axiom.Service.Tests | 91 / 91 | 91 / 91 |
| Axiom.UI.Avalonia.Tests | 37 / 37 | 37 / 37 |
| Axiom.UI.Tests | 171 / 174 | 171 / 174 |

Failing test names compared per suite from the trx files (`failset.py`, plus a check that every test that
passes on `main` exists and passes on S1a):

- **No test that passes on `main` is missing on S1a.** The 51 new results are `IpcCommandAccessTests` and
  its theory rows, plus the 3 **`IpcCallerEntryPointTests`** for the reviewer nit. All 3 **pass on
  Windows**.
- **Axiom.UI.Tests**: the same 3 `AgentHookScriptTests` fail on both trees. The VM has no Python, only the
  Store alias (exit 9009). Environment, not code.
- **Axiom.Infrastructure.Windows.Tests**: `WindowsFirewallPolicyAdapterTests.Owned_rules_all_follow_the_naming_contract`
  failed in S1a's full-suite run with `InvalidComObjectException` (COM object separated from its RCW).
  This is the known flake. Neither the adapter nor its tests are changed by the slice. 8 more runs of the
  suite per tree: `main` failed in 2 of 9 runs in total (`Capabilities_are_available` twice), S1a in 3 of 9
  (`Owned_rules_all_follow_the_naming_contract` each time). The tests and the exception are the same on
  both trees.

## R3.3 Service differential

Same scripts and order as section 4, with the state reset between builds. A Privacy Shield phase was
added; the S1b document has the detail. The installed `Axiom.Service.exe` has the same SHA-256 as the
published one: `main` `1696CC17…`, S1a `DD127DC5…`.

**175 checks per build: 171 identical after normalisation, 3 with the same JSON shape and different live
traffic (`snapshot`; the `pending` ask list in `protection.enable` and in `protection.status` after the
restart), 1 different: `publish_files`** (S1a adds `Axiom.Service.Hosting.pdb`, as before). That covers:

- core commands;
- `enforcement.status` / `.receipts` / `.evaluate` with the gate closed and open. The receipt hash chains
  are equal without normalisation;
- malformed, oversized and invalid-UTF-8 payloads, unknown command, invalid rule payloads;
- the connection matrix;
- access probes. The NETWORK logon and the second local user `tester` are denied at connect; `axiom` in a
  limited S4U task is answered;
- uninstall leftovers.

Block and unblock, identical on both builds:

1. `curl https://example.com` before: exit 0, HTTP 200.
2. `protection.enable`, then `rule.apply` (block `curl.exe` outbound): 1 firewall rule (enabled /
   Outbound / Block / `curl.exe`); curl exit 7.
3. `rule.verify`: `presentInOs:true`, `effectiveAction:"block"`.
4. After a service restart: the rule is still present and still verified; curl exit 7.
5. `rule.remove`: 0 rules; curl exit 0, HTTP 200.

A second, privacy-only pass with a fresh install per build gave **61 / 61 identical checks**, `main` vs
S1a.

## R3.4 Known flakes and limits

- `WindowsFirewallPolicyAdapterTests`: COM / RCW flake, see R3.2. Small sample; the rates are recorded,
  not explained.
- Python is absent on the VM, so 3 `AgentHookScriptTests` fail on every tree.
- The probe credential for `tester` was copied to the guest only for the access probes, removed right
  after each use, and checked absent (`TP_AFTER_AUTH=False`, `tp_present False` after each reset).
- Not covered: an enabled enforcement policy, the desktop UI, the installer, GitHub CI.


# Round 4 (2026-11-15): `main` `d0991bd` vs S1a `d207ba7`

**Author-run on the project's Windows 11 test VM. This is not CI; no GitHub-hosted run exists for this
revision.** Same VM and method as round 3. SDK 10.0.403, the version pinned by `global.json`. Every tree is a
`git archive` of its commit, expanded into an empty directory, with its own empty `NUGET_PACKAGES` folder.

| | Commit |
|---|---|
| main (pinned for this round) | `d0991bdcef4913bd626700e007bf814b2854b249` (v0.50.0 docs/CI sync; 87 commits after `1cd0b79`) |
| S1a before the lock-file commit | `d1dc1fa` = `3bc7625` + `Merge main d0991bd` (conflicts only in 6 `packages.lock.json`, `main`'s version taken) |
| **S1a tested** | **`d207ba7fc3c611112a72f3bba3df6bde88dddaa7`** = `d1dc1fa` + the lock-file commit. The commit after it changes this document only. |

## R4.1 IPC commands on `main` `d0991bd`

`IpcCommandTypes` (`src/Axiom.Contracts/Ipc/IpcProtocol.cs`) is unchanged between `1cd0b79` and `d0991bd`,
and so is `PipeServer.cs`. **No IPC command was added**, so no new classification was needed. All 32
commands are classified; `IpcCommandAccessTests.EveryCommandIsClassifiedExactlyOnce` fails if a constant
in `IpcCommandTypes.All` is unclassified. `enforcement.status` and `enforcement.receipts` are PrivateRead,
`enforcement.evaluate` is Write.

On Windows (tree `d207ba7`): `IpcCommandAccessTests` 48 / 48 and `IpcCallerEntryPointTests` 3 / 3 pass.
They include the denial cases: `PublicOnlyCallerNeverReachesAnEnforcementHandler` (status, receipts and evaluate
answer `unauthorized`), `ReadOnlyCallerReadsStatusAndReceiptsButCannotEvaluate`, `CallerFlagsGateTheClasses`
and the per-caller rows of `EnforcementCommandsPerCaller`. `PipeServer` still builds the caller with
`WindowsPipeCaller.Authenticated(sid)` after the pipe DACL and the client SID check.

## R4.2 Lock files

`main` `d0991bd` (#280) changed the lock-file model. Every lock file is now plain. Only `Axiom.Desktop` and
`Axiom.Setup` carry `win-x64`, through their `<RuntimeIdentifiers>`. Publishing uses its own
`obj/publish.packages.lock.json`, and `windows-ci.yml` restores `Axiom.Portable.slnx` and `Axiom.sln` with
`--locked-mode`. The round-3 method (restore each project in the shape of its lock file) was replaced by
exactly those two solution-level restores, plus `--locked-mode` per project.

| Restore (`--locked-mode`, fresh copy, empty package folder) | main `d0991bd` | S1a merge `d1dc1fa` (main's lock files) | S1a `d207ba7` |
|---|---|---|---|
| `dotnet restore Axiom.Portable.slnx` | exit 0 | exit 1 (`Axiom.Service.Hosting`) | exit 0 |
| `dotnet restore Axiom.sln` | exit 0 | exit 1 (7 projects, `NU1004`) | exit 0 |
| per project | 22 / 22 pass | 16 / 23 pass | **23 / 23 pass** |

The 7 projects that failed on `d1dc1fa` are `Axiom.Desktop`, `Axiom.Desktop.Avalonia.Windows`,
`Axiom.Infrastructure.Windows`, `Axiom.Service`, `Axiom.Service.Hosting`,
`Axiom.Infrastructure.Windows.Tests` and `Axiom.Service.Tests`. They fail with `NU1004` "A new project
reference to Axiom.Service.Hosting was found", or with a runtime-identifier change for the Hosting file that
still had round 3's `net10.0/win-x64` section.

**Fix (`d207ba7`).** On the VM, the `Axiom.Service.Hosting` lock file was deleted, then
`dotnet restore Axiom.sln --force-evaluate` was run (plain, like `main`'s CI). Against the committed files:

- **No NuGet package entry changed in any of the 22 files.**
- Only the 7 files above are taken. Their diff adds the `axiom.service.hosting` project entry and refreshes
  in-repo project ranges. The Hosting file loses its `win-x64` section and gets range `0.50.0`. Line endings
  are LF.
- The other 15 files differ only by NuGet's in-repo project-range refresh (for example `[0.34.0, )` to
  `[0.50.0, )`), or not at all. They are left as on `main`.

## R4.3 Clean restore, build and suites

| Step | main `d0991bd` | S1a `d207ba7` |
|---|---|---|
| `dotnet restore Axiom.sln --no-http-cache` (empty package folder) | exit 0, 88 packages, `System.CodeDom` 10.0.14 | same |
| `dotnet build Axiom.sln -c Release --no-restore` | 0 warnings, 0 errors | 0 warnings, 0 errors |
| Axiom.Contracts.Tests | 152 / 152 | 152 / 152 |
| Axiom.Core.Tests | 184 / 184 | 184 / 184 |
| Axiom.Infrastructure.Windows.Tests | 86 / 86 | 137 / 137 |
| Axiom.McpServer.Tests | 34 / 34 | 34 / 34 |
| Axiom.Persistence.Tests | 21 / 21 | 21 / 21 |
| Axiom.Presentation.Tests | 275 / 275 | 275 / 275 |
| Axiom.Service.Tests | 98 / 98 | 98 / 98 |
| Axiom.UI.Avalonia.Tests | 56 / 56 | 56 / 56 |
| Axiom.UI.Tests | 179 / 183 | 179 / 183 |

Failing names compared per suite from the trx files (`cmptrx.py`):

- **No test that passes on `main` is missing or failing on S1a.** The 51 extra results are
  `IpcCommandAccessTests` (48) and `IpcCallerEntryPointTests` (3). All pass.
- **Axiom.UI.Tests**: the same 4 `AgentHookScriptTests` fail on both trees
  (`Apply_patch_path_extraction_and_host_deny_shapes_match_each_host`,
  `Guard_helpers_block_vectors_in_a_real_python_run`,
  `Lifecycle_bridge_is_valid_python_when_python_is_available`,
  `OpenCode_bridge_compiles_when_python_is_available`). The VM has no Python. This is the environment, not
  the code.
- `WindowsFirewallPolicyAdapterTests` COM / RCW flake: the full-suite run passed on both trees. In 4 more
  runs of the suite per tree, each tree failed once, with `InvalidComObjectException` (`main`:
  `Unknown_rule_is_reported_as_absent`; S1a: `Owned_rules_all_follow_the_naming_contract`). S1a does not
  touch the adapter or its tests.

## R4.4 Service differential

Same probe script for both builds, with a product uninstall and the data roots removed between builds. The
installed `Axiom.Service.exe` has the same SHA-256 as the published one: `main` `F4E01EAF…`, S1a
`FD15F81E…`.

**168 checks per build: 166 identical after normalisation, 1 with the same shape and different live
traffic (`snapshot`: connection count and byte counters), 1 different: `publish_files`** (S1a adds
`Axiom.Service.Hosting.pdb`). That covers:

- core commands;
- `enforcement.status` / `.receipts` / `.evaluate` with the write gate closed and open, with fixed request
  ids and times. The receipt results (0, 4, 4, 5 and, after the restart, 0 receipts) are **byte-identical
  without normalisation**, hash chains included;
- malformed, oversized and invalid-UTF-8 payloads, the unknown command, invalid rule payloads, and the
  connection matrix;
- the Privacy Shield phase (identical; the S1b document has the detail).

Block, unblock and persistence, identical on both builds:

1. `curl https://example.com` before: exit 0, HTTP 200.
2. `protection.enable`, then `rule.apply` (block `curl.exe` outbound): 1 firewall rule; curl exit 7.
3. Service restart: the rule is still present, `rule.verify` gives `presentInOs:true`,
   `effectiveAction:"block"`; curl still exit 7.
4. `rule.remove`: curl exit 0, HTTP 200. `protection.disable`: 0 Axiom firewall rules.

With the gate closed, every `rule.apply` / `rule.remove` answers `not_supported` "Firewall writes are
disabled on this service." on both builds.

## R4.5 Access: authenticated caller and a second local account

The service was installed with `--allowed-sid` for `axiom`. The probe sends 10 commands: `serviceHealth`,
`capabilities`, five private reads (`snapshot`, `history.query`, `config.get`, `privacy.status`,
`enforcement.status`), `enforcement.receipts`, and two writes (`enforcement.evaluate`, `rule.apply`). It ran
in two places: after the differential above, and again on a fresh install of each build.

| Caller | main `d0991bd` | S1a `d207ba7` |
|---|---|---|
| `axiom`, Interactive elevated (install owner) | answered: reads `ok`, evaluate `ok` (`ENF-DISABLED`), `rule.apply` `not_supported` (gate closed), `history.query {}` `invalid_request`, `config.get` `not_supported` | identical |
| `axiom`, S4U limited token | same as the line above | identical |
| SSH (NETWORK logon) | denied at connect, 10 / 10 (`UnauthorizedAccessException`) | identical |
| **temporary standard local account** (member of Users only) | **denied at connect, 10 / 10** | **identical** |

The temporary account was new for each run (`axr4` + 6 random letters). It was created inside the guest,
with a random password that was generated there and never printed or copied to the host. It ran the probe
through `Start-Process -Credential` from the owner's interactive task. Afterwards the account, its profile
entry, its profile directory and the staged secret were removed, and each run checked that they were gone
(`account=False profile_dirs=0 profile_entries=0 tp_present=False`). On Windows the pipe DACL already
refuses this caller at connect, so the dispatcher's own private-read and write denial for a restricted
caller is shown by the unit tests in R4.1. The live run shows only that the Windows path still refuses.

## R4.6 Not tested in this round

- An enabled enforcement policy file (every evaluate is `ENF-DISABLED`).
- A local account that the pipe DACL admits but that is not the install owner. Windows has no such caller.
- Desktop UI, installer and setup, and any GitHub-hosted run.
- A first differential pass was discarded: a second script reinstalled the service while it was running.
  All results above come from the sequential re-run.

# Round 5 (2026-11-16): `main` `25bfcc1` vs S1a `ab7df89`

**Author-run on the project's Windows 11 test VM. This is not CI.** Same VM, SDK 10.0.403 (pinned by
`global.json`) and method as round 4. Every tree is a `git archive` of its commit, expanded into an empty
directory, with its own empty `NUGET_PACKAGES` folder.

| | Commit |
|---|---|
| main (pinned for this round) | `25bfcc176dbb40c63b34f225d31cffb254732587` (v0.64.0; 48 commits after `d0991bd`) |
| **S1a tested** | **`ab7df89b01538d5c24fd4de8752270a645f73a90`** = `c7d2575` + `Merge main 25bfcc1 (v0.64.0) into S1a` (no conflicts). The commit after it changes this document only. |

## R5.1 What `main` changed in the reviewed areas

`main` `d0991bd..25bfcc1` touches 164 files; none of them is one of S1a's 26 files. Per area:

| Area | Changed by `main`? |
|---|---|
| `IpcCommandTypes` / IPC commands (`src/Axiom.Contracts/Ipc/*`) | **No**: no command added, still 32, all classified in `IpcCommandAccess` |
| Dispatcher (S1a's `IpcRequestDispatcher`; `main` has none) and `PipeServerWorker` / `Program.cs` | **No** |
| `PipeServer` / caller authorization (`src/Axiom.Infrastructure.Windows/Ipc/*`) | **No** |
| Firewall write gate (`PipeServer`, `ProtectionController`, `FirewallRuleCoordinator`, `RuleSpecValidator`, `WindowsFirewallPolicyAdapter`) | **No** |

The only IPC-related changes are on the client side: the Avalonia Agents page now calls the existing
`enforcement.status` / `enforcement.receipts` commands, and the WPF client's `ServiceUnavailableException`
gained a `Code` property.
**The R4 runtime comparison (pipe access with a second local account, block / unblock, restart
persistence, `enforcement.*`) was therefore not repeated.** It still describes this code.

## R5.2 Lock files, restore, build

`main` changed no `packages.lock.json` and no package reference in the range. `--locked-mode`, fresh copy,
empty package folder:

| Restore | main `25bfcc1` | S1a `ab7df89` |
|---|---|---|
| `dotnet restore Axiom.Portable.slnx --locked-mode` | exit 0 | exit 0 |
| `dotnet restore Axiom.sln --locked-mode` | exit 0 | exit 0 |
| per project `--locked-mode` | 21 / 21 pass | 22 / 22 pass |

**No lock file was regenerated or changed in this round.** Clean restore (`--no-http-cache`): exit 0,
88 packages, on both trees. `dotnet build Axiom.sln -c Release --no-restore`: 0 warnings, 0 errors on both.

## R5.3 Suites, `main` → S1a (passed / total, `dotnet test` totals)

Contracts 160 → 160, Core 184 → 184, Infrastructure.Windows 86 → 137 (+51 IPC tests), McpServer 34 → 34,
Persistence 21 → 21, Presentation 287 → 287, Service 101 → 101, UI.Avalonia 62 → 62, UI.Tests 194/198 →
194/198. **No test that passes on `main` fails or is missing on S1a.** The 4 UI.Tests failures are the same
`AgentHookScriptTests` on both trees (the VM has no Python). `IpcCommandAccessTests` 48 / 48 and
`IpcCallerEntryPointTests` 3 / 3 pass. `WindowsFirewallPolicyAdapterTests` (COM/RCW flake) passed in both
full-suite runs; in 3 extra runs per tree it failed once on each (main `Unknown_rule_is_reported_as_absent`,
S1a `Capabilities_are_available`).

## R5.4 Not repeated or not tested in this round

- The service differential and the access probes (see R5.1 for why).
- An enabled enforcement policy file, desktop UI, installer.

# Round 6, host part (2026-11-17): `main` `da1987a` (v1.1.0) vs S1a, Linux host only

**Author-run on a Linux host (SDK 10.0.403). This is not CI, and no Windows run has been made for this
head yet.** It records what the host proves and what the Windows round still has to run.

| | Commit |
|---|---|
| main (pinned) | `da1987a1896275f0127eb8fe176c1a780471ebe9` (v1.1.0) |
| S1a merge | `5ec7b02` = `ec6a25d` + `Merge main da1987a`. Conflicts: 6 `packages.lock.json` only (`Axiom.Desktop`, `Axiom.Desktop.Avalonia.Windows`, `Axiom.Infrastructure.Windows`, `Axiom.Service`, `Axiom.Infrastructure.Windows.Tests`, `Axiom.Service.Tests`); `main`'s version taken |
| lock files | `d9ad0a2`, **provisional**, generated on Linux; the Windows round regenerates them |
| review fix | `d7ec667` red tests, `9a6dafa` fix, `7676ea0` classification table |

## R6.1 What changed since round 5 (`ab7df89`)

- S1a runtime code: `IpcCaller` now has `CanWrite` and `CanReadPrivate` both required, with no default.
  The positional order is `(Actor, CanWrite, CanReadPrivate, WriteDenialReason?, ReadDenialReason?)`.
  `WindowsPipeCaller.Authenticated` passes the same values as before, with named arguments
  (`CanWrite: true, CanReadPrivate: true`). `Permits`, `DenialMessage`, the classification sets,
  `IpcRequestDispatcher`, `IpcRulePolicy`, `PipeServer`, `FirewallWriteGate`, `ProtectionWriteConsent`,
  `ProtectionWorker` and `WindowsFirewallPolicyAdapter` are byte-identical to `ab7df89`.
- `main` `25bfcc1..da1987a` on the IPC path: no change in `src/Axiom.Contracts/Ipc` (still 32 commands,
  none new since v0.64.0) or in `src/Axiom.Infrastructure.Windows/Ipc`. `EnforcementController`
  changed: since v0.74/0.75 (#403), `enforcement.status` provisions the machine default policy under
  `%ProgramData%\Axiom` when the file is missing (`EnforcementPolicyProvisioner.EnsureMachineDefault`), and
  the policy path moved from `LocalApplicationData` to `CommonApplicationData`. S1a keeps
  `enforcement.status` PrivateRead as asked. On Windows this makes no access difference, because the pipe
  caller has every class. A future Unix transport should know that a private-read caller can trigger
  that one-time provisioning.

## R6.2 Host results

| Step | main `da1987a` | S1a `7676ea0` |
|---|---|---|
| `restore Axiom.Portable.slnx --locked-mode` | exit 0 | exit 0 |
| `restore Axiom.sln --locked-mode` | exit 1: NU1004 for `Axiom.Desktop` and `Axiom.Setup` (the host adds `linux-x64` to their `win-x64` RIDs); this run also logged NU1102 for `System.CodeDom` | exit 1: the same RID NU1004, plus NU1004 for `Axiom.Desktop`'s missing `Axiom.Service.Hosting` entry (its lock file is still `main`'s) |
| per-project `--locked-mode` | 20 / 22 (`Axiom.Desktop`, `Axiom.Setup` fail) | 21 / 23 (same two) |
| Release build: Portable.slnx, Infrastructure.Windows, Service, Desktop.Avalonia.Windows, Infrastructure.Windows.Tests, Service.Tests | 0 warnings, 0 errors | 0 warnings, 0 errors |

Before `d9ad0a2` (main's lock files), locked restore also failed with NU1004 (missing
`Axiom.Service.Hosting` project entry) for `Axiom.Desktop.Avalonia.Windows`, `Axiom.Infrastructure.Windows`,
`Axiom.Service`, `Axiom.Infrastructure.Windows.Tests` and `Axiom.Service.Tests`. These are the 5 files in
`d9ad0a2`. `Axiom.Desktop/packages.lock.json` is still `main`'s and has no Hosting entry. It cannot be
checked on this host, and a Linux `--force-evaluate` gave a graph that differs from `main`'s
Windows-generated file, so it is left for Windows.

Suites (`dotnet test -c Release`, passed / total). Every run had `HOME` and `XDG_*` pointed at a scratch
directory.

| Suite | main `da1987a` | S1a |
|---|---|---|
| Contracts | 169 / 170 | 169 / 170 |
| Core | 170 / 184 | 170 / 184 |
| McpServer | 34 / 34 | 34 / 34 |
| Persistence | 21 / 21 | 21 / 21 |
| Presentation | 307 / 315 | 307 / 315 |
| UI.Avalonia | 65 / 66 | 65 / 66 |
| Infrastructure.Windows | 58 / 86 | 125 / 153 |
| Service | 86 / 101 | 86 / 101 |

**The failing test names are identical per suite on both trees.** They are 67 Windows-only tests
(named pipe, WFP/COM, IP Helper, job objects, Windows paths) that cannot run on Linux. The 67 extra
Infrastructure.Windows results all pass: `IpcCommandAccessTests` 49, `IpcCallerPermissionTests` 15,
`IpcCallerEntryPointTests` 3. No test is skipped.

New tests for this round (red on `d7ec667`: 1 failed / 70, the omission test; green on `9a6dafa`):
`CallerConstructorHasNoOptionalPermissionParameters`, `RestrictedCallerHoldsOnlyPublicRead`,
`PublicOnlyCallerGetsRedactedHealthAndCapabilities`, `PublicOnlyCallerIsDeniedEveryPrivateRead`,
`CallerWithoutWriteIsDeniedEveryWrite` (2), `PrivateReaderGetsFullHealth`,
`AuthenticatedWindowsSidCallerPassesTheCheckForEveryCommand`, `UnknownCommandIsDeniedByDefault` (4),
`OversizedRequestClosesTheConnectionBeforeAnyHandler`, `RequestFloodHitsTheRateLimit`,
`SilentConnectionIsClosedAfterTheIdleTimeout`, `ClassificationTableIsTheReviewedOne`.

## R6.3 Authorization order and request limits (read from the code)

- No handler runs before the access check. `IpcRequestDispatcher.ProcessAsync` parses the envelope
  (`IpcRequestDispatcher.cs:216`), checks the protocol version (`:240`), then classifies the command and
  checks `caller.Permits` (`:251-263`) before the command `switch` (`:267`). The only work before
  the check is parsing and the version reply. Unknown commands count as Write (`IpcCommandAccess.Classify`).
- The limits have the same values as `main`'s `PipeServer`: message size 256 KiB
  (`IpcProtocol.cs:21`, enforced at `IpcRequestDispatcher.cs:153-166`), idle timeout 30 s (`:26`,
  `:140-141`), 100 requests/s (`:24`, `:186-201`), 4 pipe instances (`PipeServer.cs:23`, `:179`). On
  Windows the DACL and the client SID re-check (`PipeServer.cs:184`, `:190-195`) run before the
  dispatcher. New dispatcher-level tests cover the first three; before this round, only the pipe tests
  covered the size limit, and those cannot run off Windows.

## R6.4 Awaiting the Windows round

1. Regenerate the lock files on Windows (at least the 5 in `d9ad0a2` plus `Axiom.Desktop`), then run
   `--locked-mode` restores of `Axiom.Portable.slnx` and `Axiom.sln`, plus per project.
2. Release build of `Axiom.sln`, and every suite by failing name against `main` `da1987a`, including the
   67 Windows-only names above and the new IPC tests.
3. Windows PR CI on the exact resulting head SHA.
4. Service differential, limited to what is touched: the caller construction changed, so re-run the access
   part (authenticated SID gets write and private read: `protection.enable`, `rule.apply`, block /
   unblock; NETWORK logon and a second local user denied at connect). Upstream changed the
   `enforcement.status` handler, so re-run the `enforcement.*` part on both trees. The Privacy Shield phase
   and restart persistence are not touched by this round.
