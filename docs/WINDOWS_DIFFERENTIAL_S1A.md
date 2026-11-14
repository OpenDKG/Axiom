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
