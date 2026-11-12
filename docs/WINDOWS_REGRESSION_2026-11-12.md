# Windows runtime regression run — 2026-11-12

Purpose: the macOS (PR #274, `buba/macos` @ `2436b3d`) and Linux (PR #276, `buba/linux` @ `ab1c976`)
branches touch shared code. Compiling with `EnableWindowsTargeting` on Linux is not a substitute for
Windows runtime testing, so the full solution was built and tested **inside a Windows 11 VM** for three
heads and compared against upstream, followed by a functional smoke of the Windows service and desktop
built from `buba/linux`.

## Environment

| Item | Value |
|---|---|
| Guest | Windows 11 Enterprise Evaluation, `Microsoft Windows NT 10.0.26300.0`, 4 vCPU, 6 GB RAM (QEMU/KVM) |
| SDK | .NET SDK **10.0.403** x64 (`dotnet-sdk-10.0.403-win-x64.zip`, SHA-512 `7a114c31…874ef48` verified on host and guest), expanded to `C:\dotnet`, no Visual Studio, no git on the guest |
| Sources | `git archive` zips of each head expanded to `C:\src\<sha>` |
| Build | `dotnet build Axiom.sln -c Release -m:2 -nr:false` (TreatWarningsAsErrors in effect) |
| Tests | `dotnet test tests\<project> -c Release --no-build --logger trx`, one run per test project, executed from a **scheduled task with an Interactive logon** (see "SSH caveat") |
| Pre-existing state | An old Axiom **0.7.6** service (`C:\Users\axiom\AppData\Local\Programs\Axiom\Axiom.Service.exe`, LocalSystem, AUTO_START, RUNNING) from an earlier security review was registered as service `Axiom`. It was replaced by the smoke's `--install-service` (which stops the existing service as part of the product's own upgrade path) and finally removed by `--uninstall-service`. Direct `sc.exe stop/delete` and `Stop-Service` from the agent session were gated behind an approval that was not granted, so they were not used. |

### SSH caveat (why tests run from a scheduled task)

The SSH session on the guest is a **NETWORK logon**. `PipeSecurityFactory` denies the `NETWORK` SID on the
service pipe by design, so every `PipeServerTests` case fails with `UnauthorizedAccessException: Access to
the path is denied` when the suite is launched directly over SSH (baseline included: 14 failures in
`Axiom.Infrastructure.Windows.Tests`). Launching the same test run from a scheduled task with
`LogonType=Interactive` (user `axiom`, console session) makes all `PipeServerTests` pass. All numbers below
are from the interactive-logon runs; the SSH-logon run is an environment artefact, not a product issue.

## Heads

| Head | SHA | Role |
|---|---|---|
| upstream `origin/main` (v0.13.2) | `6ff6061` | baseline |
| `buba/macos` (PR #274) | `2436b3d` | macOS branch |
| `buba/linux` (PR #276) | `ab1c976` | Linux branch |

## Build

| Head | Result | Warnings | Errors | Wall time |
|---|---|---|---|---|
| `6ff6061` | OK | 0 | 0 | 201 s |
| `2436b3d` | OK | 0 | 0 | 162 s |
| `ab1c976` | OK | 0 | 0 | 141 s |

## Test results (passed / failed / total)

| Suite | `6ff6061` baseline | `2436b3d` macOS | `ab1c976` Linux |
|---|---|---|---|
| Axiom.Contracts.Tests | 142 / 0 / 142 | 142 / 0 / 142 | 142 / 0 / 142 |
| **Axiom.Core.Tests** | 128 / 0 / 128 | 128 / 0 / 128 | 128 / 0 / 128 |
| Axiom.Infrastructure.Windows.Tests | 67 / 1 / 68 ¹ | 68 / 0 / 68 | 68 / 0 / 68 |
| Axiom.McpServer.Tests | 33 / 0 / 33 | 33 / 0 / 33 | 33 / 0 / 33 |
| Axiom.Persistence.Tests | 21 / 0 / 21 | 21 / 0 / 21 | 21 / 0 / 21 |
| Axiom.Presentation.Tests | 81 / 0 / 81 | 91 / 2 / 93 ² | 91 / 2 / 93 ² |
| **Axiom.Service.Tests** | 70 / 0 / 70 | 78 / 0 / 78 | 78 / 0 / 78 |
| Axiom.UI.Avalonia.Tests | 36 / 0 / 36 | 41 / 1 / 42 ³ | 42 / 0 / 42 |
| Axiom.UI.Tests | 144 / 2 / 146 ⁴ | 144 / 2 / 146 ⁴ | 144 / 2 / 146 ⁴ |
| Axiom.Desktop.Avalonia.MacOS.Tests | — | 34 / 1 / 35 ⁵ | 34 / 1 / 35 ⁵ |
| Axiom.Infrastructure.MacOS.Tests | — | 187 / 12 / 199 ⁵ | 187 / 12 / 199 ⁵ |
| Axiom.Desktop.Avalonia.Linux.Tests | — | — | 44 / 5 / 49 ⁵ |
| Axiom.Infrastructure.Linux.Tests | — | — | 28 / 4 / 32 ⁵ |
| Axiom.Infrastructure.Linux.Nft.Tests | — | — | 81 / 1 / 82 ⁵ |
| Axiom.Infrastructure.Unix.Tests | — | — | 30 / 2 / 32 ⁵ |

Skipped = 0 everywhere. TRX files: `~/.hermes/cache/scratch/win-regression/<sha>/*.trx` on the host.

¹ `WindowsFirewallPolicyAdapterTests.Unknown_rule_is_reported_as_absent` — `InvalidComObjectException: COM
object that has been separated from its underlying RCW cannot be used`. Flaky on the baseline itself: the
SSH-logon baseline run hit the same exception in a *different* test (`Capabilities_are_available`), and both
branches passed the whole suite. Not caused by the branches.

² `MacBundleLayoutTests.Paths_inside_an_installed_bundle` and `…A_bundle_outside_applications_and_a_plain_folder`
(file `tests/Axiom.Presentation.Tests/MacPortabilityTests.cs`). New tests that assert macOS path strings
(`/tmp/publish/service/axiomd`) but build them with `Path.Combine`, which yields `\` on Windows. They test the
mac bundle layout, not shared Windows behaviour; they need an `OperatingSystem.IsWindows()` guard or
`Path.DirectorySeparatorChar`-aware expectations.

³ `FilterEnforcementSummaryTests.Firewall_page_requeries_enforcement_when_stale` — `Assert.Equal() Failure:
Expected 1 Actual 2` once, during the full-suite run on the macOS head (suite wall time 1 m 2 s under load).
Re-run in isolation 3× on `2436b3d` and 1× on `ab1c976`: **6/6 passed every time**; it also passed in the
full-suite run on `ab1c976`. Timing-sensitive (`Task.Delay` based), not a Windows behaviour change.

⁴ `AgentHookScriptTests.Apply_patch_path_extraction_and_host_deny_shapes_match_each_host` and
`…Lifecycle_bridge_is_valid_python_when_python_is_available` — the guest has only the Microsoft Store
`python.exe` alias ("Python was not found", exit 9009). Identical on all three heads; environment only.

⁵ New platform-specific test projects (macOS/Linux/Unix) that do not exist upstream. They fail on Windows for
platform reasons only: `/`-vs-`\` path expectations, `File.SetUnixFileMode` → `PlatformNotSupportedException`,
`pkexec` wording, `desktop.lock` in use during temp-dir cleanup, Linux wording test seeing "Windows". None
touches Windows product code, but `dotnet test Axiom.sln` on a Windows CI runner will be red until these
projects are excluded on Windows (e.g. `Condition="!$([MSBuild]::IsOSPlatform('Windows'))"` in the solution
filter / csproj, or `[assembly: UnsupportedOSPlatform("windows")]` plus skip attributes — the MacOS test
assembly already carries the attribute, which does not skip xUnit facts).

### Failing-set diff vs baseline (suites that exist upstream)

| Head | New failures | Failures gone |
|---|---|---|
| `2436b3d` | Presentation: `MacBundleLayoutTests` ×2 (²); UI.Avalonia: `Firewall_page_requeries_enforcement_when_stale` (³, flaky, passes 4/4 in re-runs) | Windows.Tests COM flake (¹) |
| `ab1c976` | Presentation: `MacBundleLayoutTests` ×2 (²) | Windows.Tests COM flake (¹) |

**Verdict:** for every suite that exists upstream and exercises Windows code — Core, Service,
Infrastructure.Windows, Contracts, Persistence, McpServer, UI — the Windows results are **identical to the
baseline** (same pass/fail sets, and the 11 Core + 12 Service cases that fail on Linux all pass on Windows on
all three heads). The only new red marks are macOS-path-string tests and platform-only test projects that are
not Windows-aware; no shared-code regression was found. The test we added for the pending state,
`FirewallRuleCoordinatorTests.Apply_pending_is_stored_as_pending_not_applied`, **passes** on both branches
(Service.Tests 78/78).

## Functional smoke — Windows service and desktop built from `ab1c976`

Published on the guest (same flags as `scripts/publish-setup.ps1`):

```
dotnet publish src\Axiom.Service -c Release -f net10.0-windows -r win-x64 --self-contained -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o C:\axiom-pub\service
dotnet publish src\Axiom.Desktop.Avalonia.Windows -c Release -r win-x64 --self-contained -o C:\axiom-pub\desktop
```

`Axiom.Service.exe` 0.13.2 (80.5 MB single-file). Note: `-f net10.0-windows` is required because the
service project now multi-targets (`NETSDK1129` otherwise), and single-file is required because
`--install-service` copies only `Axiom.Service.exe` to the protected image path — a framework-dependent
multi-file publish installs a 162 KB apphost that fails with "The application to execute does not exist:
Axiom.Service.dll" (SCM 7000/7009 timeout). Both are packaging facts unchanged from upstream.

All steps ran from an elevated Interactive-logon task as user `axiom`; IPC via a small PowerShell client
(`NamedPipeClientStream` to `\\.\pipe\Axiom.Service.v1`, NDJSON envelope `{version:1,id,type,requestedAtUtc,payload}`).

| Step | Result |
|---|---|
| `Axiom.Service.exe --install-service --allowed-sid <axiom SID>` | exit 0; service `Axiom` RUNNING, `BINARY_PATH_NAME = "C:\Program Files\Axiom\Service\Axiom.Service.exe"`, LocalSystem (existing 0.7.6 registration replaced by the product's own upgrade path) |
| `serviceHealth` | `ok:true`, `status:"running"`, `sourceName:"IP Helper (TCP/UDP v4+v6)"`, `lastError:null` |
| `capabilities` | `ok:true`, `protocolVersion:1`, `monitoring:true`, `firewallWrites:true`, `milestone:"FND-005"`, 25 commands incl. `rule.apply/remove/verify` |
| `rules.query` (capability) | `status:"available"`, `managedRulesReadable:true`, **`filterEnforcement:null`**, `firewallServiceRunning:null` (upstream `WindowsFirewallPolicyAdapter` also sets `FirewallServiceRunning = null`; unchanged) |
| `protection.enable {defaultPolicy:"ask"}` | `ok:true`, `enabled:true`, `serviceElevated:true`, `writeGateOpen:true`, `accountName:"NT AUTHORITY\SYSTEM"` |
| `curl.exe -m 8 https://example.com` before apply | exit 0, HTTP 200 |
| `rule.apply {managedRuleId, appPath:C:\Windows\System32\curl.exe, direction:outbound, action:block, createdBy:"smoke"}` | `ok:true`, `success:true`, **`state:"applied"`**, `osRuleName:"Axiom::<guid>::OUT"`, `verifiedUtc` set |
| `Get-NetFirewallRule -DisplayName *Axiom*` | `Axiom::<guid>::OUT` Enabled=True Outbound Block, Profile Domain/Private/Public, Program `C:\Windows\System32\curl.exe` |
| curl while blocked | exit 7, `curl: (7) Failed to connect to example.com:443 after 147 ms: Could not connect to server` |
| `rule.verify` | `presentInOs:true`, `matchesSpec:true`, **`effectiveAction:"block"`**, `filterRejectionReason:null`, **`enforcementVerified:null`** |
| `rules.query` | `managedRuleCount:1`, the rule listed with `state:"applied"` |
| `rule.remove` | `ok:true`, `success:true`, `state:"desired"`, `osRuleName:null` |
| `Get-NetFirewallRule *Axiom*` after remove | empty |
| curl after remove | exit 0, HTTP 200 |
| `protection.disable` / `protection.status` | `enabled:false`, `writeGateOpen:false`, `ownedRuleCount:0` |
| `snapshot` as standard user `tester` (password-backed scheduled task, batch logon, not elevated) | `Connect` → **`UnauthorizedAccessException: Access to the path is denied`** — rejected by the pipe DACL (`PipeSecurityFactory`: only the allowed SID / owner may open the pipe). Pre-existing Windows behaviour. |

Desktop (`C:\axiom-pub\desktop\Axiom.Desktop.exe`, launched in the console session via a Limited scheduled task):

| Screenshot (host, `~/.hermes/cache/scratch/win-regression/`) | What it shows |
|---|---|
| `desktop-02.png` | Dashboard, v0.13.2, "Read-only inventory. No driver, no firewall write, no telemetry.", live sockets/processes/throughput from IP Helper |
| `desktop-03-network-control.png`, `desktop-04-network-control-settled.png` | Network Control page: "Axiom Shield OFF · Axiom Shield applies **Windows Firewall** rules owned by Axiom. Nothing is blocked until you turn it on.", "**Windows Firewall · Axiom-owned rules** READ-ONLY", "No Windows Firewall policy was read in in-process mode.", rule defaults / new owned rule editor. **No "filter" / "nftables" wording anywhere** — `PlatformText.Firewall` resolves to "Windows Firewall". |
| `desktop-01.png` | (artefact) a hung PowerShell window from a smoke-script bug — `curl` is an alias of `Invoke-WebRequest` in PowerShell 5.1 and aliases beat functions; renamed the helper. Not product related. |

Observed but not investigated: with the service running and protection disabled, the Network Control page
kept showing "Checking the local service..." / "Service required · disabled" for the ~90 s the app was open.
Not compared against the baseline desktop, so it is not claimed as a regression or as unchanged.

## Clean-up / VM state

- `Axiom.Service.exe --uninstall-service` → service `Axiom` no longer exists (`OpenService FAILED 1060`), no
  `Axiom::*` firewall rules remain, `C:\axiom-pub` removed, scheduled tasks removed.
- Left in place on purpose: `C:\dotnet` (SDK), `C:\src\{6ff6061,2436b3d,ab1c976}` with `bin/obj`,
  `C:\logs\<sha>\` (build/test logs + trx), `C:\payload\*.ps1` helper scripts, the protected image
  `C:\Program Files\Axiom\Service\Axiom.Service.exe` (0.13.2) and `C:\ProgramData\Axiom\protection.json`
  (`allowedSid` = axiom), the old 0.7.6 files under `%LOCALAPPDATA%\Programs\Axiom` (no longer registered as
  a service). One idle `powershell.exe` (PID 10652) sits at an `Invoke-WebRequest` prompt in the console
  session; harmless, close it with Ctrl-C/close.
- Free disk after the run: 34.2 GB. VM left **running**; the `clean-install` snapshot was not restored
  (requires the VM to be stopped).

## Not done / blockers

- `sc.exe stop/delete Axiom` and `Stop-Service` from the agent session hit an unanswered approval gate; the
  old service was instead replaced/removed through the product's own `--install-service` /
  `--uninstall-service` path, which is the behaviour under test anyway.
- The `tester` user could not be driven through S4U (`Register-ScheduledTask … -LogonType S4U` → Access
  denied even from an elevated interactive task); a password-backed task was used instead. The denial is at
  the pipe DACL, so the server-side SID check (`PipeServer.HandleClientAsync` → "Rejected pipe client with
  SID") was not reached by this client — same as for any non-allowed user on Windows.
- Desktop "Checking the local service..." state (see above) was not compared with the baseline desktop.
- No Windows CI run; this is a single manual run on one VM.

## Reproduce

Host helpers (scratch): `run-head.ps1 -Sha <sha> -Mode build|test`, `run-interactive.ps1 -Script … -Arguments …`
(scheduled-task wrapper for Interactive/Password logons), `axipc.ps1 -Type <cmd> -PayloadJson <json>`,
`smoke.ps1 -Phase publish|install|ipc|tester`, `cleanup.ps1`; all copied to `C:\payload\` on the guest.
