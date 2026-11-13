# Windows differential test: PR A vs PR B (Windows-side service seams)

PR B adds the seams that the later macOS/Linux PRs plug into: `IIpcTransport` with the Windows
`NamedPipeIpcTransport`, the transport seam in `PipeServerWorker`, the `ServicePlatform` split with
`ServicePlatform.Windows`/`ServiceInfo.Windows`, `AxiomPaths` (data roots and service detection)
and the code that now resolves its paths through it, and the owner-only Unix file mode in
`NetworkRecoverySnapshotStore` and `ProtectionSettingsStore`. `Axiom.Service` still targets only
`net10.0-windows`. The goal of this test was to show that Windows behaves exactly as on the base.

| | Build |
|---|---|
| base (PR A) | `c0789b0` (`split/a-shared-ipc`; its later commit `f56bb09` only adds a doc) |
| B | `be183e2` (this branch before the rebase onto `f56bb09`; `src/` and `tests/` are identical to the rebased head) |

## Environment

- Windows 11 VM (QEMU/KVM, 3 GB RAM). The `axiom` admin user is logged on at the console. A
  second local user, `tester`, is used for the access probes.
- .NET SDK 10 (win-x64). Each head is built from a `git archive` of its commit.
- The service is published with `dotnet publish src/Axiom.Service -c Release -f net10.0-windows
  -r win-x64 --self-contained -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true`
  and installed through `Axiom.Service.exe --install-service --allowed-sid <axiom SID>`
  (LocalSystem).
- Tests and probes run from scheduled tasks with an Interactive logon (the pipe ACL denies
  NETWORK logons), except where a probe tests another logon type on purpose.
- The probes talk only to `\\.\pipe\Axiom.Service.v1`, the local Windows Firewall, the Axiom
  recovery snapshot and `curl.exe https://example.com` (the block/unblock target).

## Build and test suites

| Check | base | B |
|---|---|---|
| `dotnet build Axiom.sln -c Release` (Windows) | 0 warnings, 0 errors | 0 warnings, 0 errors |
| Axiom.Contracts.Tests | 142/142 | 151/151 (+9 `AxiomPathsTests` cases) |
| Axiom.Core.Tests | 128/128 | 128/128 |
| Axiom.Infrastructure.Windows.Tests | 106/106 (one run: 105/106, see below) | 106/106 |
| Axiom.McpServer.Tests | 33/33 | 33/33 |
| Axiom.Persistence.Tests | 21/21 | 21/21 |
| Axiom.Presentation.Tests | 81/81 | 81/81 |
| Axiom.Service.Tests | 70/70 | 70/70 |
| Axiom.UI.Avalonia.Tests | 37/37 | 37/37 |
| Axiom.UI.Tests | 144/146 | 144/146 (the same 2 `AgentHookScriptTests` fail on both: the VM has no `python` alias) |

On the base, `WindowsFirewallPolicyAdapterTests.Unknown_rule_is_reported_as_absent` failed once
with the known `InvalidComObjectException` (COM object separated from its RCW). Re-running the
project on the base gave 106/106 and then 105/106 with the same exception, so the test is flaky
and the failure is not related to B.

On Linux, `Axiom.sln` (`-p:EnableWindowsTargeting=true`) and `Axiom.Portable.slnx` build with
0 warnings and 0 errors. The failing test names per project are the same as on the base (they
are the Windows-only tests). The one exception was
`HeadlessNavigationTests.Main_window_navigates_through_every_page_without_a_render_error`, which
failed once with an Avalonia dispatcher-thread error and passed in both re-runs. B does not touch
the UI.

## Functional run

The same driver ran against both builds (105 compared lines: 102 identical, 3 expected differences): publish → install (health at 60 s and 180 s) → IPC
smoke with firewall enforcement → data roots and ACLs → robustness matrix → recovery. Then came a
per-command probe script and the access probes. Ids, timestamps, uptimes and live counts were
normalised before the comparison.

| Area | Checks | Result |
|---|---|---|
| Publish and install: exit codes, service image path, LocalSystem account, health at 0/60/180 s | 10 | identical |
| IPC smoke: `serviceHealth`, `capabilities`, `rules.query`, `protection.status/enable/disable`, `rule.apply/verify/remove`, `snapshot` | 12 | 11 identical, 1 expected difference |
| Enforcement: `curl.exe` 200 → blocked (exit 7) after `rule.apply` → 200 after `rule.remove` | 3 | identical |
| File listings under `C:\ProgramData\Axiom`, `C:\Program Files\Axiom` and the LocalSystem profile's `LocalAppData\Axiom` | 3 lists | identical |
| `icacls` of `C:\ProgramData\Axiom`, every file in it, the service directory and `Axiom.Service.exe` | 9 | identical |
| Robustness: malformed JSON, empty line, invalid UTF-8, 11 envelope shapes, 70 KiB / 2 MiB requests, unknown command, bad payloads, gate closed, idle client (EOF after about 30 s), disconnect mid-request, 20 concurrent clients, 200 rapid connects, stop with a client connected, start after stop | 40 | identical |
| Restart persistence: enable, apply a block rule, restart the service, status/verify/firewall/curl after the restart, remove, disable, 0 Axiom rules at the end | 14 | 12 identical, 2 expected differences |
| Recovery: `networkRecovery.capture` / `restore` over IPC, `--recover-network` dry run (exit 1), `--apply` while the service runs (exit 6), `--apply` with the service stopped (exit 5), restart, firewall rules and DNS afterwards | 11 | identical |
| Phase markers and the event-2001 lookup | 3 | identical |
| Per-command probes: `config.get`, `diagnostics.export`, `live.events`, `history.query` (none / wrong / valid payload), `traffic.history`, `privacy.status`, `threatshare.status`, `networkRecovery.capture/restore`, `protection.lockdown`, `rule.*` error paths, unknown command, firewall rule count | 20 | identical |
| Access: NETWORK logon (SSH) denied; `tester` (a different user, password batch logon) denied for read and write; `axiom` S4U (limited token, same SID) allowed, write gate closed | 6 | identical |

The 3 expected differences are all the `pending` list in the `protection.enable`/`status`
replies. That list is the live ask queue: which applications were making connections at that
moment (`MsMpEng.exe`, `msedgewebview2.exe`, `curl.exe` and so on). The fields, the
`ownedRuleCount` and the other values are the same.

Notes:

- The recovery restore ends in `failed` / exit 5 on **both** heads. The snapshot on the VM is
  from an earlier run, and its adapter id no longer reads back (`dns_verify_missing`). The
  outcome, messages and exit codes are byte-identical. What this shows is that the
  `ServicePlatform` hooks (snapshot path, elevation check, service-running check, adapters,
  actor) behave the same. It does not show a successful restore on this VM.
- Log event 2001 keeps the Windows text `Pipe <pipe> allows SID <sid>`. Its message template
  changes from `Pipe {Pipe} allows SID {Sid}` to `{Kind} {Endpoint} {Verb} {Callers}`, so the
  structured property names in that one event are different. The VM's Application log has no
  `Axiom` provider entries on either head, so the rendered line was not compared at runtime.

## Clean-up

`Axiom.Service.exe --uninstall-service` exited 0. Afterwards the service was absent, there were
0 Axiom firewall rules, no `Ax*` scheduled tasks and no `Axiom.Service` process. The temporary
password file was deleted after each access run, and its absence was checked. The VM was then
shut down. The uninstaller leaves `C:\Program Files\Axiom\Service\Axiom.Service.exe` in place,
as it does on the base (`ServiceInstaller` is not changed by this PR).
