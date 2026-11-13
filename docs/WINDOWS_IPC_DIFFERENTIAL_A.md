# Windows differential test: `origin/main` vs this branch (shared IPC dispatcher)

This branch moves the firewall write gate to `Axiom.Core` and moves the request loop of the Windows
pipe server into the portable `IpcRequestDispatcher` (new `Axiom.Service.Hosting`). On Windows
`PipeServer` passes `IpcCaller.FullAccess(sid)`, so the read-only and redacted access classes of
`IpcCommandAccess` never narrow a Windows caller. The goal of this test was to show that a Windows
user sees no change in behaviour.

| | Build |
|---|---|
| main | `77cc50a` (`origin/main`, release 0.17.0) |
| A | `c0789b0` (this branch, 3 commits on `77cc50a`) |

## Environment

- Windows 11 VM (QEMU/KVM, 3 GB RAM). The `axiom` admin user is logged on at the console. A
  second local user, `tester`, is used for the access probes.
- .NET SDK 10 (win-x64). Each head is built from a `git archive` of its commit.
- The service is published with `dotnet publish src/Axiom.Service -c Release -f net10.0-windows
  -r win-x64 --self-contained -p:PublishSingleFile=true` and installed through the product's own
  `Axiom.Service.exe --install-service --allowed-sid <axiom SID>` (runs as LocalSystem).
- The pipe ACL denies NETWORK logons. All tests and probes therefore run from scheduled tasks
  with an Interactive logon, except where a probe tests a different logon type on purpose.
- The probes talk only to `\\.\pipe\Axiom.Service.v1`, the local Windows Firewall and
  `curl.exe https://example.com` (the block/unblock target).

## Build and test suites

| Check | main | A |
|---|---|---|
| `dotnet build Axiom.sln -c Release` (Windows) | 0 warnings, 0 errors | 0 warnings, 0 errors |
| Axiom.Contracts.Tests | 142/142 | 142/142 |
| Axiom.Core.Tests | 128/128 | 128/128 |
| Axiom.Infrastructure.Windows.Tests | 68/68 | 106/106 (+38 new `IpcCommandAccessTests`) |
| Axiom.McpServer.Tests | 33/33 | 33/33 |
| Axiom.Persistence.Tests | 21/21 | 21/21 |
| Axiom.Presentation.Tests | 81/81 | 81/81 |
| Axiom.Service.Tests | 70/70 | 70/70 |
| Axiom.UI.Avalonia.Tests | 37/37 | 37/37 |
| Axiom.UI.Tests | 144/146 | 144/146 (the same 2 `AgentHookScriptTests` fail on both: the VM has no `python` alias) |

On Linux, `Axiom.sln` (`-p:EnableWindowsTargeting=true`) and `Axiom.Portable.slnx` both build
with 0 warnings and 0 errors.

## Smoke run (install → IPC → firewall block → remove)

The same script ran against both builds. After normalising ids, timestamps and live counts, 43 of
46 lines match. The 3 lines that differ:

| Line | main | A | Reason |
|---|---|---|---|
| install exit code | 1060 | 0 | main was the first install on a clean VM (no service to replace yet); A replaced it. |
| first `serviceHealth` | 6 limitations | `limitations: []` | A was queried at uptime 0, before the first capture (`lastCaptureUtc: null`, `connectionCount: 0`). See below. |
| `protection.enable` | pending list | pending list differs | The live list of pending apps depends on which processes had sockets at that moment. |

Block/unblock worked on both builds: curl returned 200 before the rule, exit 7 while blocked and
200 after the rule was removed. After cleanup, 0 `Axiom*` firewall rules were left.

## The empty `limitations` on A's first `serviceHealth`

`serviceHealth` is answered by `PipeServerWorker.CreateHealth`, which this branch does not change
(`git diff 77cc50a -- src/Axiom.Service/PipeServerWorker.cs` is empty). The dispatcher calls the
same `healthProvider` delegate, and Windows callers get `FullAccess`, so the redacted health of
`IpcCommandAccess` is never used. `Limitations` comes from `cache.Latest?.Limitations ?? []`, so
it is empty until the first connection snapshot exists. Main was first queried at uptime 5 s and
A at uptime 0 s.

To check this, both builds were reinstalled and queried at the same uptime:

| Uptime | main | A |
|---|---|---|
| 60 s | 6 limitations, `lastCaptureUtc` set | the same 6 limitations, `lastCaptureUtc` set |
| 180 s | 6 limitations | the same 6 limitations |

At the same uptime the results match. This is a timing artefact, not a regression, so no code
change was needed.

## Robustness and error-handling matrix

The same script (64 checks) ran against each build. Each run started 3 minutes after installing a
fresh service, so both had the same uptime. Ids, timestamps, uptime, live counts and the pending
list are normalised; durations are rounded to whole seconds.
**Result: 64 of 64 checks match. No regressions and no expected differences.**

| Check | Result on main and A (the same) |
|---|---|
| malformed JSON | `invalid_request` "Malformed JSON envelope." (zero id); service still alive |
| empty line | `invalid_request` "Malformed JSON envelope."; the server then closes the connection (a request sent next on the same connection fails with "Pipe is broken") |
| invalid UTF-8 bytes | `invalid_request` "Malformed JSON envelope." |
| invalid UTF-8 in a string | decoded to U+FFFD, then `unknown_command` |
| `{}`, `{"version":1}`, missing `type`, id is a number or not a GUID, `type` is a number, JSON array | `invalid_request` "Malformed JSON envelope." |
| `null` | `invalid_request` "Empty envelope." |
| missing `id` | accepted; answered with a generated id |
| `version: 2` | `invalid_request` "Unsupported protocol version 2." |
| `version: "1"` (string) | accepted |
| 70 KiB request | answered normally |
| 2 MiB request | the server closes the pipe while the request is still being written ("Pipe is broken"); service still alive |
| unknown command | `unknown_command` |
| `rule.remove` with an invalid or unknown GUID, `rule.apply` with a wrong payload type, a bad enum value, or with the gate closed | `not_supported` "Firewall writes are disabled on this service." (gate checked before payload validation); 0 rules created |
| `rule.verify {}` | `invalid_request` "Rule verify payload is invalid." |
| `history.query "yesterday"` | `invalid_request` "History query payload is invalid." |
| idle client (connects, sends nothing; up to 120 s) | the server closes the connection after about 30 s |
| disconnect in the middle of a request | service still alive |
| 20 clients that all connect, send and keep the connection open | 4 connect and get an answer; 16 time out in `Connect` (the server has 4 pipe instances, and the test held each connection open until it had sent all 20 requests) |
| 200 quick connect/disconnect cycles | 200/200 connect; service still alive |
| service stopped while a client is connected | the client's pending read returns 0 bytes (EOF); the service stops cleanly and restarts |
| restart persistence | `protection.enable` → `rule.apply` (block curl.exe) → 1 rule, curl exit 7 → service restart → `protection.status` still enabled, `rule.verify` presentInOs/matchesSpec/block, curl still exit 7 → `rule.remove` → curl 200 → `protection.disable` → 0 rules |

### Access probes

| Caller | main | A |
|---|---|---|
| `axiom` over SSH (NETWORK logon) | `Connect` denied ("Access to the path is denied") | the same |
| `tester` (a second local user, batch logon) | `Connect` denied | the same |
| `axiom` S4U, not elevated | `serviceHealth` answered in full (6 limitations); `rule.apply` gets `not_supported` (gate closed) | the same |

## Desktop

The Windows desktop from this branch (`Axiom.Desktop.Avalonia.Windows`, self-contained win-x64)
ran in the console session. Screenshots were compared with the main build:

- Agent Dashboard: the same layout and counters (0/0/0/0); "Blackbox is unavailable … (127.0.0.1:9700)" appears on both.
- Network Dashboard: the same cards, throughput chart, connection events and top applications. Only the live counts differ.
- Network Control: the same on both. Axiom Shield shows OFF / "unknown" / "Checking the local
  service…", the Windows Firewall card shows READ-ONLY and "Service required · disabled", and the
  page reports "No Windows Firewall policy was read in in-process mode". Main shows the same text
  when started the same way (without `--service`), so this is not caused by this branch.

## Not covered

- The test ran on one VM. Group Policy-managed firewalls and domain-joined machines were not tested.
- The probe for 20 clients at once measures the 4-instance pipe limit together with the test's
  own way of holding connections open. It shows that both builds behave the same, not how much
  load the service can take.
