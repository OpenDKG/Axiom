# macOS port review (2026-11-11, branch buba/macos @ 30748b5)

Two independent read-only reviews (Swift filter + packaging; .NET daemon, infra, desktop host). Findings marked
[verified] were confirmed on the VM or in source by the integrator.

## Critical

1. **Root daemon runs a user-owned binary.** [verified] [FIXED 1388da4: `--install-service` copies the publish dir to
   `/Library/PrivilegedHelperTools/com.axiom.service` (root:wheel, 0755/0644), verifies owner/mode with `stat` and
   refuses to bootstrap otherwise; plist points there; `--uninstall-service` removes it and restores DNS; see
   MACOS_ARCHITECTURE.md §5.3 and MACOS_TEST_REPORT.md "Hardening".] `LaunchdServiceInstaller.cs:72` points `ProgramArguments`
   at `Environment.ProcessPath` = `/Applications/Axiom.app/Contents/Resources/service/axiomd`; in the VM that file
   is `dev:staff 0755`. launchd checks the plist owner, not the program. Any process of the installing user can
   replace `axiomd` or a neighbouring `.dll`/`.dylib` and get root at the next restart. Windows is safe because
   Program Files is admin-only.
   Fix: `--install-service` copies the publish dir to a root-owned location
   (`/Library/PrivilegedHelperTools/com.axiom.service/`), verifies owner/mode before bootstrap, and the plist points
   there. Long term: signed `.pkg` with postinstall, or SMAppService with a code-signing requirement.

## High

2. **Any local uid >= 501 can drive machine-wide state.** [FIXED afb60ba: write commands only for root, the
   installing uid (`ProtectionSettings.AllowedUid`, recorded by `--install-service`) and `admin` group members
   (`AllowAdminGroupWrites`, default true); every IPC command is classified in `IpcCommandAccess` (test-enforced,
   unknown = write); other users get `unauthorized` and the denial is logged; see §5.4.] `PeerAuthorization.cs`, socket mode 0666. A standard
   account can `privacy_configure` with an attacker upstream (DNS hijack for all users), apply/remove rules for every
   user, toggle protection, and read all users' history. Windows restricts to one persisted SID.
   Fix now: write commands only for the installing uid (persist like `AllowedSid`) or `admin` group members;
   read commands for uid >= 501. Later: authorize by code-signing identity (audit token -> `SecCodeCopyGuestWithAttributes`
   -> TeamID/bundle requirement) or launchd socket activation + XPC.
3. **Machine data directory is world-readable.** [verified] [FIXED 0f31d68: data root 0700, `filter/` 0755,
   `rules.json` 0644, every other daemon file 0600 — enforced at daemon start (`MacDataDirectoryPermissions`) and at
   write time (mode set on the temp file before the atomic rename; SQLite db/-wal/-shm after open); docs fixed.] `axiom.db`, `-wal`, `-shm`, managed-rules.json are
   `root:admin 0644`; `FilterRulesFile.PublishedMode` 0644 is also used for the DNS backup although the docs say
   0600. Fix: data root 0700 (`filter/` 0755 for the extension), `UnixCreateMode` on every store write, fix docs.
4. **Developer ID activation path unproven.** [FILTER HALF DONE 3bae86e: `build.sh` builds `libAxiomSysext.dylib`
   (`axiom_sysext_activate/deactivate/set_filter/status`, JSON out, `SysextCore.swift` shared with the helper) so the
   main `Axiom` process can submit the requests itself; README "Which activation path for Developer ID builds"
   recommends it and lists the signing contract (`Axiom` signed with `axiom-sysext.entitlements`).] [.NET HALF DONE
   0ab52e6: `FilterExtensionManager` P/Invokes `libAxiomSysext.dylib` from `Contents/MacOS` (`DylibSysextLibrary`,
   worker thread, `axiom_sysext_free`), falls back to the `axiom-sysext` child process when the dylib is missing or
   throws `DllNotFound`/`EntryPointNotFound`/`BadImageFormat`, logs the path used; `package-app.sh` ships + signs the
   dylib; `Axiom.entitlements` carries `system-extension.install`, `networkextension` and the app group. VM: `activate
   via dylib … state=activated`, extension `[activated enabled]`, daemon `AxiomFilter connected`. Developer ID itself
   still unverified (no team).] `build.sh` signs `axiom-sysext` as a secondary executable with
   restricted entitlements (`system-extension.install`, `networkextension`). With SIP on, those need a provisioning
   profile, and `Contents/embedded.provisionprofile` vouches only for the main executable. Ad hoc + SIP off never
   checks this. Fix: submit `OSSystemExtensionRequest` from the main `Axiom` process via a small Swift dylib
   (P/Invoke), or ship the helper as its own `.app` with its own profile.
5. **Upgrade path keyed on version strings that never change.** [FIXED 3bae86e (filter side): `build.sh` fails without
   `AXIOM_VERSION` when `AXIOM_SIGN_IDENTITY` is set, dev builds default to `0.0.<commits>` / `<commits>.<timestamp>`;
   `activate` replaces on version/build or cdhash difference (`SecCodeCopySigningInformation`), `--force` always;
   README "Versioning" is the contract for `package-app.sh` (must export both and always rebuild). Verified: three
   consecutive dev builds each replaced the previous one, `systemextensionsctl list` shows the new build; a repeated
   `activate` with the same cdhash keeps it (`replaced:false`). 33ac363/ba8f715: ad hoc helpers also re-create the
   NEFilterManager configuration after an upgrade — without that nesessionmanager rejects the session and the filter
   silently allows everything. `package-app.sh` passing the version is the other agent's item.] `package-app.sh` skips `build.sh` when
   `macos/build/axiom-sysext` exists and does not pass `AXIOM_VERSION`; `AXIOM_BUILD` defaults to 1; the helper keeps
   the installed extension when version+build match. A release upgrade would keep old filter code.
   Fix: always rebuild, `AXIOM_VERSION=$VERSION`, `AXIOM_BUILD` from CI, compare cdhash or force on version change.
6. **Rejected rules are invisible.** [FIXED 9366faa: `filter.rules {generation, applied, rejected:[{id,reason}], error,
   dropped}` after every reload (right after `filter.hello`), and with `error` when the file itself was rejected; §3.2.
   UI display is the .NET side.] [UI HALF DONE a3bf1b5: `FlowEventParser` parses `filter.rules`, `FilterStatus`
   keeps the latest report, `rules.query`/`capabilities` expose `capability.filterEnforcement {generation,
   appliedRuleCount, rejectedRules:[{ruleId,reason}], fileError, droppedEvents}` and `rule.verify` sets
   `filterRejectionReason` (no effective action); the Firewall page shows "N rule(s) not enforced by the filter" with
   id + reason and a banner for a rejected file / dropped events. VM: `remoteAddresses:["1.2.3"]` (accepted by the
   daemon, rejected by the filter) → `screenshots/macos/firewall-rejected-rules.png`.] `RuleStore.swift:155` only os_logs a skipped rule; daemon and UI believe it is
   enforced. Fix: `filter.rules {generation, applied, rejected:[{id,reason}]}` event; show on the Firewall page.

## Medium

7. [FIXED 5d5189e: `UpstreamRediscovery` polls `DiscoverUpstreams()` every 10 s (2 s after 3 consecutive upstream failures, `DnsProxyServer.UpstreamFailureStreak`) and `DnsProxyServer.UpdateUpstreams` swaps the list without touching the listener; a loopback-only discovery (our own 127.0.0.1) uses the backup's saved servers; macOS only, Windows unchanged.] Upstream resolvers discovered once (`PrivacyShieldController.cs:346`); Wi-Fi/VPN switch while the shield is on
   leaves dead upstreams -> machine-wide DNS outage. Re-discover on `State:/Network/Global/DNS` change or on failure.
8. [FIXED 99ce513: `axiomd --restore-dns` restores from the backup without the daemon; the daemon runs from the root-owned helper dir (#1) so moving the bundle does not remove the program; with `{SuccessfulExit:false}` + `ThrottleInterval` a missing program cannot hot-loop.] Deleting/moving the bundle with the shield on strands DNS at 127.0.0.1 (KeepAlive loops on a missing program,
   no restore). Follows from #1; add `axiomd --restore-dns`.
9. [FIXED 99ce513: `KeepAlive {SuccessfulExit:false}`, `ThrottleInterval 10`, `/etc/newsyslog.d/com.axiom.service.conf` (5 MB, keep 5, compressed) written by `--install-service`, removed by `--uninstall-service`; tests.] `KeepAlive=true` restarts a clean exit forever; single unbounded log file. Use `KeepAlive {SuccessfulExit:false}`
   and a `newsyslog.d` entry.
10. [FIXED 2ac3c5f: `LibProcSocketScanner.Shared` — one pass per 2 s shared by `MacConnectionSource` and `MacDnsProcessLookup`, a DNS miss refreshes at most every 500 ms; test asserts 5 passes for ten 1 s polls and no second pass for a burst of misses.] libproc fallback scans every pid every second, twice (`MacConnectionSource`, `MacDnsProcessLookup`). Share one
    scanner, poll 2-5 s, or use `net.inet.tcp.pcblist_n`.
11. [FIXED 9366faa: `RuleStore.loadFile` = `open(O_RDONLY|O_NOFOLLOW|O_CLOEXEC)`, `fstat`, regular file, uid 0,
    `!(mode & 022)`, size cap, read from the fd; rejection keeps the last table, is logged once per reason and reported
    in `filter.rules.error`. Unit + e2e tested (chown 501 / chmod 666 / symlink).] Rule file read via path twice (stat then read, follows symlinks). Enforce root-only invariant:
    `open(O_NOFOLLOW)`, `fstat`, `st_uid==0 && !(mode & 022)`, read from the fd.
12. [FIXED 9366faa: rule paths realpath'd on load, flow paths realpath'd once per (pid, pidversion) and cached,
    comparison case-insensitive; responsible pid via `responsibility_get_pid_responsible_for_pid` (dlsym) emitted as
    `responsiblePid`/`responsiblePath`, rules match owner **or** responsible path. App Translocation documented as a
    limitation. The daemon writing realpath is optional now.] Attribution is the socket owner, not the app: WebKit networking, `nsurlsessiond`, translocated apps will not
    match `/Applications/Foo.app` prefix rules; `hasPrefix` is case-sensitive on case-insensitive APFS; `/var` vs
    `/private/var`. Daemon writes `realpath()`, filter compares case-insensitively, consider the responsible pid.
13. [FIXED 9366faa: loopback destinations are exempt unless `remoteAddresses` names a loopback address; flows still
    reported. Unit + e2e tested.] Loopback flows evaluated by ordinary rules: "block app X" also kills its DNS through the Privacy Shield proxy.
    Skip loopback unless the rule names it (Windows Firewall ignores loopback).
14. [FIXED 9366faa: in-flight counter (4096) checked before `queue.async`, drops counted and reported as `dropped` in
    `filter.hello`/`filter.rules`; backlog is a testable `EventQueue`; `.medium` kept but `flow.stats` coalesced to one
    per flow per 2 s.] `EventSink.send` does one `queue.async` per event before the bounded queue applies: a flow flood grows the
    dispatch backlog. `statisticsReportFrequency = .medium` emits ~1 event/s per live flow. Atomic in-flight counter,
    `.low` or batched stats.
15. [FIXED 11871d6: ProgramArguments `/usr/bin/open -b com.axiom.firewall --args --autostart` when running from a bundle; the executable path only as fallback; an old pinned plist reads as stale and `Repair` upgrades it; tests.] Autostart LaunchAgent pins the current path (translocated for quarantined apps). Use
15. [Swift part done 9366faa: a rejected rule is logged once per (id, reason), not per reload.] Autostart LaunchAgent pins the current path (translocated for quarantined apps). Use
    `open -b com.axiom.firewall --args --autostart` or `SMAppService.loginItem`.
16. [FIXED da36443: signs Mach-O files only (magic bytes, deepest first), `--timestamp` only with a Developer ID identity, `dsymutil` for the Swift extension/helper when `AXIOM_SIGN_IDENTITY` is set (no dSYM for .NET; portable pdb stays in `publish/`), and `Axiom.pkg` via `pkgbuild` with a postinstall that runs `axiomd --install-service` (`AXIOM_INSTALLER_IDENTITY` to sign it).] `package-app.sh` codesigns every regular file with `--timestamp` (hundreds of timestamp calls, signs .json/.pdb).
    Sign Mach-O only; produce dSYMs. Docs claim a `.pkg` is produced; it is not.
17. [FIXED 9366faa: `NENetworkRule(remoteNetworkEndpoint:…)` under `#available(macOS 15)`, legacy path in
    `@available(macOS, deprecated: 15.0)` helpers; `build.sh` compiles with `-warnings-as-errors` (clean on the 15.8
    SDK).] macOS 13/14 code paths (`NWHostEndpoint`, `NENetworkRule(remoteNetwork:)`, deprecated in 15) compiled but
    never run; add `#available(macOS 15)` branch with `nw_endpoint` initialisers before Tahoe removes them.
18. [FIXED 0016a09: `macos/Tests/fixtures/rules-cases.json` (17 address-entry cases, 8 rule sets / 22 verdict cases from the Swift unit cases) is read by `FilterRulesTests`; `FilterRuleMatcher` moved to the test project as the reference implementation. Swift side wires the same file (#other agent).] Dead .NET `FilterRuleMatcher` (204 lines, tests only). Delete, or make it a cross-language contract test sharing
    fixtures with the Swift tests.

## Low

19. [FIXED 8c7f12a: `SecItemCopyMatching/SecItemAdd/SecItemUpdate`, `kSecClassGenericPassword`, service `com.axiom.firewall`, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`; minimal CFDictionary/CFData/CFString interop; AES-GCM design and tests unchanged.] Legacy `SecKeychainFind/AddGenericPassword`; ad hoc re-signs change the item ACL -> Keychain prompts on every
    rebuild. Migrate to `SecItemAdd/CopyMatching`.
20. [FIXED ca8b752: max 4 concurrent connections per non-root uid (root unlimited), counted after authorization, released on close; test opens 4 idle sockets and shows the 5th refused.] IPC DoS: 16 slots x 30 s idle, any user. Per-uid cap.
21. [FIXED 11871d6: lock + Listen run before any other startup work; the second instance retries `SignalExisting` once after 300 ms.] Single-instance race between `TryAcquire` and `Listen`; second launch may exit without showing the window.
22. [FIXED a7b9934: `Axiom.Contracts.ToolProcess` (argument list, both streams, timeout kills the tree) backs `ProcessRunner`, `MacElevation.RunAsync` and `FilterExtensionManager`; `PipeServerWorker` has one `LoggerMessage` with the OS wording as parameters.] Three near-identical "run tool with timeout" helpers; `PipeServerWorker` branches only for a log string.
23. Unconnected UDP sockets get one verdict; document. `exit(0)` after `stopFilter` logs as unexpected exit; document.
20. IPC DoS: 16 slots x 30 s idle, any user. Per-uid cap.
21. Single-instance race between `TryAcquire` and `Listen`; second launch may exit without showing the window.
22. Three near-identical "run tool with timeout" helpers; `PipeServerWorker` branches only for a log string.
23. [DONE 045c118: both documented in `macos/README.md` "Behaviour notes" and ARCHITECTURE §3.4.] Unconnected UDP sockets get one verdict; document. `exit(0)` after `stopFilter` logs as unexpected exit; document.
24. `deploy-to-vm.sh` hardcodes `/home/buba`; mark dev-only.
25. [FIXED 11871d6: menu items read "Service: running" / "Filter: on" (disabled) once running; Overview line becomes "Protection active: firewall writes enabled…" when the resolver runs or writes are enabled; `MacDnsConfigurator.ListActiveServices` skips services whose device reports `status: inactive` (restore still covers every service). AppleScript quit: see MACOS_TEST_REPORT.md.] Cosmetic: menu offers Install/Turn On while running; Overview says "read-only inventory" with the shield on;
    Privacy Shield redirects inactive network services; AppleScript quit reports -128.

## Test gaps

- Swift: `EventSink` (drop-oldest, framing), `RuleStore` watch/poll races, IPv6/UDP/QUIC traffic, translocation,
  upgrade-replace, crash relaunch. No CI.
- .NET: [DONE 2ac3c5f: `MacConnectionSourceAndIdentityTests`] ~~`MacConnectionSource` aggregation/dedupe, `MacProcessIdentityResolver` cache/promotion~~, `LibProcLayout`
- Swift: [PARTLY DONE 9366faa: 147 checks — `EventQueue` drop-oldest/partial-line framing, sink in-flight limit +
  `dropped`, wire framing over a real Unix socket (hello first, untrusted peer refused), `RuleStore` identity
  rejection + reload/keep-last-table, loopback, case/realpath/responsible matching, `filter.rules` JSON; shared
  fixtures `Tests/fixtures/rules-cases.json` (9 groups, 36 cases). Upgrade-replace verified manually in the VM.]
  Still open: IPv6/UDP/QUIC traffic, translocation, crash relaunch. No CI.
- .NET: `MacConnectionSource` aggregation/dedupe, `MacProcessIdentityResolver` cache/promotion, `LibProcLayout`
  against a real arm64 dump, `ChildSignal`, getpeereid path, `MacProtectionSetup` flows (VM-only).
- Apple silicon: never executed. Developer ID / notarization: never executed.

## What is good

- Verdict path does no IO, immutable rule table swapped under a lock; invalid rules never widen to "any"; last good
  table kept; explicit `flow.close` for dropped flows.
- Clean seams (`IIpcTransport`, `IPrivacyDnsPlatform`, `IConnectionSnapshotSource`, `IProcessRunner`); the 957-line
  dispatcher extraction removed a Windows-only duplicate instead of adding one.
- No shell invocations anywhere; XML/plist escaping; bounded line readers; atomic temp+rename writes; DNS
  backup-before-change with retry and "unknown state" handling.
- Windows path results verified byte-identical; libproc layouts verified against SDK headers; LP64-identical on arm64.
- Honest docs and test report.

## Strategic

1. Root-owned daemon install via signed `.pkg` (postinstall copies, chowns, bootstraps; uninstall restores DNS).
2. Authorize by code-signing identity, or XPC over `NEMachServiceName` for filter<->daemon and launchd socket
   activation for app<->daemon; removes rule-file trust and lets the extension be sandboxed.
3. Activation from the main `Axiom` process (Swift dylib) so entitlements, profile and `Bundle.main` line up.
4. CI matrix: macos-14 (arm64) + macos-13 (x64) runners build both RIDs, run the MacOS test projects natively,
   `swift test`, `codesign --verify`, layout test against `lsof`; Linux leg for pure tests; Windows leg for path parity.
5. Upstream PR plan, in this order: (a) zero-behaviour refactors (AxiomPaths, FirewallWriteGate, IpcRequestDispatcher,
   seams, PlatformText/AgentPlatform); (b) Infrastructure.MacOS + tests; (c) Service dual-TFM; (d) Desktop host;
   (e) UI fixes; (f) Swift extension + packaging.
6. `axiomd --doctor`: prints socket modes, owners, DNS backup state, launchd status. Would have caught #1, #3, #8.
   [DONE ba292ef: `axiomd --doctor [--json]` — launchd state/program, plist target+owner, helper dir audit, socket
   modes, data root and per-file modes, DNS per service + backup, Privacy Shield state, filter extension; exit 0 only
   when every check passes; root-only checks are SKIP for a normal user.]


# GitHub review 2026-11-12 (PR #274, reviewer a-51-50, branch `buba/macos-desktop` on v0.13.2)

Principle applied (upstream `docs/ENFORCEMENT.md`): observation is not enforcement; never render a verified claim
without a real boundary. Base merged first: `79f4ff3` (origin/main `6ff6061`, v0.13.2, one conflict in
`AiAnalystPageViewModel.cs` resolved keeping upstream's `_suppressApiKeyInputChanged` guard).

| # | Severity | File:line | Finding | Fix | Commit |
|---|---|---|---|---|---|
| 1 | P0 | `src/Axiom.Infrastructure.MacOS/Ipc/PeerAuthorization.cs:99` | any uid ≥ 501 got `Allowed=true` read-only, exposing `snapshot`, `live.events`, `history.query`, `diagnostics.export`, `privacy.status`, `threatShare.status` on the 0666 socket | ☑ three command classes (`IpcCommandAccess`: PublicRead / PrivateRead / Write, every `IpcCommandTypes` constant in exactly one, reflection test); `PeerDecision` adds `CanReadPrivate`; pure `PeerAuthorization.Decide(uid, policy)`: root and the installing uid read and write, admins per `AllowAdminGroupWrites`, every other uid gets only redacted `serviceHealth` + `capabilities`, unknown credentials are closed; the shared dispatcher denies with `unauthorized` before any handler. Tests: `PeerAuthorizationTests` (owner/admin/other/root/unknown over every private read and write), `UnixSocketIpcTests.SecondStandardUserGetsPublicHealthOnlyOverTheSocket` (real socket, uid 502), `IpcCommandAccessTests`. | `b200c00` |
| 2 | P0 | `src/Axiom.Infrastructure.MacOS/Filter/MacFirewallPolicyAdapter.cs:164` | `UpsertOwnedRuleAsync` returned `Success/Applied/VerifiedUtc` from a readback of rules.json without extension acknowledgement | ☑ write → bounded wait (2 s) for the `filter.rules` ack of the published generation → `Applied` (verifiedUtc = ack time) only when connected + exact generation acked + no file error + rule not rejected; `Pending` ("awaiting AxiomFilter acknowledgement of generation N (…)") otherwise; `Failed` with the filter's reason for a rejected rule/file; stored state projected through the live snapshot; coordinator stores Pending as Pending. Tests: `FilterEnforcementLifecycleTests` (12 scenarios of handoff §5/§6), `FilterRulesTests`, `FirewallRuleCoordinatorTests.Apply_pending_is_stored_as_pending_not_applied`. | `7b2a95b` |
| 3 | P0 | `MacFirewallPolicyAdapter.cs:393` | `Verify` derived `EffectiveAction` from the on-disk rule while the filter was disconnected or on an older generation | ☑ `effectiveAction` only under the same enforcement conditions, else null + note (never connected / disconnected, last seen / acknowledged G, not N / rejected); new `EffectiveRuleReport.EnforcementVerified` (null on Windows). Tests in `FilterEnforcementLifecycleTests` (absent, older generation, disconnect after enforce, filter restart with stale ack, rejected). | `7b2a95b` |
| 4 | High | `src/Axiom.Infrastructure.MacOS/Filter/FilterStatus.cs:215` | `HasRecentHello` treated a disconnected extension as active for 10 min; `GetCapabilitiesAsync` used it for `FirewallServiceRunning` | ☑ `HasRecentHello`/`HelloLifetime` removed; `FilterStatus` keeps `LastSeenUtc` (diagnostic), `IsConnected` (live count), `AckedGeneration` (per connection) and derives `Unavailable/Degraded/Pending/Verified`; disconnect degrades immediately; the daemon republishes on every filter connection so a reconnect needs a fresh ack; `FirewallServiceRunning` = connected now, `status = degraded` while disconnected; `filterEnforcement {state, connected, publishedGeneration, ackedGeneration, lastSeenUtc, lastAckUtc}`; Firewall page shows connected/disconnected (last seen) and pending truthfully. Tests: `FilterEnforcementLifecycleTests` (FilterStatus block), `FilterRulesTests.CapabilitiesReportLiveConnectionNotRecentHello`, `FilterEnforcementSummaryTests.Unverified_enforcement_is_a_banner_never_an_enforces_line`. | `7b2a95b` |
| 5 | Medium | `src/Axiom.Infrastructure.MacOS/Launchd/LaunchdServiceInstaller.cs:165` | newsyslog entry mode 644 for the daemon log (and launchd created it 0644) | ☑ `MacLogPermissions`: log dir 0700, log + archives 0600, pre-created by the installer before launchd opens it, fixed on upgrade, re-applied at daemon start; newsyslog mode `600`. Tests: `MacLogPermissionsTests`, `LaunchdServiceInstallerTests` (install, upgrade with a 0644 log/archive, uninstall). | `5dd4532` |

VM evidence for all five: `docs/MACOS_TEST_REPORT.md` rows AF–AL.
