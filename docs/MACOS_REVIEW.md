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
4. **Developer ID activation path unproven.** `build.sh` signs `axiom-sysext` as a secondary executable with
   restricted entitlements (`system-extension.install`, `networkextension`). With SIP on, those need a provisioning
   profile, and `Contents/embedded.provisionprofile` vouches only for the main executable. Ad hoc + SIP off never
   checks this. Fix: submit `OSSystemExtensionRequest` from the main `Axiom` process via a small Swift dylib
   (P/Invoke), or ship the helper as its own `.app` with its own profile.
5. **Upgrade path keyed on version strings that never change.** `package-app.sh` skips `build.sh` when
   `macos/build/axiom-sysext` exists and does not pass `AXIOM_VERSION`; `AXIOM_BUILD` defaults to 1; the helper keeps
   the installed extension when version+build match. A release upgrade would keep old filter code.
   Fix: always rebuild, `AXIOM_VERSION=$VERSION`, `AXIOM_BUILD` from CI, compare cdhash or force on version change.
6. **Rejected rules are invisible.** `RuleStore.swift:155` only os_logs a skipped rule; daemon and UI believe it is
   enforced. Fix: `filter.rules {generation, applied, rejected:[{id,reason}]}` event; show on the Firewall page.

## Medium

7. Upstream resolvers discovered once (`PrivacyShieldController.cs:346`); Wi-Fi/VPN switch while the shield is on
   leaves dead upstreams -> machine-wide DNS outage. Re-discover on `State:/Network/Global/DNS` change or on failure.
8. Deleting/moving the bundle with the shield on strands DNS at 127.0.0.1 (KeepAlive loops on a missing program,
   no restore). Follows from #1; add `axiomd --restore-dns`.
9. `KeepAlive=true` restarts a clean exit forever; single unbounded log file. Use `KeepAlive {SuccessfulExit:false}`
   and a `newsyslog.d` entry.
10. libproc fallback scans every pid every second, twice (`MacConnectionSource`, `MacDnsProcessLookup`). Share one
    scanner, poll 2-5 s, or use `net.inet.tcp.pcblist_n`.
11. Rule file read via path twice (stat then read, follows symlinks). Enforce root-only invariant:
    `open(O_NOFOLLOW)`, `fstat`, `st_uid==0 && !(mode & 022)`, read from the fd.
12. Attribution is the socket owner, not the app: WebKit networking, `nsurlsessiond`, translocated apps will not
    match `/Applications/Foo.app` prefix rules; `hasPrefix` is case-sensitive on case-insensitive APFS; `/var` vs
    `/private/var`. Daemon writes `realpath()`, filter compares case-insensitively, consider the responsible pid.
13. Loopback flows evaluated by ordinary rules: "block app X" also kills its DNS through the Privacy Shield proxy.
    Skip loopback unless the rule names it (Windows Firewall ignores loopback).
14. `EventSink.send` does one `queue.async` per event before the bounded queue applies: a flow flood grows the
    dispatch backlog. `statisticsReportFrequency = .medium` emits ~1 event/s per live flow. Atomic in-flight counter,
    `.low` or batched stats.
15. Autostart LaunchAgent pins the current path (translocated for quarantined apps). Use
    `open -b com.axiom.firewall --args --autostart` or `SMAppService.loginItem`.
16. `package-app.sh` codesigns every regular file with `--timestamp` (hundreds of timestamp calls, signs .json/.pdb).
    Sign Mach-O only; produce dSYMs. Docs claim a `.pkg` is produced; it is not.
17. macOS 13/14 code paths (`NWHostEndpoint`, `NENetworkRule(remoteNetwork:)`, deprecated in 15) compiled but
    never run; add `#available(macOS 15)` branch with `nw_endpoint` initialisers before Tahoe removes them.
18. Dead .NET `FilterRuleMatcher` (204 lines, tests only). Delete, or make it a cross-language contract test sharing
    fixtures with the Swift tests.

## Low

19. Legacy `SecKeychainFind/AddGenericPassword`; ad hoc re-signs change the item ACL -> Keychain prompts on every
    rebuild. Migrate to `SecItemAdd/CopyMatching`.
20. IPC DoS: 16 slots x 30 s idle, any user. Per-uid cap.
21. Single-instance race between `TryAcquire` and `Listen`; second launch may exit without showing the window.
22. Three near-identical "run tool with timeout" helpers; `PipeServerWorker` branches only for a log string.
23. Unconnected UDP sockets get one verdict; document. `exit(0)` after `stopFilter` logs as unexpected exit; document.
24. `deploy-to-vm.sh` hardcodes `/home/buba`; mark dev-only.
25. Cosmetic: menu offers Install/Turn On while running; Overview says "read-only inventory" with the shield on;
    Privacy Shield redirects inactive network services; AppleScript quit reports -128.

## Test gaps

- Swift: `EventSink` (drop-oldest, framing), `RuleStore` watch/poll races, IPv6/UDP/QUIC traffic, translocation,
  upgrade-replace, crash relaunch. No CI.
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
