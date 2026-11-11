# Axiom for macOS — port report for the maintainer

Date: 2026-11-11. Branch `buba/macos` (52 commits on top of `main` f08ffdd / v0.10.6). Not pushed; local only.
Scope: 247 files, +23.3k / −1.6k lines. Shared (Windows-relevant) code: 99 files, +2.6k / −2.2k, mostly
extraction into portable projects. The WPF projects (`Axiom.UI`, `Axiom.Desktop`) are untouched except 26 lines.

Detailed docs in the branch: `docs/MACOS_ARCHITECTURE.md` (contract + as built), `docs/MACOS_TEST_REPORT.md`
(rows A–AE with evidence), `docs/MACOS_REVIEW.md` (two independent reviews, all 25 findings ticked with commit
ids), `macos/README.md` (Swift filter), `docs/screenshots/macos/` (every page).

## 1. What was accomplished

Axiom runs on macOS with the same shared Core/Contracts/Persistence/Presentation/UI.Avalonia code as Windows,
plus three macOS-specific pieces:

| Piece | Windows counterpart | Where |
|---|---|---|
| `Axiom.app` desktop host (Avalonia, menu-bar icon, native menu, Keychain, LaunchAgent autostart, single instance) | `Axiom.Desktop.Avalonia.Windows` | `src/Axiom.Desktop.Avalonia.MacOS` |
| `axiomd` launchd root daemon (same `Axiom.Service` project, `net10.0` target) | Windows service | `src/Axiom.Service` + `src/Axiom.Service.Hosting` + `src/Axiom.Infrastructure.MacOS` |
| `com.axiom.firewall.filter` NEFilterDataProvider system extension (Swift) + `axiom-sysext` helper + `libAxiomSysext.dylib` | Windows Firewall rules | `macos/` |

Verified end to end in a macOS 15.8.3 VM through the app's own UI (all PASS):
service install via admin prompt (≈3 s), filter activation + approval, live Connections with app names,
block an app from Connections → `curl` blocked while `python3` to the same host works, unblock from the
Firewall page, Privacy Shield on/off (system DNS → 127.0.0.1, `doubleclick.net` NXDOMAIN, DNS restored),
every page rendered, menu-bar icon, quit/relaunch/single instance, upgrade in place, uninstall.

Security hardening done after an independent review: daemon copied to a root-owned
`/Library/PrivilegedHelperTools/com.axiom.service/` and verified before launch; IPC writes limited to root,
the installing user and `admin` members (reads for any uid ≥ 501); data dir 0700 / files 0600; rules file
must be root-owned and not group/world-writable; per-uid connection cap; `axiomd --doctor` self-check;
`axiomd --restore-dns` recovery.

Gate on Linux: `dotnet build Axiom.sln -c Release -p:EnableWindowsTargeting=true` 0 errors / 0 warnings.
Tests: Contracts 78, McpServer 33, Persistence 18, Presentation 24, UI.Avalonia 33, Infrastructure.MacOS 152,
Desktop.Avalonia.MacOS 35 pass; Swift filter 147 checks + 61 e2e checks pass in the VM. Pre-existing
Linux-only failures unchanged: Core 10, Service 7, Infrastructure.Windows 19 (Windows paths / FileShare).

## 2. What changed in shared code (Windows must stay byte-identical; it does, by test)

- `Axiom.Contracts.AxiomPaths`: single source for machine/user data roots and service-mode detection.
  Windows results unchanged (`%ProgramData%\Axiom`, `%LocalAppData%\Axiom`, `!UserInteractive`).
  Unix: `/Library/Application Support/Axiom`, `~/Library/Application Support/Axiom`, service = `AXIOM_SERVICE=1` or euid 0.
- `IpcPipe.Endpoint`: pipe name on Windows, `/var/run/axiom/axiom.sock` on Unix. `IpcPipeClient` uses it.
- `Axiom.Service.Hosting` (new, portable): `IpcRequestDispatcher` + handlers extracted from `PipeServer`
  (which is now transport only, old constructor kept), `DnsProxyServer`/`DnsProtocol` moved here, seams
  `IIpcTransport`, `IPrivacyDnsPlatform`, `IDnsAppAttributor`. `ProtectionWriteConsent` + new
  `FirewallWriteGate` moved to `Axiom.Core/Firewall`. Windows wrappers: `NamedPipeIpcTransport`,
  `WindowsDnsProcessLookup`, `WindowsPrivacyDnsPlatform`.
- `Axiom.Service` multi-targets `net10.0-windows;net10.0`; Windows-only files excluded from `net10.0`;
  per-OS wiring in `ServicePlatform.Windows.cs` / `ServicePlatform.Unix.cs`.
- Contracts additions (null on Windows): `LiveConnection.RemoteHost`, `ProtectionSettings.AllowedUid`,
  `FirewallCapabilityReport.FilterEnforcement`, `EffectiveRuleReport.FilterRejectionReason`.
- `Axiom.Presentation`: `PlatformText` (macOS wording), `MacElevation`, `AgentPlatform` (POSIX hook scripts,
  no `.exe`), `OptionalModuleInstaller/Uninstaller` return "not available on macOS" off Windows.
- `Axiom.UI.Avalonia`: native window chrome off Windows, vector icons instead of Segoe glyphs, selection kept
  across the 1 s refresh (fixes "Block outbound" doing nothing), Firewall page refresh on open + rejected-rules
  block, Events toolbar columns, one file re-encoded from cp1252 to UTF-8.
- `Axiom.sln` / `Axiom.Portable.slnx` gained the MacOS projects and tests.

## 3. macOS-specific notes the maintainer must know

Platform behaviour
- **Enforcement is a Network Extension, not pf.** pf has no per-app concept and the Application Firewall is
  inbound-only. The Swift extension holds its own rule table (`filter/rules.json`, written by the daemon) and
  streams flow events over `/var/run/axiom/filter.sock`. Core is unchanged; `MacFirewallPolicyAdapter`
  implements `IFirewallPolicyAdapter`.
- **Blocked TCP = connect timeout, not refusal.** NE drop verdicts swallow the SYN; apps see a ~30 s hang.
  ICMP is not filterable. Unconnected UDP sockets get one verdict for the socket.
- **Enabling, disabling or upgrading the filter drops TCP connections opened while it ran**, including SSH.
  The app warns; upgrades over SSH must be detached.
- **First approval needs the GUI session**: System Settings › General › Login Items & Extensions › Network
  Extensions, then the "Filter Network Content" prompt. Deactivation over SSH fails (error 13).
- **Attribution is the socket owner.** Safari/WebKit and `nsurlsessiond` traffic belongs to the network
  process, not the app. The filter also reports and matches the *responsible* process
  (`responsibility_get_pid_responsible_for_pid`, private API, LuLu-proven); App Translocation paths of
  quarantined apps will not match `/Applications/...` rules. Paths are compared case-insensitively on realpath.
- **Loopback is exempt** unless a rule names a loopback address (Windows Firewall ignores loopback too);
  otherwise "block app X" would also kill its DNS through the Privacy Shield proxy.
- **Fail-open.** A missing or invalid rules file keeps the last good table or allows everything at first start.
  Rejected rules are reported (`filter.rules` event) and shown on the Firewall page instead of being silent.
- **Daemon validation is looser than the filter in one spot**: `RuleSpecValidator` accepts short IPv4 forms
  like `1.2.3` (`IPAddress.TryParse`) that the filter rejects. Reported in the UI; validator not tightened.
- **DNS switching is done by the daemon**, not the app (no elevation prompt): `networksetup -setdnsservers`
  on active services, backup written before the change, restored on disable/uninstall/next start, upstreams
  re-discovered every 10 s. macOS cannot use a non-53 resolver port, so Privacy Shield only works on port 53.
- **DNS queries are usually attributed to `mDNSResponder`**, because apps resolve through it.
- **Keychain instead of DPAPI**: a random AES-GCM key in the login Keychain (SecItem API). With ad hoc
  signing every rebuild changes the identity; Developer ID avoids the prompts.
- **`Environment.UserInteractive` is always true on Unix**, `CommonApplicationData` is `/usr/share`. Never use
  them for service detection or data roots; use `AxiomPaths`.
- **Inbound socket-activated services** (sshd) are attributed to `/sbin/launchd` (pid 1).

Build, signing, distribution
- .NET parts publish on Linux (`scripts/macos/package-app.sh osx-x64|osx-arm64`); the Swift extension needs a
  Mac (Command Line Tools are enough, no Xcode). `package-app.sh --skip-publish --build-filter` on a Mac
  embeds, signs inside-out (Mach-O only) and produces `Axiom.app` and `Axiom.pkg` (pkgbuild, postinstall
  runs `axiomd --install-service`).
- Versioning contract: `AXIOM_VERSION` / `AXIOM_BUILD` are passed to the extension; the helper replaces the
  installed extension when version/build or cdhash differ; a release build fails without a version.
- **Development machines need SIP off + `systemextensionsctl developer on`** for ad hoc signed extensions.
  **Ad hoc rebuilds pin the NE filter config to the old cdhash**: the filter then reports "running" while
  allowing everything. Activation now resets the configuration on replace (one extra "Allow" prompt per dev
  upgrade). Developer ID builds should not hit this.
- **Release needs an Apple Developer Program team with the Network Extension capability** (self-serve in
  the portal per reports; unverified), Developer ID Application + Installer certificates, provisioning
  profiles for app and extension (app group becomes `<TEAMID>.com.axiom.firewall`), notarization. Env:
  `AXIOM_SIGN_IDENTITY`, `AXIOM_TEAM_ID`, `AXIOM_APP_PROFILE`, `AXIOM_INSTALLER_IDENTITY`.
- Recommended activation path for Developer ID is in-process via `libAxiomSysext.dylib` (entitlements live on
  the main executable); the `axiom-sysext` helper remains a fallback. The dylib path is proven ad hoc only.
- `publish -r osx-*` adds RID sections to `packages.lock.json`; they are reverted, not committed.

Layout on an installed Mac
```
/Applications/Axiom.app                                   user-owned bundle (app, dylib, helper, extension, service payload)
/Library/PrivilegedHelperTools/com.axiom.service/         root-owned copy of the daemon that launchd runs
/Library/LaunchDaemons/com.axiom.service.plist            KeepAlive {SuccessfulExit:false}, ThrottleInterval 10, AXIOM_SERVICE=1
/etc/newsyslog.d/com.axiom.service.conf                   log rotation (5 MB × 5)
/Library/Logs/Axiom/axiomd.log
/Library/Application Support/Axiom/                       0700; db, settings, DNS backup 0600; filter/rules.json 0644
/var/run/axiom/axiom.sock (0666, auth by getpeereid)      /var/run/axiom/filter.sock (0600, filter → daemon)
~/Library/Application Support/Axiom/                      per-user UI settings, desktop.log
~/Library/LaunchAgents/com.axiom.firewall.agent.plist     autostart via `open -b com.axiom.firewall`
```

Useful commands: `axiomd --install-service | --uninstall-service | --doctor [--json] | --restore-dns`,
`axiom-sysext activate|deactivate|enable|disable|status [--force]`, `systemextensionsctl list`,
`log stream --predicate 'subsystem == "com.axiom.firewall.filter"'`.

## 4. Not done / unverified

- Apple silicon: compiles (universal filter, osx-arm64 publish) but has never run. VM is Intel only.
- Developer ID signing, notarization, SIP-on activation: no Apple team available.
- macOS 13/14 code paths compile but were only executed on 15.
- IPv6/QUIC traffic, App Translocation, crash-relaunch of the extension: untested.
- Agent protection: config/hook locations (`~/.claude`, `~/.codex`, …) assumed equal to the Windows
  equivalents under `~`; not verified tool by tool. DKG/Blackbox guided installers are not available on macOS.
- No CI. Known flaky test under load: `HeadlessNavigationTests` (passes alone).
- Cosmetic: in the VM the application menu shows Avalonia's default menu instead of the custom NativeMenu
  (menu-bar icon menu works); AppleScript `quit` returns −128 although the app quits.
- Upstream: the shared-code changes are behaviour-neutral on Windows but touch 99 files. Suggested PR order:
  (1) `AxiomPaths` + `FirewallWriteGate` + `IpcRequestDispatcher`/seams + `PlatformText`/`AgentPlatform`,
  (2) `Axiom.Infrastructure.MacOS` + tests, (3) `Axiom.Service` dual-TFM, (4) `Axiom.Desktop.Avalonia.MacOS`,
  (5) UI fixes, (6) `macos/` + packaging.
