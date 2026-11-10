# Axiom for macOS — architecture

Status: in development on branch `buba/macos` (as-built notes in §5, build/test in §6)
Target: macOS 13 Ventura and later, Apple silicon (arm64) and Intel (x64)

This document is the contract between the macOS components. Windows behaviour is unchanged.

## 1. Components

```text
/Applications/Axiom.app
  Contents/MacOS/Axiom                         Avalonia desktop app (Axiom.Desktop.Avalonia.MacOS), runs as the user
  Contents/Resources/service/axiomd            Axiom.Service published for macOS, runs as root via launchd
  Contents/Library/SystemExtensions/
    com.axiom.firewall.filter.systemextension  Swift NEFilterDataProvider (AxiomFilter), runs as root, managed by macOS
/Library/LaunchDaemons/com.axiom.service.plist launchd job for axiomd
/Library/Application Support/Axiom/            machine data (database, shield, privacy, filter state)
~/Library/Application Support/Axiom/           per-user UI settings
```

| Windows piece | macOS piece |
|---|---|
| Windows service `Axiom.Service` | launchd daemon `axiomd` (same `Axiom.Service` project, `net10.0` target) |
| Named pipe with SID ACL | Same .NET `NamedPipeServerStream`, which is a Unix domain socket on macOS, at `/var/run/axiom/axiom.sock`. The daemon checks the peer uid with `getpeereid`. |
| Windows Firewall rules owned by Axiom | Rule table enforced by the AxiomFilter system extension |
| IP Helper connection table + ESTATS bytes | Flow events and byte reports from AxiomFilter; libproc socket enumeration as fallback |
| DNS proxy on 127.0.0.1:53 + adapter DNS rewrite | Same `DnsProxyServer` on 127.0.0.1:53 + `networksetup -setdnsservers` per network service, restored on stop (fail-safe identical in spirit) |
| Process identity (path, signer, Store package) | Path from `proc_pidpath`, signer from code signature (`codesign`/Security), bundle id from `Info.plist` |
| DPAPI secrets | Keychain (desktop host) |
| MSIX / Setup | `Axiom.app` + installer `.pkg`, `scripts/macos/*` |

## 2. Platform data roots

`Axiom.Contracts.AxiomPaths` decides roots:

- machine data: Windows `%ProgramData%\Axiom`; macOS `/Library/Application Support/Axiom`; Linux `/var/lib/axiom`
- user data: `Environment.SpecialFolder.LocalApplicationData/Axiom` (macOS: `~/Library/Application Support/Axiom`)
- `AXIOM_DATA_DIR` overrides as today.

`Environment.UserInteractive` is always true on Unix, so service-mode detection on macOS uses `AXIOM_SERVICE=1` (set in the launchd plist) or `geteuid()==0`.

## 3. Filter extension ⇄ daemon contract

### 3.1 Rules (daemon → filter)

The daemon owns the rule list and writes it atomically (write temp + rename) to

`/Library/Application Support/Axiom/filter/rules.json` (root:wheel 0644)

```json
{
  "schemaVersion": 1,
  "generation": 42,
  "failOpen": true,
  "rules": [
    {
      "id": "0f8b5c1e-...-guid",
      "appPath": "/Applications/Foo.app",
      "direction": "outbound",
      "action": "block",
      "protocol": "any",
      "remoteAddresses": ["1.2.3.4", "10.0.0.0/8"],
      "remotePorts": "80,443,1000-2000",
      "enabled": true
    }
  ]
}
```

- `direction`: `outbound` | `inbound`. `action`: `block` | `allow`. `protocol`: `any` | `tcp` | `udp` | `icmp` (matched as not-filtered for now).
- `appPath` matches the flow's process executable path exactly, or any executable inside it when `appPath` is a directory/bundle (prefix + `/`). Empty `appPath` or `*` means any app.
- `remoteAddresses` empty = any. Entries are IPs or CIDRs; the token `*` = any.
- `remotePorts` null/empty = any.
- Semantics match Windows Firewall: an enabled matching **block** rule wins over any allow rule; with no match, traffic is allowed (default allow, as Windows default outbound).
- The filter watches the file (DispatchSource on the directory) and reloads within 1 s. If the file is missing or invalid the filter keeps the last good table (or allows everything at first start: fail-open).

### 3.2 Flow events (filter → daemon)

The daemon listens on a Unix stream socket `/var/run/axiom/filter.sock` (root:wheel 0600). The filter connects as a client, reconnects every 2 s when the daemon is down, and never blocks a verdict on the socket (bounded in-memory queue, drop oldest).

Newline-delimited JSON, one object per line:

```json
{"type":"flow.open","id":"<uuid>","ts":"2026-11-10T10:13:18.756Z","pid":1194,"path":"/usr/bin/curl","direction":"outbound","protocol":"tcp","localAddress":"10.0.2.15","localPort":53122,"remoteAddress":"17.253.144.10","remotePort":443,"remoteHost":"apple.com","verdict":"allow","ruleId":null}
{"type":"flow.stats","id":"<uuid>","ts":"...","bytesIn":1234,"bytesOut":567}
{"type":"flow.close","id":"<uuid>","ts":"...","bytesIn":1234,"bytesOut":567}
{"type":"filter.hello","ts":"...","version":"1.0.0","generation":42}
```

`remoteHost` is the hostname the app connected by, when macOS supplies it (also on DNS flows to port 53). Verdicts: `allow` | `block`.

### 3.3 Filter lifecycle

The desktop app installs/activates the system extension (OSSystemExtensionRequest) and enables the NEFilterManager configuration through a small Swift helper executable embedded in the app: `Axiom.app/Contents/MacOS/axiom-sysext` (`activate` | `deactivate` | `status`, JSON on stdout). The .NET app runs it as a child process.

### 3.4 Implementation notes (AxiomFilter / axiom-sysext as built, `macos/`)

Verified end to end on macOS 15.8.3 (x86_64 VM, ad hoc signed); see `macos/README.md` for the helper's JSON fields, exit codes, packaging table and entitlements. These refine §3.1–3.3 without changing the wire formats:

- **Rules.** Document-level problems (unreadable file, invalid JSON, `schemaVersion` ≠ 1, `rules` not an array) keep the last good table. A single invalid rule (unknown action/direction/protocol, bad port spec, or a non-empty `remoteAddresses` with no valid entry) is skipped and logged; it never widens to "any". `remoteAddresses` also accepts `a-b` IP ranges (Windows syntax); IPv4-mapped IPv6 addresses match IPv4 rules. `appPath` matching is case-sensitive on the `proc_pidpath` real path (symlinks resolved by the kernel: e.g. `/usr/bin/python3` runs `…/Python3.framework/…/Python.app/Contents/MacOS/Python`). `failOpen` is parsed but the filter is always fail-open (no table, or an unloadable first table, allows everything). Reload latency measured at ≈ 0.05 s (directory DispatchSource + 1 s stat poll as a safety net). The filter creates `/Library/Application Support/Axiom/filter` (0755) if missing.
- **Blocking.** A block verdict is `NEFilterNewFlowVerdict.drop()`: TCP clients see a connect timeout (SYN dropped), not a reset.
- **Coverage.** All TCP/UDP socket flows in both directions plus outbound loopback (127.0.0.0/8, ::1) so connections to local services such as the DNS proxy are attributed to the client app; inbound loopback is not filtered (it duplicates the client side). Inbound connections to launchd socket-activated services (e.g. sshd) are attributed to `/sbin/launchd` (pid 1).
- **Events.** `id` is `NEFilterFlow.identifier` (lowercase UUID). `pid` is -1 and `path` null when the process cannot be resolved; `protocol` may be `other`. `localAddress`/`localPort` are usually `0.0.0.0`/`0` on outbound flows (not yet bound when the verdict is made). `flow.stats` arrive about once per second for allowed flows that live longer than that (NEFilterReport statistics, `.medium` frequency); `flow.close` carries the final counters. macOS sends no close report for dropped flows, so the filter emits `flow.close` with zero bytes immediately after a blocked `flow.open`. `filter.hello` is sent first on every connection **and again after every successful rules reload** (its `generation` is the generation now enforced; -1 before any table loaded). Events produced while the daemon is down are queued (20 000 lines / 8 MB, drop oldest) and delivered after the hello on reconnect. The filter only talks to a peer whose `getpeereid` uid is 0.
- **Lifecycle.** The extension exits 0.5 s after `stopFilter` (LuLu pattern) so upgrades re-register the Mach service. `axiom-sysext` must run from `Axiom.app/Contents/MacOS` (as main executable or as a secondary executable — both verified); it has `enable`/`disable` commands in addition to the contract's three. Activation and filter enable work from a non-GUI context once approved, but first approval, the "Filter Network Content" prompt and deactivation (admin password) need the GUI login session. Disabling, deactivating or upgrading the filter resets TCP connections that were established while it was active (macOS behaviour, independent of flow reporting).

## 4. Build and packaging

- .NET: `dotnet publish -r osx-arm64|osx-x64 --self-contained` for `Axiom.Desktop.Avalonia.MacOS` and `Axiom.Service` (builds on Linux).
- Swift: `macos/AxiomFilter` built with Xcode Command Line Tools (`macos/build.sh`), on a Mac or the macOS CI runner.
- `scripts/macos/package-app.sh` assembles `Axiom.app`, signs (Developer ID when `AXIOM_SIGN_IDENTITY` is set, ad hoc otherwise), and builds `Axiom.pkg`.
- Release signing/notarization needs an Apple Developer Program team with the Network Extension capability. Development builds run ad hoc signed on a Mac with SIP disabled and `systemextensionsctl developer on`.

## 5. As built

Verified on macOS 15.8.3 (x86_64 QEMU VM, SIP off, ad hoc signed); acceptance results are in
[`MACOS_TEST_REPORT.md`](MACOS_TEST_REPORT.md).

### 5.1 Components

| Piece | Project / path | Notes |
|---|---|---|
| Desktop app | `src/Axiom.Desktop.Avalonia.MacOS` → `Axiom.app/Contents/MacOS/Axiom` | Shared `Axiom.UI.Avalonia` pages, native window chrome, menu-bar (status item) menu, single instance (a second `open` activates the running window). Platform wording comes from `Axiom.Presentation.PlatformText`; Windows strings are unchanged. |
| Daemon | `src/Axiom.Service` (`net10.0` target, assembly `axiomd`) → `Contents/Resources/service/axiomd` | launchd job `com.axiom.service` (`/Library/LaunchDaemons/com.axiom.service.plist`, `AXIOM_SERVICE=1`), log `/Library/Logs/Axiom/axiomd.log`. Installed from the app through the administrator password prompt (`LaunchdServiceInstaller`). |
| Portable service core | `src/Axiom.Service.Hosting` | IPC dispatch, Privacy Shield `DnsProxyServer`, policy code shared by the Windows service and `axiomd`. |
| macOS platform layer | `src/Axiom.Infrastructure.MacOS` | `Ipc/UnixSocketIpcTransport` + `PeerAuthorization`, `Dns/MacDnsConfigurator` + `MacPrivacyDnsPlatform`, `Filter/*` (rules file, event server, policy adapter), `Monitoring/*` (flow table, libproc fallback), `Launchd/*`, `Interop/*` (libproc, getpeereid, SIGCHLD re-exec, process runner). |
| Filter | `macos/AxiomFilter` (Swift `NEFilterDataProvider` system extension) + `axiom-sysext` helper | See §3.4 and `macos/README.md`. |

### 5.2 Deviations from the original contract

- **`Axiom.Service.Hosting` extraction.** The portable dispatch code moved out of `Axiom.Service` into a shared project instead of being copied; `Axiom.Service` multi-targets `net10.0-windows;net10.0` and selects the platform in `Platform/ServicePlatform.{Windows,Unix}.cs`.
- **Seams instead of forks.** `IIpcTransport` (named pipe with SID ACL on Windows, Unix socket on macOS), `IPrivacyDnsPlatform` (Windows: UAC helper changes adapter DNS; macOS: the daemon switches DNS itself) and `IDnsAppAttributor` (who sent a DNS query: Windows IP Helper table, macOS libproc lookup).
- **Custom Unix socket transport.** §1 planned to reuse `NamedPipeServerStream`; the daemon uses its own listener at `/var/run/axiom/axiom.sock` instead, so the peer can be checked with `getpeereid` before any byte is read. Allowed peers: uid 0 and console users (uid ≥ 501). The line protocol is unchanged.
- **DNS switching is owned by the daemon.** While the Privacy Shield resolver runs on port 53, `axiomd` saves every enabled network service's DNS servers to a backup file (machine data root, 0600) and points the service at 127.0.0.1 with `networksetup -setdnsservers`. On disable, resolver stop, service stop or uninstall it restores the saved servers (automatic DNS when the service had none). Fail-safe: the next daemon start restores any service still pointing only at loopback; unreadable services are retried and, if they were redirected by Axiom, restored from the backup, which is kept until the state is known. The desktop app shows this as "System DNS (switched by the Axiom daemon)" and never prompts. All changes are logged as `Privacy Shield DNS: …` in `axiomd.log`. Every enabled service is redirected, including ones without an active interface (e.g. "Built-in Serial Port (1)" in the VM); they are restored the same way.
- **`AxiomPaths.ServicePrivateDataDirectory`.** Windows keeps `%LocalAppData%\Axiom` for the service account. On Unix the root daemon has no meaningful profile, so service-private stores (threat-share state, Privacy Shield blocked history) live in the machine data root with owner-only files.
- **SIGCHLD re-exec for admin-prompt installs.** `osascript … with administrator privileges` starts the command with SIGCHLD ignored, so .NET never sees child processes exit (`launchctl` looked hung). Privileged CLI modes reset SIGCHLD to default and `execv` themselves once (`Interop/ChildSignal`).
- **Filter is always fail-open.** `failOpen` in the rules file is parsed but ignored: without a valid table the filter allows everything.
- **Blocked TCP shows a connect timeout.** A block is `.drop()`; clients see the SYN dropped (e.g. `curl` exit 7 / timeout), not a reset.
- **Axiom's own daemon is never prompted.** Axiom Shield's "new outbound application" list skips executables inside the running `Axiom.app` bundle (the daemon forwards Privacy Shield queries upstream), as well as SIP-protected system paths.

## 6. Build, install, test

### 6.1 Development (Linux + macOS VM)

1. **Publish on Linux:** `scripts/macos/package-app.sh osx-x64 --no-sign` (or `osx-arm64`) publishes the desktop app and `axiomd` self-contained and assembles an unsigned `build/macos/<rid>/Axiom.app`. Run `git checkout -- '*.lock.json'` afterwards (publishing adds RID sections to the lock files).
2. **Sign on a Mac/VM:** copy the tree and run `scripts/macos/package-app.sh osx-x64 --skip-publish --build-filter`. This builds the Swift filter and `axiom-sysext` with the Command Line Tools (`macos/build.sh`), embeds them and signs inside-out (ad hoc unless `AXIOM_SIGN_IDENTITY` is set).
3. **Dev loop:** `scripts/macos/deploy-to-vm.sh` does steps 1–2 against the VM over SSH, installs to `/Applications/Axiom.app`, and restarts `com.axiom.service` when it is installed.
4. **Dev machine requirements:** SIP disabled and `systemextensionsctl developer on` (both need the GUI session and a password), so an ad hoc signed system extension can be activated. First activation still needs approval in System Settings > General > Login Items & Extensions > Network Extensions and the "Filter Network Content" prompt.
5. **Tests on Linux:** `dotnet build Axiom.sln -c Release -p:EnableWindowsTargeting=true`, then `dotnet test` the `tests/Axiom.*.Tests` projects. `Axiom.Infrastructure.MacOS.Tests` covers the DNS configurator, rules/events, socket peer checks and libproc layouts with fakes (SO_PEERCRED on Linux).

### 6.2 Release

- An Apple Developer Program team with the **Network Extension** capability (content filter, system extension) and the app group `group.com.axiom.firewall` (prefixed with the team id).
- **Developer ID signing:** `AXIOM_SIGN_IDENTITY="Developer ID Application: … (TEAMID)"` and `AXIOM_TEAM_ID` (derived from the identity if unset) for `package-app.sh` (signs with hardened runtime and a secure timestamp).
- **Provisioning profiles:** Developer ID profiles for the app (`AXIOM_APP_PROFILE`, embedded as `Contents/embedded.provisionprofile`) and for the filter extension (`AXIOM_FILTER_PROFILE`, used by `macos/build.sh`), both carrying the Network Extension entitlement (`content-filter-provider-systemextension`).
- **Notarization:** submit the signed app/pkg with `xcrun notarytool submit --wait` and staple (`xcrun stapler staple`). Notarized releases run with SIP on and without developer mode.
- Apple-silicon builds (`osx-arm64`) must be validated on real hardware; the VM is Intel only.
