# Axiom for macOS — architecture

Status: in development on branch `buba/macos` (as-built notes in §5, build/test in §6)
Target: macOS 13 Ventura and later, Apple silicon (arm64) and Intel (x64)

This document is the contract between the macOS components. Windows behaviour is unchanged.

## 1. Components

```text
/Applications/Axiom.app
  Contents/MacOS/Axiom                         Avalonia desktop app (Axiom.Desktop.Avalonia.MacOS), runs as the user
  Contents/Resources/service/axiomd            Axiom.Service published for macOS; only used to run --install-service
  Contents/Library/SystemExtensions/
    com.axiom.firewall.filter.systemextension  Swift NEFilterDataProvider (AxiomFilter), runs as root, managed by macOS
/Library/PrivilegedHelperTools/com.axiom.service/  root:wheel copy of the daemon publish dir; launchd runs axiomd from here
/Library/LaunchDaemons/com.axiom.service.plist launchd job for axiomd (root:wheel 0644)
/Library/Application Support/Axiom/            machine data, root 0700 (database, shield, privacy, filter state)
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
- **Path matching** (review #12): `appPath` is canonicalised with `realpath` when the file exists (so `/var/…` and `/private/var/…` agree) and compared **case-insensitively** (the system volume is case-insensitive APFS). A rule matches a flow when it matches the path of the socket-owning process **or** the path of the *responsible* process (`responsibility_get_pid_responsible_for_pid`: the app that launched `sh -c curl`, a WebKit networking helper, an XPC service). Limitation: App Translocation — a quarantined app run from `~/Downloads` executes from `/private/var/folders/…/AppTranslocation/<uuid>/d/Foo.app`; a rule for the original path does not match until the app is moved to `/Applications`.
- **Loopback** (review #13): destinations in `127.0.0.0/8` / `::1` are **exempt** from a rule unless its `remoteAddresses` explicitly names a loopback address (`127.0.0.1`, `127.0.0.0/8`, `::1`, a range starting in loopback). `0.0.0.0/0` / `::/0` do not count. So "block app X" never cuts X off from the Privacy Shield resolver on `127.0.0.1:53`; loopback flows are still reported for attribution. Windows Firewall likewise ignores loopback.
- **Rejected rules** (review #6): an invalid rule (unknown action/direction/protocol, bad ports, no valid address, relative `appPath`) is skipped and reported in the `filter.rules` event (§3.2) with its `id` (or `#<index>` when it has none) and a reason; it never widens to "any".
- **File identity** (review #11): the filter opens the file with `O_NOFOLLOW|O_CLOEXEC`, `fstat`s the descriptor and requires a regular file owned by root (uid 0) that is neither group- nor world-writable (`mode & 022 == 0`), then reads from that descriptor. A symlink, a non-root owner or a writable mode rejects the file: the last good table stays in force and the rejection is reported in `filter.rules` (`error`) and logged once per distinct reason.
- The filter watches the file (DispatchSource on the directory) and reloads within 1 s. If the file is missing or invalid the filter keeps the last good table (or allows everything at first start: fail-open).

### 3.2 Flow events (filter → daemon)

The daemon listens on a Unix stream socket `/var/run/axiom/filter.sock` (root:wheel 0600). The filter connects as a client, reconnects every 2 s when the daemon is down, and never blocks a verdict on the socket (bounded in-memory queue, drop oldest).

Newline-delimited JSON, one object per line:

```json
{"type":"flow.open","id":"<uuid>","ts":"2026-11-10T10:13:18.756Z","pid":1194,"path":"/usr/bin/curl","direction":"outbound","protocol":"tcp","localAddress":"10.0.2.15","localPort":53122,"remoteAddress":"17.253.144.10","remotePort":443,"remoteHost":"apple.com","verdict":"allow","ruleId":null,"responsiblePid":1190,"responsiblePath":"/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"}
{"type":"flow.stats","id":"<uuid>","ts":"...","bytesIn":1234,"bytesOut":567}
{"type":"flow.close","id":"<uuid>","ts":"...","bytesIn":1234,"bytesOut":567}
{"type":"filter.hello","ts":"...","version":"1.0.0","generation":42,"dropped":0}
{"type":"filter.rules","ts":"...","generation":42,"applied":7,"rejected":[{"id":"0f8b5c1e-…","reason":"unknown protocol sctp"}],"error":null,"dropped":0}
```

`remoteHost` is the hostname the app connected by, when macOS supplies it (also on DNS flows to port 53). Verdicts: `allow` | `block`.

- `responsiblePid` / `responsiblePath` (review #12): the responsible process when it differs from `pid`/`path` (e.g. the Terminal that ran `sh -c curl`, the app behind a WebKit networking process); `null` otherwise. Rules were matched against both paths. Readers must tolerate the keys being absent (older filters).
- `filter.hello` is sent first on every connection and again after every successful reload; `filter.rules` (review #6) follows it after every reload: `generation` and `applied` (number of enabled rules enforced) describe the table now in force, `rejected` lists the skipped rules with reasons. When the **file** was rejected (identity check, invalid JSON, unsupported schema) `filter.rules` is sent without a hello, `error` carries the reason and `generation`/`applied`/`rejected` describe the table that is still in force. Readers must ignore unknown event types.
- `dropped` (review #14): total number of events the filter had to drop so far (backlog overflow or too many events in flight); monotonic per extension process. A daemon that sees it grow knows its flow table is incomplete.
- **Consumer side** (daemon, .NET): `FlowEventParser` parses `filter.rules` (rejected list capped at 256 entries, wrong field types ignored) and the `dropped` counter of both events; `FilterStatus` keeps the latest report (`FilterRulesReport`) and the highest `dropped` seen, and takes the generation of a file-rejection event as the one still enforced. `MacFirewallPolicyAdapter` exposes it on the IPC contract: `capabilities` / `rules.query` → `capability.filterEnforcement {generation, appliedRuleCount, rejectedRules:[{ruleId, reason}], fileError, droppedEvents, reportedUtc}` (null on Windows and until the first report); `rule.verify` → `filterRejectionReason` (the rule then has no `effectiveAction`) plus a note. The Firewall page renders `rejectedRules` as "N rule(s) not enforced by the filter" with id + reason, and `fileError` / `droppedEvents > 0` as a banner (`FilterEnforcementSummary`). The daemon's own validation is not a superset of the filter's (e.g. `IPAddress.TryParse` accepts `1.2.3`), which is why the report matters.

### 3.3 Filter lifecycle

The desktop app installs/activates the system extension (OSSystemExtensionRequest) and enables the NEFilterManager configuration from the main `Axiom` process through `Contents/MacOS/libAxiomSysext.dylib` (P/Invoke: `axiom_sysext_activate(force, wait, timeoutSeconds)` / `deactivate` / `set_filter` / `status` → JSON string, freed with `axiom_sysext_free`), the path Developer ID builds need (§3.4 "Activation from the main process"). The same operations exist as a small Swift helper executable, `Axiom.app/Contents/MacOS/axiom-sysext` (`activate` | `deactivate` | `status`, JSON on stdout), which `FilterExtensionManager` runs as a child process when the dylib is missing or cannot be loaded (`DllNotFoundException`, `EntryPointNotFoundException`, `BadImageFormatException`); the path used is written to `desktop.log` (`[sysext] <command> via dylib|helper …`). Exit codes are identical on both paths (0 ok, 1 error, 2 timeout, 3 needs approval, 4 reboot required; the dylib carries them in the JSON `exitCode` field). The dylib call blocks for up to the timeout, so the .NET side runs it on a dedicated worker thread; the Swift side services the request callbacks on a private dispatch queue and needs no main run loop.

### 3.4 Implementation notes (AxiomFilter / axiom-sysext as built, `macos/`)

Verified end to end on macOS 15.8.3 (x86_64 VM, ad hoc signed); see `macos/README.md` for the helper's JSON fields, exit codes, packaging table and entitlements. These refine §3.1–3.3 without changing the wire formats:

- **Rules.** Document-level problems (unreadable file, invalid JSON, `schemaVersion` ≠ 1, `rules` not an array) keep the last good table. A single invalid rule (unknown action/direction/protocol, bad port spec, or a non-empty `remoteAddresses` with no valid entry) is skipped and logged; it never widens to "any". `remoteAddresses` also accepts `a-b` IP ranges (Windows syntax); IPv4-mapped IPv6 addresses match IPv4 rules. `appPath` matching is case-sensitive on the `proc_pidpath` real path (symlinks resolved by the kernel: e.g. `/usr/bin/python3` runs `…/Python3.framework/…/Python.app/Contents/MacOS/Python`). `failOpen` is parsed but the filter is always fail-open (no table, or an unloadable first table, allows everything). Reload latency measured at ≈ 0.05 s (directory DispatchSource + 1 s stat poll as a safety net). The filter creates `/Library/Application Support/Axiom/filter` (0755) if missing.
- **Blocking.** A block verdict is `NEFilterNewFlowVerdict.drop()`: TCP clients see a connect timeout (SYN dropped), not a reset.
- **Coverage.** All TCP/UDP socket flows in both directions plus outbound loopback (127.0.0.0/8, ::1) so connections to local services such as the DNS proxy are attributed to the client app; inbound loopback is not filtered (it duplicates the client side). Inbound connections to launchd socket-activated services (e.g. sshd) are attributed to `/sbin/launchd` (pid 1).
- **Events.** `id` is `NEFilterFlow.identifier` (lowercase UUID). `pid` is -1 and `path` null when the process cannot be resolved; `protocol` may be `other`. `localAddress`/`localPort` are usually `0.0.0.0`/`0` on outbound flows (not yet bound when the verdict is made). `flow.stats`: macOS reports statistics about once per second per allowed flow (`.medium`); the filter forwards at most one `flow.stats` per flow every 2 s (review #14); `flow.close` carries the final counters. macOS sends no close report for dropped flows, so the filter emits `flow.close` with zero bytes immediately after a blocked `flow.open`. `filter.hello` is sent first on every connection **and again after every successful rules reload**, followed by `filter.rules` (its `generation` is the generation now enforced; -1 before any table loaded). Events produced while the daemon is down are queued (20 000 lines / 8 MB, drop oldest, the hello is never dropped) and delivered after the hello on reconnect; at most 4096 events may wait for the sink queue at any time, beyond that the verdict path drops them (`dropped`). The filter only talks to a peer whose `getpeereid` uid is 0.
- **UDP** (review #23). The content filter sees *sockets*, not datagrams: an unconnected UDP socket (`sendto` to several peers from one socket, e.g. a resolver or QUIC client) produces **one** flow and **one** verdict for the first destination; later destinations of the same socket are not re-evaluated. Per-destination UDP rules therefore apply to connected sockets (and to each new socket); the common cases — `curl`, DNS lookups via mDNSResponder, browsers — open a socket per destination or connect it.
- **Lifecycle.** The extension exits 0.5 s after `stopFilter` (LuLu pattern) so upgrades re-register the Mach service; macOS logs that as an unexpected exit of the extension — this is intended and the system relaunches the extension on demand (review #23). `axiom-sysext` must run from `Axiom.app/Contents/MacOS` (as main executable or as a secondary executable — both verified); it has `enable`/`disable` commands in addition to the contract's three. Activation and filter enable work from a non-GUI context once approved, but first approval, the "Filter Network Content" prompt and deactivation (admin password) need the GUI login session. Disabling, deactivating or upgrading the filter resets TCP connections that were established while it was active (macOS behaviour, independent of flow reporting).
- **Upgrades** (review #5). `build.sh` stamps the extension with `AXIOM_VERSION`/`AXIOM_BUILD` (required in release mode; dev builds get `0.0.<commits>` / `<commits>.<timestamp>` so every build differs). `activate` replaces the installed extension whenever version/build differ, or when both code-directory hashes are readable and differ; `--force` always replaces. See `macos/README.md` "Versioning".
- **Activation from the main process** (review #4). `build.sh` also produces `libAxiomSysext.dylib` with C entry points (`axiom_sysext_activate` …) returning the same JSON as `axiom-sysext`, so the Avalonia host can submit the `OSSystemExtensionRequest` itself once it is signed with the sysext entitlements; the helper executable keeps working for development. Which path a Developer ID build should use is documented in `macos/README.md`.

## 4. Build and packaging

- Launchd: `KeepAlive {SuccessfulExit: false}` with `ThrottleInterval 10` (a crash restarts the daemon, a clean exit does not; a missing program cannot hot-loop); `/etc/newsyslog.d/com.axiom.service.conf` rotates `axiomd.log` at 5 MB, keeps 5 compressed. Both are written by `--install-service` and removed by `--uninstall-service`.
- Login item: `~/Library/LaunchAgents/com.axiom.firewall.agent.plist` runs `/usr/bin/open -b com.axiom.firewall --args --autostart` (the executable path is pinned only when the app does not run from a bundle), so app translocation or moving the bundle does not break it.
- Keychain: the secret-protection key is a `kSecClassGenericPassword` item (service `com.axiom.firewall`, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`) through `SecItemCopyMatching/SecItemAdd`.
- Rule semantics contract: `macos/Tests/fixtures/rules-cases.json` is read by the .NET tests (reference `FilterRuleMatcher` in the test project) and the Swift tests.

- .NET: `dotnet publish -r osx-arm64|osx-x64 --self-contained` for `Axiom.Desktop.Avalonia.MacOS` and `Axiom.Service` (builds on Linux).
- Swift: `macos/AxiomFilter` built with Xcode Command Line Tools (`macos/build.sh`), on a Mac or the macOS CI runner.
- `scripts/macos/package-app.sh` copies `macos/build/libAxiomSysext.dylib` into `Contents/MacOS` when `build.sh` produced it (next to `axiom-sysext`, which stays as the fallback and diagnostics CLI), signs it with the same identity as the runtime libraries (identifier `com.axiom.firewall.sysextlib`, no entitlements — a library cannot carry them) and verifies it; the main executable is signed with `scripts/macos/Axiom.entitlements` (`system-extension.install`, `networkextension` `content-filter-provider-systemextension`, the app group, plus the .NET JIT entitlements) so the in-process `OSSystemExtensionRequest` is honoured.
- `scripts/macos/package-app.sh` assembles `Axiom.app`, signs inside-out (Mach-O files only, detected by magic bytes; Developer ID with hardened runtime and secure timestamp when `AXIOM_SIGN_IDENTITY` is set, ad hoc otherwise — ad hoc has no timestamp), writes dSYMs for the Swift extension/helper with a Developer ID identity (`build/macos/<rid>/dSYMs`; .NET has no dSYM, its portable `.pdb`s stay in `publish/`), and builds `build/macos/<rid>/Axiom.pkg` with `pkgbuild` (root `/Applications/Axiom.app`, postinstall runs `axiomd --install-service`; signed with `AXIOM_INSTALLER_IDENTITY` when set).
- Release signing/notarization needs an Apple Developer Program team with the Network Extension capability. Development builds run ad hoc signed on a Mac with SIP disabled and `systemextensionsctl developer on`.

## 5. As built

Verified on macOS 15.8.3 (x86_64 QEMU VM, SIP off, ad hoc signed); acceptance results are in
[`MACOS_TEST_REPORT.md`](MACOS_TEST_REPORT.md).

### 5.1 Components

| Piece | Project / path | Notes |
|---|---|---|
| Desktop app | `src/Axiom.Desktop.Avalonia.MacOS` → `Axiom.app/Contents/MacOS/Axiom` | Shared `Axiom.UI.Avalonia` pages, native window chrome, menu-bar (status item) menu, single instance (a second `open` activates the running window). Platform wording comes from `Axiom.Presentation.PlatformText`; Windows strings are unchanged. |
| Daemon | `src/Axiom.Service` (`net10.0` target, assembly `axiomd`) → `Contents/Resources/service/axiomd`, installed copy at `/Library/PrivilegedHelperTools/com.axiom.service/axiomd` | launchd job `com.axiom.service` (`/Library/LaunchDaemons/com.axiom.service.plist`, `AXIOM_SERVICE=1`), log `/Library/Logs/Axiom/axiomd.log`. Installed from the app through the administrator password prompt (`LaunchdServiceInstaller`, see §5.3). `axiomd --doctor [--json]` audits the installation (§5.5). |
| Portable service core | `src/Axiom.Service.Hosting` | IPC dispatch, Privacy Shield `DnsProxyServer`, policy code shared by the Windows service and `axiomd`. |
| macOS platform layer | `src/Axiom.Infrastructure.MacOS` | `Ipc/UnixSocketIpcTransport` + `PeerAuthorization`, `Dns/MacDnsConfigurator` + `MacPrivacyDnsPlatform`, `Filter/*` (rules file, event server, policy adapter), `Monitoring/*` (flow table, libproc fallback), `Launchd/*`, `Interop/*` (libproc, `LibProcSocketScanner` — one socket-table pass per 2 s shared by the connection poll and DNS attribution, getpeereid, SIGCHLD re-exec, process runner over `Axiom.Contracts.ToolProcess`). IPC: 16 slots, at most 4 concurrent connections per non-root uid. |
| Filter | `macos/AxiomFilter` (Swift `NEFilterDataProvider` system extension) + `axiom-sysext` helper | See §3.4 and `macos/README.md`. |

### 5.2 Deviations from the original contract

- **`Axiom.Service.Hosting` extraction.** The portable dispatch code moved out of `Axiom.Service` into a shared project instead of being copied; `Axiom.Service` multi-targets `net10.0-windows;net10.0` and selects the platform in `Platform/ServicePlatform.{Windows,Unix}.cs`.
- **Seams instead of forks.** `IIpcTransport` (named pipe with SID ACL on Windows, Unix socket on macOS), `IPrivacyDnsPlatform` (Windows: UAC helper changes adapter DNS; macOS: the daemon switches DNS itself) and `IDnsAppAttributor` (who sent a DNS query: Windows IP Helper table, macOS libproc lookup).
- **Custom Unix socket transport.** §1 planned to reuse `NamedPipeServerStream`; the daemon uses its own listener at `/var/run/axiom/axiom.sock` instead, so the peer can be checked with `getpeereid` before any byte is read. Allowed peers: uid 0 and console users (uid ≥ 501); write commands are further restricted (§5.4). The line protocol is unchanged.
- **DNS switching is owned by the daemon.** While the Privacy Shield resolver runs on port 53, `axiomd` saves every enabled network service's DNS servers to a backup file (machine data root, 0600) and points the service at 127.0.0.1 with `networksetup -setdnsservers`. On disable, resolver stop, service stop or uninstall it restores the saved servers (automatic DNS when the service had none). Fail-safe: the next daemon start restores any service still pointing only at loopback; unreadable services are retried and, if they were redirected by Axiom, restored from the backup, which is kept until the state is known. The desktop app shows this as "System DNS (switched by the Axiom daemon)" and never prompts. All changes are logged as `Privacy Shield DNS: …` in `axiomd.log`. Only enabled services whose device (`networksetup -listnetworkserviceorder`) reports `status: active` in `ifconfig` are redirected; services without a known device or status line are redirected conservatively; restore covers every enabled service in the backup. **Upstream rediscovery:** while the resolver runs, `UpstreamRediscovery` re-reads the system resolvers (`scutil --dns` through `MacDnsConfigurator.DiscoverSystemResolvers`) every 10 s, and every 2 s once three consecutive queries got no upstream answer (`DnsProxyServer.UpstreamFailureStreak`); a different list is swapped in with `DnsProxyServer.UpdateUpstreams` without restarting the listener; a discovery that only yields 127.0.0.1 (ourselves) or nothing keeps the current list (the platform substitutes the backup's saved servers). Without the daemon, `sudo axiomd --restore-dns` restores the saved servers from the backup file.
- **`AxiomPaths.ServicePrivateDataDirectory`.** Windows keeps `%LocalAppData%\Axiom` for the service account. On Unix the root daemon has no meaningful profile, so service-private stores (threat-share state, Privacy Shield blocked history) live in the machine data root with owner-only files.
- **SIGCHLD re-exec for admin-prompt installs.** `osascript … with administrator privileges` starts the command with SIGCHLD ignored, so .NET never sees child processes exit (`launchctl` looked hung). Privileged CLI modes reset SIGCHLD to default and `execv` themselves once (`Interop/ChildSignal`).
- **Filter is always fail-open.** `failOpen` in the rules file is parsed but ignored: without a valid table the filter allows everything.
- **Blocked TCP shows a connect timeout.** A block is `.drop()`; clients see the SYN dropped (e.g. `curl` exit 7 / timeout), not a reset.
- **Axiom's own daemon is never prompted.** Axiom Shield's "new outbound application" list skips executables inside the running `Axiom.app` bundle (the daemon forwards Privacy Shield queries upstream), as well as SIP-protected system paths.

### 5.3 Root-owned daemon install (`--install-service` / `--uninstall-service`)

launchd checks the owner of the plist, not of the program, so a daemon that runs out of the user-owned `Axiom.app`
bundle could be replaced by any process of that user. The app therefore still runs
`<bundle>/Contents/Resources/service/axiomd --install-service` behind the administrator prompt, but that process:

1. copies its own publish directory to a staging directory under `/Library/PrivilegedHelperTools`, sets directories
   and executables to 0755 and data files to 0644, runs `chown -R 0:0` on it;
2. verifies the copy with `stat` (`PrivilegedHelperLayout.Audit`): every entry uid 0, nothing group/world-writable,
   `axiomd` present and executable — otherwise it refuses with the list of offending paths and bootstraps nothing;
3. `launchctl bootout`s a running job, renames the staging directory over `/Library/PrivilegedHelperTools/com.axiom.service`
   (previous copy removed), re-verifies the final location;
4. tightens the data directory (§5.4 modes), records the installing uid (`SUDO_UID` or the owner of `/dev/console`) as
   `AllowedUid` in `protection.json`, writes the plist with `ProgramArguments`/`WorkingDirectory` pointing at the helper
   copy, then `launchctl enable` + `bootstrap`.

Re-running is an upgrade in place (stop, replace, start); the dev deploy script does exactly that. `--uninstall-service`
boots the job out, deletes the plist, restores system DNS from the Privacy Shield backup when one exists (independent of
whether the daemon was running) and removes the helper directory. Replacing files inside `Axiom.app` afterwards has no
effect on the running daemon; writing into the helper directory needs root.

### 5.4 Authorization and file modes

| Caller (peer uid from `getpeereid`) | Connect / read-only commands | Write commands |
|---|---|---|
| root (0) | yes | yes |
| installing user (`protection.json` `AllowedUid`) | yes | yes |
| member of group `admin` (getgrouplist; `AllowAdminGroupWrites`, default true) | yes | yes |
| any other local account (uid ≥ 501) | yes | **denied**: `unauthorized` error, logged with the actor |
| system accounts (1–500), `nobody`, unknown peer | connection closed | — |

`IpcCommandAccess` classifies every command (test-enforced: each `IpcCommandTypes` constant is in exactly one list; an
unlisted command counts as a write). Read-only: `capabilities`, `serviceHealth`, `snapshot`, `live.events`,
`rule.verify`, `rules.query`, `history.query`, `traffic.history`, `privacy.status`, `config.get`, `diagnostics.export`,
`protection.status`, `threatshare.status`. Everything else (`rule.apply/remove`, `privacy.configure`,
`privacy.sources.update`, `privacy.history.clear`, `config.set`, `protection.*` changes, `threatshare.*` changes) is a write.
Windows is unchanged: the named pipe admits one SID with full access.

Machine data directory `/Library/Application Support/Axiom` (`MacDataDirectoryPermissions`, applied at every daemon start
and at write time): the root is `root 0700`; `filter/` is 0755 and `filter/rules.json` 0644 (read by the extension);
every other file the daemon writes — `axiom.db` with `-wal`/`-shm`, `filter/managed-rules.json`, `protection.json`,
`privacy-shield-*.json`, `privacy-shield-blocked.jsonl`, `threat-share.json`, `privacy-shield-dns-backup.json` — is 0600.
Sockets: `/var/run/axiom/axiom.sock` 0666 (peer-checked), `filter.sock` 0600.

### 5.5 `axiomd --doctor`, `--restore-dns`

`sudo axiomd --restore-dns` restores the system DNS from the Privacy Shield backup without the daemon (same code path as the fail-safe on daemon start / uninstall); use it if the daemon cannot start while the shield was on.


Prints one `PASS|WARN|FAIL|SKIP name: detail` line per check (`--json` for a machine-readable document) and exits 0 when
nothing is WARN/FAIL: launchd job state and program path, plist target and owner, helper directory audit, both sockets
(existence, type, mode, owner), data root and per-file modes, DNS servers of every enabled network service plus the
backup file, Privacy Shield state from the settings, and the filter extension from `systemextensionsctl list`. Run as a
normal user it reports what it can and marks the root-only checks (data files, DNS backup, settings) as SKIP.

## 6. Build, install, test

### 6.1 Development (Linux + macOS VM)

1. **Publish on Linux:** `scripts/macos/package-app.sh osx-x64 --no-sign` (or `osx-arm64`) publishes the desktop app and `axiomd` self-contained and assembles an unsigned `build/macos/<rid>/Axiom.app`. Run `git checkout -- '*.lock.json'` afterwards (publishing adds RID sections to the lock files).
2. **Sign on a Mac/VM:** copy the tree and run `scripts/macos/package-app.sh osx-x64 --skip-publish --build-filter`. This builds the Swift filter and `axiom-sysext` with the Command Line Tools (`macos/build.sh`), embeds them and signs inside-out (ad hoc unless `AXIOM_SIGN_IDENTITY` is set).
3. **Dev loop:** `scripts/macos/deploy-to-vm.sh` does steps 1–2 against the VM over SSH, installs to `/Applications/Axiom.app`, and re-runs `axiomd --install-service` (upgrade of the root-owned helper copy) when `com.axiom.service` is installed.
4. **Dev machine requirements:** SIP disabled and `systemextensionsctl developer on` (both need the GUI session and a password), so an ad hoc signed system extension can be activated. First activation still needs approval in System Settings > General > Login Items & Extensions > Network Extensions and the "Filter Network Content" prompt.
5. **Tests on Linux:** `dotnet build Axiom.sln -c Release -p:EnableWindowsTargeting=true`, then `dotnet test` the `tests/Axiom.*.Tests` projects. `Axiom.Infrastructure.MacOS.Tests` covers the DNS configurator, rules/events, socket peer checks and libproc layouts with fakes (SO_PEERCRED on Linux).

### 6.2 Release

- An Apple Developer Program team with the **Network Extension** capability (content filter, system extension) and the app group `group.com.axiom.firewall` (prefixed with the team id).
- **Developer ID signing:** `AXIOM_SIGN_IDENTITY="Developer ID Application: … (TEAMID)"` and `AXIOM_TEAM_ID` (derived from the identity if unset) for `package-app.sh` (signs with hardened runtime and a secure timestamp).
- **Provisioning profiles:** Developer ID profiles for the app (`AXIOM_APP_PROFILE`, embedded as `Contents/embedded.provisionprofile`) and for the filter extension (`AXIOM_FILTER_PROFILE`, used by `macos/build.sh`), both carrying the Network Extension entitlement (`content-filter-provider-systemextension`).
- **Notarization:** submit the signed app/pkg with `xcrun notarytool submit --wait` and staple (`xcrun stapler staple`). Notarized releases run with SIP on and without developer mode.
- Apple-silicon builds (`osx-arm64`) must be validated on real hardware; the VM is Intel only.
