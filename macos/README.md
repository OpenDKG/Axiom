# Axiom for macOS — filter system extension and `axiom-sysext`

Swift sources for the macOS enforcement layer. The contract with the .NET daemon and the
desktop app is `docs/MACOS_ARCHITECTURE.md` §3; this file covers building, testing and
packaging.

```text
macos/
  AxiomFilter/            NEFilterDataProvider system extension (com.axiom.firewall.filter)
    main.swift              entry point (NEProvider.startSystemExtensionMode)
    FilterDataProvider.swift  verdicts, NEFilterReport byte counts, lifecycle
    RuleTable.swift         rules.json parsing + matching (no NetworkExtension dependency)
    RuleStore.swift         rules.json load, directory watch + 1 s poll, hot swap
    EventSink.swift         non-blocking client for /var/run/axiom/filter.sock
    FlowInspector.swift     audit token -> pid/path, endpoints, remote host name
    Info.plist              template (@VERSION@ @BUILD@ @APP_GROUP@)
    AxiomFilter.entitlements
  AxiomSysext/            activation helper CLI
    main.swift              argument parsing, JSON on stdout, exit codes
    SysextCore.swift        OSSystemExtensionRequest / NEFilterManager logic (shared with the dylib)
    axiom-sysext.entitlements
  AxiomSysextLib/
    Exports.swift           @_cdecl entry points -> libAxiomSysext.dylib (P/Invoke from Axiom)
  Tests/
    main.swift              unit tests (build.sh test): rules, loopback, paths, file identity, EventSink
    fixtures/rules-cases.json  shared rule/verdict fixtures (also used by the .NET contract tests)
    filter-listener.py      stand-in daemon listener on filter.sock (root)
    e2e-rules.py            end-to-end rule tests against real traffic (root)
    e2e-socket.sh           socket absent / stale / reconnect tests (root)
  build.sh
```

## Build

Requires only the Xcode Command Line Tools (`xcode-select --install`); tested with CLT 16.4 /
Swift 6.1 on macOS 15.8 (x86_64). Deployment target macOS 13.

```sh
macos/build.sh                  # -> macos/build/com.axiom.firewall.filter.systemextension
                                #    macos/build/axiom-sysext
                                #    macos/build/libAxiomSysext.dylib
ARCH=universal macos/build.sh   # x86_64 | arm64 | universal (lipo), default: this Mac's arch
macos/build.sh testapp          # also macos/build/Axiom.app (development host app)
macos/build.sh test             # unit tests (147 checks + Tests/fixtures/rules-cases.json)
```

All Swift is compiled with `-warnings-as-errors`; the macOS 13/14 code paths (`NWHostEndpoint`,
`NENetworkRule(remoteNetwork:)`) live in helpers that are themselves `@available(macOS,
deprecated: 15.0)` so they compile warning-free against the macOS 15 SDK while macOS 15+ uses
the `nw_endpoint`-based initialisers (`remoteFlowEndpoint`, `NENetworkRule(remoteNetworkEndpoint:)`).

Signing: ad hoc by default. Set `AXIOM_SIGN_IDENTITY="Developer ID Application: … (TEAMID)"` for a
Developer ID build (hardened runtime + timestamp). The app group is
`group.com.axiom.firewall` for ad hoc builds and `<TEAMID>.com.axiom.firewall` for Developer ID
builds (`AXIOM_TEAM_ID` overrides the team id parsed from the identity). The extension's
`NEMachServiceName` is `<app group>.filter`, generated to match. `AXIOM_FILTER_PROFILE` /
`AXIOM_APP_PROFILE` embed provisioning profiles.

### Versioning (contract with `scripts/macos/package-app.sh`)

`build.sh` stamps the extension's `CFBundleShortVersionString` / `CFBundleVersion` from two
environment variables; the packaging script **must export them** before calling `build.sh`
(and must always rebuild the filter for a release — never reuse a stale `macos/build`):

| Variable | Release mode (`AXIOM_SIGN_IDENTITY` set) | Dev mode (ad hoc) |
|---|---|---|
| `AXIOM_VERSION` | **required** — `build.sh` fails without it; pass the product version (`1.2.3`; a `-pre`/`+meta` suffix is allowed) | default `0.0.<git commit count>` |
| `AXIOM_BUILD` | default: git commit count; CI should pass its monotonically increasing build number (1–3 dot-separated integers) | default `<git commit count>.<UTC build timestamp>` — **every build differs** |

The git-derived defaults need a git checkout; in an exported tree they fall back to `0`, which is
still unique per build in dev mode because of the timestamp. The extension's `Info.plist` also
records `AxiomSourceRevision` (`git describe --always --dirty`).

Upgrade rule in `axiom-sysext activate` (and `axiom_sysext_activate`): the installed extension is
replaced when its version or build differ from the embedded one, **or** when the two code
directory hashes (cdhash, read with `SecCodeCopySigningInformation`; the installed copy under
`/Library/SystemExtensions` is readable on a default install) differ; `--force` replaces
unconditionally. Only an identical version+build+cdhash is kept. `status` reports the cdhash of
the embedded and every installed copy.

Ad hoc builds only load with SIP disabled and `systemextensionsctl developer on`.
Release builds need an Apple Developer Program team with the Network Extension and
System Extension capabilities and Developer ID provisioning profiles for
`com.axiom.firewall` and `com.axiom.firewall.filter` (not verified here: no team available).

## Packaging into Axiom.app

| File in `Axiom.app` | From | Signed with |
|---|---|---|
| `Contents/Library/SystemExtensions/com.axiom.firewall.filter.systemextension` | `build/com.axiom.firewall.filter.systemextension` (copy the bundle as is) | `AxiomFilter.entitlements`: `com.apple.developer.networking.networkextension = [content-filter-provider-systemextension]`, `com.apple.security.application-groups = [<app group>]`; identifier `com.axiom.firewall.filter`; hardened runtime; not sandboxed |
| `Contents/MacOS/axiom-sysext` | `build/axiom-sysext` | `axiom-sysext.entitlements`: `com.apple.developer.system-extension.install = true`, networkextension `[content-filter-provider-systemextension]`, app group; identifier `com.axiom.firewall`; hardened runtime |
| `Contents/MacOS/libAxiomSysext.dylib` | `build/libAxiomSysext.dylib` | identifier `com.axiom.firewall.sysextlib`, hardened runtime, **no entitlements** (a library cannot carry them) |
| `Contents/MacOS/Axiom` (Avalonia app) | packaging script | when it runs `axiom-sysext` as a child process: none of the above. When it calls `libAxiomSysext.dylib` instead: `axiom-sysext.entitlements` (system-extension.install, networkextension, app group) on the main executable |
| `Contents/embedded.provisionprofile` | Developer ID profile for `com.axiom.firewall` | — |
| extension `Contents/embedded.provisionprofile` | Developer ID profile for `com.axiom.firewall.filter` (`AXIOM_FILTER_PROFILE`) | — |

Sign inside-out: the extension bundle and `axiom-sysext` are already signed by `build.sh`; if
the packaging script re-signs them it must pass the same entitlements, then sign the app bundle
last (without `--deep`). `build.sh testapp` shows the exact sequence.

The app must be installed in `/Applications` for activation (OSSystemExtensionError 3
otherwise).

### Where `axiom-sysext` must live (verified)

`OSSystemExtensionRequest` looks the extension up in the **main bundle of the calling
process**. Foundation resolves `Bundle.main` to the enclosing `.app` for any executable in
`Contents/MacOS`, so both layouts work and were tested on macOS 15.8:

- `axiom-sysext` as `CFBundleExecutable` (`build.sh testapp`, default);
- a different main executable (`Axiom`) with `axiom-sysext` next to it
  (`AXIOM_TESTAPP_LAYOUT=helper build.sh testapp`): activation/upgrade succeeded from the helper.

Run outside an app bundle, `axiom-sysext` refuses with exit 1 (the system never answers such
requests). macOS names the requesting executable in its prompts ("“axiom-sysext” would like to
use a new network extension"); the "Filter Network Content" prompt uses the app name ("Axiom").

### Which activation path for Developer ID builds (review #4)

With SIP on, the restricted entitlements (`com.apple.developer.system-extension.install`,
`com.apple.developer.networking.networkextension`) are only honoured for an executable whose
signature is vouched for by a provisioning profile, and `Contents/embedded.provisionprofile`
vouches for the **main executable** of the bundle. Two layouts satisfy this:

1. **Recommended: the main `Axiom` executable submits the requests itself** through
   `libAxiomSysext.dylib` (P/Invoke, see below). Then `Bundle.main`, the entitlements and the
   profile all belong to the one executable Apple checks, the prompts show "Axiom", and no
   secondary executable needs restricted entitlements. `package-app.sh` must then sign
   `Contents/MacOS/Axiom` with `axiom-sysext.entitlements` (the same file the helper uses).
2. Development / fallback: `axiom-sysext` as a secondary executable in `Contents/MacOS`. Works ad
   hoc with SIP off (verified) and may work for Developer ID when the profile's entitlements cover
   it, but that is unproven; keep it for the dev loop and as a CLI for diagnostics.

#### `libAxiomSysext.dylib`

```c
char *axiom_sysext_activate(int force, int waitForApproval, int timeoutSeconds);  // force bit 1: replace, bit 2: reset filter config
char *axiom_sysext_deactivate(int timeoutSeconds);
char *axiom_sysext_set_filter(int enable, int timeoutSeconds);   // enable / disable
char *axiom_sysext_status(int timeoutSeconds);                   // 0 = default 15 s
int   axiom_sysext_exit_code(const char *json);                  // "exitCode" field, -1 if unparsable
void  axiom_sysext_free(char *json);
const char *axiom_sysext_version(void);                          // "1"
```

Each call is synchronous, returns a malloc'd UTF-8 JSON string with exactly the fields and
`state`/`exitCode` values `axiom-sysext` prints (free it with `axiom_sysext_free`), and finishes
within `timeoutSeconds` (+5 s worst case). The requests are serviced on a private queue, so the
caller's main run loop is not required — but the call blocks, so invoke it from a worker thread.
.NET: `[DllImport("libAxiomSysext.dylib")] static extern IntPtr axiom_sysext_activate(int force, int wait, int timeout);`
then `Marshal.PtrToStringUTF8` and `axiom_sysext_free`. The library is loaded relative to the
executable (`@executable_path/libAxiomSysext.dylib`).

## `axiom-sysext`

```text
axiom-sysext activate|deactivate|enable|disable|status [--timeout SECONDS] [--no-wait] [--force]
```

| Command | Does |
|---|---|
| `activate` | Submits the activation request (install / upgrade; an installed copy with the same version, build **and** cdhash is kept unless `--force`), re-creates the filter configuration when an ad hoc signed helper replaced the extension or `--reset-filter` is given (see "Ad hoc builds and the filter configuration"), waits for user approval (up to `--timeout`, default 120 s; `--no-wait` returns exit 3 immediately when approval is needed), then saves and enables the `NEFilterManager` configuration (`filterSockets`, data provider `com.axiom.firewall.filter`, description "Axiom Firewall"). The first enable shows the "Filter Network Content" Allow prompt. |
| `deactivate` | Removes the filter configuration, then submits the deactivation request (needs an admin password prompt: run it from the GUI session). |
| `enable` / `disable` | Only toggles the filter configuration; the extension stays installed. |
| `status` | No changes or prompts (15 s default timeout). |

Exactly one JSON object is printed on stdout; progress goes to stderr. Exit codes: 0 ok,
1 error, 2 timeout, 3 waiting for user approval, 4 reboot required, 64 usage. Fields:
`command`, `ok`, `state`, `exitCode`, `appBundle`, `extensionIdentifier`, optional
`message`, `error {domain, code, message}`, `extension {path, version, build, cdhash}` (embedded
copy), `filter {configured, enabled, description, dataProvider}`, `installed[]` (status:
`{version, build, enabled, awaitingUserApproval, uninstalling, path, cdhash}`), `replaced`
(activate: true when an installed copy was replaced, false when kept) and `installedCdhash`.

`state` values: activate → `activated` | `needs_approval` | `reboot_required` | `error` |
`timeout`; deactivate → `deactivated`; status → `running` | `installed_filter_disabled` |
`needs_approval` | `not_installed`; enable/disable → `enabled` | `disabled`.

Example:

```json
{"appBundle":"/Applications/Axiom.app","command":"status","exitCode":0,"extension":{"build":"6","path":"/Applications/Axiom.app/Contents/Library/SystemExtensions/com.axiom.firewall.filter.systemextension","version":"1.0.0"},"extensionIdentifier":"com.axiom.firewall.filter","filter":{"configured":true,"dataProvider":"com.axiom.firewall.filter","description":"Axiom Firewall","enabled":true},"installed":[{"awaitingUserApproval":false,"build":"6","enabled":true,"path":"/Library/SystemExtensions/…/com.axiom.firewall.filter.systemextension","uninstalling":false,"version":"1.0.0"}],"ok":true,"state":"running"}
```

## Development test loop (SIP off, developer mode on)

```sh
macos/build.sh testapp               # every dev build gets a new CFBundleVersion
sudo rm -rf /Applications/Axiom.app && sudo cp -R macos/build/Axiom.app /Applications/
/Applications/Axiom.app/Contents/MacOS/axiom-sysext activate
#   first install: approve in System Settings > General > Login Items & Extensions >
#   Network Extensions (toggle + password), then allow "Filter Network Content"
# The e2e scripts need filter.sock: stop the real daemon while they run (if installed).
sudo launchctl bootout system/com.axiom.service
sudo python3 macos/Tests/filter-listener.py --out /tmp/flows.jsonl --seconds 300 &
sudo python3 macos/Tests/e2e-rules.py --events /tmp/flows.jsonl
sudo macos/Tests/e2e-socket.sh       # with no other listener running
sudo launchctl bootstrap system /Library/LaunchDaemons/com.axiom.service.plist
log stream --info --predicate 'subsystem == "com.axiom.firewall.filter"'
```

Upgrades (different version/build or cdhash) replace the running extension without new
prompts; the old process exits on `stopFilter`. Note that **disabling or replacing the filter
resets TCP connections that were established while it was active** (observed with and without
flow reports, e.g. SSH sessions into the Mac drop): run upgrades from a local shell or detached
(`nohup … &`).

### Ad hoc builds and the filter configuration

The `NEFilterManager` configuration is bound to the code signature of the process that saved
it. For an ad hoc signature that is the exact cdhash, so after the helper is rebuilt
`nesessionmanager` logs `Rejecting agent com.axiom.firewall because it does not satisfy the
code signature requirements` / `Failed to launch com.axiom.firewall`, the filter session never
starts and all traffic is allowed although `status` says `running`. `activate` therefore
removes and re-creates the configuration when the helper is ad hoc signed **and** it replaced
the installed extension (reported as `"adHocSigned"`/`"filterReset": true`), which re-shows the
"Filter Network Content" prompt once per upgrade; a repeated `activate` that keeps the
extension does not prompt. If only the helper was rebuilt (extension unchanged) run
`activate --reset-filter`. Developer ID signatures satisfy a stable designated requirement and
keep their configuration across upgrades.

## Behaviour notes (review #23)

- **UDP is judged per socket.** The content filter sees socket flows, not datagrams. An
  unconnected UDP socket that `sendto`s several peers gets one `handleNewFlow` for its first
  destination and one verdict for the socket's lifetime; later destinations are not
  re-evaluated or reported. Connected UDP sockets and new sockets are evaluated normally
  (DNS via mDNSResponder, `curl`, browsers all behave that way).
- **`exit(0)` after `stopFilter` is intended.** The extension exits 0.5 s after completing
  `stopFilter` so that an upgraded copy can register its Mach service (LuLu does the same).
  macOS logs this as an unexpected exit of the extension process; the system relaunches the
  extension on demand, nothing is lost.
- **Loopback flows** are reported but exempt from rules that do not name a loopback address;
  **paths** are matched case-insensitively on realpath and also against the responsible
  process; **App Translocation** (quarantined apps run from `~/Downloads`) defeats path rules
  until the app is moved to `/Applications` — see `docs/MACOS_ARCHITECTURE.md` §3.1.
