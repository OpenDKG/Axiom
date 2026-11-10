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
    main.swift
    axiom-sysext.entitlements
  Tests/
    main.swift              rule-table unit tests (build.sh test)
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
ARCH=universal macos/build.sh   # x86_64 | arm64 | universal (lipo), default: this Mac's arch
macos/build.sh testapp          # also macos/build/Axiom.app (development host app)
macos/build.sh test             # rule-table unit tests
```

Signing: ad hoc by default. Set `AXIOM_SIGN_IDENTITY="Developer ID Application: … (TEAMID)"` for a
Developer ID build (hardened runtime + timestamp). The app group is
`group.com.axiom.firewall` for ad hoc builds and `<TEAMID>.com.axiom.firewall` for Developer ID
builds (`AXIOM_TEAM_ID` overrides the team id parsed from the identity). The extension's
`NEMachServiceName` is `<app group>.filter`, generated to match. `AXIOM_FILTER_PROFILE` /
`AXIOM_APP_PROFILE` embed provisioning profiles. `AXIOM_VERSION` / `AXIOM_BUILD` set
`CFBundleShortVersionString` / `CFBundleVersion`: **bump `AXIOM_BUILD` for every build you
want macOS to install over the active one** (`activate` keeps an active extension with the
same version and build unless `--force`).

Ad hoc builds only load with SIP disabled and `systemextensionsctl developer on`.
Release builds need an Apple Developer Program team with the Network Extension and
System Extension capabilities and Developer ID provisioning profiles for
`com.axiom.firewall` and `com.axiom.firewall.filter` (not verified here: no team available).

## Packaging into Axiom.app

| File in `Axiom.app` | From | Signed with |
|---|---|---|
| `Contents/Library/SystemExtensions/com.axiom.firewall.filter.systemextension` | `build/com.axiom.firewall.filter.systemextension` (copy the bundle as is) | `AxiomFilter.entitlements`: `com.apple.developer.networking.networkextension = [content-filter-provider-systemextension]`, `com.apple.security.application-groups = [<app group>]`; identifier `com.axiom.firewall.filter`; hardened runtime; not sandboxed |
| `Contents/MacOS/axiom-sysext` | `build/axiom-sysext` | `axiom-sysext.entitlements`: `com.apple.developer.system-extension.install = true`, networkextension `[content-filter-provider-systemextension]`, app group; identifier `com.axiom.firewall`; hardened runtime |
| `Contents/MacOS/Axiom` (Avalonia app) | packaging script | needs none of the above for the filter (it only runs `axiom-sysext`) |
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

## `axiom-sysext`

```text
axiom-sysext activate|deactivate|enable|disable|status [--timeout SECONDS] [--no-wait] [--force]
```

| Command | Does |
|---|---|
| `activate` | Submits the activation request (install / upgrade; same version+build kept unless `--force`), waits for user approval (up to `--timeout`, default 120 s; `--no-wait` returns exit 3 immediately when approval is needed), then saves and enables the `NEFilterManager` configuration (`filterSockets`, data provider `com.axiom.firewall.filter`, description "Axiom Firewall"). The first enable shows the "Filter Network Content" Allow prompt. |
| `deactivate` | Removes the filter configuration, then submits the deactivation request (needs an admin password prompt: run it from the GUI session). |
| `enable` / `disable` | Only toggles the filter configuration; the extension stays installed. |
| `status` | No changes or prompts (15 s default timeout). |

Exactly one JSON object is printed on stdout; progress goes to stderr. Exit codes: 0 ok,
1 error, 2 timeout, 3 waiting for user approval, 4 reboot required, 64 usage. Fields:
`command`, `ok`, `state`, `exitCode`, `appBundle`, `extensionIdentifier`, optional
`message`, `error {domain, code, message}`, `extension {path, version, build}` (embedded
copy), `filter {configured, enabled, description, dataProvider}`, `installed[]` (status:
`{version, build, enabled, awaitingUserApproval, uninstalling, path}`), `replaced` (activate).

`state` values: activate → `activated` | `needs_approval` | `reboot_required` | `error` |
`timeout`; deactivate → `deactivated`; status → `running` | `installed_filter_disabled` |
`needs_approval` | `not_installed`; enable/disable → `enabled` | `disabled`.

Example:

```json
{"appBundle":"/Applications/Axiom.app","command":"status","exitCode":0,"extension":{"build":"6","path":"/Applications/Axiom.app/Contents/Library/SystemExtensions/com.axiom.firewall.filter.systemextension","version":"1.0.0"},"extensionIdentifier":"com.axiom.firewall.filter","filter":{"configured":true,"dataProvider":"com.axiom.firewall.filter","description":"Axiom Firewall","enabled":true},"installed":[{"awaitingUserApproval":false,"build":"6","enabled":true,"path":"/Library/SystemExtensions/…/com.axiom.firewall.filter.systemextension","uninstalling":false,"version":"1.0.0"}],"ok":true,"state":"running"}
```

## Development test loop (SIP off, developer mode on)

```sh
AXIOM_BUILD=7 macos/build.sh testapp
sudo rm -rf /Applications/Axiom.app && sudo cp -R macos/build/Axiom.app /Applications/
/Applications/Axiom.app/Contents/MacOS/axiom-sysext activate
#   first install: approve in System Settings > General > Login Items & Extensions >
#   Network Extensions (toggle + password), then allow "Filter Network Content"
sudo python3 macos/Tests/filter-listener.py --out /tmp/flows.jsonl --seconds 300 &
sudo python3 macos/Tests/e2e-rules.py --events /tmp/flows.jsonl
sudo macos/Tests/e2e-socket.sh       # with no other listener running
log stream --info --predicate 'subsystem == "com.axiom.firewall.filter"'
```

Upgrades (higher `AXIOM_BUILD`) replace the running extension without new prompts; the old
process exits on `stopFilter`. Note that **disabling or replacing the filter resets TCP
connections that were established while it was active** (observed with and without flow
reports, e.g. SSH sessions into the Mac drop): run upgrades from a local shell or detached
(`nohup … &`).
