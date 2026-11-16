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
  AxiomSysext/            app-like activation host (AxiomFilterHost.app) and CLI
    main.swift              argument parsing, JSON on stdout, exit codes
    SysextCore.swift        OSSystemExtensionRequest / NEFilterManager logic
    Info.plist              host bundle template (@VERSION@ @BUILD@ @GIT@)
    axiom-sysext.entitlements         signed host: restricted entitlements
    axiom-sysext-adhoc.entitlements   ad hoc host: deliberately no restricted entitlements
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
macos/build.sh                  # -> macos/build/AxiomFilterHost.app
                                #    Contents/MacOS/axiom-sysext
                                #    Contents/Library/SystemExtensions/com.axiom.firewall.filter.systemextension
ARCH=universal macos/build.sh   # x86_64 | arm64 | universal (lipo), default: this Mac's arch
macos/build.sh test             # unit tests (149 checks, including Tests/fixtures/rules-cases.json)
```

All Swift is compiled with `-warnings-as-errors`; the macOS 13/14 code paths (`NWHostEndpoint`,
`NENetworkRule(remoteNetwork:)`) live in helpers that are themselves `@available(macOS,
deprecated: 15.0)` so they compile warning-free against the macOS 15 SDK while macOS 15+ uses
the `nw_endpoint`-based initialisers (`remoteFlowEndpoint`, `NENetworkRule(remoteNetworkEndpoint:)`).

Signing: ad hoc by default. Set `AXIOM_SIGN_IDENTITY="Developer ID Application: … (TEAMID)"` for a
Developer ID build (hardened runtime + timestamp); a signed build also requires
`AXIOM_HOST_PROFILE` and `AXIOM_FILTER_PROFILE`. The app group is
`group.com.axiom.firewall` for ad hoc builds and `<TEAMID>.com.axiom.firewall` for Developer ID
builds (`AXIOM_TEAM_ID` overrides the team id parsed from the identity). The extension's
`NEMachServiceName` is `<app group>.filter`, generated to match. Ad hoc builds claim no
restricted entitlements (TN3125) and the host answers `state=unavailable` with a "signed package
required" message instead of attempting an unauthorised request.

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

Upgrade rule in `axiom-sysext activate`: the installed extension is
replaced when its version or build differ from the embedded one, **or** when the two code
directory hashes (cdhash, read with `SecCodeCopySigningInformation`; the installed copy under
`/Library/SystemExtensions` is readable on a default install) differ; `--force` replaces
unconditionally. Only an identical version+build+cdhash is kept. `status` reports the cdhash of
the embedded and every installed copy.

Ad hoc builds cannot activate the extension: the host deliberately carries no restricted
entitlements. Release builds need an Apple Developer Program team with the Network Extension and
System Extension capabilities, a Developer ID provisioning profile for the host
(`com.axiom.firewall.host`, `AXIOM_HOST_PROFILE`) and for the extension
(`com.axiom.firewall.filter`, `AXIOM_FILTER_PROFILE`); the host profile authorises the Team ID,
System Extension install, Network Extension and app group, the extension profile the Team ID,
Network Extension and app group (not verified here: no team available).

## Packaging into `/Applications`

The JIT UI (`Axiom.app`) and the app-like activation host are **separate top-level apps**.
OSSystemExtensionRequest verifies that the extension is in the *requesting app's*
`Contents/Library/SystemExtensions` and that the requesting app is in an Applications directory;
a host nested inside `Axiom.app` is therefore not a documented layout. The extension is owned by
`AxiomFilterHost.app`, not by `Axiom.app`.

| File in `AxiomFilterHost.app` | From | Signed with |
|---|---|---|
| `Contents/MacOS/axiom-sysext` | `build/AxiomFilterHost.app/...` | `axiom-sysext.entitlements`: `com.apple.developer.system-extension.install = true`, networkextension `[content-filter-provider-systemextension]`, app group; identifier `com.axiom.firewall.host`; hardened runtime. Ad hoc builds get `axiom-sysext-adhoc.entitlements` (empty). |
| `Contents/Library/SystemExtensions/com.axiom.firewall.filter.systemextension` | the Swift extension bundle | `AxiomFilter.entitlements`: `com.apple.developer.networking.networkextension = [content-filter-provider-systemextension]`, `com.apple.security.application-groups = [<app group>]`; identifier `com.axiom.firewall.filter`; hardened runtime; not sandboxed |
| `Contents/embedded.provisionprofile` | `AXIOM_HOST_PROFILE` | authorises the two restricted entitlements and app group on the host's main executable (`com.axiom.firewall.host`) |
| extension `Contents/embedded.provisionprofile` | `AXIOM_FILTER_PROFILE` | authorises the extension's Network Extension entitlement (`com.axiom.firewall.filter`) |

| File in `Axiom.app` | Signed with |
|---|---|
| `Contents/MacOS/Axiom` (Avalonia/.NET UI) | `Axiom.entitlements`: only the hardened-runtime relaxations (`allow-jit`, `allow-unsigned-executable-memory`, `disable-library-validation`). No restricted entitlements, no profile, in every mode. |
| `Contents/Resources/service/axiomd` | `axiomd.entitlements` (root daemon) |

`package-app.sh` copies the already-signed host from `macos/build`, verifies its authority/Team ID
against `AXIOM_SIGN_IDENTITY`/`AXIOM_TEAM_ID` for a signed release, validates both profiles
(application identifier, Team ID, required entitlements), and refuses to produce a signed artifact
when a profile is missing or mismatched. The UI is signed last.

The host must be installed in `/Applications` for activation (OSSystemExtensionError 3
otherwise). `Axiom.pkg` installs both apps and refuses an alternate (offline) target volume before
starting the daemon. Uninstall removes both bundles.

### Why the host is a separate app (review #4)

With SIP on, the restricted entitlements (`com.apple.developer.system-extension.install`,
`com.apple.developer.networking.networkextension`) are only honoured for code whose signature is
vouched for by a provisioning profile. Apple TN3125 ("Inside Code Signing: Provisioning
Profiles") says a standalone executable cannot claim a restricted entitlement because there is no
place to embed its profile; the documented workaround is an app-like bundle whose main executable
is the daemon and whose `Contents/embedded.provisionprofile` authorises it. The same TN explains
that `Contents/embedded.provisionprofile` vouches for the bundle's **main executable**.

The earlier in-process `libAxiomSysext.dylib` path put the Network Extension entitlement on the
JIT UI and was killed by AMFI on macOS 26.6 ("Hardened Runtime relaxation entitlements disallowed
on System Extensions"); the dylib and the bare helper are no longer built or shipped. The host is
native and non-JIT, owns the extension and its profile, and is the only process with the
restricted entitlements. `FilterExtensionManager` runs it as a child process over the unchanged
one-JSON-object NDJSON interface (`desktop.log` records `via host`).

Ad hoc limitation: without an Apple identity there is no profile, so the ad hoc host claims no
restricted entitlements. It still starts and answers `status` with `state=unavailable` and a
clear "signed package required" message; it never reports `running`, `Protected` or `Verified`.

Signed runtime activation, the System Settings approval, the "Filter Network Content" prompt and
enforcement are **not verified** here: the lab has no Apple team, profiles or GUI approval. Code,
package layout, entitlements and profile checks are implemented and build/test covered.

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
{"appBundle":"/Applications/AxiomFilterHost.app","command":"status","exitCode":0,"extension":{"build":"6","path":"/Applications/AxiomFilterHost.app/Contents/Library/SystemExtensions/com.axiom.firewall.filter.systemextension","version":"1.0.0"},"extensionIdentifier":"com.axiom.firewall.filter","filter":{"configured":true,"dataProvider":"com.axiom.firewall.filter","description":"Axiom Firewall","enabled":true},"installed":[{"awaitingUserApproval":false,"build":"6","enabled":true,"path":"/Library/SystemExtensions/…/com.axiom.firewall.filter.systemextension","uninstalling":false,"version":"1.0.0"}],"ok":true,"state":"running"}
```

## Development test loop

```sh
macos/build.sh                       # ad hoc host: no restricted entitlements
sudo rm -rf /Applications/AxiomFilterHost.app
sudo ditto macos/build/AxiomFilterHost.app /Applications/AxiomFilterHost.app
/Applications/AxiomFilterHost.app/Contents/MacOS/axiom-sysext status
#   ad hoc: state=unavailable, "signed package required" - this is intentional.
```

A signed build needs `AXIOM_HOST_PROFILE` and `AXIOM_FILTER_PROFILE`; then the same executable
submits the request. The first install shows the approval in System Settings > General > Login
Items & Extensions > Network Extensions (toggle + password), then the "Filter Network Content"
prompt.

The e2e scripts need filter.sock; stop the real daemon while they run (if installed):

```sh
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

### Ad hoc builds

The ad hoc host carries no restricted entitlements and `SysextCore` refuses every restricted
command with `state=unavailable` before touching `OSSystemExtensionRequest` or `NEFilterManager`.
There is no ad hoc activation route; SIP-off/`systemextensionsctl developer on` do not authorise
the entitlements. Signed builds keep the existing upgrade/reset behaviour: `activate` re-creates
the filter configuration when `--reset-filter` is given or when the signature changed.

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
