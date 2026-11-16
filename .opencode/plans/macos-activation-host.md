# macOS activation host — implementation plan

Status: approved for local DCO commit by independent re-review of 1850d61 (tree
484e5208009120694e4f60a9716eaa52011269b1). Rejected checkpoint 9513176; corrected code
1270dd0. This is not production certification: signed activation, notarization, Gatekeeper
acceptance and enforcement remain unverified. Scope: release-blocking macOS activation of
`com.axiom.firewall.filter` without running restricted NetworkExtension entitlements in the
Avalonia/.NET (JIT) UI process.

## Evidence (official Apple docs, fetched 2026-11-15)

- “Installing System Extensions and Drivers”: during activation macOS verifies the extension is
  in the **requesting app's** `Contents/Library/SystemExtensions`, and that the **requesting app**
  is in an appropriate `Applications` directory. Same Team ID as the extension.
- `OSSystemExtensionError.unsupportedParentBundleLocation`: the extension's parent app must be a
  macOS app in `Applications`.
- TN3125: a standalone executable cannot claim a restricted entitlement because there is nowhere
  to embed the authorising provisioning profile; wrap it in an **app-like structure**.
- Xcode “Signing a daemon with a restricted entitlement”: an app target with
  `Contents/embedded.provisionprofile` and the daemon code as its main executable. The profile
  authorises the main executable's restricted entitlements.
- macOS 26 AMFI observation in this repo: a JIT app carrying the Network Extension entitlement is
  killed at exec. A correctly provisioned signature was not tested, so the in-process JIT path is
  not a defensible release route.

## Chosen topology (smallest documented model)

A separate top-level **app-like activation host**, installed as a sibling of `Axiom.app`:

```text
/Applications/Axiom.app/                         UI only (JIT; no restricted entitlements)
/Applications/AxiomFilterHost.app/               CFBundleIdentifier com.axiom.firewall.host
  Contents/Info.plist                            CFBundleExecutable = axiom-sysext
  Contents/embedded.provisionprofile             AXIOM_HOST_PROFILE (signed builds)
  Contents/MacOS/axiom-sysext                    native host/CLI; restricted entitlements
  Contents/Library/SystemExtensions/
    com.axiom.firewall.filter.systemextension    AXIOM_FILTER_PROFILE
```

Rejected alternatives:

- Bare `Axiom.app/Contents/MacOS/axiom-sysext`: TN3125 says it cannot carry restricted
  entitlements; no place for its profile.
- `libAxiomSysext.dylib` in the JIT UI: would put NetworkExtension in the JIT process; macOS 26
  rejects it and the profile authorises the app main executable, not the dylib.
- Host nested inside `Axiom.app/Contents/...`: activation verifies the *requesting app's* location
  and its own `Contents/Library/SystemExtensions`; nesting is not documented as an appropriate
  Applications location and would make ownership ambiguous.
- Rewriting `Axiom.app`'s main executable as a native launcher with the JIT UI as a child: valid
  but larger and riskier for the already-running UI; not needed once the host is a top-level app.

The UI keeps the existing one-shot NDJSON subprocess contract. `FilterExtensionManager` invokes
`/Applications/AxiomFilterHost.app/Contents/MacOS/axiom-sysext <command> …` instead of the dylib.
No XPC, no new daemon, no new dependency.

## Files and seams

- `src/Axiom.Presentation/MacElevation.cs`: `MacBundleLayout` resolves the sibling host app and
  host executable/Applications location; remove dylib path.
- `src/Axiom.Desktop.Avalonia.MacOS/FilterExtensionManager.cs`: one host path; remove library
  preference/fallback, keep JSON/exit-code/approval/timeout parsing. Gate activation on host
  presence and host in `/Applications`; status may run anywhere.
- Delete `src/Axiom.Desktop.Avalonia.MacOS/SysextLibrary.cs` and `macos/AxiomSysextLib/Exports.swift`
  after all callers move (no in-process path remains).
- `macos/AxiomSysext/*`: host app Info.plist + entitlements; ad hoc builds sign the host with an
  empty entitlement set and fail closed with a clear “signed package required” message; signed
  builds require the host profile. Reuse `SysextCore` and `main.swift`.
- `macos/build.sh`: build/sign `AxiomFilterHost.app` (extension inside it); remove the dylib and
  testapp layouts; require `AXIOM_HOST_PROFILE` + `AXIOM_FILTER_PROFILE` for signed builds.
- `scripts/macos/package-app.sh`: Axiom.app ships UI+axiomd only, JIT-only entitlements; copy and
  sign/verify `AxiomFilterHost.app`; require both profiles and validate bundle/team/app-group/
  entitlement match before a signed artifact; add host to the pkg payload; dSYMs for host and
  extension. Signed mode fails clearly on missing/mismatched profiles. Ad hoc/UI-only mode still
  assembles and signs a runnable UI, with activation reported unavailable.
- `scripts/macos/Axiom.entitlements`: JIT relaxations only (signed and ad hoc alike). Remove
  `Axiom-adhoc.entitlements` once tests migrate. Remove `AXIOM_APP_PROFILE`.
- Installer postinstall: refuse a non-startup target volume (`$3` not `/`) before running
  `axiomd --install-service`, so an offline-volume install never starts a live-root daemon.
- Docs: `macos/README.md`, `docs/MACOS_ARCHITECTURE.md`, `docs/MACOS_PORT_REPORT.md`; truthful
  “signed runtime unverified” statements.

## Trust boundaries

- UI remains unprivileged and carries no restricted entitlements; it only starts the signed host
  with a fixed argument vector (`ToolProcess`, no shell).
- Host is the only process with `system-extension.install`, NetworkExtension and app-group
  entitlements; it edits NEFilterManager and submits OSSystemExtensionRequest from its own bundle.
- Extension keeps its own NetworkExtension + app-group profile and Team ID; host and extension
  must share Team ID and app group.
- No credentials, no privileged helper changes, no SIP change, no fallback loop that hides
  entitlement errors.

## Review corrections

Independent review rejected `9513176`; topology was accepted. Corrections:
1. Re-create NEFilterManager config for every replaced extension/host (signed and ad hoc);
   `--reset-filter` remains.
2. Validate exact profile values (NE array, app group, boolean-true install), with negative tests.
3. Approval instructions say Axiom Network Filter (the host display name).
4. Capture previous plist before swap; retain the moved-aside helper on partial move; never
   bootstrap after a failed plist restore.

## Implementation checkpoint

- Approved reviewed tip `1850d61` (tree `484e5208009120694e4f60a9716eaa52011269b1`);
  corrected code `1270dd0` (tree `5ba8287b3797e1091f362a4887dc4f45b246615b`).
- Exact-source guest build: corrected 1270dd0 code build (ad hoc, arm64); `Axiom.pkg` SHA-256
  `f377d406eddb3a7eb8dac78a5eef71f41b6c79cbb94d629bc53a701c36c31ba3`; app tar SHA-256
  `5aa6278a5b020d6102d7857fb6be536b722d981299657ed4da00804c8cbdb55f`.
- Docs-tip rebuild 1850d61: `Axiom.pkg` SHA-256
  `0d10692ffef2a50ccc3bbf1d12ff1058ec0d34a0c10c5873dd0c657363f122ba`; app archive SHA-256
  `7c0836a4c2d062330c0cff81ece14ee82b76a0d091fc7ac56ba7b83905cdfc9a`.
  Same host/extension code; packaging/signature bytes differ.
- Private artifacts: `artifacts/1270dd0/` and docs-tip `artifacts/1850d61/`; old rejected
  `artifacts/9513176/` preserved untouched.
- Guest suites: contracts 148, presentation 215, desktop 34, UI Avalonia 54, infra 264,
  Swift 153/153, packaging 12/12; all exit 0. Signed runtime activation remains unverified.

## Rollback

Revert this change set as one commit range; the prior artifacts and commits are preserved. The
old dylib/helper files stop being shipped, so rollback also restores `macos/AxiomSysextLib`,
`SysextLibrary.cs`, the package dylib copy and the old docs/tests.

## Acceptance / tests

- Manager tests: host path is the only invocation; arguments with spaces; status/error/approval/
  timeout/reboot parsing; missing host, host outside `/Applications`, notStarted/cancel.
- Layout tests: sibling host path, host Applications gate, plain-folder behaviour.
- Swift: 153/153 filter/activation checks compile and pass; host app bundle/Info.plist is
  produced; ad hoc host has no restricted entitlements; signed host has them.
- Packaging bash 3.2 tests (12/12): wrapper unset/empty/populated; ad hoc vs signed; profile
  missing/mismatch and wrong NE/group/bool values fail; payload contains both apps; host extension
  ownership; postinstall refuses alternate volume.
- Guest suites: contracts, presentation, desktop, UI Avalonia, infra, Swift and packaging.
- Guest rebuild of latest source; verify host/extension/profile/entitlements/codesign/pkg/Gatekeeper
  statically. No install/activation/enforcement claim without real profiles and user console.
