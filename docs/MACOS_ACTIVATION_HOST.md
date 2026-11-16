# macOS activation host — approved handoff

Status: **approved for a local DCO commit** by the independent re-review of `1850d61`
(tree `484e5208009120694e4f60a9716eaa52011269b1`). The re-review closed all four findings from
the `9513176` rejection. This is not production certification: signed activation, notarization,
Gatekeeper acceptance and enforcement remain unverified. The final metadata-only handoff commit
does not change the reviewed code.

## Upstream position

- Canonical repository: `https://github.com/a-51-50/Axiom`
- Canonical `main` observed read-only on 2026-11-16: `fe1a6ee` (release 0.65.0).
- This branch is PR #274-derived (`3040997` plus the approved filter commits), **not** latest main:
  at observation it was 125 commits ahead of and 137 commits behind canonical `main`.
- No merge, rebase, push or publication was performed. Do not read this branch as latest-main
  integrated work.

## Independent review outcome

Reviewed tip `1850d61`; corrected code `1270dd0`; rejected prior checkpoint `9513176`; cumulative
base `815d400`. The reviewer approved the local DCO commit and recorded:

1. **Closed** — `filterRefreshRequired` is `explicitReset || replaced`, called without an ad hoc
   term; a failed save remains `state=error`. Four policy cases are tested.
2. **Closed** — profile arrays and the boolean install entitlement are value-checked, not just
   present. The reviewer's local fake-toolchain packaging run was 12/12 PASS, including wrong
   network-extension, wrong app group and false install boolean.
3. **Closed** — prompts and the native approval message use `Axiom Network Filter`; the desktop
   test asserts it.
4. **Closed** — previous plist is read before `Swap`, the moved-aside path is recorded before the
   second move, and a failed plist restore never bootstraps the previous helper.

Review limits: the reviewer did not re-run the guest suites, privileged activation, hashes or
Gatekeeper checks. Builder-reported guest results below are not a second independent execution.
The reviewer did not assess any code after `1850d61`; this final commit is metadata only.

## Plan and topology

`Axiom.app` remains the JIT/Avalonia UI and carries only hardened-runtime relaxations. A separate
top-level `/Applications/AxiomFilterHost.app` (`com.axiom.firewall.host`) is the app-like host:

```text
AxiomFilterHost.app/
  Contents/Info.plist                       CFBundleExecutable = axiom-sysext
  Contents/embedded.provisionprofile        AXIOM_HOST_PROFILE (signed builds)
  Contents/MacOS/axiom-sysext               native host/CLI, restricted entitlements
  Contents/Library/SystemExtensions/
    com.axiom.firewall.filter.systemextension   AXIOM_FILTER_PROFILE
```

macOS activates an extension only when it is in the *requesting app’s*
`Contents/Library/SystemExtensions` and that app is in an Applications directory. A bare helper
cannot carry restricted entitlements (TN3125); a host nested inside `Axiom.app` is not the
requesting app in an appropriate location. `FilterExtensionManager` runs the host as a child
process over the existing one-JSON-object/exit-code interface. Ad hoc hosts carry no restricted
entitlements and fail closed with `state=unavailable`.

## Review corrections

### 1. Refresh the filter configuration on every replacement

`AxiomFilterHost.app` is re-signed whenever the host or extension changes, and the saved
`NEFilterManager` configuration is bound to the previous signature. `activate` now re-creates the
configuration for every replaced extension (signed or ad hoc), not only for ad hoc signatures.
`--reset-filter` still forces the same path when nothing was replaced. If saving the new
configuration fails, the command reports `state=error`; it does not report `activated`/running.

Policy is in `macos/AxiomSysext/FilterRefreshPolicy.swift`; callers and docs are updated. Swift
tests cover unchanged, explicit reset, replaced, and both.

### 2. Exact profile values, not key presence

`scripts/macos/package-app.sh` now rejects a signed package unless:

- the host profile’s `com.apple.developer.system-extension.install` is boolean `true`;
- host and filter `com.apple.developer.networking.networkextension` are arrays containing
  `content-filter-provider-systemextension`;
- host and filter `com.apple.security.application-groups` are arrays containing the exact
  `$APP_GROUP`;
- application identifier and Team ID still match the expected bundle IDs.

Wrong values, wrong types and empty arrays fail before an artifact is produced. Packaging tests
exercise wrong network-extension value, wrong application group, and a non-true install boolean.

### 3. Approval instructions use the shown app name

The approval prompt and menu summary now say **Axiom Network Filter** (the host’s
`CFBundleDisplayName`), not “Axiom”. The macOS approval message uses the same name. Tests assert
the user-facing strings.

### 4. Safer helper/plist rollback

- The previous plist is captured before the helper swap and before the new plist is written.
- `Swap` records the moved-aside path before the second move can throw, so a partial move is still
  restorable instead of leaking the old helper under `.old-*`.
- If restoring the previous plist fails, the previous helper is restored but **not** bootstrapped;
  the service never starts with the wrong job definition.

Tests cover a failed second move (old copy preserved) and a plist-restore failure (helper restored,
no bootstrap).

## Build and sign

Ad hoc/UI-only build (no activation):

```sh
scripts/macos/package-app.sh osx-arm64 --build-filter
```

This produces `build/macos/osx-arm64/Axiom.app`, `AxiomFilterHost.app` and `Axiom.pkg`. The ad hoc
artifacts are intentionally rejected by Gatekeeper and the host reports activation unavailable.

Signed release build (requires a real Apple team; not exercised here):

```sh
export AXIOM_SIGN_IDENTITY="Developer ID Application: … (TEAMID)"
export AXIOM_INSTALLER_IDENTITY="Developer ID Installer: … (TEAMID)"
export AXIOM_HOST_PROFILE=/path/to/host.provisionprofile
export AXIOM_FILTER_PROFILE=/path/to/filter.provisionprofile
export AXIOM_VERSION=0.24.0
scripts/macos/package-app.sh osx-arm64 --build-filter
```

`AXIOM_BUILD` defaults to 1 in the packager. The host profile must authorise
`com.axiom.firewall.host` plus System Extension install, Network Extension and the app group; the
filter profile must authorise `com.axiom.firewall.filter` plus Network Extension and the app group.
The packager validates both before signing. The installer payload installs both apps in
`/Applications`; postinstall refuses a non-startup target volume before starting the daemon.

The exact-source artifact is kept outside Git (no `.pkg`/`.tar.gz` in the repository). Its
SHA-256 and build provenance are listed below.

## Test status (exact corrected source, macOS 26.6.2 arm64)

All commands used ordinary restore (not `--locked-mode`/`--no-restore`):

| Suite | Result | Exit |
|---|---|---|
| contracts | 148 passed | 0 |
| presentation | 215 passed | 0 |
| desktop macOS | 34 passed | 0 |
| UI Avalonia | 54 passed | 0 |
| infrastructure macOS | 264 passed | 0 |
| Swift filter/activation | 153/153 checks | 0 |
| packaging (stock bash 3.2) | 12/12 PASS | 0 |

A Linux-local infrastructure run fails `CA1859` in `DnsTests.cs` with the local SDK 10.0.115 and
has the same failure on pristine `3040997`; the guest SDK 10.0.403 passes. Ordinary restore changes
10 of 26 `packages.lock.json` files (RID/TFM sections); exact diffs are kept in private evidence,
not in this repository. A locked/offline restore was not reproduced.

## Provenance

- Approved reviewed tip: `1850d61`; tree `484e5208009120694e4f60a9716eaa52011269b1`.
- Corrected code checkpoint: `1270dd0`; tree `5ba8287b3797e1091f362a4887dc4f45b246615b`.
- Base: `3040997` (PR #274-derived), cumulative review base `815d400`.
- Guest toolchain: macOS 26.6.2 (25G83) arm64, CLT Swift 6.3.3, .NET SDK 10.0.403, stock bash
  3.2.57.
- Corrected code-checkpoint artifact: `Axiom.pkg` SHA-256
  `f377d406eddb3a7eb8dac78a5eef71f41b6c79cbb94d629bc53a701c36c31ba3`;
  `Axiom-1270dd0-app.tar.gz` SHA-256
  `5aa6278a5b020d6102d7857fb6be536b722d981299657ed4da00804c8cbdb55f`.
- Docs-tip rebuild from `1850d61`: `Axiom.pkg` SHA-256
  `0d10692ffef2a50ccc3bbf1d12ff1058ec0d34a0c10c5873dd0c657363f122ba`;
  app archive SHA-256
  `7c0836a4c2d062330c0cff81ece14ee82b76a0d091fc7ac56ba7b83905cdfc9a`.
  It contains the same host/extension code as `1270dd0`; packaging/signature bytes differ. The
  installer remains a private artifact, not a Git file.
- Full private evidence: source archive, lock diffs, test logs, codesign/entitlement/profile
  state, payload/signature/Gatekeeper output, per-file hashes and guest/controller checksums.

## Known runtime gates

- No Apple team, Developer ID certificates or provisioning profiles were available. Signed
  activation, notarization, Gatekeeper acceptance and enforcement are **unverified**.
- Ad hoc builds are not production-ready: no restricted entitlements, no activation.
- No privileged install/activation/DNS/firewall change, SIP change or install-side effect was
  performed.
- UI window/display behavior is not claimed; the pre-existing guest process was left untouched.
- The private installer is not committed to Git; the parent/user decides whether a binary belongs
  in distribution storage.
