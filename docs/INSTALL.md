# Installing Axiom — core, Complete and optional modules

> **Development build - use at your own risk.** Axiom is under active development and may contain
> defects, incomplete features or regressions. Firewall changes can interrupt connectivity, DNS
> changes can break name resolution, and agent hooks can block tools or files. Do not rely on it as
> your only security control. Where possible, test firewall and DNS changes in a VM, keep backups
> and keep a recovery path. The setup keeps
> **Install Axiom** disabled until you acknowledge these risks.

The bootstrap prefers `Axiom-*-win-x64.zip` release assets and falls back to the
historical portable archives retained on releases published before the rename.

The **core portable installer** can install the desktop application for the current Windows user
without administrator rights, Windows service registration, a driver or firewall changes.
**Complete installation is different:** it can download and install DKG, Blackbox and agent hooks
with separate prerequisites, terms, prompts and network access. Later enabling **Axiom Shield**
requires an explicit administrator approval to install the privileged Windows service.

The recommended GitHub release asset is `Axiom-Setup.exe`: a single self-contained setup
executable with the desktop and service payload embedded. Double-click it, keep or change the two
options, and click **Install Axiom**. It installs for the current user, creates a Start Menu
shortcut, and starts the application. No .NET runtime, administrator rights, service registration or
firewall change is required.

A core-only Microsoft Store (MSIX) build is also available for Store distribution. It excludes the
optional DKG/Blackbox installers and agent hooks. See [STORE.md](STORE.md) for the package build,
Partner Center identity, submission and local test procedure.

The setup's **Complete installation** option runs the official Blackbox and DKG installers, starts
their loopback services and installs agent hooks after Blackbox is ready. The third-party installers
may show their own prompts/terms, download large packages and require network access. Uncheck it for
**Partial installation**: only core Axiom is installed; no Blackbox, DKG, OpenCode, OpenChamber
or Codex files will be created or changed. Axiom also provisions Axiom-managed hooks for detected
harnesses once per build at startup, preserving user-authored hooks. Codex still requires its own
one-time `/hooks` trust review. VirusTotal is optional and its API key is configured later on the
Security page.

The portable installer copies two
self-contained executables (desktop and optional service), verifies their SHA-256 and creates a
Start Menu shortcut.

## Requirements

- Windows 11 x64 (Windows 10 x64 is best-effort).
- No .NET runtime: the published build is self-contained.
- No administrator rights for **core portable copying/launching**; Axiom Shield and some optional
  actions can require elevation.
- A local core archive can be installed without internet. The online bootstrap, Complete
  installation, source-list updates and third-party integrations require connectivity.

## Install

The shortest scripted path from a GitHub release is the bootstrap installer. **Review the remote
script before executing it**; alternatively download the Axiom-Setup.exe binary from an authorized
release and inspect its published SHA-256. The bootstrap downloads the latest
`Axiom-<version>-win-x64.zip`, verifies `SHA256SUMS.txt`, installs for the current user and starts
the app:

```powershell
irm https://raw.githubusercontent.com/a-51-50/Axiom/main/scripts/install-from-github.ps1 | iex
```

The pipeline executes remote PowerShell content immediately, so review the fetched source and
validate the repository before using it. The bootstrap itself does not modify Windows Firewall,
but optional Complete setup/Shield actions are separate and may require further consent. You can also download the release ZIP and run `install-portable.ps1` manually.

From the repository root, after a standalone build:

```powershell
.\scripts\publish-standalone.ps1
.\scripts\install-portable.ps1
```

Or point at an existing executable:

```powershell
.\scripts\install-portable.ps1 -Source D:\Dist\Axiom.Desktop.exe
```

Defaults:

| Item | Location |
|---|---|
| Executable | `%LOCALAPPDATA%\Programs\Axiom\Axiom.Desktop.exe` |
| Service (optional, run manually) | `%LOCALAPPDATA%\Programs\Axiom\Axiom.Service.exe` |
| Manifest (version, SHA-256, time) | `%LOCALAPPDATA%\Programs\Axiom\install.json` |
| Start Menu shortcut | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Axiom.lnk` |
| Local data (created by the service) | `%LOCALAPPDATA%\Axiom` |

Use `-NoShortcut` to skip the shortcut and `-InstallDir` to choose another directory.

## First run

The desktop starts the bundled `Axiom.Service.exe` automatically when it sits next to the
executable. This is a per-user console process, not a registered Windows service. If it cannot start,
the app falls back to in-process monitoring.

The first run can offer optional module setup. **Core monitoring, Axiom Shield, DNS-adapter changes
and third-party agent hooks are different consent surfaces.** Do not assume selecting Complete
means the firewall is already enforcing policy; verify Axiom Shield status separately.

The first-run wizard:

- built-in service and local file scanner are listed as already present;
- DKG and Blackbox are optional and unchecked by default;
- the warning lists downloads, third-party terms, possible UAC and local node/wallet creation;
- **Apply** stays disabled until you accept the terms; **Skip for now** continues without installing;
- selected official installers open in a visible PowerShell window.

VirusTotal and the community feed are configured later on Security; they are not installed by the
wizard.

## Uninstall

```powershell
.\scripts\uninstall-portable.ps1
```

This removes only the installed executable, the manifest and the shortcut. Local data is kept by
default; add `-RemoveData` to delete the Axiom database (`axiom.db` and WAL sidecars). Unknown
files in the installation directory are never deleted. Junction and symbolic-link paths are skipped
so cleanup cannot recurse into user data outside the installation.

## Upgrading from an earlier build

The public product name changed to Axiom. On first start, Axiom runs a one-time local migration:
it moves legacy data into `%LOCALAPPDATA%\Axiom`, renames the database to `axiom.db`, migrates the
starter-feed URL and removes legacy startup/shortcut entries. Existing legacy firewall rules are
still recognized as Axiom-owned so they can be migrated when the write gate is enabled. Stop the
old build before starting Axiom.

## Code signing and SmartScreen

The portable GitHub release is not code-signed. Windows SmartScreen may warn on first launch. The
Microsoft Store package is signed by Microsoft as part of Store submission; see [STORE.md](STORE.md).

Verify the published SHA-256 before running an archive downloaded from the internet:

```powershell
Get-FileHash .\Axiom-<version>-win-x64.zip -Algorithm SHA256
```

Compare it with `SHA256SUMS.txt` from the same release.

## Build a release archive

```powershell
.\scripts\build-release.ps1
```

This publishes the standalone desktop and service builds, packs `Axiom.Desktop.exe`,
`Axiom.Service.exe`, `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md` and the portable
install/uninstall scripts into `artifacts\release\Axiom-<version>-win-x64.zip`, and writes
`SHA256SUMS.txt`. Nothing is uploaded.

From an extracted release archive:

```powershell
.\install-portable.ps1 -Source .\Axiom.Desktop.exe
```

Silent setup requires an explicit risk acknowledgement: `Axiom-Setup.exe --silent --accept-risk`.

## What the core `install-portable.ps1` copy step does not do

The items below describe the core copy script, **not** all possible Complete setup, Shield and
optional module actions.

- It copies `Axiom.Service.exe` and the desktop starts it as a per-user console process; it does
  not register or start a Windows service.
- It does not create, change or remove Windows Firewall rules.
- It does not add itself to startup. You can enable **Start Axiom with Windows** later in Settings; this writes only the per-user startup Run value.
- It does not request administrator rights or elevation.
- It does not download anything.

The core portable script is separate from the consented Axiom Shield Windows service registration
and from optional Blackbox/DKG installation. Portable release artifacts are not yet Authenticode
signed; verify their provenance before installing and keep a recovery path for firewall/DNS changes.
