# Installing Axiom (portable, per-user)

> **Development build - use at your own risk.** Axiom is under active development and may contain
> defects, incomplete features or regressions. Firewall changes can interrupt connectivity, DNS
> changes can break name resolution, and agent hooks can block tools or files. Do not rely on it as
> your only security control. Where possible, test firewall and DNS changes in a VM, keep backups
> and keep a recovery path. The setup keeps
> **Install Axiom** disabled until you acknowledge these risks.

The bootstrap prefers `Axiom-*-win-x64.zip` release assets and falls back to legacy
`Netpetra-*-win-x64.zip` assets for releases published before the rename.

Axiom can be installed for the current Windows user without administrator rights, a Windows
service registration, a driver or any firewall change. The recommended GitHub release asset is `Axiom-Setup.exe`: a single self-contained setup
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
or Codex files will be created or changed. VirusTotal is optional and its API key is configured
later on the Security page.

The portable installer copies two
self-contained executables (desktop and optional service), verifies their SHA-256 and creates a
Start Menu shortcut.

## Requirements

- Windows 11 x64 (Windows 10 x64 is best-effort).
- No .NET runtime: the published build is self-contained.
- No administrator rights.
- No network access during install; the executable is copied from a local file.

## Install

The shortest path from a GitHub release is the bootstrap installer. It downloads the latest
`Axiom-<version>-win-x64.zip`, verifies `SHA256SUMS.txt`, installs for the current user and starts
the app:

```powershell
irm https://raw.githubusercontent.com/a-51-50/Axiom/main/scripts/install-from-github.ps1 | iex
```

This runs a remote script; read it first if you prefer. It needs no administrator rights and makes
no firewall change. You can also download the release ZIP and run `install-portable.ps1` manually.

From the repository root, after a standalone build:

```powershell
.\scripts\publish-standalone.ps1
.\scripts\install-portable.ps1
```

Or point at an existing executable:

```powershell
.\scripts\install-portable.ps1 -Source D:\Dist\Netpetra.Desktop.exe
```

Defaults:

| Item | Location |
|---|---|
| Executable | `%LOCALAPPDATA%\Programs\Netpetra\Netpetra.Desktop.exe` |
| Service (optional, run manually) | `%LOCALAPPDATA%\Programs\Netpetra\Netpetra.Service.exe` |
| Manifest (version, SHA-256, time) | `%LOCALAPPDATA%\Programs\Netpetra\install.json` |
| Start Menu shortcut | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Axiom.lnk` |
| Local data (created by the service) | `%LOCALAPPDATA%\Netpetra` |

Use `-NoShortcut` to skip the shortcut and `-InstallDir` to choose another directory.

## First run

The desktop starts the bundled `Netpetra.Service.exe` automatically when it sits next to the
executable. This is a per-user console process, not a registered Windows service. If it cannot start,
the app falls back to in-process monitoring.

The first run shows a setup wizard:

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
default; add `-RemoveData` to delete the Axiom database (`netpetra.db` and WAL sidecars). Unknown
files in the installation directory are never deleted. Junction and symbolic-link paths are skipped
so cleanup cannot recurse into user data outside the installation.

## Upgrading from an earlier build

The public product name changed to Axiom, but the service name, Named Pipe, per-user data
directory, database file and owned-rule prefix remain Netpetra for compatibility. Stop the old
build before starting Axiom. Existing data under `%LOCALAPPDATA%\Netpetra` is reused; no database
migration is required. Previously owned firewall rules remain recognized.

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

This publishes the standalone desktop and service builds, packs `Netpetra.Desktop.exe`,
`Netpetra.Service.exe`, `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md` and the portable
install/uninstall scripts into `artifacts\release\Axiom-<version>-win-x64.zip`, and writes
`SHA256SUMS.txt`. Nothing is uploaded.

From an extracted release archive:

```powershell
.\install-portable.ps1 -Source .\Netpetra.Desktop.exe
```

Silent setup requires an explicit risk acknowledgement: `Axiom-Setup.exe --silent --accept-risk`.

## What the portable install does not do

- It copies `Netpetra.Service.exe` and the desktop starts it as a per-user console process; it does
  not register or start a Windows service.
- It does not create, change or remove Windows Firewall rules.
- It does not add itself to startup. You can enable **Start Axiom with Windows** later in Settings; this writes only the per-user startup Run value.
- It does not request administrator rights or elevation.
- It does not download anything.

A full MSI installer, service registration, signing and uninstall verification belong to the
installer milestone; the portable script is the supported per-user path until then.
