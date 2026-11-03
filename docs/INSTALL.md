# Installing Netpetra (portable, per-user)

Netpetra can be installed for the current Windows user without administrator rights, a Windows
service, a driver or any firewall change. The portable installer copies one self-contained
executable, verifies its SHA-256 and creates a Start Menu shortcut.

## Requirements

- Windows 11 x64 (Windows 10 x64 is best-effort).
- No .NET runtime: the published build is self-contained.
- No administrator rights.
- No network access during install; the executable is copied from a local file.

## Install

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
| Manifest (version, SHA-256, time) | `%LOCALAPPDATA%\Programs\Netpetra\install.json` |
| Start Menu shortcut | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Netpetra.lnk` |
| Local data (created by the service) | `%LOCALAPPDATA%\Netpetra` |

Use `-NoShortcut` to skip the shortcut and `-InstallDir` to choose another directory.

## Uninstall

```powershell
.\scripts\uninstall-portable.ps1
```

This removes only the installed executable, the manifest and the shortcut. Local data is kept by
default; add `-RemoveData` to delete the Netpetra database (`netpetra.db` and WAL sidecars). Unknown
files in the installation directory are never deleted.

## Upgrading from an earlier build

The service, Named Pipe, data directory and owned-rule prefix changed with the Netpetra rename.
Stop the old build before starting Netpetra. The old database is not migrated automatically; to keep
its history, copy `%LOCALAPPDATA%\Netrigil\netrigil.db` to
`%LOCALAPPDATA%\Netpetra\netpetra.db` before the first start. Previously owned firewall rules use
the old prefix and are not renamed; remove them with the old build before enabling writes.

## Code signing and SmartScreen

The current release is not code-signed. Windows SmartScreen may warn on first launch. Verify the
published SHA-256 before running an archive downloaded from the internet:

```powershell
Get-FileHash .\Netpetra-<version>-win-x64.zip -Algorithm SHA256
```

Compare it with `SHA256SUMS.txt` from the same release.

## Build a release archive

```powershell
.\scripts\build-release.ps1
```

This publishes the standalone build, packs `Netpetra.Desktop.exe` with `LICENSE`, `NOTICE`,
`THIRD_PARTY_NOTICES.md` and the portable install/uninstall scripts into
`artifacts\release\Netpetra-<version>-win-x64.zip`, and writes `SHA256SUMS.txt`. Nothing is uploaded.

From an extracted release archive:

```powershell
.\install-portable.ps1 -Source .\Netpetra.Desktop.exe
```

## What the portable install does not do

- It does not install or start a Windows service.
- It does not create, change or remove Windows Firewall rules.
- It does not add itself to startup.
- It does not request administrator rights or elevation.
- It does not download anything.

A full MSI installer, service registration, signing and uninstall verification belong to the
installer milestone; the portable script is the supported per-user path until then.
