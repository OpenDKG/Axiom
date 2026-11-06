# Microsoft Store (MSIX) distribution

Axiom has a **core-only** MSIX package for Microsoft Store distribution. The Store signs the
package, so this channel does not require a code-signing certificate, SmartScreen reputation or a
separate installer. The portable GitHub release remains a separate, unsigned channel.

## What is in the Store package

Included:

- the WPF desktop application;
- local IP Helper monitoring with the bundled per-user service process;
- history, applications, events, firewall inventory, overview and settings;
- reputation-provider configuration, the community feed and local SHA-256 file scanning;
- the opt-in local Privacy Shield DNS resolver (manual adapter DNS integration; no automatic DNS
  adapter changes);
- local CSV/support features.

Explicitly excluded:

- OriginTrail DKG and Umanitek Blackbox installers;
- OpenCode, OpenChamber, Codex, Claude Code, Cursor, GitHub Copilot CLI, Gemini CLI, Windsurf
  Cascade, Cline and Hermes hook installation;
- changes to third-party agent configuration;
- HKCU `Run` autostart registration.

The app detects MSIX package identity at startup and hides or blocks the excluded features even when
the package is sideloaded. The package does not contain `Axiom-Setup.exe`; the optional module
installation flow and agent-hook flow are disabled at runtime and are not exposed in the Store UI.

Firewall writes remain off unless both documented test-VM environment variables are set. The Store
package does not request elevation and does not require firewall changes to start.

## Build

Prerequisites:

- Windows 10/11 x64;
- .NET 10 SDK pinned by `global.json`;
- Windows 10/11 SDK with `makeappx.exe` (the script finds the newest x64 SDK copy).

```powershell
.\scripts\build-msix.ps1
```

Outputs:

| File | Purpose |
|---|---|
| `artifacts\store\Axiom-<version>-x64.msix` | MSIX package |
| `artifacts\store\Axiom-<version>-x64.msixupload` | ZIP container for Partner Center |
| `artifacts\store\SHA256SUMS.txt` | Hashes |
| `artifacts\store\package-info.json` | Identity and build scope |

The default manifest identity is a local placeholder. For Store submission, use the exact values
from **Partner Center → your app → Package identity**:

```powershell
.\scripts\build-msix.ps1 `
  -IdentityName "12345Publisher.Axiom" `
  -Publisher "CN=01234567-89ab-cdef-0123-456789abcdef" `
  -PublisherDisplayName "Axiom"
```

The same values can be supplied through:

- `AXIOM_STORE_IDENTITY_NAME`
- `AXIOM_STORE_PUBLISHER`
- `AXIOM_STORE_PUBLISHER_DISPLAY_NAME`

`Publisher` must be the complete Partner Center value, including `CN=`. The generated
`.msixupload` is a ZIP containing the `.msix`; that is the format Partner Center accepts. The Store
signs the package during submission. Do not sign the package with a self-signed certificate for a
Store upload.

## Partner Center submission

1. Register or sign in to Partner Center and reserve the app name.
2. Copy `Identity Name`, `Publisher` and `Publisher Display Name` into the build command above.
3. Build the `.msixupload` with a clean version.
4. In the submission, upload `Axiom-<version>-x64.msixupload` on the **Packages** page.
5. Complete:
   - Properties (category: networking/security, privacy policy URL, support URL);
   - Age ratings;
   - Store listing (description, screenshots, 300×300 and other required Store images);
   - Pricing and availability;
   - Submission notes explaining that the package is a full-trust desktop app and that optional
     third-party installers and agent hooks are intentionally absent.
6. Submit for certification.

The package assets are generated from `src\Axiom.UI\Resources\axiom-icon.png` by
`packaging\msix\generate-assets.ps1`. They are committed so a normal build does not require
image tooling.

## Local test package

An unsigned MSIX cannot be installed normally. For an isolated test VM, you can sign a **local test
copy** with a self-signed certificate whose subject exactly matches the package `Publisher`, then
trust that certificate for the current user:

```powershell
$subject = "CN=Axiom"
$cert = New-SelfSignedCertificate `
  -Type CodeSigningCert `
  -Subject $subject `
  -CertStoreLocation Cert:\CurrentUser\My `
  -KeyExportPolicy Exportable

$password = ConvertTo-SecureString "test-only" -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath .\artifacts\store\test.pfx -Password $password
Export-Certificate -Cert $cert -FilePath .\artifacts\store\test.cer

# A self-signed root is trusted only on this test VM/account. Remove it afterwards.
Import-Certificate `
  -FilePath .\artifacts\store\test.cer `
  -CertStoreLocation Cert:\CurrentUser\Root
Import-Certificate `
  -FilePath .\artifacts\store\test.cer `
  -CertStoreLocation Cert:\CurrentUser\TrustedPeople

& "C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe" sign `
  /fd SHA256 /f .\artifacts\store\test.pfx /p "test-only" `
  .\artifacts\store\Axiom-0.4.21-x64.msix

Add-AppxPackage .\artifacts\store\Axiom-0.4.21-x64.msix
```

Sideloading must be enabled on the test VM. Never use this test certificate for a public release.
The Store-signed package does not need it.

## Verification checklist

On a clean Windows test VM:

- install the signed test package or a Store flight;
- launch Axiom from the Start menu;
- confirm monitoring, history, the firewall inventory and local file scanning;
- confirm the Security page has no DKG/Blackbox install actions;
- confirm there is no Agents page and no hook installation action;
- confirm no HKCU Run startup value is created;
- confirm no OpenCode/Codex/Claude/Cursor/Copilot/Gemini/Windsurf/Cline files are changed;
- close the app and confirm the bundled service process stops or is reusable;
- upgrade the package to a newer version and confirm local data remains readable;
- uninstall and confirm Windows removes the package data as expected.

The package is intentionally not installed by the repository build script. Building and submitting
it are separate actions from creating the portable GitHub release.

## Known certification risks

This is a full-trust desktop package. Microsoft Store review can still reject or request changes for:

- security/firewall functionality;
- full-trust capabilities;
- network access and external reputation lookups;
- the privacy policy and support URL;
- Store listing images or metadata.

The core-only scope reduces risk because the package does not download third-party installers,
modify other applications' configuration or register a background Windows service. It does not
guarantee certification. Test with a Store flight before announcing the Store channel.
