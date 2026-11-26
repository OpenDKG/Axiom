// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Axiom.Contracts;
using Axiom.Contracts.Blackbox;
using Axiom.Contracts.Modules;

namespace Axiom.Presentation;

/// <summary>
/// The DKG release Axiom installs. It must match the network the installer initialises: Axiom
/// pins a reviewed release in <c>Resources/dkg/package-lock.json</c> and passes <c>--network testnet</c>.
/// </summary>
public static class DkgRelease
{
    public const string PackageName = "@origintrail-official/dkg";

    public const string PinnedVersion = "10.1.2";

    public const string Network = "testnet";

    public static string PackageSpec => $"{PackageName}@{PinnedVersion}";
}

/// <summary>
/// Launches the optional third-party installers only after the UI has shown an explicit warning.
/// The installers run in a visible PowerShell window so the user can read every step; Axiom does
/// not hide or silently execute a remote script.
/// </summary>
public sealed class OptionalModuleInstaller
{
    private static readonly ModuleLaunchGate DkgLaunch = new(TimeSpan.FromSeconds(90));
    private static readonly ModuleLaunchGate BlackboxLaunch = new(TimeSpan.FromSeconds(60));

    private const string DkgPackageJsonResource = "Axiom.Presentation.Resources.dkg.package.json";

    private const string DkgPackageLockResource = "Axiom.Presentation.Resources.dkg.package-lock.json";

    // Pinned vendor installer digest. Update only after reviewing a new official release.
    private const string BlackboxInstallerSha256 = "261122F5E879596E88D63C30D5D36D12B4E155986F83AA3EB83ADEB406E41179";

    /// <summary>Marker recording which pinned vendor build is installed in this tree.</summary>
    private const string InstalledBuildMarker = ".axiom-blackbox-build";
    internal const string BlackboxRequirementsResource =
        "Axiom.Presentation.Resources.blackbox.requirements.lock.txt";
    private const string BlackboxRequirementsFileName = "axiom-requirements.lock.txt";

    internal static string BlackboxDashboardLauncherCode => BlackboxDashboardRuntime.LauncherCode;

    public string DkgRoot { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Axiom",
        "modules",
        "dkg");

    public string DkgHome { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Axiom",
        "modules",
        "dkg-home");

    public string BlackboxRoot { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Axiom",
        "modules",
        "blackbox");

    public string DkgCommand => Path.Combine(DkgRoot, "node_modules", ".bin", AgentPlatform.NpmShimName("dkg"));

    /// <summary>
    /// Runs the optional-module installers on Windows (PowerShell), Linux (bash), and macOS (bash).
    /// </summary>
    public static bool IsInstallSupported =>
        OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    public static string UnsupportedInstallMessage { get; } =
        $"Guided module installation is not available on {UnsupportedPlatformName} yet. " +
        "Run the Axiom installer with --complete or install the module manually, then click Check again.";

    private static string UnsupportedPlatformName =>
        OperatingSystem.IsMacOS() ? "macOS" : OperatingSystem.IsLinux() ? "Linux" : "this platform";

    /// <summary>Blackbox's own node tree; its DKG runtime lives below this folder.</summary>
    public string HermesBlackboxNode { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "hermes",
        "blackbox",
        "node");

    public bool IsDkgInstalled => File.Exists(DkgCommand);

    /// <summary>True when a DKG CLI exists in the per-user folder, the Hermes config, or on PATH.</summary>
    public bool IsDkgAvailable
    {
        get
        {
            var (configuredBin, _) = ResolveConfiguredDkg();
            if (configuredBin is not null && File.Exists(configuredBin) && !IsUnsafeInstallRoot(configuredBin))
            {
                return true;
            }

            return ResolveDkgCommand().Command is not null;
        }
    }

    /// <summary>
    /// Why the last install request did nothing, or null when it started.
    /// </summary>
    public string? LastError { get; private set; }

    /// <summary>
    /// Opens the visible winget script that installs missing optional-module prerequisites.
    /// </summary>
    public void InstallPrerequisites(ModulePrerequisiteReport report, bool includeVcRedist = false)
    {
        ArgumentNullException.ThrowIfNull(report);
        LastError = null;

        if (DistributionContext.IsStorePackage)
        {
            LastError = "Prerequisite installation is not available in the Microsoft Store build.";
            return;
        }

        if (report.IsSatisfied && (OperatingSystem.IsWindows() ? !includeVcRedist : true))
        {
            return;
        }

        if (OperatingSystem.IsWindows())
        {
            StartPowerShell(ModulePrerequisites.BuildBootstrapScript(report, includeVcRedist, interactive: true));
        }
        else
        {
            StartUnixShell(ModulePrerequisites.BuildUnixBootstrapScript(report), "install-prereqs.sh");
        }
    }

    /// <summary>
    /// Silently installs missing optional-module prerequisites via winget/apt/brew during complete Setup.
    /// </summary>
    public bool InstallPrerequisitesAndWait(
        ModulePrerequisiteReport report,
        bool includeVcRedist = false,
        Action<string>? log = null)
    {
        ArgumentNullException.ThrowIfNull(report);
        LastError = null;

        if (DistributionContext.IsStorePackage)
        {
            LastError = "Prerequisite installation is not available in the Microsoft Store build.";
            log?.Invoke(LastError);
            return false;
        }

        if (report.IsSatisfied && (OperatingSystem.IsWindows() ? !includeVcRedist : true))
        {
            return true;
        }

        var ok = OperatingSystem.IsWindows()
            ? RunPowerShellScript(
                ModulePrerequisites.BuildBootstrapScript(report, includeVcRedist, interactive: false),
                log)
            : RunUnixShellScript(ModulePrerequisites.BuildUnixBootstrapScript(report), log);
        if (!ok)
        {
            LastError = $"Automatic prerequisite install did not finish cleanly for: {report.MissingSummary}.";
        }

        return ok;
    }

    /// <summary>
    /// Installs the DKG CLI into a per-user folder, then opens the official interactive setup on
    /// testnet and starts the node. The user answers the official prompts; nothing is hidden.
    /// </summary>
    public void InstallDkg()
    {
        LastError = null;
        if (DistributionContext.IsStorePackage)
        {
            LastError = "This optional third-party module is not included in the Microsoft Store build.";
            return;
        }

        if (IsUnsafeInstallRoot(DkgRoot, DkgHome))
        {
            LastError = "DKG install refused: its target path contains a junction or symbolic link.";
            return;
        }

        if (!EnsureDkgManifests(null))
        {
            LastError = "Could not write the pinned DKG npm manifest.";
            return;
        }

        if (OperatingSystem.IsWindows())
        {
            StartPowerShell(BuildDkgScript());
        }
        else
        {
            StartUnixShell(BuildUnixDkgScript(), "install-dkg.sh");
        }
    }

    public bool InstallDkgAndWait(Action<string>? log = null)
    {
        if (DistributionContext.IsStorePackage)
        {
            log?.Invoke("DKG is not available in the Microsoft Store build.");
            return false;
        }

        if (IsUnsafeInstallRoot(DkgRoot, DkgHome))
        {
            log?.Invoke("DKG install refused: its target path contains a junction or symbolic link.");
            return false;
        }

        if (ResolveNpmExecutable() is null)
        {
            log?.Invoke(
                "DKG prerequisite missing: npm is not installed or not on PATH. " +
                "Install Node.js LTS (https://nodejs.org) so DKG can be installed.");
            return false;
        }

        if (!EnsureDkgManifests(log))
        {
            return false;
        }

        return OperatingSystem.IsWindows()
            ? RunPowerShellScript(BuildDkgScript(), log)
            : RunUnixShellScript(BuildUnixDkgScript(), log);
    }

    private string BuildDkgScript()
    {
        var pathPreamble = string.Join(
            Environment.NewLine,
            new[] { ModulePrerequisites.Probe().BuildPathPreamble(), BuildNodePathPreamble() }
                .Where(line => !string.IsNullOrWhiteSpace(line)));
        return $$"""
            $ErrorActionPreference = 'Stop'
            {{pathPreamble}}
            $dkgRoot = '{{Escape(DkgRoot)}}'
            $dkgHome = '{{Escape(DkgHome)}}'
            $dkg = Join-Path $dkgRoot 'node_modules\.bin\dkg.cmd'
            $dkgVersion = '{{DkgRelease.PinnedVersion}}'
            New-Item -ItemType Directory -Force -Path $dkgRoot, $dkgHome | Out-Null
            $packagePath = Join-Path $dkgRoot 'node_modules\@origintrail-official\dkg\package.json'
            $installed = $null
            if (Test-Path $packagePath) {
              try { $installed = (Get-Content $packagePath -Raw | ConvertFrom-Json).version } catch { $installed = $null }
            }
            if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
              throw 'DKG prerequisite missing: npm is not installed or not on PATH. Install Node.js LTS and retry Repair.'
            }
            if ($installed -ne $dkgVersion -or -not (Test-Path $dkg)) {
              if (Test-Path $dkg) {
                $env:DKG_HOME = $dkgHome
                Write-Host "Stopping Axiom's DKG $installed before upgrading to $dkgVersion..." -ForegroundColor Yellow
                $prevErrorAction = $ErrorActionPreference
                $ErrorActionPreference = 'Continue'
                try { & $dkg stop 2>&1 | Out-Null } finally { $ErrorActionPreference = $prevErrorAction }
                Start-Sleep -Seconds 2
              }
              Write-Host "Installing pinned @origintrail-official/dkg $dkgVersion from the Axiom lockfile..." -ForegroundColor Cyan
              npm ci --prefix $dkgRoot --ignore-scripts --no-fund --no-audit
              if ($LASTEXITCODE -ne 0) { throw "npm ci failed with exit code $LASTEXITCODE" }
            }
            Write-Host 'Building the better-sqlite3 native module for this Node version...' -ForegroundColor Cyan
            npm rebuild better-sqlite3 --prefix $dkgRoot
            if ($LASTEXITCODE -ne 0) { throw "better-sqlite3 rebuild failed with exit code $LASTEXITCODE" }
            $env:DKG_HOME = $dkgHome
            Write-Host 'Running non-interactive DKG setup with defaults...' -ForegroundColor Cyan
            $answers = 1..14 | ForEach-Object { '' }
            $answers | & $dkg init --network {{DkgRelease.Network}} --role edge --store oxigraph -y
            if ($LASTEXITCODE -eq 0) {
              $configPath = Join-Path $dkgHome 'config.json'
              if (Test-Path $configPath) {
                try {
                  $config = Get-Content $configPath -Raw | ConvertFrom-Json
                  if ($null -eq $config.autoUpdate) {
                    $config | Add-Member -NotePropertyName autoUpdate -NotePropertyValue ([pscustomobject]@{ enabled = $false; source = 'npm' })
                  } else {
                    $config.autoUpdate.enabled = $false
                  }
                  if ($null -ne $config.store -and $config.store.backend -eq 'oxigraph-server') {
                    if ($null -eq $config.store.options) {
                      $config.store | Add-Member -NotePropertyName options -NotePropertyValue ([pscustomobject]@{})
                    }
                    if ($config.store.options -is [pscustomobject] -and $null -eq $config.store.options.PSObject.Properties['walRestartThresholdBytes']) {
                      $config.store.options | Add-Member -NotePropertyName walRestartThresholdBytes -NotePropertyValue {{ModuleStorageMaintenance.DefaultOxigraphWalRestartThresholdBytes}}
                    }
                  }
                  [System.IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
                  Write-Host 'DKG auto-update is disabled; Axiom pins the installed version.' -ForegroundColor Yellow
                } catch {
                  Write-Warning "Could not disable DKG auto-update: $_"
                }
              }
              Write-Host 'Starting the DKG node in the background...' -ForegroundColor Cyan
              Start-Process -FilePath $dkg -WorkingDirectory $dkgRoot -WindowStyle Hidden -ArgumentList @('start')
            }
            Write-Host 'DKG setup finished. Return to Axiom and click Check again.' -ForegroundColor Green
            """;
    }

    /// <summary>
    /// Writes the exact npm manifest and lockfile the installer runs. <c>npm ci</c> refuses to run
    /// without them, and the lockfile fixes transitive packages instead of npm's caret ranges.
    /// </summary>
    private bool EnsureDkgManifests(Action<string>? log)
    {
        try
        {
            Directory.CreateDirectory(DkgRoot);
            WriteIfChanged(Path.Combine(DkgRoot, "package.json"), ReadEmbedded(DkgPackageJsonResource));
            WriteIfChanged(Path.Combine(DkgRoot, "package-lock.json"), ReadEmbedded(DkgPackageLockResource));
            return true;
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            log?.Invoke("DKG install refused: could not write the pinned npm manifest: " + exception.Message);
            return false;
        }
    }

    private static string ReadEmbedded(string name)
    {
        using var stream = typeof(OptionalModuleInstaller).Assembly.GetManifestResourceStream(name)
            ?? throw new InvalidOperationException($"Embedded resource {name} is missing.");
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private static void WriteIfChanged(string path, string content)
    {
        if (File.Exists(path) &&
            string.Equals(File.ReadAllText(path), content, StringComparison.Ordinal))
        {
            return;
        }

        File.WriteAllText(path, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }

    /// <summary>
    /// Writes the hash-locked list of the dashboard's Python packages that pip installs from.
    /// </summary>
    private bool EnsureBlackboxRequirements(Action<string>? log)
    {
        try
        {
            Directory.CreateDirectory(BlackboxRoot);
            WriteIfChanged(BlackboxRequirementsPath, ReadEmbedded(BlackboxRequirementsResource));
            return true;
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            log?.Invoke("Blackbox dependency install refused: could not write the pinned requirements file: " + exception.Message);
            return false;
        }
    }

    private string BlackboxRequirementsPath => Path.Combine(BlackboxRoot, BlackboxRequirementsFileName);

    internal const string IntelMacRepairUnavailableMessage =
        "Axiom does not repair the Blackbox Python packages on Intel Macs: the pinned cryptography " +
        "release has no Intel macOS build. Reinstall Blackbox with its own installer.";

    /// <summary>Why the dependency repair cannot run on this computer, or null when it can.</summary>
    internal static string? BlackboxRepairBlocker(bool isMacOS, Architecture architecture) =>
        isMacOS && architecture == Architecture.X64 ? IntelMacRepairUnavailableMessage : null;

    /// <summary>
    /// pip installs exactly the locked versions, verifies each download's hash and resolves nothing else.
    /// </summary>
    internal static string BuildBlackboxPipArguments(string requirementsPath) =>
        $"-m pip install --disable-pip-version-check --quiet --require-hashes --no-deps -r \"{requirementsPath}\"";

    /// <summary>
    /// Downloads Umanitek's official Windows installer to a local file, prints its SHA-256 and runs
    /// it with the Oxigraph backend (no Docker). The caller must have shown a warning first.
    /// </summary>
    public void InstallBlackbox()
    {
        LastError = null;
        if (DistributionContext.IsStorePackage)
        {
            LastError = "This optional third-party module is not included in the Microsoft Store build.";
            return;
        }

        if (IsUnsafeInstallRoot(BlackboxRoot))
        {
            LastError = "Blackbox install refused: its target path contains a junction or symbolic link.";
            return;
        }

        if (OperatingSystem.IsWindows())
        {
            var writeError = "";
            if (!EnsureBlackboxRequirements(message => writeError = message))
            {
                LastError = writeError;
                return;
            }

            StartPowerShell(BuildBlackboxScript());
        }
        else
        {
            StartUnixShell(BuildUnixBlackboxScript(), "install-blackbox.sh");
        }
    }

    public bool InstallBlackboxAndWait(Action<string>? log = null)
    {
        if (DistributionContext.IsStorePackage)
        {
            log?.Invoke("Blackbox is not available in the Microsoft Store build.");
            return false;
        }

        if (IsUnsafeInstallRoot(BlackboxRoot))
        {
            log?.Invoke("Blackbox install refused: its target path contains a junction or symbolic link.");
            return false;
        }

        if (IsPinnedBuildInstalled())
        {
            log?.Invoke("Blackbox pinned build is already installed; reusing the existing runtime (no vendor reinstall).");
            EnsureBlackboxDependencies(log);
            var launcherOutdated = ResolveBlackboxAgentRoot() is { } agent &&
                                   ShouldUpgradeRunningLauncher(Path.Combine(agent, "start-dashboard.py"));
            if (!LocalModuleRuntime.IsPortListening(LocalModuleRuntime.BlackboxPort) || launcherOutdated)
            {
                log?.Invoke(launcherOutdated
                    ? "Restarting the Blackbox dashboard with the updated quiet launcher..."
                    : "Starting the installed Blackbox dashboard...");
                StartBlackboxDashboard();
            }

            return true;
        }

        if (OperatingSystem.IsWindows() && !EnsureBlackboxRequirements(log))
        {
            return false;
        }

        var installed = OperatingSystem.IsWindows()
            ? RunPowerShellScript(BuildBlackboxScript(), log)
            : RunUnixShellScript(BuildUnixBlackboxScript(), log);
        if (installed)
        {
            try
            {
                File.WriteAllText(Path.Combine(BlackboxRoot, InstalledBuildMarker), BlackboxInstallerSha256);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
            }
        }

        return installed;
    }

    private bool IsPinnedBuildInstalled()
    {
        try
        {
            var marker = Path.Combine(BlackboxRoot, InstalledBuildMarker);
            if (!File.Exists(marker) ||
                !string.Equals(File.ReadAllText(marker).Trim(), BlackboxInstallerSha256, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return File.Exists(AgentPlatform.VenvPython(Path.Combine(BlackboxRoot, "agent-blackbox")));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private string BuildBlackboxScript()
    {
        var pathPreamble = ModulePrerequisites.Probe().BuildPathPreamble();
        return $$"""
            $ErrorActionPreference = 'Stop'
            {{pathPreamble}}
            $dir = '{{Escape(BlackboxRoot)}}'
            New-Item -ItemType Directory -Force -Path $dir | Out-Null
            Set-Location $dir
            $installer = Join-Path $dir 'blackbox-install.ps1'

            # Blackbox supports Python 3.11-3.13 only, so a 3.15 path must never become the fallback:
            # the vendor then dies with a Python traceback. Axiom's PATH preamble puts a compatible
            # interpreter first. Do not probe `py -3.x` here: a missing minor prints a red
            # "No runtime installed" error from the launcher before the installer even starts.
            $python = Get-Command python -ErrorAction SilentlyContinue
            $pythonVersion = if ($python) {
              $prevErrorAction = $ErrorActionPreference
              $ErrorActionPreference = 'Continue'
              try {
                $value = (& $python.Source -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null)
                if ($LASTEXITCODE -eq 0) { ([string]$value).Trim() } else { $null }
              } finally {
                $ErrorActionPreference = $prevErrorAction
              }
            } else { $null }
            if ($pythonVersion -notmatch '^3\.(11|12|13)$') {
              throw "Blackbox requires Python 3.11-3.13, but Axiom found $(if ($pythonVersion) { "Python $pythonVersion" } else { 'no usable Python' }). Run Setup's prerequisite install (Python 3.12) and retry Repair."
            }

            # Older builds left a py.cmd shim here that could point at an incompatible interpreter.
            Remove-Item (Join-Path $dir 'py.cmd') -Force -ErrorAction SilentlyContinue

            Write-Host 'Downloading the official Umanitek Blackbox installer...' -ForegroundColor Cyan
            if (-not (Test-Path $installer) -or (Get-Item $installer).Length -eq 0) {
              try { Invoke-WebRequest -UseBasicParsing -Uri 'https://blackbox-w.umanitek.ai' -OutFile $installer }
              catch { Write-Warning "Vendor download failed: $($_.Exception.Message)" }
            }
            if (-not (Test-Path $installer) -or (Get-Item $installer).Length -eq 0) {
              throw 'Could not download the Umanitek Blackbox installer (https://blackbox-w.umanitek.ai).'
            }
            $hash = (Get-FileHash $installer -Algorithm SHA256).Hash.ToUpperInvariant()
            Write-Host "Installer SHA256: $hash" -ForegroundColor Yellow
            if ($hash -ne '{{BlackboxInstallerSha256}}') {
              Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue
              throw "Blackbox installer hash mismatch. Expected {{BlackboxInstallerSha256}}, got $hash. Refusing to run an unpinned installer."
            }
            Write-Host 'Installer hash matches the pinned Axiom digest.' -ForegroundColor Green
            $sys32 = Join-Path $env:SystemRoot 'System32'
            $hasVcRuntime = (Test-Path (Join-Path $sys32 'vcruntime140.dll')) -and (Test-Path (Join-Path $sys32 'msvcp140.dll'))
            $storeBackend = if ($hasVcRuntime) { 'oxigraph' } else { 'auto' }
            if (-not $hasVcRuntime) {
              Write-Warning 'VC++ 2015-2022 redistributable not detected; selecting Blackbox store backend auto.'
            } else {
              Write-Host 'Running the official installer with the Oxigraph backend (no Docker).' -ForegroundColor Cyan
            }
            $env:BLACKBOX_MODE = 'block'
            $env:BLACKBOX_ATTACH_ALL = '1'
            # Axiom always wants the vendored Blackbox tree. Telling the vendor not to reuse an
            # existing Hermes also skips its `hermes.exe --version` probe, which prints a Python
            # traceback when the user's Hermes runtime is broken (issue #370 follow-up).
            $env:BLACKBOX_USE_EXISTING_HERMES = '0'
            $agentRepo = Join-Path $dir 'agent-blackbox'
            if ((Test-Path (Join-Path $agentRepo '.git')) -and (Get-Command git -ErrorAction SilentlyContinue)) {
                # Discard CRLF/tracked-file drift without triggering PS 5.1 NativeCommandError on stderr.
                $prevErrorAction = $ErrorActionPreference
                $ErrorActionPreference = 'Continue'
                try {
                    & git -c core.autocrlf=false -C $agentRepo checkout -- . 2>&1 | Out-Null
                } finally {
                    $ErrorActionPreference = $prevErrorAction
                }
            }
            # Everything from the vendor installer onward is best-effort repair. Native tools write
            # progress and warnings to stderr; with ErrorActionPreference=Stop Windows PowerShell 5.1
            # turns that into a terminating NativeCommandError and aborts before the dashboard is started.
            $ErrorActionPreference = 'Continue'
            $vendorExit = 0
            try {
              & $installer -StoreBackend $storeBackend
              if ($null -ne $LASTEXITCODE) { $vendorExit = $LASTEXITCODE }
            } catch {
              Write-Warning "Vendor installer reported an error: $($_.Exception.Message)"
              $vendorExit = 1
            }
            if ($vendorExit -ne 0) {
              # The pinned vendor build can fail its own "dependency environment committed" check.
              # Repair it once with the vendor CLI; a usable venv is what Axiom actually needs.
              $hermesExe = Join-Path $dir 'agent-blackbox\venv\Scripts\hermes.exe'
              if (-not (Test-Path $hermesExe)) { $hermesExe = Join-Path $env:LOCALAPPDATA 'hermes\bin\hermes.exe' }
              if (Test-Path $hermesExe) {
                Write-Host "Vendor installer exited $vendorExit; running 'hermes pm repair'..." -ForegroundColor Yellow
                & $hermesExe pm repair 2>&1 | ForEach-Object { Write-Host $_ }
              }
            }

            # The vendor pins the LF SHA-256 of the BIP-39 wordlist, but a Windows git clone with
            # core.autocrlf=true writes CRLF and seed-phrase detection disables itself. Normalize every
            # installed copy back to LF so the pinned hash matches (issue #324 / #320).
            foreach ($bip39 in @(
              (Join-Path $dir 'agent-blackbox\plugins\blackbox\kernel\crypto_secrets\bip39_english.txt'),
              (Join-Path $env:LOCALAPPDATA 'hermes\plugins\blackbox\kernel\crypto_secrets\bip39_english.txt'),
              (Join-Path $env:USERPROFILE '.hermes\plugins\blackbox\kernel\crypto_secrets\bip39_english.txt')
            )) {
              if (-not (Test-Path $bip39)) { continue }
              $bytes = [System.IO.File]::ReadAllBytes($bip39)
              $normalized = New-Object byte[] $bytes.Length
              $count = 0
              for ($i = 0; $i -lt $bytes.Length; $i++) {
                if ($bytes[$i] -eq 13 -and ($i + 1) -lt $bytes.Length -and $bytes[$i + 1] -eq 10) { continue }
                $normalized[$count] = $bytes[$i]
                $count++
              }
              if ($count -ne $bytes.Length) {
                $trimmed = New-Object byte[] $count
                [Array]::Copy($normalized, $trimmed, $count)
                [System.IO.File]::WriteAllBytes($bip39, $trimmed)
                Write-Host "Normalized $bip39 to LF ($count bytes)." -ForegroundColor Yellow
              }
              Write-Host ("$bip39 SHA256: " + (Get-FileHash $bip39 -Algorithm SHA256).Hash) -ForegroundColor Yellow
            }
            $venv = Join-Path $dir 'agent-blackbox\venv\Scripts\python.exe'
            $venvW = Join-Path $dir 'agent-blackbox\venv\Scripts\pythonw.exe'
            if (Test-Path $venv) {
              Write-Host 'Repairing missing Blackbox Python dependencies...' -ForegroundColor Cyan
              $requirements = Join-Path $dir '{{BlackboxRequirementsFileName}}'
              & $venv -m pip install --disable-pip-version-check --require-hashes --no-deps -r $requirements
              if ($LASTEXITCODE -ne 0) { throw "Blackbox dependency repair failed with exit code $LASTEXITCODE" }
              $hermes = Join-Path $dir 'agent-blackbox\venv\Scripts\hermes.exe'
              if (Test-Path $hermes) {
                & $hermes plugins enable blackbox --no-allow-tool-override
              }
              $agent = Join-Path $dir 'agent-blackbox'
              $launcher = Join-Path $agent 'start-dashboard.py'
              $code = '{{BlackboxDashboardLauncherCode.Replace("'", "''")}}'
              [System.IO.File]::WriteAllText($launcher, $code, (New-Object System.Text.UTF8Encoding($false)))
              $dashboard = 'http://127.0.0.1:9700'
              $running = $false
              try { Invoke-WebRequest $dashboard -UseBasicParsing -TimeoutSec 2 | Out-Null; $running = $true } catch { }
              if (-not $running) {
                Write-Host 'Starting the Blackbox dashboard...' -ForegroundColor Cyan
                $dashExe = if (Test-Path $venvW) { $venvW } else { $venv }
                Start-Process -FilePath $dashExe -ArgumentList @($launcher) -WorkingDirectory $agent -WindowStyle Hidden
                Start-Sleep -Seconds 8
              }
              try {
                Invoke-WebRequest $dashboard -UseBasicParsing -TimeoutSec 5 | Out-Null
                Write-Host 'Blackbox dashboard is up at http://127.0.0.1:9700.' -ForegroundColor Green
              } catch {
                Write-Warning "Blackbox dashboard did not answer yet. Start it from Axiom with the Start button."
              }
            }
            if (-not (Test-Path $venv)) {
              throw 'Blackbox runtime is not usable: the vendor venv is missing.'
            }
            Write-Host 'Blackbox setup finished. Return to Axiom and click Check again.' -ForegroundColor Green
            exit 0
            """;
    }

    /// <summary>The DKG CLI and home the guard and node actually use, when the Hermes config names them.</summary>
    private (string? Bin, string? Home) ResolveConfiguredDkg()
    {
        try
        {
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var configPath = HermesConfigLocation.Resolve(localAppData, userProfile, File.Exists);
            if (!File.Exists(configPath))
            {
                return (null, null);
            }

            var text = File.ReadAllText(configPath);
            return (DkgHomeResolver.ReadConfiguredBin(text), DkgHomeResolver.ReadConfiguredHome(text));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return (null, null);
        }
    }

    /// <summary>
    /// Starts an installed DKG node without reinstalling it. Returns false when the local CLI is
    /// missing.
    /// </summary>
    public bool StartDkg() => !DistributionContext.IsStorePackage &&
        DkgLaunch.Start(static () => LocalModuleRuntime.AnyDkgPortListening, LaunchDkg);

    private bool LaunchDkg()
    {
        var (configuredBin, configuredHome) = ResolveConfiguredDkg();
        string? command;
        var useOwnHome = false;
        if (configuredBin is not null && File.Exists(configuredBin) && !IsUnsafeInstallRoot(configuredBin))
        {
            command = configuredBin;
        }
        else
        {
            (command, useOwnHome) = ResolveDkgCommand();
        }

        if (command is null)
        {
            return false;
        }

        var (fileName, arguments) = OperatingSystem.IsWindows()
            ? ("cmd.exe", $"/c \"\"{command}\" start\"")
            : (command, "start");
        var startInfo = new ProcessStartInfo(fileName, arguments)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            WorkingDirectory = Path.GetDirectoryName(command) ?? DkgRoot,
        };

        var effectiveHome = useOwnHome ? DkgHome : configuredHome;
        if (!string.IsNullOrWhiteSpace(effectiveHome))
        {
            startInfo.Environment["DKG_HOME"] = effectiveHome;
            ModuleStorageMaintenance.EnsureOxigraphWalMaintenance(Path.Combine(effectiveHome, "config.json"));
        }

        try
        {
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return false;
            }

            BackgroundWindowHider.HideDescendants(TimeSpan.FromSeconds(20));
            return true;
        }
        catch (Exception exception) when (exception is
                     Win32Exception or InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Prefers the Axiom-managed per-user install; otherwise uses an existing `dkg` command from
    /// PATH so a user-installed node (with its own DKG_HOME) can be started from the app.
    /// </summary>
    private (string? Command, bool UseOwnHome) ResolveDkgCommand()
    {
        if (File.Exists(DkgCommand) && !IsUnsafeInstallRoot(DkgRoot, DkgHome, DkgCommand))
        {
            return (DkgCommand, true);
        }

        var path = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrWhiteSpace(path))
        {
            return (null, false);
        }

        var directories = path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries).AsEnumerable();
        if (OperatingSystem.IsMacOS())
        {
            directories = directories.Concat(AgentPlatform.MacExtraSearchDirectories(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)));
        }

        var names = OperatingSystem.IsWindows() ? new[] { "dkg.cmd", "dkg.exe", "dkg.bat" } : new[] { "dkg" };
        foreach (var directory in directories)
        {
            foreach (var name in names)
            {
                try
                {
                    var candidate = Path.Combine(directory.Trim(), name);
                    if (File.Exists(candidate))
                    {
                        return (candidate, false);
                    }
                }
                catch (ArgumentException)
                {
                    // A malformed PATH entry is skipped; the next one may still resolve.
                }
            }
        }

        return (null, false);
    }

    /// <summary>
    /// Starts the installed Blackbox dashboard without reinstalling it. Returns false when the
    /// per-user virtual environment is missing.
    /// </summary>
    public bool StartBlackboxDashboard()
    {
        if (DistributionContext.IsStorePackage)
        {
            return false;
        }

        return BlackboxLaunch.Start(
            static () => LocalModuleRuntime.IsPortListening(LocalModuleRuntime.BlackboxPort),
            LaunchBlackboxDashboard,
            PrepareBlackboxDashboard);
    }

    private bool PrepareBlackboxDashboard()
    {
        if (ResolveBlackboxAgentRoot() is not { } agent ||
            !LocalModuleRuntime.IsPortListening(LocalModuleRuntime.BlackboxPort))
        {
            return true;
        }

        var launcher = Path.Combine(agent, "start-dashboard.py");
        if (!ShouldUpgradeRunningLauncher(launcher))
        {
            return true;
        }

        if (IsUnsafeInstallRoot(BlackboxRoot, agent, launcher) ||
            !LocalModuleRuntime.StopBlackboxDashboard(launcher))
        {
            return false;
        }

        WaitForPortToClose(LocalModuleRuntime.BlackboxPort, TimeSpan.FromSeconds(10));
        return !LocalModuleRuntime.IsPortListening(LocalModuleRuntime.BlackboxPort);
    }

    private bool LaunchBlackboxDashboard()
    {
        var agent = ResolveBlackboxAgentRoot();
        if (agent is null)
        {
            return false;
        }

        var venv = AgentPlatform.VenvPythonNoConsole(agent);
        if (!File.Exists(venv) || IsUnsafeInstallRoot(BlackboxRoot, agent, venv))
        {
            return false;
        }

        BlackboxWordlistNormalizer.NormalizeAll();
        EnsureBlackboxDependencies();

        try
        {
            var launcher = Path.Combine(agent, "start-dashboard.py");
            if (IsUnsafeInstallRoot(launcher))
            {
                return false;
            }

            File.WriteAllText(
                launcher,
                BlackboxDashboardLauncherCode,
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

            var startInfo = new ProcessStartInfo(venv, $"\"{launcher}\"")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                WorkingDirectory = agent,
            };

            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return false;
            }

            BackgroundWindowHider.HideDescendants(TimeSpan.FromSeconds(20));
            return true;
        }
        catch (Exception exception) when (exception is
                     Win32Exception or InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Stops only Axiom-owned module processes. Used before a restart so a hung or duplicated
    /// runtime cannot keep the port. Returns true when the cleanup script ran.
    /// </summary>
    public bool StopModuleProcesses(bool blackbox, bool dkg, Action<string>? log = null)
    {
        var markers = new List<string>();
        if (blackbox)
        {
            markers.Add(Path.Combine(BlackboxRoot, "agent-blackbox"));
            if (ResolveBlackboxAgentRoot() is { } agentRoot)
            {
                markers.Add(agentRoot);
            }

            markers.Add("start-dashboard.py");
            markers.Add("plugins.blackbox.dashboard");
        }

        if (dkg)
        {
            markers.Add(Path.Combine(BlackboxRoot, "agent-blackbox", "dkg"));
            markers.Add(HermesBlackboxNode);
            markers.Add(DkgRoot);
            markers.Add(DkgHome);
        }

        bool Stop() => LocalModuleRuntime.StopProcesses(markers, log);
        if (blackbox && dkg)
        {
            return DkgLaunch.Stop(() => BlackboxLaunch.Stop(Stop));
        }

        if (blackbox)
        {
            return BlackboxLaunch.Stop(Stop);
        }

        return !dkg || DkgLaunch.Stop(Stop);
    }

    /// <summary>
    /// Repairs the installed local services without reinstalling them: stop a hung or duplicated
    /// runtime, start one node and one dashboard, and let the caller verify the endpoints.
    /// <paramref name="restart"/> forces a clean restart when a process owns the port but no longer
    /// answers the module contract.
    /// </summary>
    public bool RepairLocalModules(
        bool blackbox,
        bool dkg,
        bool restartBlackbox = false,
        bool restartDkg = false,
        Action<string>? log = null)
    {
        LastError = null;
        if (DistributionContext.IsStorePackage)
        {
            LastError = "Optional modules are not included in the Microsoft Store build.";
            return false;
        }

        if (!IsInstallSupported)
        {
            // Repair stops processes with a PowerShell script and reinstalls Python packages; module
            // installation and repair are Windows-only for now.
            LastError = UnsupportedInstallMessage;
            log?.Invoke(UnsupportedInstallMessage);
            return false;
        }

        var ok = true;

        if (dkg && IsDkgAvailable)
        {
            var dkgUp = LocalModuleRuntime.AnyDkgPortListening;
            if (!dkgUp || restartDkg)
            {
                log?.Invoke(restartDkg && dkgUp
                    ? "Repair: stopping the DKG node that no longer answers, then starting one node."
                    : "Repair: starting the installed DKG node.");
                StopModuleProcesses(blackbox: false, dkg: true, log);
                if (restartDkg)
                {
                    WaitForAnyDkgPortToClose(TimeSpan.FromSeconds(10));
                }

                if (!StartDkg())
                {
                    LastError = "The installed DKG CLI could not be started; repair it from the module card.";
                    ok = false;
                }
            }
        }

        if (blackbox && IsBlackboxRuntimeInstalled)
        {
            var blackboxUp = LocalModuleRuntime.IsPortListening(LocalModuleRuntime.BlackboxPort);
            if (!blackboxUp || restartBlackbox)
            {
                log?.Invoke(restartBlackbox && blackboxUp
                    ? "Repair: stopping the dashboard that no longer answers, then starting one dashboard."
                    : "Repair: starting the installed Blackbox dashboard.");
                StopModuleProcesses(blackbox: true, dkg: false, log);
                if (restartBlackbox)
                {
                    WaitForPortToClose(LocalModuleRuntime.BlackboxPort, TimeSpan.FromSeconds(10));
                }

                EnsureBlackboxDependencies(log);
                if (!StartBlackboxDashboard())
                {
                    LastError = "The Blackbox virtual environment is missing or unusable; reinstall Blackbox.";
                    ok = false;
                }
            }
        }

        return ok;
    }

    /// <summary>
    /// Installs the dashboard's runtime dependencies when the venv lost them (a vendor update can
    /// leave the editable install without them). The check keeps a healthy venv untouched.
    /// </summary>
    private void EnsureBlackboxDependencies(Action<string>? log = null)
    {
        if (ResolveBlackboxAgentRoot() is not { } agent)
        {
            return;
        }

        var python = AgentPlatform.VenvPython(agent);
        var pythonInfo = new FileInfo(python);
        if (!pythonInfo.Exists || pythonInfo.Length == 0)
        {
            return;
        }

        var importCheck = OperatingSystem.IsWindows()
            ? "-c \"import cryptography, fastapi, uvicorn, aiohttp, psutil, ruamel.yaml, yaml, rich, pywintypes\""
            : "-c \"import cryptography, fastapi, uvicorn, aiohttp, psutil, ruamel.yaml, yaml, rich\"";
        if (LocalModuleRuntime.RunProcess(
                python,
                importCheck,
                log: null,
                TimeSpan.FromSeconds(30)))
        {
            return;
        }

        if (BlackboxRepairBlocker(OperatingSystem.IsMacOS(), RuntimeInformation.OSArchitecture) is { } blocker)
        {
            log?.Invoke(blocker);
            return;
        }

        log?.Invoke("Repair: installing the missing Blackbox dashboard dependencies...");
        if (!EnsureBlackboxRequirements(log))
        {
            return;
        }

        LocalModuleRuntime.RunProcess(
            python,
            BuildBlackboxPipArguments(BlackboxRequirementsPath),
            log,
            TimeSpan.FromMinutes(10));
    }

    private bool IsBlackboxRuntimeInstalled
    {
        get
        {
            var agent = ResolveBlackboxAgentRoot();
            return agent is not null && AgentPlatform.HasVenvPython(agent);
        }
    }

    /// <summary>
    /// The vendor checkout Axiom manages, or one an earlier install left under the Hermes home.
    /// Returns null when neither has a usable virtual environment.
    /// </summary>
    private string? ResolveBlackboxAgentRoot()
    {
        var candidates = new[]
        {
            Path.Combine(BlackboxRoot, "agent-blackbox"),
            Path.Combine(HermesBlackboxNode, "..", "agent-blackbox"),
        };

        foreach (var candidate in candidates)
        {
            if (AgentPlatform.HasVenvPython(candidate))
            {
                return Path.GetFullPath(candidate);
            }
        }

        return null;
    }

    internal static bool ShouldUpgradeRunningLauncher(string launcherPath)
    {
        try
        {
            if (!File.Exists(launcherPath))
            {
                return false;
            }

            var current = File.ReadAllText(launcherPath).Replace("\r\n", "\n", StringComparison.Ordinal);
            return !string.Equals(current, BlackboxDashboardLauncherCode, StringComparison.Ordinal);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static void WaitForPortToClose(int port, TimeSpan timeout)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline && LocalModuleRuntime.IsPortListening(port))
        {
            Thread.Sleep(250);
        }
    }

    private static void WaitForAnyDkgPortToClose(TimeSpan timeout)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline && LocalModuleRuntime.AnyDkgPortListening)
        {
            Thread.Sleep(250);
        }
    }

    public static bool HasVcRuntime(string? windowsDirectory = null)
    {
        if (windowsDirectory is null && !OperatingSystem.IsWindows())
        {
            return true;
        }

        var root = windowsDirectory ?? Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrWhiteSpace(root))
        {
            return false;
        }

        var system32 = Path.Combine(root, "System32");
        return File.Exists(Path.Combine(system32, "vcruntime140.dll")) &&
               File.Exists(Path.Combine(system32, "msvcp140.dll"));
    }

    public static string SelectBlackboxStoreBackend(bool hasVcRuntime) =>
        hasVcRuntime ? "oxigraph" : "auto";

    public static string? ResolveNpmExecutable(
        string? pathVariable = null,
        Func<string, bool>? fileExists = null,
        string? programFiles = null,
        string? programFilesX86 = null,
        string? localAppData = null)
    {
        var exists = fileExists ?? File.Exists;
        var names = OperatingSystem.IsWindows()
            ? new[] { "npm.cmd", "npm.exe" }
            : new[] { "npm" };

        var candidates = new List<string>();
        var path = pathVariable ?? Environment.GetEnvironmentVariable("PATH");
        if (!string.IsNullOrWhiteSpace(path))
        {
            candidates.AddRange(path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries));
        }

        if (OperatingSystem.IsWindows())
        {
            foreach (var root in new[]
                     {
                         programFiles ?? Environment.GetEnvironmentVariable("ProgramFiles"),
                         Environment.GetEnvironmentVariable("ProgramW6432"),
                         programFilesX86 ?? Environment.GetEnvironmentVariable("ProgramFiles(x86)"),
                     })
            {
                if (!string.IsNullOrWhiteSpace(root))
                {
                    candidates.Add(Path.Combine(root, "nodejs"));
                }
            }

            var local = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (!string.IsNullOrWhiteSpace(local))
            {
                candidates.Add(Path.Combine(local, "Programs", "nodejs"));
            }
        }
        else
        {
            var userHome = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            candidates.Add("/opt/homebrew/bin");
            candidates.Add("/usr/local/bin");
            candidates.Add("/usr/bin");
            if (!string.IsNullOrWhiteSpace(userHome))
            {
                candidates.Add(Path.Combine(userHome, ".local", "bin"));
                candidates.Add(Path.Combine(userHome, ".npm-global", "bin"));
            }
        }

        foreach (var rawDir in candidates)
        {
            var trimmed = rawDir.Trim().Trim('"');
            if (string.IsNullOrWhiteSpace(trimmed))
            {
                continue;
            }

            foreach (var name in names)
            {
                try
                {
                    var full = Path.Combine(trimmed, name);
                    if (exists(full))
                    {
                        return full;
                    }
                }
                catch (ArgumentException)
                {
                }
            }
        }

        return null;
    }

    public static string BuildNodePathPreamble(
        string? pathVariable = null,
        Func<string, bool>? fileExists = null,
        string? programFiles = null,
        string? programFilesX86 = null,
        string? localAppData = null)
    {
        var npmPath = ResolveNpmExecutable(pathVariable, fileExists, programFiles, programFilesX86, localAppData);
        var dir = npmPath is null ? null : Path.GetDirectoryName(npmPath);
        if (string.IsNullOrWhiteSpace(dir))
        {
            return string.Empty;
        }

        return $"$env:PATH = '{Escape(dir)};' + $env:PATH";
    }

    public static string ResolvePowerShellExecutable(
        string? pathVariable = null,
        Func<string, bool>? fileExists = null,
        string? programFiles = null)
    {
        var exists = fileExists ?? File.Exists;
        var path = pathVariable ?? Environment.GetEnvironmentVariable("PATH");
        if (!string.IsNullOrWhiteSpace(path))
        {
            var candidates = OperatingSystem.IsWindows()
                ? new[] { "pwsh.exe", "pwsh.cmd" }
                : new[] { "pwsh" };
            foreach (var directory in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmed = directory.Trim().Trim('"');
                if (string.IsNullOrWhiteSpace(trimmed))
                {
                    continue;
                }

                foreach (var name in candidates)
                {
                    try
                    {
                        var full = Path.Combine(trimmed, name);
                        if (exists(full))
                        {
                            return full;
                        }
                    }
                    catch (ArgumentException)
                    {
                    }
                }
            }
        }

        if (OperatingSystem.IsWindows())
        {
            foreach (var root in new[]
                     {
                         programFiles,
                         Environment.GetEnvironmentVariable("ProgramFiles"),
                         Environment.GetEnvironmentVariable("ProgramW6432"),
                     })
            {
                if (string.IsNullOrWhiteSpace(root))
                {
                    continue;
                }

                var standard = Path.Combine(root, "PowerShell", "7", "pwsh.exe");
                if (exists(standard))
                {
                    return standard;
                }
            }

            return "powershell.exe";
        }

        return "pwsh";
    }

    private static bool IsUnsafeInstallRoot(params string[] paths) =>
        paths.Any(StorageSafety.IsReparsePointInPath);

    private static bool RunPowerShellScript(string script, Action<string>? log)
    {
        if (!IsInstallSupported)
        {
            log?.Invoke(UnsupportedInstallMessage);
            return false;
        }

        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var startInfo = new ProcessStartInfo(
            ResolvePowerShellExecutable(),
            $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        log?.Invoke("Running third-party installer silently in the background...");
        try
        {
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                log?.Invoke("Could not start PowerShell.");
                return false;
            }

            BackgroundWindowHider.HideDescendants(TimeSpan.FromMinutes(10));

            var logGate = new object();
            process.OutputDataReceived += (_, args) =>
            {
                if (string.IsNullOrWhiteSpace(args.Data) || log is null)
                {
                    return;
                }

                lock (logGate)
                {
                    log(args.Data);
                }
            };
            process.ErrorDataReceived += (_, args) =>
            {
                if (string.IsNullOrWhiteSpace(args.Data) || log is null)
                {
                    return;
                }

                lock (logGate)
                {
                    log(args.Data);
                }
            };

            process.StandardInput.Close();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            if (!process.WaitForExit((int)TimeSpan.FromMinutes(15).TotalMilliseconds))
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch (Exception exception) when (exception is InvalidOperationException or Win32Exception)
                {
                }

                try
                {
                    process.CancelOutputRead();
                }
                catch (InvalidOperationException)
                {
                }

                try
                {
                    process.CancelErrorRead();
                }
                catch (InvalidOperationException)
                {
                }

                log?.Invoke("Installer timed out after 15 minutes.");
                return false;
            }

            // Ensure asynchronous output/error streams finish flushing after process exit.
            process.WaitForExit();
            log?.Invoke($"Installer finished with exit code {process.ExitCode}.");
            return process.ExitCode == 0;
        }
        catch (Exception exception) when (exception is Win32Exception or InvalidOperationException or IOException)
        {
            log?.Invoke($"Could not run PowerShell installer: {exception.Message}");
            return false;
        }
    }

    private static void StartPowerShell(string script)
    {
        if (!IsInstallSupported)
        {
            return;
        }

        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var startInfo = new ProcessStartInfo(
            ResolvePowerShellExecutable(),
            $"-NoProfile -ExecutionPolicy Bypass -NoExit -EncodedCommand {encoded}")
        {
            UseShellExecute = true,
            WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        };

        using var _ = Process.Start(startInfo);
    }

    private static string Escape(string value) => value.Replace("'", "''", StringComparison.Ordinal);

    private static string EscapeBash(string value) => value.Replace("'", "'\\''", StringComparison.Ordinal);

    private string BuildUnixDkgScript()
    {
        var pathPreamble = ModulePrerequisites.Probe().BuildUnixPathPreamble();
        return $$"""
            #!/usr/bin/env bash
            set -euo pipefail
            {{pathPreamble}}
            dkgRoot='{{EscapeBash(DkgRoot)}}'
            dkgHome='{{EscapeBash(DkgHome)}}'
            dkg="$dkgRoot/node_modules/.bin/dkg"
            dkgVersion='{{DkgRelease.PinnedVersion}}'
            mkdir -p "$dkgRoot" "$dkgHome"
            pkgPath="$dkgRoot/node_modules/@origintrail-official/dkg/package.json"
            installed=""
            if [ -f "$pkgPath" ] && command -v node >/dev/null 2>&1; then
              installed=$(node -e "try{console.log(require(process.argv[1]).version||'')}catch{}" "$pkgPath" 2>/dev/null || true)
            fi
            if ! command -v npm >/dev/null 2>&1; then
              echo "DKG prerequisite missing: npm is not installed or not on PATH." >&2
              exit 1
            fi
            if [ "$installed" != "$dkgVersion" ] || [ ! -x "$dkg" ]; then
              if [ -x "$dkg" ]; then
                DKG_HOME="$dkgHome" "$dkg" stop >/dev/null 2>&1 || true
                sleep 2
              fi
              echo "Installing pinned @origintrail-official/dkg $dkgVersion from the Axiom lockfile..."
              npm ci --prefix "$dkgRoot" --ignore-scripts --no-fund --no-audit
            fi
            echo "Building the better-sqlite3 native module for this Node version..."
            npm rebuild better-sqlite3 --prefix "$dkgRoot"
            export DKG_HOME="$dkgHome"
            echo "Running non-interactive DKG setup with defaults..."
            printf '\n\n\n\n\n\n\n\n\n\n\n\n\n\n' | "$dkg" init --network {{DkgRelease.Network}} --role edge --store oxigraph -y
            configPath="$dkgHome/config.json"
            if [ -f "$configPath" ] && command -v node >/dev/null 2>&1; then
              node -e '
                const fs = require("fs");
                const p = process.argv[1];
                const wal = Number(process.argv[2]);
                const cfg = JSON.parse(fs.readFileSync(p, "utf8"));
                cfg.autoUpdate = Object.assign(cfg.autoUpdate || {}, { enabled: false, source: "npm" });
                if (cfg.store && cfg.store.backend === "oxigraph-server") {
                  cfg.store.options = cfg.store.options || {};
                  if (cfg.store.options.walRestartThresholdBytes == null) cfg.store.options.walRestartThresholdBytes = wal;
                }
                fs.writeFileSync(p, JSON.stringify(cfg, null, 2));
              ' "$configPath" "{{ModuleStorageMaintenance.DefaultOxigraphWalRestartThresholdBytes}}" || true
            fi
            echo "Starting the DKG node in the background..."
            nohup "$dkg" start </dev/null >/dev/null 2>&1 &
            echo "DKG setup finished. Return to Axiom and click Check again."
            """;
    }

    private string BuildUnixBlackboxScript()
    {
        var pathPreamble = ModulePrerequisites.Probe().BuildUnixPathPreamble();
        const string pinnedRevision = "6df9193f8ba1d0a7adb39701d67c59b560408f8d";
        return $$"""
            #!/usr/bin/env bash
            set -euo pipefail
            {{pathPreamble}}
            dir='{{EscapeBash(BlackboxRoot)}}'
            agent="$dir/agent-blackbox"
            mkdir -p "$dir"
            if ! command -v git >/dev/null 2>&1; then
              echo "Git is required to install Blackbox." >&2
              exit 1
            fi
            if [ ! -d "$agent/.git" ]; then
              rm -rf "$agent"
              git init -q "$agent"
              git -C "$agent" fetch -q --depth 1 https://github.com/umanitek/agent-blackbox.git "{{pinnedRevision}}"
              git -C "$agent" checkout -q --detach FETCH_HEAD
            else
              git -C "$agent" checkout -q -- . >/dev/null 2>&1 || true
            fi
            cd "$agent"
            BLACKBOX_SETUP_ONLY=false BLACKBOX_USE_EXISTING_HERMES=0 BLACKBOX_MODE=block \
              BLACKBOX_HERMES_SETUP=never BLACKBOX_SYNC_MODE=wait BLACKBOX_ATTACH_ALL=1 \
              bash scripts/blackbox-install.sh --store oxigraph
            python=$("$agent/scripts/run-in-hermes-env" python3 -c \
              'import sys; from plugins.blackbox.guard import hooks; print(sys.executable)' | tail -n 1)
            launcher="$agent/axiom-blackbox-python"
            printf '#!/bin/bash\nexport HERMES_HOME=%q\nexec %q "$@"\n' "${HERMES_HOME:-$HOME/.hermes}" "$python" > "$launcher"
            chmod 0700 "$launcher"
            cat > "$agent/start-dashboard.py" <<'AXIOM_DASH_EOF'
            {{BlackboxDashboardLauncherCode}}
            AXIOM_DASH_EOF
            if ! curl --noproxy '*' -fsS --max-time 2 http://127.0.0.1:9700 >/dev/null 2>&1; then
              nohup "$launcher" "$agent/start-dashboard.py" </dev/null >/dev/null 2>&1 &
              sleep 4
            fi
            echo "Blackbox setup finished. Return to Axiom and click Check again."
            """;
    }

    private static bool RunUnixShellScript(string script, Action<string>? log)
    {
        var shell = File.Exists("/bin/bash") ? "/bin/bash" : "/bin/sh";
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(script));
        var runner = $"eval \"$(printf '%s' '{encoded}' | base64 -d 2>/dev/null || printf '%s' '{encoded}' | base64 -D)\"";
        return LocalModuleRuntime.RunProcess(
            shell,
            $"-c \"{runner.Replace("\"", "\\\"", StringComparison.Ordinal)}\"",
            log,
            TimeSpan.FromMinutes(15));
    }

    private void StartUnixShell(string script, string fileName)
    {
        if (!IsInstallSupported)
        {
            return;
        }

        try
        {
            var scriptsDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Axiom",
                "scripts");
            Directory.CreateDirectory(scriptsDir);
            var scriptPath = Path.Combine(scriptsDir, fileName);
            File.WriteAllText(scriptPath, script.Replace("\r\n", "\n", StringComparison.Ordinal), new UTF8Encoding(false));
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(
                    scriptPath,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }

            if (OperatingSystem.IsMacOS())
            {
                using var _ = Process.Start(new ProcessStartInfo("/usr/bin/open", $"-a Terminal \"{scriptPath}\"") { UseShellExecute = false });
                return;
            }

            foreach (var (term, args) in new[]
                     {
                         ("x-terminal-emulator", $"-e bash \"{scriptPath}\""),
                         ("gnome-terminal", $"-- bash \"{scriptPath}; read -p 'Press Enter to close...' _\""),
                         ("konsole", $"-e bash \"{scriptPath}\""),
                         ("xfce4-terminal", $"-e \"bash '{scriptPath}'\""),
                     })
            {
                if (File.Exists($"/usr/bin/{term}") || File.Exists($"/bin/{term}"))
                {
                    using var _ = Process.Start(new ProcessStartInfo(term, args) { UseShellExecute = false });
                    return;
                }
            }

            using var __ = Process.Start(new ProcessStartInfo(File.Exists("/bin/bash") ? "/bin/bash" : "/bin/sh", $"\"{scriptPath}\"")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            });
        }
        catch (Exception exception) when (exception is Win32Exception or InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            LastError = $"Could not start module installer: {exception.Message}";
        }
    }
}
