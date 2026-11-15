// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using Axiom.Contracts;
using Axiom.Contracts.Blackbox;

namespace Axiom.Presentation;

/// <summary>
/// The DKG release Axiom installs. It must match the network the installer initialises: npm's
/// <c>latest</c> tag is the mainnet build, while testnet uses a different version.
/// </summary>
public static class DkgRelease
{
    public const string PackageName = "@origintrail-official/dkg";

    public const string PinnedVersion = "10.1.0";

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
    private const string DkgPackageJsonResource = "Axiom.Presentation.Resources.dkg.package.json";

    private const string DkgPackageLockResource = "Axiom.Presentation.Resources.dkg.package-lock.json";

    // Pinned vendor installer digest. Update only after reviewing a new official release.
    private const string BlackboxInstallerSha256 = "261122F5E879596E88D63C30D5D36D12B4E155986F83AA3EB83ADEB406E41179";

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

    public string DkgCommand => Path.Combine(DkgRoot, "node_modules", ".bin", "dkg.cmd");

    public bool IsDkgInstalled => File.Exists(DkgCommand);

    /// <summary>True when a DKG CLI exists in the per-user folder or on PATH.</summary>
    public bool IsDkgAvailable => ResolveDkgCommand().Command is not null;

    /// <summary>
    /// Installs the DKG CLI into a per-user folder, then opens the official interactive setup on
    /// testnet and starts the node. The user answers the official prompts; nothing is hidden.
    /// </summary>
    public void InstallDkg()
    {
        if (DistributionContext.IsStorePackage)
        {
            return;
        }

        if (IsUnsafeInstallRoot(DkgRoot, DkgHome))
        {
            return;
        }

        if (!EnsureDkgManifests(null))
        {
            return;
        }

        StartPowerShell(BuildDkgScript());
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

        if (!EnsureDkgManifests(log))
        {
            return false;
        }

        return RunPowerShellScript(BuildDkgScript(), log);
    }

    private string BuildDkgScript()
    {
        return $$"""
            $ErrorActionPreference = 'Stop'
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
            if ($installed -ne $dkgVersion -or -not (Test-Path $dkg)) {
              if (Test-Path $dkg) {
                $env:DKG_HOME = $dkgHome
                Write-Host "Stopping Axiom's DKG $installed before upgrading to $dkgVersion..." -ForegroundColor Yellow
                & $dkg stop 2>$null | Out-Null
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
    /// Downloads Umanitek's official Windows installer to a local file, prints its SHA-256 and runs
    /// it with the Oxigraph backend (no Docker). The caller must have shown a warning first.
    /// </summary>
    public void InstallBlackbox()
    {
        if (DistributionContext.IsStorePackage)
        {
            return;
        }

        if (IsUnsafeInstallRoot(BlackboxRoot))
        {
            return;
        }

        StartPowerShell(BuildBlackboxScript());
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

        return RunPowerShellScript(BuildBlackboxScript(), log);
    }

    private string BuildBlackboxScript()
    {
        return $$"""
            $ErrorActionPreference = 'Stop'
            $dir = '{{Escape(BlackboxRoot)}}'
            New-Item -ItemType Directory -Force -Path $dir | Out-Null
            Set-Location $dir
            $installer = Join-Path $dir 'blackbox-install.ps1'

            # The vendor installer calls 'py -3.12'. On a clean Windows without the launcher
            # python.exe receives '-3' and the venv is never created; provide a shim for this run.
            $pyOk = $false
            if (Get-Command py -ErrorAction SilentlyContinue) {
              & py -3.12 --version *> $null
              $pyOk = ($LASTEXITCODE -eq 0)
            }
            if (-not $pyOk -and (Get-Command python -ErrorAction SilentlyContinue)) {
              $shim = Join-Path $dir 'py.cmd'
              $shimText = "@echo off`r`nsetlocal`r`nset `"ARGS=%*`"`r`nset `"ARGS=%ARGS:-3.12=%`"`r`nset `"ARGS=%ARGS:-3=%`"`r`npython %ARGS%`r`n"
              Set-Content -Path $shim -Value $shimText -Encoding Ascii
              $env:PATH = $dir + ';' + $env:PATH
              Write-Host 'Provided a py launcher shim for the vendor installer.' -ForegroundColor Yellow
            }

            Write-Host 'Downloading the official Umanitek Blackbox installer...' -ForegroundColor Cyan
            if (-not (Test-Path $installer) -or (Get-Item $installer).Length -eq 0) {
              try { Invoke-WebRequest -UseBasicParsing -Uri 'https://blackbox-w.umanitek.ai' -OutFile $installer }
              catch { Write-Warning "Vendor download failed: $($_.Exception.Message)" }
            }
            $hash = (Get-FileHash $installer -Algorithm SHA256).Hash.ToUpperInvariant()
            Write-Host "Installer SHA256: $hash" -ForegroundColor Yellow
            if ($hash -ne '{{BlackboxInstallerSha256}}') {
              throw "Blackbox installer hash mismatch. Expected {{BlackboxInstallerSha256}}, got $hash. Refusing to run an unpinned installer."
            }
            Write-Host 'Installer hash matches the pinned Axiom digest.' -ForegroundColor Green
            $sys32 = Join-Path $env:SystemRoot 'System32'
            $hasVcRuntime = (Test-Path (Join-Path $sys32 'vcruntime140.dll')) -and (Test-Path (Join-Path $sys32 'msvcp140.dll'))
            $storeBackend = if ($hasVcRuntime) { 'oxigraph' } else { 'oxigraph-worker' }
            if (-not $hasVcRuntime) {
              Write-Warning 'VC++ 2015-2022 redistributable not detected; defaulting Blackbox store backend to embedded oxigraph-worker.'
            } else {
              Write-Host 'Running the official installer with the Oxigraph backend (no Docker).' -ForegroundColor Cyan
            }
            $env:BLACKBOX_MODE = 'block'
            $env:BLACKBOX_ATTACH_ALL = '1'
            & $installer -StoreBackend $storeBackend

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
              & $venv -m pip install ruamel.yaml python-dotenv rich pyyaml aiohttp cryptography psutil fastapi uvicorn
              if ($LASTEXITCODE -ne 0) { throw "Blackbox dependency repair failed with exit code $LASTEXITCODE" }
              $hermes = Join-Path $dir 'agent-blackbox\venv\Scripts\hermes.exe'
              if (Test-Path $hermes) {
                & $hermes plugins enable blackbox --no-allow-tool-override
              }
              $agent = Join-Path $dir 'agent-blackbox'
              $launcher = Join-Path $agent 'start-dashboard.py'
              $code = "import argparse`nfrom plugins.blackbox.dashboard import cmd_dashboard`nraise SystemExit(cmd_dashboard(argparse.Namespace(port=None)))`n"
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
            Write-Host 'Blackbox setup finished. Return to Axiom and click Check again.' -ForegroundColor Green
            """;
    }

    /// <summary>The DKG CLI and home the guard and node actually use, when the Hermes config names them.</summary>
    private (string? Bin, string? Home) ResolveConfiguredDkg()
    {
        try
        {
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var configPath = Path.Combine(localAppData, "hermes", "config.yaml");
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
    public bool StartDkg()
    {
        if (DistributionContext.IsStorePackage)
        {
            return false;
        }

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

        var startInfo = new ProcessStartInfo("cmd.exe", $"/c \"\"{command}\" start\"")
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

        foreach (var directory in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            foreach (var name in new[] { "dkg.cmd", "dkg.exe", "dkg.bat" })
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

        var agent = Path.Combine(BlackboxRoot, "agent-blackbox");
        var venvPythonW = Path.Combine(agent, "venv", "Scripts", "pythonw.exe");
        var venvPython = Path.Combine(agent, "venv", "Scripts", "python.exe");
        var venv = File.Exists(venvPythonW) ? venvPythonW : venvPython;
        if (!File.Exists(venv) || IsUnsafeInstallRoot(BlackboxRoot, agent, venv))
        {
            return false;
        }

        BlackboxWordlistNormalizer.NormalizeAll();

        try
        {
            var launcher = Path.Combine(agent, "start-dashboard.py");
            File.WriteAllText(
                launcher,
                "import argparse\n" +
                "from plugins.blackbox.dashboard import cmd_dashboard\n" +
                "raise SystemExit(cmd_dashboard(argparse.Namespace(port=None)))\n",
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

    public static bool HasVcRuntime(string? windowsDirectory = null)
    {
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
        hasVcRuntime ? "oxigraph" : "oxigraph-worker";

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
        BackgroundWindowHider.HideDescendants(TimeSpan.FromMinutes(10));
        using var process = Process.Start(startInfo);
        if (process is null)
        {
            log?.Invoke("Could not start PowerShell.");
            return false;
        }

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
        process.WaitForExit();
        log?.Invoke($"Installer finished with exit code {process.ExitCode}.");
        return process.ExitCode == 0;
    }

    private static void StartPowerShell(string script)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var startInfo = new ProcessStartInfo(
            ResolvePowerShellExecutable(),
            $"-NoProfile -ExecutionPolicy Bypass -NoExit -EncodedCommand {encoded}")
        {
            UseShellExecute = true,
            WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        };

        Process.Start(startInfo);
    }

    private static string Escape(string value) => value.Replace("'", "''", StringComparison.Ordinal);
}
