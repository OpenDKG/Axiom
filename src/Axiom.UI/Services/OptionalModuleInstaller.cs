// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using Axiom.Contracts;

namespace Axiom.UI.Services;

/// <summary>
/// Launches the optional third-party installers only after the UI has shown an explicit warning.
/// The installers run in a visible PowerShell window so the user can read every step; Axiom does
/// not hide or silently execute a remote script.
/// </summary>
public sealed class OptionalModuleInstaller
{
    private const string DkgPackage = "@origintrail-official/dkg@latest";

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

    /// <summary>
    /// Why the last install request did nothing, or null when it started. The UI shows this text:
    /// a silent return looks like a broken button.
    /// </summary>
    public string? LastError { get; private set; }

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

        return RunPowerShellScript(BuildDkgScript(), log);
    }

    private string BuildDkgScript()
    {
        var pathPreamble = ModulePrerequisites.Probe().BuildPathPreamble();
        return $$"""
            $ErrorActionPreference = 'Stop'
            {{pathPreamble}}
            $dkgRoot = '{{Escape(DkgRoot)}}'
            $dkgHome = '{{Escape(DkgHome)}}'
            $dkg = Join-Path $dkgRoot 'node_modules\.bin\dkg.cmd'
            New-Item -ItemType Directory -Force -Path $dkgRoot, $dkgHome | Out-Null
            if (-not (Test-Path $dkg)) {
              Write-Host 'Installing @origintrail-official/dkg (local, --ignore-scripts)...' -ForegroundColor Cyan
              npm install --prefix $dkgRoot --ignore-scripts --no-fund --no-audit '{{DkgPackage}}'
              if ($LASTEXITCODE -ne 0) { throw "npm install failed with exit code $LASTEXITCODE" }
            }
            Write-Host 'Building the better-sqlite3 native module for this Node version...' -ForegroundColor Cyan
            npm rebuild better-sqlite3 --prefix $dkgRoot
            if ($LASTEXITCODE -ne 0) { throw "better-sqlite3 rebuild failed with exit code $LASTEXITCODE" }
            $env:DKG_HOME = $dkgHome
            Write-Host 'Running non-interactive DKG setup with defaults...' -ForegroundColor Cyan
            $answers = 1..14 | ForEach-Object { '' }
            $answers | & $dkg init --network testnet --role edge --store oxigraph -y
            if ($LASTEXITCODE -eq 0) {
              Write-Host 'Starting the DKG node in the background...' -ForegroundColor Cyan
              Start-Process -FilePath $dkg -WorkingDirectory $dkgRoot -WindowStyle Hidden -ArgumentList @('start')
            }
            Write-Host 'DKG setup finished. Return to Axiom and click Check again.' -ForegroundColor Green
            """;
    }

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
        var pathPreamble = ModulePrerequisites.Probe().BuildPathPreamble();
        return $$"""
            $ErrorActionPreference = 'Stop'
            {{pathPreamble}}
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
            Write-Host 'Running the official installer with the Oxigraph backend (no Docker).' -ForegroundColor Cyan
            & $installer -StoreBackend oxigraph
            $venv = Join-Path $dir 'agent-blackbox\venv\Scripts\python.exe'
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
                Start-Process -FilePath $venv -ArgumentList @($launcher) -WorkingDirectory $agent -WindowStyle Hidden
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

    /// <summary>
    /// Opens the visible winget script that installs the missing optional-module prerequisites.
    /// </summary>
    public void InstallPrerequisites(ModulePrerequisiteReport report)
    {
        LastError = null;

        if (DistributionContext.IsStorePackage)
        {
            LastError = "Prerequisite installation is not available in the Microsoft Store build.";
            return;
        }

        if (report.IsSatisfied)
        {
            return;
        }

        StartPowerShell(ModulePrerequisites.BuildBootstrapScript(report));
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

        if (!File.Exists(DkgCommand) || IsUnsafeInstallRoot(DkgRoot, DkgHome, DkgCommand))
        {
            return false;
        }

        var startInfo = new ProcessStartInfo("cmd.exe", $"/c \"\"{DkgCommand}\" start\"")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            WorkingDirectory = DkgRoot,
        };
        startInfo.Environment["DKG_HOME"] = DkgHome;

        try
        {
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return false;
            }

            ProcessWindowHider.Start(process.Id);
            return true;
        }
        catch (Exception exception) when (exception is
                     Win32Exception or InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
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
        var venv = Path.Combine(agent, "venv", "Scripts", "python.exe");
        if (!File.Exists(venv) || IsUnsafeInstallRoot(BlackboxRoot, agent, venv))
        {
            return false;
        }

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

            ProcessWindowHider.Start(process.Id);
            return true;
        }
        catch (Exception exception) when (exception is
                     Win32Exception or InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static bool IsUnsafeInstallRoot(params string[] paths) =>
        paths.Any(StorageSafety.IsReparsePointInPath);

    private static bool RunPowerShellScript(string script, Action<string>? log)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var startInfo = new ProcessStartInfo(
            "powershell.exe",
            $"-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}")
        {
            UseShellExecute = true,
            WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            WindowStyle = ProcessWindowStyle.Normal,
        };

        log?.Invoke("A third-party installer window is opening. Follow its prompts and terms.");
        using var process = Process.Start(startInfo);
        if (process is null)
        {
            log?.Invoke("Could not start PowerShell.");
            return false;
        }

        process.WaitForExit();
        log?.Invoke($"Installer window finished with exit code {process.ExitCode}.");
        return process.ExitCode == 0;
    }

    private static void StartPowerShell(string script)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var startInfo = new ProcessStartInfo(
            "powershell.exe",
            $"-NoProfile -ExecutionPolicy Bypass -NoExit -EncodedCommand {encoded}")
        {
            UseShellExecute = true,
            WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        };

        Process.Start(startInfo);
    }

    private static string Escape(string value) => value.Replace("'", "''", StringComparison.Ordinal);
}
