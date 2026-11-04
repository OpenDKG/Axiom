// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.IO;
using System.Text;

namespace Netpetra.UI.Services;

/// <summary>
/// Launches the optional third-party installers only after the UI has shown an explicit warning.
/// The installers run in a visible PowerShell window so the user can read every step; Netpetra does
/// not hide or silently execute a remote script.
/// </summary>
public sealed class OptionalModuleInstaller
{
    private const string DkgPackage = "@origintrail-official/dkg@latest";

    public string DkgRoot { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Netpetra",
        "modules",
        "dkg");

    public string DkgHome { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Netpetra",
        "modules",
        "dkg-home");

    public string BlackboxRoot { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Netpetra",
        "modules",
        "blackbox");

    public string DkgCommand => Path.Combine(DkgRoot, "node_modules", ".bin", "dkg.cmd");

    public bool IsDkgInstalled => File.Exists(DkgCommand);

    /// <summary>
    /// Installs the DKG CLI into a per-user folder, then opens the official interactive setup on
    /// testnet and starts the node. The user answers the official prompts; nothing is hidden.
    /// </summary>
    public void InstallDkg() => StartPowerShell(BuildDkgScript());

    public bool InstallDkgAndWait(Action<string>? log = null) =>
        RunPowerShellScript(BuildDkgScript(), log);

    private string BuildDkgScript()
    {
        return $$"""
            $ErrorActionPreference = 'Stop'
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
            Write-Host 'Starting the official DKG testnet setup. Answer the prompts in this window.' -ForegroundColor Cyan
            & $dkg init --network testnet --role edge --store oxigraph
            if ($LASTEXITCODE -eq 0) {
              Write-Host 'Starting the DKG node...' -ForegroundColor Cyan
              & $dkg start
            }
            Write-Host 'DKG setup finished. Return to Netpetra and click Check again.' -ForegroundColor Green
            """;
    }

    /// <summary>
    /// Downloads Umanitek's official Windows installer to a local file, prints its SHA-256 and runs
    /// it with the Oxigraph backend (no Docker). The caller must have shown a warning first.
    /// </summary>
    public void InstallBlackbox() => StartPowerShell(BuildBlackboxScript());

    public bool InstallBlackboxAndWait(Action<string>? log = null) =>
        RunPowerShellScript(BuildBlackboxScript(), log);

    private string BuildBlackboxScript()
    {
        return $$"""
            $ErrorActionPreference = 'Stop'
            $dir = '{{Escape(BlackboxRoot)}}'
            New-Item -ItemType Directory -Force -Path $dir | Out-Null
            Set-Location $dir
            $installer = Join-Path $dir 'blackbox-install.ps1'
            Write-Host 'Downloading the official Umanitek Blackbox installer...' -ForegroundColor Cyan
            Invoke-WebRequest -UseBasicParsing -Uri 'https://blackbox-w.umanitek.ai' -OutFile $installer
            $hash = (Get-FileHash $installer -Algorithm SHA256).Hash
            Write-Host "Installer SHA256: $hash" -ForegroundColor Yellow
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
                Write-Warning "Blackbox dashboard did not answer yet. Start it from Netpetra with the Start button."
              }
            }
            Write-Host 'Blackbox setup finished. Return to Netpetra and click Check again.' -ForegroundColor Green
            """;
    }

    /// <summary>
    /// Starts an installed DKG node without reinstalling it. Returns false when the local CLI is
    /// missing.
    /// </summary>
    public bool StartDkg()
    {
        if (!File.Exists(DkgCommand))
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

        Process.Start(startInfo);
        return true;
    }

    /// <summary>
    /// Starts the installed Blackbox dashboard without reinstalling it. Returns false when the
    /// per-user virtual environment is missing.
    /// </summary>
    public bool StartBlackboxDashboard()
    {
        var agent = Path.Combine(BlackboxRoot, "agent-blackbox");
        var venv = Path.Combine(agent, "venv", "Scripts", "python.exe");
        if (!File.Exists(venv))
        {
            return false;
        }

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

        Process.Start(startInfo);
        return true;
    }

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
