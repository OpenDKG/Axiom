// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.IO;
using System.Text;

namespace Netpetra.UI.Services;

/// <summary>
/// Removes only Netpetra-owned optional-module files. Blackbox and DKG cleanup runs in a visible
/// PowerShell window; unrelated Hermes profiles, global Python/npm packages and user data are kept.
/// </summary>
public sealed class OptionalModuleUninstaller
{
    private static string ModulesRoot => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Netpetra",
        "modules");

    public string BlackboxRoot => Path.Combine(ModulesRoot, "blackbox");

    public string DkgRoot => Path.Combine(ModulesRoot, "dkg");

    public string DkgHome => Path.Combine(ModulesRoot, "dkg-home");

    public string BlackboxCommand => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".local",
        "bin",
        "blackbox.cmd");

    public string OpenCodePlugin => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".config",
        "opencode",
        "plugins",
        "netpetra-blackbox.ts");

    public string OpenCodeLegacyPlugin => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".config",
        "opencode",
        "plugin",
        "netpetra-blackbox.ts");

    public bool IsBlackboxInstalled => Directory.Exists(BlackboxRoot) || File.Exists(BlackboxCommand);

    public bool IsDkgInstalled => Directory.Exists(DkgRoot) || Directory.Exists(DkgHome);

    public void UninstallBlackbox()
    {
        var hermes = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".hermes");

        var script = $$"""
            $ErrorActionPreference = 'Continue'
            $root = '{{Escape(BlackboxRoot)}}'
            $hermes = '{{Escape(hermes)}}'
            $command = '{{Escape(BlackboxCommand)}}'
            $openCodePlugin = '{{Escape(OpenCodePlugin)}}'
            $openCodeLegacyPlugin = '{{Escape(OpenCodeLegacyPlugin)}}'
            Write-Host 'Stopping Blackbox/DKG processes owned by this installation...' -ForegroundColor Cyan
            Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
              Where-Object { $_.CommandLine -and $_.CommandLine.Contains($root) } |
              ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
            $task = Get-ScheduledTask -TaskName 'Agent Blackbox DKG node' -ErrorAction SilentlyContinue
            if ($task) {
              Unregister-ScheduledTask -TaskName 'Agent Blackbox DKG node' -Confirm:$false -ErrorAction SilentlyContinue
              Write-Host 'Removed scheduled task: Agent Blackbox DKG node'
            }
            if (Test-Path $root) { Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue }
            if (Test-Path $command) { Remove-Item $command -Force -ErrorAction SilentlyContinue }
            if (Test-Path $openCodePlugin) { Remove-Item $openCodePlugin -Force -ErrorAction SilentlyContinue }
            if (Test-Path $openCodeLegacyPlugin) { Remove-Item $openCodeLegacyPlugin -Force -ErrorAction SilentlyContinue }
            $blackboxHome = Join-Path $hermes 'blackbox'
            if (Test-Path $blackboxHome) { Remove-Item $blackboxHome -Recurse -Force -ErrorAction SilentlyContinue }
            Get-ChildItem (Join-Path $hermes 'logs') -Filter 'blackbox-*' -ErrorAction SilentlyContinue |
              Remove-Item -Force -ErrorAction SilentlyContinue
            Write-Host 'Blackbox files removed. Other Hermes data and global packages were kept.' -ForegroundColor Green
            """;

        StartPowerShell(script);
    }

    public void UninstallDkg()
    {
        var script = $$"""
            $ErrorActionPreference = 'Continue'
            $root = '{{Escape(DkgRoot)}}'
            $home = '{{Escape(DkgHome)}}'
            Write-Host 'Stopping local DKG processes...' -ForegroundColor Cyan
            Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
              Where-Object { $_.CommandLine -and ($_.CommandLine.Contains($root) -or $_.CommandLine.Contains($home)) } |
              ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
            if (Test-Path $root) { Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue }
            if (Test-Path $home) { Remove-Item $home -Recurse -Force -ErrorAction SilentlyContinue }
            Write-Host 'Local DKG node and its testnet home removed.' -ForegroundColor Green
            """;

        StartPowerShell(script);
    }

    public void RemoveReputationSettings() => DeleteFile(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Netpetra",
        "reputation.json"));

    public void RemoveCommunitySettings() => DeleteFile(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Netpetra",
        "community-feed.json"));

    private static void DeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
#pragma warning disable CA1031 // Cleanup is best effort; the UI reports the next probe state.
        catch (Exception)
#pragma warning restore CA1031
        {
        }
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
