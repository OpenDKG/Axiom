// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.IO;
using System.Text;

namespace Netpetra.UI.Services;

/// <summary>
/// Removes only Netpetra-owned optional-module files. Blackbox and DKG cleanup runs in a visible
/// PowerShell window; unrelated Hermes profiles, global Python/npm packages, user data and
/// user-authored agent files are kept.
/// </summary>
public sealed class OptionalModuleUninstaller
{
    private readonly string _userProfile;

    private readonly string _localAppData;

    public OptionalModuleUninstaller(string? userProfile = null, string? localAppData = null)
    {
        _userProfile = userProfile ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _localAppData = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    }

    private string ModulesRoot => Path.Combine(_localAppData, "Netpetra", "modules");

    public string BlackboxRoot => Path.Combine(ModulesRoot, "blackbox");

    public string DkgRoot => Path.Combine(ModulesRoot, "dkg");

    public string DkgHome => Path.Combine(ModulesRoot, "dkg-home");

    public string BlackboxCommand => Path.Combine(
        _userProfile,
        ".local",
        "bin",
        "blackbox.cmd");

    public string OpenCodePlugin => Path.Combine(
        _userProfile,
        ".config",
        "opencode",
        "plugins",
        "netpetra-blackbox.ts");

    public string OpenCodeLegacyPlugin => Path.Combine(
        _userProfile,
        ".config",
        "opencode",
        "plugin",
        "netpetra-blackbox.ts");

    public bool IsBlackboxInstalled => Directory.Exists(BlackboxRoot) || File.Exists(BlackboxCommand);

    public string ReputationSettingsPath => Path.Combine(_localAppData, "Netpetra", "reputation.json");

    public string CommunitySettingsPath => Path.Combine(_localAppData, "Netpetra", "community-feed.json");

    public bool IsDkgInstalled => Directory.Exists(DkgRoot) || Directory.Exists(DkgHome);

    /// <summary>
    /// Removes only the Netpetra-managed OpenCode plugin. A user-authored plugin at either the
    /// current or legacy path is never deleted.
    /// </summary>
    public bool RemoveManagedOpenCodePlugin()
    {
        var removed = false;
        removed |= RemoveManagedFile(OpenCodePlugin);
        removed |= RemoveManagedFile(OpenCodeLegacyPlugin);
        return removed;
    }

    public void UninstallBlackbox()
    {
        PrepareBlackboxRemoval();
        StartPowerShell(BuildBlackboxUninstallScript());
    }

    public bool UninstallBlackboxAndWait()
    {
        PrepareBlackboxRemoval();
        return RunPowerShellScript(BuildBlackboxUninstallScript());
    }

    public void UninstallDkg() => StartPowerShell(BuildDkgUninstallScript());

    public bool UninstallDkgAndWait() => RunPowerShellScript(BuildDkgUninstallScript());

    private void PrepareBlackboxRemoval()
    {
        new CodexProtection().Remove();
        RemoveManagedOpenCodePlugin();
    }

    private string BuildBlackboxUninstallScript()
    {
        var hermes = Path.Combine(_userProfile, ".hermes");
        return $$"""
            $ErrorActionPreference = 'Continue'
            $root = '{{Escape(BlackboxRoot)}}'
            $hermes = '{{Escape(hermes)}}'
            $command = '{{Escape(BlackboxCommand)}}'
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
            $blackboxHome = Join-Path $hermes 'blackbox'
            if (Test-Path $blackboxHome) { Remove-Item $blackboxHome -Recurse -Force -ErrorAction SilentlyContinue }
            Get-ChildItem (Join-Path $hermes 'logs') -Filter 'blackbox-*' -ErrorAction SilentlyContinue |
              Remove-Item -Force -ErrorAction SilentlyContinue
            Write-Host 'Blackbox files removed. Other Hermes data and global packages were kept.' -ForegroundColor Green
            """;
    }

    private string BuildDkgUninstallScript() => $$"""
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

    public void RemoveReputationSettings() => DeleteFile(ReputationSettingsPath);

    public void RemoveCommunitySettings() => DeleteFile(CommunitySettingsPath);

    private static bool RemoveManagedFile(string path)
    {
        try
        {
            if (!File.Exists(path) ||
                !File.ReadAllText(path).Contains("Managed by Netpetra", StringComparison.Ordinal))
            {
                return false;
            }

            StorageSafety.BackupFile(path);
            File.Delete(path);
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

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

    private static bool RunPowerShellScript(string script)
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

        using var process = Process.Start(startInfo);
        if (process is null)
        {
            return false;
        }

        process.WaitForExit();
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
