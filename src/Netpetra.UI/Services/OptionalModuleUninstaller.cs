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

    public string OpenCodePluginDirectory => Path.Combine(
        _userProfile,
        ".config",
        "opencode",
        "plugins",
        "netpetra-blackbox");

    public string OpenCodePlugin => Path.Combine(OpenCodePluginDirectory, "index.ts");

    public string OpenCodeV1Plugin => Path.Combine(
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
    /// Removes only Netpetra-managed OpenCode V2/V1 plugins. A user-authored plugin at any current
    /// or legacy path is never deleted.
    /// </summary>
    public bool RemoveManagedOpenCodePlugin()
    {
        var removed = false;
        removed |= RemoveManagedFile(OpenCodePlugin);
        removed |= RemoveManagedFile(OpenCodeV1Plugin);
        removed |= RemoveManagedFile(OpenCodeLegacyPlugin);
        TryRemoveEmptyDirectory(OpenCodePluginDirectory);
        return removed;
    }

    private static void TryRemoveEmptyDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path) &&
                !StorageSafety.IsReparsePointInPath(path) &&
                !Directory.EnumerateFileSystemEntries(path).Any())
            {
                Directory.Delete(path);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
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
        new ClaudeProtection().Remove();
        new CursorProtection().Remove();
        new CopilotProtection().Remove();
        new GeminiProtection().Remove();
        new WindsurfProtection().Remove();
        new ClineProtection().Remove();
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
            function Test-ReparsePath($path) {
              $current = [IO.Path]::GetFullPath($path)
              while ($current) {
                if (Test-Path -LiteralPath $current) {
                  $item = Get-Item -LiteralPath $current -Force -ErrorAction SilentlyContinue
                  if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                    return $true
                  }
                }
                $parent = Split-Path -Parent $current
                if (-not $parent -or $parent -eq $current) { break }
                $current = $parent
              }
              return $false
            }
            function Remove-SafeFile($path) {
              if (-not (Test-Path -LiteralPath $path) -or (Test-ReparsePath $path)) {
                if (Test-Path -LiteralPath $path) { Write-Warning "Skipped reparse point: $path" }
                return
              }
              Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            }
            function Remove-SafeDirectory($path) {
              if (-not (Test-Path -LiteralPath $path) -or (Test-ReparsePath $path)) {
                if (Test-Path -LiteralPath $path) { Write-Warning "Skipped reparse point: $path" }
                return
              }
              Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
            }
            Write-Host 'Stopping Blackbox/DKG processes owned by this installation...' -ForegroundColor Cyan
            Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
              Where-Object { $_.CommandLine -and $_.CommandLine.Contains($root) } |
              ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
            $task = Get-ScheduledTask -TaskName 'Agent Blackbox DKG node' -ErrorAction SilentlyContinue
            if ($task) {
              Unregister-ScheduledTask -TaskName 'Agent Blackbox DKG node' -Confirm:$false -ErrorAction SilentlyContinue
              Write-Host 'Removed scheduled task: Agent Blackbox DKG node'
            }
            Remove-SafeDirectory $root
            Remove-SafeFile $command
            $blackboxHome = Join-Path $hermes 'blackbox'
            Remove-SafeDirectory $blackboxHome
            $logs = Join-Path $hermes 'logs'
            if ((Test-Path -LiteralPath $logs) -and -not (Test-ReparsePath $logs)) {
              Get-ChildItem -LiteralPath $logs -Filter 'blackbox-*' -ErrorAction SilentlyContinue | ForEach-Object {
                if (-not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                  Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
                }
              }
            }
            Write-Host 'Blackbox files removed. Other Hermes data and global packages were kept.' -ForegroundColor Green
            """;
    }

    private string BuildDkgUninstallScript() => $$"""
        $ErrorActionPreference = 'Continue'
        $root = '{{Escape(DkgRoot)}}'
        $home = '{{Escape(DkgHome)}}'
        function Test-ReparsePath($path) {
          $current = [IO.Path]::GetFullPath($path)
          while ($current) {
            if (Test-Path -LiteralPath $current) {
              $item = Get-Item -LiteralPath $current -Force -ErrorAction SilentlyContinue
              if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                return $true
              }
            }
            $parent = Split-Path -Parent $current
            if (-not $parent -or $parent -eq $current) { break }
            $current = $parent
          }
          return $false
        }
        function Remove-SafeDirectory($path) {
          if (-not (Test-Path -LiteralPath $path) -or (Test-ReparsePath $path)) {
            if (Test-Path -LiteralPath $path) { Write-Warning "Skipped reparse point: $path" }
            return
          }
          Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
        Write-Host 'Stopping local DKG processes...' -ForegroundColor Cyan
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
          Where-Object { $_.CommandLine -and ($_.CommandLine.Contains($root) -or $_.CommandLine.Contains($home)) } |
          ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        Remove-SafeDirectory $root
        Remove-SafeDirectory $home
        Write-Host 'Local DKG node and its testnet home removed.' -ForegroundColor Green
        """;

    public void RemoveReputationSettings() => DeleteFile(ReputationSettingsPath);

    public void RemoveCommunitySettings() => DeleteFile(CommunitySettingsPath);

    private static bool RemoveManagedFile(string path)
    {
        try
        {
            if (!File.Exists(path) ||
                StorageSafety.IsReparsePointInPath(path) ||
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
            if (File.Exists(path) && !StorageSafety.IsReparsePointInPath(path))
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
