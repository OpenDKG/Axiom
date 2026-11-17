// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.Modules;

/// <summary>
/// Builds PowerShell removal scripts shared across desktop and presentation uninstallers.
/// </summary>
/// <remarks>
/// Every script must run on Windows PowerShell 5.1. That runtime is .NET Framework, which has no
/// <c>String.Contains(string, StringComparison)</c> overload; calling it throws
/// "Cannot find an overload for Contains and the argument count: 2". Use an ordinal
/// <c>IndexOf</c> check instead.
/// </remarks>
public static class ModuleUninstallScripts
{
    private const string SafeDirectoryHelpers = """
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
        function Test-CommandLineMentions($commandLine, $needles) {
          if (-not $commandLine) { return $false }
          foreach ($needle in $needles) {
            if (-not $needle) { continue }
            if ($commandLine.IndexOf([string]$needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
              return $true
            }
          }
          return $false
        }
        function Stop-ModuleProcesses($needles) {
          $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object { Test-CommandLineMentions $_.CommandLine $needles })
          foreach ($p in $procs) {
            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
          }
          foreach ($p in $procs) {
            Wait-Process -Id $p.ProcessId -Timeout 5 -ErrorAction SilentlyContinue
          }
          Write-Host "Stopped $($procs.Count) module process(es)." -ForegroundColor Cyan
          return $procs.Count
        }
        function Remove-SafeFile($path) {
          if (-not (Test-Path -LiteralPath $path) -or (Test-ReparsePath $path)) {
            if (Test-Path -LiteralPath $path) { Write-Warning "Skipped reparse point: $path" }
            return
          }
          try {
            $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReadOnly)) {
              $item.Attributes = $item.Attributes -band (-bnot [IO.FileAttributes]::ReadOnly)
            }
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
          } catch {
            Write-Warning "Could not remove file '$path': $($_.Exception.Message)"
          }
        }
        function Remove-SafeDirectory($path) {
          if (-not (Test-Path -LiteralPath $path) -or (Test-ReparsePath $path)) {
            if (Test-Path -LiteralPath $path) { Write-Warning "Skipped reparse point: $path" }
            return
          }
          for ($attempt = 0; $attempt -lt 3; $attempt++) {
            try {
              Get-ChildItem -LiteralPath $path -Recurse -Force -Attributes ReadOnly -ErrorAction SilentlyContinue | ForEach-Object {
                if (-not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                  try { $_.Attributes = $_.Attributes -band (-bnot [IO.FileAttributes]::ReadOnly) } catch { }
                }
              }
              Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
              return
            } catch {
              if ($attempt -lt 2) {
                Start-Sleep -Milliseconds 350
              } else {
                Write-Warning "Some files in '$path' could not be removed cleanly: $($_.Exception.Message)"
              }
            }
          }
        }
        function Remove-ModuleTask($taskName) {
          if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) { return }
          try {
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($task) {
              Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
              Write-Host "Removed scheduled task: $taskName" -ForegroundColor Green
            }
          } catch {
            Write-Warning "Could not remove scheduled task '$taskName' (it may need administrator rights): $($_.Exception.Message)"
          }
        }
        """;

    public static string BuildBlackboxScript(
        string blackboxRoot,
        string hermesHome,
        string blackboxHome,
        string blackboxCommand)
    {
        return $$"""
            $ErrorActionPreference = 'Continue'
            $root = '{{Escape(blackboxRoot)}}'
            $hermes = '{{Escape(hermesHome)}}'
            $blackboxHome = '{{Escape(blackboxHome)}}'
            $command = '{{Escape(blackboxCommand)}}'
            $plugin = Join-Path (Join-Path $hermes 'plugins') 'blackbox'
            {{SafeDirectoryHelpers}}
            Write-Host 'Stopping Blackbox and its DKG node...' -ForegroundColor Cyan
            $null = Stop-ModuleProcesses @(
              $root,
              $blackboxHome,
              (Join-Path $root 'agent-blackbox'),
              'start-dashboard.py',
              'hermes_cli.main blackbox',
              'origintrail-official\dkg'
            )
            foreach ($taskName in @('Agent Blackbox DKG node', 'Agent Blackbox dashboard', 'Axiom Blackbox dashboard', 'Axiom DKG node')) {
              Remove-ModuleTask $taskName
            }
            Remove-SafeDirectory $root
            Remove-SafeFile $command
            Remove-SafeDirectory $blackboxHome
            Remove-SafeDirectory $plugin
            $logs = Join-Path $hermes 'logs'
            if ((Test-Path -LiteralPath $logs) -and -not (Test-ReparsePath $logs)) {
              Get-ChildItem -LiteralPath $logs -Filter 'blackbox-*' -ErrorAction SilentlyContinue | ForEach-Object {
                if (-not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                  Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
                }
              }
            }
            if (Test-Path -LiteralPath $command) {
              Write-Warning "The Blackbox command file is still present: $command"
            }
            if (Test-Path -LiteralPath $root) {
              Write-Warning "Some Blackbox files are still present in $root (a running process may hold them). Close it and run Uninstall again."
              exit 1
            }
            Write-Host 'Blackbox files removed. Other Hermes data and global packages were kept.' -ForegroundColor Green
            exit 0
            """;
    }

    public static string BuildDkgScript(string dkgRoot, string dkgHome)
    {
        // Never assign to $home: PowerShell reserves $HOME as a read-only automatic variable.
        return $$"""
            $ErrorActionPreference = 'Continue'
            $dkgRoot = '{{Escape(dkgRoot)}}'
            $dkgHome = '{{Escape(dkgHome)}}'
            {{SafeDirectoryHelpers}}
            Write-Host 'Stopping local DKG processes...' -ForegroundColor Cyan
            $null = Stop-ModuleProcesses @(
              $dkgRoot,
              $dkgHome,
              'origintrail-official\dkg'
            )
            Remove-ModuleTask 'Axiom DKG node'
            Remove-SafeDirectory $dkgRoot
            Remove-SafeDirectory $dkgHome
            if ((Test-Path -LiteralPath $dkgRoot) -or (Test-Path -LiteralPath $dkgHome)) {
              Write-Warning 'Some DKG files are still present (a running node may hold them). Close it and run Uninstall again.'
              exit 1
            }
            Write-Host 'Local DKG node and its testnet home removed.' -ForegroundColor Green
            exit 0
            """;
    }

    private static string Escape(string value) => value.Replace("'", "''", StringComparison.Ordinal);
}
