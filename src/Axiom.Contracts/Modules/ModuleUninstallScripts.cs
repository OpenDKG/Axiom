// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.Modules;

/// <summary>
/// Builds PowerShell removal scripts shared across desktop and presentation uninstallers.
/// </summary>
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
            {{SafeDirectoryHelpers}}
            Write-Host 'Stopping Blackbox/DKG processes owned by this installation...' -ForegroundColor Cyan
            $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
              Where-Object {
                $_.CommandLine -and (
                  $_.CommandLine.Contains($root, [System.StringComparison]::OrdinalIgnoreCase) -or
                  $_.CommandLine.Contains($blackboxHome, [System.StringComparison]::OrdinalIgnoreCase) -or
                  $_.CommandLine.Contains('start-dashboard.py', [System.StringComparison]::OrdinalIgnoreCase))
              })
            foreach ($p in $procs) {
              Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
            }
            if ($procs.Count -gt 0) {
              foreach ($p in $procs) {
                Wait-Process -Id $p.ProcessId -Timeout 5 -ErrorAction SilentlyContinue
              }
            }
            if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
              foreach ($taskName in @('Agent Blackbox DKG node', 'Agent Blackbox dashboard')) {
                try {
                  $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                  if ($task) {
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
                    Write-Host "Removed scheduled task: $taskName"
                  }
                } catch {
                  Write-Warning "Could not remove scheduled task '$taskName' (may require administrator rights): $($_.Exception.Message)"
                }
              }
            }
            Remove-SafeDirectory $root
            Remove-SafeFile $command
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

    public static string BuildDkgScript(string dkgRoot, string dkgHome)
    {
        // Never assign to $home: PowerShell reserves $HOME as a read-only automatic variable.
        return $$"""
            $ErrorActionPreference = 'Continue'
            $dkgRoot = '{{Escape(dkgRoot)}}'
            $dkgHome = '{{Escape(dkgHome)}}'
            {{SafeDirectoryHelpers}}
            Write-Host 'Stopping local DKG processes...' -ForegroundColor Cyan
            $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
              Where-Object {
                $_.CommandLine -and (
                  $_.CommandLine.Contains($dkgRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
                  $_.CommandLine.Contains($dkgHome, [System.StringComparison]::OrdinalIgnoreCase))
              })
            foreach ($p in $procs) {
              Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
            }
            if ($procs.Count -gt 0) {
              foreach ($p in $procs) {
                Wait-Process -Id $p.ProcessId -Timeout 5 -ErrorAction SilentlyContinue
              }
            }
            Remove-SafeDirectory $dkgRoot
            Remove-SafeDirectory $dkgHome
            Write-Host 'Local DKG node and its testnet home removed.' -ForegroundColor Green
            """;
    }

    private static string Escape(string value) => value.Replace("'", "''", StringComparison.Ordinal);
}
