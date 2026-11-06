// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;

namespace Netpetra.UI.Services;

/// <summary>
/// Explicit UAC-gated adapter DNS helper. Axiom never elevates itself or changes DNS silently;
/// the user confirms the Windows elevation prompt for each action.
/// </summary>
public static class PrivacyShieldDnsHelper
{
    public static string BackupPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Netpetra",
        "privacy-shield-dns-backup.json");

    public static async Task<int> EnableAsync(
        string interfaceAlias,
        string resolverAddress,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(interfaceAlias);
        ArgumentException.ThrowIfNullOrWhiteSpace(resolverAddress);

        var alias = Escape(interfaceAlias);
        var backup = Escape(BackupPath);
        var script = $$"""
            $ErrorActionPreference = 'Stop'
            $backup = '{{backup}}'
            $alias = '{{alias}}'
            $resolver = '{{Escape(resolverAddress)}}'
            if (-not (Test-Path -LiteralPath $backup)) {
              $directory = Split-Path -Parent $backup
              New-Item -ItemType Directory -Force -Path $directory | Out-Null
              $entries = @(Get-DnsClientServerAddress | Where-Object { $_.AddressFamily -in 2,23 } | ForEach-Object {
                [pscustomobject]@{
                  interfaceAlias = $_.InterfaceAlias
                  interfaceIndex = $_.InterfaceIndex
                  addressFamily = [int]$_.AddressFamily
                  serverAddresses = @($_.ServerAddresses)
                }
              })
              [pscustomobject]@{
                capturedUtc = [DateTimeOffset]::UtcNow.ToString('O')
                machine = $env:COMPUTERNAME
                interfaces = $entries
              } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $backup -Encoding UTF8
            }
            Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses @($resolver)
            try {
              if ($resolver -notlike '*:*') {
                Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses @('::1')
              }
            } catch {
              Write-Warning "IPv6 loopback DNS was not set: $($_.Exception.Message)"
            }
            Write-Host "DNS for '$alias' now points at the Privacy Shield loopback resolver."
            """;

        return await RunElevatedAsync(script, cancellationToken).ConfigureAwait(false);
    }

    public static async Task<int> RestoreAsync(CancellationToken cancellationToken)
    {
        var backup = Escape(BackupPath);
        var script = $$"""
            $ErrorActionPreference = 'Stop'
            $backup = '{{backup}}'
            if (-not (Test-Path -LiteralPath $backup)) {
              throw 'No Privacy Shield DNS backup exists.'
            }
            $snapshot = Get-Content -LiteralPath $backup -Raw | ConvertFrom-Json
            foreach ($entry in @($snapshot.interfaces)) {
              if (@($entry.serverAddresses).Count -eq 0) {
                Set-DnsClientServerAddress -InterfaceAlias $entry.interfaceAlias -ResetServerAddresses
              } else {
                Set-DnsClientServerAddress -InterfaceAlias $entry.interfaceAlias -ServerAddresses @($entry.serverAddresses)
              }
            }
            Write-Host 'Original adapter DNS settings restored.'
            """;

        return await RunElevatedAsync(script, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<int> RunElevatedAsync(string script, CancellationToken cancellationToken)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var startInfo = new ProcessStartInfo(
            "powershell.exe",
            $"-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}")
        {
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden,
        };

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("The elevated DNS helper could not start.");
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        return process.ExitCode;
    }

    private static string Escape(string value) => value.Replace("'", "''", StringComparison.Ordinal);
}
