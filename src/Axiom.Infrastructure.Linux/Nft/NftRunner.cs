// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Runtime.Versioning;

namespace Axiom.Infrastructure.Linux.Nft;

/// <summary>Outcome of one <c>nft</c> invocation.</summary>
public sealed record NftResult(int ExitCode, string StandardOutput, string StandardError)
{
    public bool Succeeded => ExitCode == 0;
}

/// <summary>The only way the engine talks to nftables; faked in tests, a child process in the daemon.</summary>
public interface INftRunner
{
    /// <summary>Runs <c>nft &lt;args&gt;</c>; <paramref name="standardInput"/> (when not null) is piped to stdin.</summary>
    Task<NftResult> RunAsync(IReadOnlyList<string> args, string? standardInput, CancellationToken ct);
}

/// <summary>Runs the system <c>nft</c> binary (root daemon). Never a shell: arguments are passed verbatim.</summary>
[SupportedOSPlatform("linux")]
public sealed class NftProcessRunner : INftRunner
{
    public const string DefaultBinary = "/usr/sbin/nft";

    private readonly string _binary;
    private readonly TimeSpan _timeout;

    public NftProcessRunner(string? binary = null, TimeSpan? timeout = null)
    {
        _binary = string.IsNullOrWhiteSpace(binary) ? DefaultBinary : binary;
        _timeout = timeout ?? TimeSpan.FromSeconds(20);
    }

    public async Task<NftResult> RunAsync(IReadOnlyList<string> args, string? standardInput, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(args);
        var start = new ProcessStartInfo(_binary)
        {
            RedirectStandardInput = standardInput is not null,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        start.Environment.Remove("NOTIFY_SOCKET"); // keep systemd's notify channel to the main pid
        foreach (var arg in args)
        {
            start.ArgumentList.Add(arg);
        }

        using var process = new Process { StartInfo = start };
        try
        {
            process.Start();
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return new NftResult(127, string.Empty, $"{_binary}: {exception.Message}");
        }

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutSource.CancelAfter(_timeout);
        var token = timeoutSource.Token;
        try
        {
            var stdout = process.StandardOutput.ReadToEndAsync(token);
            var stderr = process.StandardError.ReadToEndAsync(token);
            if (standardInput is not null)
            {
                await process.StandardInput.WriteAsync(standardInput.AsMemory(), token).ConfigureAwait(false);
                process.StandardInput.Close();
            }

            await process.WaitForExitAsync(token).ConfigureAwait(false);
            return new NftResult(process.ExitCode, await stdout.ConfigureAwait(false), await stderr.ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            TryKill(process);
            return new NftResult(124, string.Empty, $"{_binary} timed out after {_timeout.TotalSeconds:F0}s");
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            throw;
        }
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // The process is gone or not ours to kill; nothing else to do.
        }
    }
}
