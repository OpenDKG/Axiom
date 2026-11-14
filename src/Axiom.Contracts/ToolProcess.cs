// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using System.Diagnostics;

namespace Axiom.Contracts;

/// <summary>Outcome of one helper-tool run. <see cref="ExitCode"/> is -1 when the tool did not start, -2 on timeout.</summary>
public sealed record ToolProcessResult(int ExitCode, string StandardOutput, string StandardError)
{
    public const int NotStartedExitCode = -1;

    public const int TimedOutExitCode = -2;

    public bool Succeeded => ExitCode == 0;

    public bool TimedOut => ExitCode == TimedOutExitCode;
}

/// <summary>
/// The one "run a system tool with an argument list, capture both streams, bound the wait"
/// implementation shared by the macOS daemon (<c>networksetup</c>, <c>launchctl</c>, <c>stat</c>),
/// the administrator prompt (<c>osascript</c>) and the filter helper (<c>axiom-sysext</c>). No
/// shell is ever involved; arguments are passed as a list. Review #22.
/// </summary>
public static class ToolProcess
{
    public static ToolProcessResult Run(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout) =>
        RunAsync(fileName, arguments, timeout, CancellationToken.None).GetAwaiter().GetResult();

    /// <summary>
    /// Runs the tool; a timeout (or cancellation) kills the whole process tree and reports
    /// <see cref="ToolProcessResult.TimedOutExitCode"/>. Pass <see cref="Timeout.InfiniteTimeSpan"/> to wait
    /// for the tool (cancellation still applies).
    /// </summary>
    public static async Task<ToolProcessResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);
        ArgumentNullException.ThrowIfNull(arguments);

        var startInfo = new ProcessStartInfo(fileName)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = false,
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        try
        {
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return new ToolProcessResult(ToolProcessResult.NotStartedExitCode, string.Empty, $"{fileName} did not start.");
            }

            using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            if (timeout != Timeout.InfiniteTimeSpan)
            {
                bounded.CancelAfter(timeout);
            }

            // Read both streams concurrently so a chatty tool cannot block on a full pipe.
            var stdout = process.StandardOutput.ReadToEndAsync(bounded.Token);
            var stderr = process.StandardError.ReadToEndAsync(bounded.Token);
            try
            {
                await process.WaitForExitAsync(bounded.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                TryKill(process);
                return new ToolProcessResult(
                    ToolProcessResult.TimedOutExitCode,
                    string.Empty,
                    cancellationToken.IsCancellationRequested
                        ? $"{fileName} was cancelled."
                        : $"{fileName} timed out after {timeout.TotalSeconds:0} s.");
            }

            return new ToolProcessResult(process.ExitCode, await stdout.ConfigureAwait(false), await stderr.ConfigureAwait(false));
        }
        catch (Exception exception) when (exception is Win32Exception or InvalidOperationException or IOException)
        {
            return new ToolProcessResult(ToolProcessResult.NotStartedExitCode, string.Empty, exception.Message);
        }
    }

    private static void TryKill(Process process)
    {
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch (Exception exception) when (exception is InvalidOperationException or Win32Exception)
        {
            // Already exited.
        }
    }
}
