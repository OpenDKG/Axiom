// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Net.Sockets;
using System.Text;

namespace Axiom.Presentation;

/// <summary>
/// Local process and port helpers for the optional Blackbox and DKG modules. The supervisor uses
/// them to tell "still starting" from "down", and to avoid starting a second copy of a node that
/// already owns its port.
/// </summary>
public static class LocalModuleRuntime
{
    public const int BlackboxPort = 9700;

    /// <summary>Blackbox's bundled DKG node. The standalone Axiom node uses 9200.</summary>
    public const int BlackboxDkgPort = 9320;

    public const int StandaloneDkgPort = 9200;

    /// <summary>
    /// True when something is listening on the loopback port. This is deliberate: a listener that
    /// has not finished its HTTP handshake still must not be joined by a second process.
    /// </summary>
    public static bool IsPortListening(int port, int timeoutMilliseconds = 500)
    {
        try
        {
            using var client = new TcpClient();
            var task = client.ConnectAsync("127.0.0.1", port);
            if (!task.Wait(timeoutMilliseconds))
            {
                return false;
            }

            return client.Connected;
        }
        catch (Exception exception) when (exception is
                     SocketException or AggregateException or ObjectDisposedException or InvalidOperationException)
        {
            return false;
        }
    }

    public static bool AnyDkgPortListening =>
        IsPortListening(BlackboxDkgPort) || IsPortListening(StandaloneDkgPort);

    /// <summary>
    /// Waits for a module port, polling in short steps. Returns true as soon as the port accepts a
    /// connection; the HTTP contract is verified separately by <c>OptionalModuleProbe</c>.
    /// </summary>
    public static async Task<bool> WaitForPortAsync(
        int port,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (IsPortListening(port))
            {
                return true;
            }

            await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
        }

        return IsPortListening(port);
    }

    /// <summary>
    /// Stops module processes whose command line mentions one of the Axiom-owned paths or markers.
    /// Windows PowerShell 5.1 cannot call <c>String.Contains(string, StringComparison)</c>, so the
    /// script uses an ordinal <c>IndexOf</c>. Nothing outside the given markers is touched.
    /// </summary>
    public static bool StopProcesses(
        IEnumerable<string> markers,
        Action<string>? log = null,
        int timeoutSeconds = 30)
    {
        var needles = markers
            .Where(marker => !string.IsNullOrWhiteSpace(marker))
            .Select(marker => "'" + marker.Replace("'", "''", StringComparison.Ordinal) + "'")
            .ToArray();
        if (needles.Length == 0)
        {
            return true;
        }

        var script = $$"""
            $ErrorActionPreference = 'Continue'
            $needles = @({{string.Join(", ", needles)}})
            $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
              Where-Object {
                $line = $_.CommandLine
                if (-not $line) { return $false }
                foreach ($needle in $needles) {
                  if ($line.IndexOf([string]$needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
                }
                return $false
              })
            foreach ($p in $procs) {
              Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
            }
            foreach ($p in $procs) {
              Wait-Process -Id $p.ProcessId -Timeout 5 -ErrorAction SilentlyContinue
            }
            Write-Output "stopped=$($procs.Count)"
            """;

        return RunHiddenPowerShell(script, log, TimeSpan.FromSeconds(timeoutSeconds));
    }

    /// <summary>Runs a short hidden process and mirrors its output to the caller's log.</summary>
    public static bool RunProcess(
        string fileName,
        string arguments,
        Action<string>? log,
        TimeSpan timeout)
    {
        var startInfo = new ProcessStartInfo(fileName, arguments)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        try
        {
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                log?.Invoke($"Could not start {Path.GetFileName(fileName)}.");
                return false;
            }

            using var deadline = new CancellationTokenSource(timeout);
            var output = process.StandardOutput.ReadToEndAsync(deadline.Token);
            var error = process.StandardError.ReadToEndAsync(deadline.Token);
            var completion = Task.WhenAll(output, error, process.WaitForExitAsync(deadline.Token));
            try
            {
                completion.WaitAsync(deadline.Token).GetAwaiter().GetResult();
            }
            catch (OperationCanceledException) when (deadline.IsCancellationRequested)
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
                {
                }

                // Wait briefly for the killed process's pipe reads and exit waiter to settle before
                // disposing the Process streams, and observe any fault so it never surfaces as an
                // UnobservedTaskException.
                try
                {
                    completion.WaitAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();
                }
                catch (Exception exception) when (exception is OperationCanceledException or IOException or InvalidOperationException or TimeoutException)
                {
                }

                _ = completion.ContinueWith(
                    static task => _ = task.Exception,
                    CancellationToken.None,
                    TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);

                log?.Invoke($"{Path.GetFileName(fileName)} timed out.");
                return false;
            }

            foreach (var line in (output.GetAwaiter().GetResult() + "\n" + error.GetAwaiter().GetResult())
                         .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                         .TakeLast(12))
            {
                log?.Invoke(line);
            }

            return process.ExitCode == 0;
        }
        catch (Exception exception) when (exception is
                     System.ComponentModel.Win32Exception or InvalidOperationException or
                     IOException or UnauthorizedAccessException)
        {
            log?.Invoke($"{Path.GetFileName(fileName)} failed: {exception.Message}");
            return false;
        }
    }

    /// <summary>Runs a short hidden PowerShell script and mirrors its output to the caller's log.</summary>
    public static bool RunHiddenPowerShell(string script, Action<string>? log, TimeSpan timeout)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        return RunProcess(
            OptionalModuleInstaller.ResolvePowerShellExecutable(),
            $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}",
            log,
            timeout);
    }
}
