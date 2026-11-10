// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using Axiom.Contracts.Threat;

namespace Axiom.Presentation;

/// <summary>
/// Runs the local Blackbox reporter for one indicator. It must run in the signed-in user's session:
/// the reporter key, the DKG identity and the reporter-terms consent live in that profile, not in
/// the service account. The CLI applies consent, cooldown, the daily cap and its own severity floor.
/// </summary>
public sealed class ThreatShareCli
{
    private readonly Func<string?> _resolveHermesPath;

    public ThreatShareCli(Func<string?>? hermesPathResolver = null)
    {
        _resolveHermesPath = hermesPathResolver ?? DefaultHermesPath;
    }

    public async Task<(bool Submitted, string Outcome)> ReportAsync(
        ThreatShareCandidate candidate,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(candidate);

        var hermes = _resolveHermesPath();
        if (hermes is null)
        {
            return (false, "the Blackbox hermes CLI was not found");
        }

        try
        {
            var start = new ProcessStartInfo(hermes)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = Path.GetDirectoryName(hermes) ?? string.Empty,
            };

            foreach (var argument in new[]
                     {
                         "blackbox", "report",
                         "--type", "ioc",
                         "--ioc-type", candidate.IndicatorType,
                         "--value", candidate.Value,
                         "--context", candidate.Context,
                         "--severity", "high",
                     })
            {
                start.ArgumentList.Add(argument);
            }

            start.Environment["HERMES_HOME"] = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "hermes");

            using var process = Process.Start(start);
            if (process is null)
            {
                return (false, "the Blackbox CLI could not be started");
            }

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(45));

            var stdoutTask = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var stderrTask = process.StandardError.ReadToEndAsync(timeout.Token);
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            var text = ((await stdoutTask.ConfigureAwait(false)) + "\n" +
                        (await stderrTask.ConfigureAwait(false))).Replace("\r", string.Empty);

            if (text.Contains("Report shared with the community", StringComparison.Ordinal))
            {
                return (true, "shared");
            }

            if (text.Contains("Already shared with the community", StringComparison.Ordinal))
            {
                return (true, "already shared");
            }

            if (text.Contains("Daily report cap reached", StringComparison.Ordinal))
            {
                return (false, "daily report cap reached");
            }

            var line = text
                .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .FirstOrDefault(value => value.Length > 0);
            return (false, line ?? $"exit code {process.ExitCode}");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return (false, "the Blackbox CLI timed out");
        }
        catch (Exception exception) when (exception is
                     System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return (false, exception.Message);
        }
    }

    /// <summary>True when the user's Blackbox profile already holds the reporter-terms consent.</summary>
    public static bool ConsentPresent() =>
        File.Exists(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "hermes",
            "blackbox",
            "sharing_consent.json"));

    private static string? DefaultHermesPath()
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var candidates = new[]
        {
            AgentPlatform.VenvTool(Path.Combine(local, "Axiom", "modules", "blackbox", "agent-blackbox"), "hermes"),
            Path.Combine(local, "hermes", "bin", AgentPlatform.ExecutableName("hermes")),
            Path.Combine(local, "Programs", "hermes", AgentPlatform.ExecutableName("hermes")),
        };

        foreach (var candidate in candidates)
        {
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        foreach (var entry in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
                 .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = Path.Combine(entry.Trim(), AgentPlatform.ExecutableName("hermes"));
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }
}
