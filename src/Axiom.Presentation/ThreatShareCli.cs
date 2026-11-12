// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using Axiom.Contracts.Threat;

namespace Axiom.Presentation;

/// <summary>What the Blackbox reporter said about one attempt.</summary>
public enum ThreatShareReportStatus
{
    Shared = 0,
    AlreadyShared = 1,

    /// <summary>The daily cap is reached. The candidate must stay queued, not be consumed.</summary>
    CapReached = 2,

    /// <summary>The reporter refused the value on policy or schema grounds.</summary>
    Rejected = 3,

    /// <summary>Timeout, missing CLI, node offline or an unknown failure that may succeed later.</summary>
    RetryableFailure = 4,

    /// <summary>
    /// The reporter ran but its result is unknown (for example a timeout after start). The value may
    /// already be published, so this is never retried automatically.
    /// </summary>
    UnknownOutcome = 5,
}

public sealed record ThreatShareReportResult(ThreatShareReportStatus Status, string Outcome)
{
    public bool Submitted =>
        Status is ThreatShareReportStatus.Shared or ThreatShareReportStatus.AlreadyShared;

    /// <summary>True when the attempt may have reached the network without a confirmed result.</summary>
    public bool Ambiguous => Status == ThreatShareReportStatus.UnknownOutcome;
}

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

    public async Task<ThreatShareReportResult> ReportAsync(
        ThreatShareCandidate candidate,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(candidate);

        var hermes = _resolveHermesPath();
        if (hermes is null)
        {
            return new(ThreatShareReportStatus.RetryableFailure, "the Blackbox hermes CLI was not found");
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

            start.Environment[BlackboxPaths.HermesHomeVariable] = BlackboxPaths.ResolveHermesHome();

            using var process = Process.Start(start);
            if (process is null)
            {
                return new(ThreatShareReportStatus.RetryableFailure, "the Blackbox CLI could not be started");
            }

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(45));

            var stdoutTask = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var stderrTask = process.StandardError.ReadToEndAsync(timeout.Token);
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            var text = ((await stdoutTask.ConfigureAwait(false)) + "\n" +
                        (await stderrTask.ConfigureAwait(false))).Replace("\r", string.Empty);

            return Classify(text, process.ExitCode);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new(
                ThreatShareReportStatus.UnknownOutcome,
                "the Blackbox CLI timed out after it started; the report may already be published");
        }
        catch (Exception exception) when (exception is
                     System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return new(ThreatShareReportStatus.RetryableFailure, exception.Message);
        }
    }

    /// <summary>
    /// Maps one reporter run to a result. Unknown text after a completed run is treated as an
    /// ambiguous outcome, not as a retryable failure: the reporter may already have published.
    /// </summary>
    public static ThreatShareReportResult Classify(string text, int exitCode)
    {
        ArgumentNullException.ThrowIfNull(text);

        if (text.Contains("Report shared with the community", StringComparison.Ordinal))
        {
            return new(ThreatShareReportStatus.Shared, "shared");
        }

        if (text.Contains("Already shared with the community", StringComparison.Ordinal))
        {
            return new(ThreatShareReportStatus.AlreadyShared, "already shared");
        }

        if (text.Contains("Daily report cap reached", StringComparison.Ordinal))
        {
            return new(ThreatShareReportStatus.CapReached, "daily report cap reached");
        }

        var line = text
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault(value => value.Length > 0) ?? $"exit code {exitCode}";

        if (IsPolicyRefusal(text))
        {
            return new(ThreatShareReportStatus.Rejected, line);
        }

        if (IsOffline(text))
        {
            return new(ThreatShareReportStatus.RetryableFailure, line);
        }

        return new(ThreatShareReportStatus.UnknownOutcome, line);
    }

    private static bool IsOffline(string text) =>
        text.Contains("not running", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("offline", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("ECONNREFUSED", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("connection refused", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("cannot connect", StringComparison.OrdinalIgnoreCase);

    private static bool IsPolicyRefusal(string text) =>
        text.Contains("invalid", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("unsupported", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("rejected", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("not eligible", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("consent required", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("severity too low", StringComparison.OrdinalIgnoreCase);

    /// <summary>True when the user's Blackbox profile already holds the reporter-terms consent.</summary>
    public static bool ConsentPresent() => File.Exists(BlackboxPaths.ConsentPath());

    /// <summary>Shows which profile the reporter will use and whether its key and consent exist.</summary>
    public static string DescribeReporterProfile()
    {
        var hermes = BlackboxPaths.ResolveHermesHome();
        var blackbox = BlackboxPaths.ResolveBlackboxHome();
        var consent = File.Exists(Path.Combine(blackbox, "sharing_consent.json"));
        var key = File.Exists(Path.Combine(blackbox, "reporter_key.pem"));
        return $"Reporter profile: {hermes}. Consent {(consent ? "present" : "missing")}, " +
               $"reporter key {(key ? "present" : "missing")}.";
    }

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
