// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.IO;
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
///
/// The vendor launcher is not always usable: its venv can be a different Python minor version than
/// the dependency environment Hermes commits, and the launcher then imports the other ABI's
/// compiled packages. <see cref="ThreatShareLauncher"/> therefore offers the committed runtime
/// interpreter first and keeps the vendor launcher and the reporter module as fallbacks, so a share
/// never fails just because of that packaging mismatch.
/// </summary>
public sealed class ThreatShareCli
{
    private static readonly TimeSpan PlanTimeout = TimeSpan.FromSeconds(30);

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

        var plans = ThreatShareLauncher.BuildPlans(
            candidate,
            BlackboxRoot(),
            ThreatShareLauncher.FindRuntimePython(),
            _resolveHermesPath(),
            VenvPython(),
            BlackboxPaths.ResolveHermesHome());

        if (plans.Count == 0)
        {
            return new(ThreatShareReportStatus.RetryableFailure, "the Blackbox reporter was not found");
        }

        string? unavailable = null;
        foreach (var plan in plans)
        {
            var result = await RunPlanAsync(plan, cancellationToken).ConfigureAwait(false);
            if (result is not null)
            {
                return result;
            }

            unavailable = $"the Blackbox reporter could not run through {plan.Description}";
        }

        return new(ThreatShareReportStatus.RetryableFailure, unavailable ?? "the Blackbox reporter is unavailable");
    }

    /// <summary>Runs one plan; null means the CLI itself is unavailable and the next plan should run.</summary>
    private static async Task<ThreatShareReportResult?> RunPlanAsync(
        ThreatShareLaunchPlan plan,
        CancellationToken cancellationToken)
    {
        try
        {
            var start = new ProcessStartInfo(plan.FileName)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = plan.WorkingDirectory,
            };

            foreach (var argument in plan.Arguments)
            {
                start.ArgumentList.Add(argument);
            }

            foreach (var (key, value) in plan.Environment)
            {
                start.Environment[key] = value;
            }

            using var process = Process.Start(start);
            if (process is null)
            {
                return null;
            }

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(PlanTimeout);

            var stdoutTask = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var stderrTask = process.StandardError.ReadToEndAsync(timeout.Token);
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            var text = ((await stdoutTask.ConfigureAwait(false)) + "\n" +
                        (await stderrTask.ConfigureAwait(false))).Replace("\r", string.Empty);

            var result = Classify(text, process.ExitCode);
            return IsUnavailable(text) ? null : result;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new(
                ThreatShareReportStatus.UnknownOutcome,
                "the Blackbox reporter timed out after it started; the report may already be published");
        }
        catch (Exception exception) when (exception is
                     System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return null;
        }
    }

    /// <summary>
    /// Maps one reporter run to a result. Unknown text after a completed run is treated as an
    /// ambiguous outcome, not as a retryable failure: the reporter may already have published.
    /// A launcher that never reached the reporter is retryable and lets the next plan run.
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

        if (IsUnavailable(text))
        {
            return new(ThreatShareReportStatus.RetryableFailure, line);
        }

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

    /// <summary>True when the launcher never reached the reporter (plugin not registered, wrong interpreter).</summary>
    public static bool IsUnavailable(string text) =>
        text.Contains("is not a `hermes` command", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("Failed to load plugin", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("No module named", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("is not recognized as an internal or external command", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("cannot find the file", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("The system cannot find the file", StringComparison.OrdinalIgnoreCase);

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

    /// <summary>True when the profile already holds the reporter's signing key.</summary>
    public static bool ReporterKeyPresent() => File.Exists(BlackboxPaths.ReporterKeyPath());

    /// <summary>The Blackbox installation root (vendor tree, venv and reporter module).</summary>
    public static string BlackboxRoot() =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Axiom", "modules", "blackbox", "agent-blackbox");

    public static string VenvPython() => Path.Combine(BlackboxRoot(), "venv", "Scripts", "python.exe");

    /// <summary>The local ruleset text, used to refuse an indicator the node already knows.</summary>
    public static string ReadRuleset()
    {
        try
        {
            var path = Path.Combine(BlackboxPaths.ResolveBlackboxHome(), "ruleset.json");
            return File.Exists(path) ? File.ReadAllText(path) : string.Empty;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return string.Empty;
        }
    }

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
            Path.Combine(local, "Axiom", "modules", "blackbox", "agent-blackbox", "venv", "Scripts", "hermes.exe"),
            Path.Combine(local, "hermes", "bin", "hermes.exe"),
            Path.Combine(local, "Programs", "hermes", "hermes.exe"),
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
            var candidate = Path.Combine(entry.Trim(), "hermes.exe");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }
}
