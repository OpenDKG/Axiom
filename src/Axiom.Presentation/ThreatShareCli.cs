// SPDX-License-Identifier: GPL-3.0-or-later
using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
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

    /// <summary>Operator requested retraction of their own previously shared report.</summary>
    Retracted = 6,
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
    private static readonly TimeSpan LocalRulesetFreshnessWindow = TimeSpan.FromHours(24);
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

        if (!ThreatShareVocabulary.IsPublishableReason(candidate.Reason))
        {
            return new(
                ThreatShareReportStatus.Rejected,
                "reason is 'unknown' or unsupported; classify with evidence before publishing");
        }

        if (!candidate.CanPublishToCommunity)
        {
            var reason = string.IsNullOrWhiteSpace(candidate.EligibilityExplanation)
                ? "candidate is kept local until stronger evidence is available"
                : candidate.EligibilityExplanation;
            return new(ThreatShareReportStatus.Rejected, reason);
        }

        if (!ThreatSharingConsent.HasConsent())
        {
            return new(
                ThreatShareReportStatus.Rejected,
                "manual threat reporting is disabled in Axiom");
        }

        if (ThreatSharePreflight.CategoryRefusal(candidate.IndicatorType, candidate.Value, candidate.Detail) is { } category)
        {
            return new(ThreatShareReportStatus.Rejected, category);
        }

        var execution = await ExecuteAsync(
            ThreatShareLauncher.ReportArguments(candidate),
            cancellationToken,
            manualReport: true).ConfigureAwait(false);

        return execution.ImmediateFailure ?? Classify(execution.Output, execution.ExitCode);
    }

    public async Task<ThreatShareReportResult> RetractAsync(
        string indicatorId,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(indicatorId))
        {
            return new(ThreatShareReportStatus.Rejected, "an indicator identifier is required to retract");
        }

        var execution = await ExecuteAsync(
            ["blackbox", "report", "--retract", indicatorId.Trim()],
            cancellationToken).ConfigureAwait(false);

        return execution.ImmediateFailure ?? ClassifyRetract(execution.Output, execution.ExitCode);
    }

    private sealed record CommandExecution(
        string Output,
        int ExitCode,
        ThreatShareReportResult? ImmediateFailure);

    private async Task<CommandExecution> ExecuteAsync(
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken,
        bool manualReport = false)
    {
        var root = BlackboxRoot();
        var runtime = ThreatShareLauncher.FindRuntimePython();
        var venv = VenvPython();
        var home = BlackboxPaths.ResolveHermesHome();
        var plans = manualReport
            ? ThreatShareLauncher.BuildManualReportPlans(arguments, root, runtime, venv, home)
            : ThreatShareLauncher.BuildPlans(arguments, root, runtime, _resolveHermesPath(), venv, home);

        if (plans.Count == 0)
        {
            return new(
                string.Empty,
                -1,
                new(ThreatShareReportStatus.RetryableFailure, "the Blackbox reporter was not found"));
        }

        string? last = null;
        foreach (var plan in plans)
        {
            var execution = await RunPlanAsync(plan, cancellationToken).ConfigureAwait(false);
            if (execution is not null)
            {
                return execution;
            }

            last = plan.Description;
        }

        return new(
            string.Empty,
            -1,
            new(
                ThreatShareReportStatus.RetryableFailure,
                $"the Blackbox reporter could not run through {last ?? "any launcher"}"));
    }

    /// <summary>Runs one plan; null means the launcher never reached the reporter, so the next runs.</summary>
    private static async Task<CommandExecution?> RunPlanAsync(
        ThreatShareLaunchPlan plan,
        CancellationToken cancellationToken)
    {
        var started = false;
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

            started = true;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(PlanTimeout);

            var stdoutTask = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var stderrTask = process.StandardError.ReadToEndAsync(timeout.Token);
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            var text = ((await stdoutTask.ConfigureAwait(false)) + "\n" +
                        (await stderrTask.ConfigureAwait(false))).Replace("\r", string.Empty);

            var manualReporterStarted = text.Contains(ThreatShareLauncher.ManualReportStarted, StringComparison.Ordinal);
            text = text.Replace(ThreatShareLauncher.ManualReportStarted, string.Empty, StringComparison.Ordinal);
            return !manualReporterStarted && IsUnavailable(text)
                ? null
                : new CommandExecution(text, process.ExitCode, null);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new(
                string.Empty,
                -1,
                new(
                    ThreatShareReportStatus.UnknownOutcome,
                    "the Blackbox reporter timed out after it started; the report may already be published"));
        }
        catch (Exception exception) when (exception is
                     System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return started
                ? new(string.Empty, -1, new(ThreatShareReportStatus.UnknownOutcome,
                    "the Blackbox reporter started but its result could not be read"))
                : null;
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

        var line = FirstNonEmptyLine(text, exitCode);

        if (text.Contains("Queued for automatic retry", StringComparison.OrdinalIgnoreCase))
        {
            return new(ThreatShareReportStatus.UnknownOutcome,
                "Blackbox did not confirm delivery; check the community graph before retrying manually");
        }

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

    public static ThreatShareReportResult ClassifyRetract(string text, int exitCode)
    {
        ArgumentNullException.ThrowIfNull(text);

        if (text.Contains("Retraction shared for:", StringComparison.Ordinal) ||
            text.Contains("withdrawn", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("Retracted", StringComparison.OrdinalIgnoreCase))
        {
            return new(
                ThreatShareReportStatus.Retracted,
                "retraction submitted; existing CC0 replicas may persist");
        }

        var line = FirstNonEmptyLine(text, exitCode);

        if (text.Contains("Invalid retraction", StringComparison.OrdinalIgnoreCase) ||
            IsPolicyRefusal(text))
        {
            return new(ThreatShareReportStatus.Rejected, line);
        }

        if (text.Contains("Retraction FAILED", StringComparison.OrdinalIgnoreCase) ||
            IsOffline(text))
        {
            return new(ThreatShareReportStatus.RetryableFailure, line);
        }

        return new(ThreatShareReportStatus.UnknownOutcome, line);
    }

    private static string FirstNonEmptyLine(string text, int exitCode) =>
        text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault(value => value.Length > 0) ?? $"exit code {exitCode}";

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
        text.Contains("not submitted:", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("invalid", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("unsupported", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("rejected", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("not eligible", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("consent required", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("severity too low", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Best-effort read-only inspection of Blackbox's compiled local ruleset to label candidates as
    /// Known (verified), Previously reported (community), Disputed, Revoked, Potentially new, or Unknown.
    /// Returns <see cref="ThreatShareNoveltyStatus.Unknown"/> whenever missing, unreadable, or stale.
    /// </summary>
    public static ThreatShareNoveltyStatus InspectLocalGraphNovelty(
        string indicatorId,
        string? blackboxHome = null,
        DateTimeOffset? nowUtc = null)
    {
        if (string.IsNullOrWhiteSpace(indicatorId))
        {
            return ThreatShareNoveltyStatus.Unknown;
        }

        var home = string.IsNullOrWhiteSpace(blackboxHome)
            ? BlackboxPaths.ResolveBlackboxHome()
            : blackboxHome;
        var rulesetPath = Path.Combine(home, "ruleset.json");
        if (!File.Exists(rulesetPath))
        {
            return ThreatShareNoveltyStatus.Unknown;
        }

        try
        {
            using var stream = new FileStream(rulesetPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var doc = JsonDocument.Parse(stream);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return ThreatShareNoveltyStatus.Unknown;
            }

            if (ContainsRevokedEntry(root, indicatorId))
            {
                return ThreatShareNoveltyStatus.Revoked;
            }

            if (ContainsVerifiedEntry(root, indicatorId))
            {
                return ThreatShareNoveltyStatus.KnownVerified;
            }

            if (TryReadCommunityEntry(root, indicatorId, out var disputed))
            {
                return disputed
                    ? ThreatShareNoveltyStatus.Disputed
                    : ThreatShareNoveltyStatus.PreviouslyReportedCommunity;
            }

            if (!IsFreshSyncedRuleset(root, nowUtc ?? DateTimeOffset.UtcNow))
            {
                return ThreatShareNoveltyStatus.Unknown;
            }

            return ThreatShareNoveltyStatus.PotentiallyNewLocalOnly;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return ThreatShareNoveltyStatus.Unknown;
        }
    }

    public static bool IsSandboxModeEnabled(
        string? hermesHome = null,
        string? environmentOverride = null)
    {
        var envValue = environmentOverride ?? Environment.GetEnvironmentVariable("BLACKBOX_COMMUNITY_SANDBOX");
        if (!string.IsNullOrWhiteSpace(envValue))
        {
            var trimmed = envValue.Trim();
            if (trimmed is "1" or "true" or "TRUE" or "yes" or "on")
            {
                return true;
            }

            if (trimmed is "0" or "false" or "FALSE" or "no" or "off")
            {
                return false;
            }
        }

        var home = string.IsNullOrWhiteSpace(hermesHome) ? BlackboxPaths.ResolveHermesHome() : hermesHome;
        var configPath = Path.Combine(home, "config.yaml");
        if (!File.Exists(configPath))
        {
            return false;
        }

        try
        {
            using var stream = new FileStream(configPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(stream);
            while (reader.ReadLine() is { } line)
            {
                var trimmed = line.Trim();
                if (trimmed.StartsWith("community_sandbox:", StringComparison.OrdinalIgnoreCase))
                {
                    var value = trimmed["community_sandbox:".Length..].Trim().Trim('"', '\'');
                    return value is "true" or "True" or "1" or "yes" or "on";
                }
            }

            return false;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>Computes the SHA-256 hex digest of <c>reporter_key.pem</c> strictly read-only without modifying it.</summary>
    public static string? ComputeReporterKeySha256(string? blackboxHome = null)
    {
        var home = string.IsNullOrWhiteSpace(blackboxHome)
            ? BlackboxPaths.ResolveBlackboxHome()
            : blackboxHome;
        var keyPath = Path.Combine(home, "reporter_key.pem");
        if (!File.Exists(keyPath))
        {
            return null;
        }

        try
        {
            using var stream = new FileStream(keyPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var hash = SHA256.HashData(stream);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static bool ContainsRevokedEntry(JsonElement root, string indicatorId)
    {
        if (root.TryGetProperty("kill_list", out var killList) &&
            killList.ValueKind == JsonValueKind.Object &&
            killList.TryGetProperty(indicatorId, out _))
        {
            return true;
        }

        if (root.TryGetProperty("curator_revoked", out var revoked) &&
            revoked.ValueKind == JsonValueKind.Array)
        {
            foreach (var entry in revoked.EnumerateArray())
            {
                if (entry.ValueKind == JsonValueKind.String &&
                    string.Equals(entry.GetString(), indicatorId, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                if (entry.ValueKind == JsonValueKind.Object &&
                    entry.TryGetProperty("identifier", out var idProp) &&
                    string.Equals(idProp.GetString(), indicatorId, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool ContainsVerifiedEntry(JsonElement root, string indicatorId)
    {
        if (root.TryGetProperty("graph_threats", out var threats) &&
            threats.ValueKind == JsonValueKind.Array)
        {
            foreach (var entry in threats.EnumerateArray())
            {
                if (entry.ValueKind == JsonValueKind.Object &&
                    entry.TryGetProperty("identifier", out var idProp) &&
                    string.Equals(idProp.GetString(), indicatorId, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }

        if (root.TryGetProperty("ioc", out var iocs) &&
            iocs.ValueKind == JsonValueKind.Object)
        {
            if (iocs.TryGetProperty(indicatorId, out _))
            {
                return true;
            }

            var prefixSplit = indicatorId.Split(':', 3);
            if (prefixSplit.Length == 3 && iocs.TryGetProperty(prefixSplit[2], out _))
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryReadCommunityEntry(JsonElement root, string indicatorId, out bool disputed)
    {
        disputed = false;
        if (!root.TryGetProperty("community", out var community) ||
            community.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        if (!community.TryGetProperty(indicatorId, out var entry) ||
            entry.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        if (entry.TryGetProperty("disputed", out var disputedProp))
        {
            disputed = disputedProp.ValueKind switch
            {
                JsonValueKind.True => true,
                JsonValueKind.String => string.Equals(disputedProp.GetString(), "yes", StringComparison.OrdinalIgnoreCase) ||
                                        string.Equals(disputedProp.GetString(), "true", StringComparison.OrdinalIgnoreCase),
                _ => false,
            };
        }

        return true;
    }

    private static bool IsFreshSyncedRuleset(JsonElement root, DateTimeOffset nowUtc)
    {
        if (!root.TryGetProperty("synced_at", out var syncedProp) ||
            syncedProp.ValueKind != JsonValueKind.Number ||
            !syncedProp.TryGetDouble(out var syncedUnix) ||
            syncedUnix <= 0)
        {
            return false;
        }

        var syncedAt = DateTimeOffset.FromUnixTimeSeconds((long)syncedUnix);
        return nowUtc - syncedAt <= LocalRulesetFreshnessWindow;
    }

    /// <summary>True when the user's Blackbox profile already holds the reporter-terms consent.</summary>
    public static bool ConsentPresent() => File.Exists(BlackboxPaths.ConsentPath());

    /// <summary>Shows which profile the reporter will use and whether its key, consent, and lane exist.</summary>
    public static string DescribeReporterProfile()
    {
        var hermes = BlackboxPaths.ResolveHermesHome();
        var blackbox = BlackboxPaths.ResolveBlackboxHome();
        var consent = File.Exists(Path.Combine(blackbox, "sharing_consent.json"));
        var key = File.Exists(Path.Combine(blackbox, "reporter_key.pem"));
        var lane = IsSandboxModeEnabled(hermes) ? "Sandbox lane (test only)" : "Production graph (CC0 1.0 replicated)";
        return $"Reporter profile: {hermes}. Consent {(consent ? "present" : "missing")}, " +
               $"reporter key {(key ? "present" : "missing")}, destination: {lane}.";
    }

    /// <summary>True when the profile already holds the reporter's signing key.</summary>
    public static bool ReporterKeyPresent() => File.Exists(BlackboxPaths.ReporterKeyPath());

    /// <summary>The Blackbox installation root (vendor tree, venv and reporter module).</summary>
    public static string BlackboxRoot() =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Axiom", "modules", "blackbox", "agent-blackbox");

    public static string VenvPython() => Path.Combine(BlackboxRoot(), "venv", "Scripts", "python.exe");

    /// <summary>The local ruleset text, used by the preflight to refuse a known indicator.</summary>
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

    /// <summary>
    /// Streams <c>ruleset.json</c> in fixed pooled chunks to find which candidate identifiers already exist,
    /// avoiding loading hundreds of megabytes into a single string on the Large Object Heap.
    /// </summary>
    public static HashSet<string> FindKnownIdentifiersInRuleset(IEnumerable<ThreatShareCandidate> candidates)
    {
        ArgumentNullException.ThrowIfNull(candidates);

        var remaining = new List<string>();
        var seenInputs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var candidate in candidates)
        {
            if (string.IsNullOrEmpty(candidate.IndicatorType) || string.IsNullOrEmpty(candidate.Value))
            {
                continue;
            }

            var id = ThreatSharePreflight.KnownIdentifier(candidate.IndicatorType, candidate.Value);
            if (seenInputs.Add(id))
            {
                remaining.Add(id);
            }
        }

        var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (remaining.Count == 0)
        {
            return found;
        }

        try
        {
            var path = Path.Combine(BlackboxPaths.ResolveBlackboxHome(), "ruleset.json");
            if (!File.Exists(path))
            {
                return found;
            }

            const int chunkSize = 65_536;
            var maxLen = remaining.Max(static id => id.Length);
            var overlapCapacity = Math.Max(maxLen - 1, 0);
            var buffer = ArrayPool<char>.Shared.Rent(chunkSize + overlapCapacity);
            try
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, chunkSize);
                using var reader = new StreamReader(stream, detectEncodingFromByteOrderMarks: true);

                var carry = 0;
                while (remaining.Count > 0)
                {
                    var read = reader.Read(buffer, carry, chunkSize);
                    if (read == 0)
                    {
                        break;
                    }

                    var total = carry + read;
                    var span = buffer.AsSpan(0, total);
                    for (var i = remaining.Count - 1; i >= 0; i--)
                    {
                        var id = remaining[i];
                        if (span.Contains(id, StringComparison.OrdinalIgnoreCase))
                        {
                            found.Add(id);
                            remaining.RemoveAt(i);
                        }
                    }

                    carry = overlapCapacity > 0 ? Math.Min(total, overlapCapacity) : 0;
                    if (carry > 0)
                    {
                        buffer.AsSpan(total - carry, carry).CopyTo(buffer);
                    }
                }
            }
            finally
            {
                ArrayPool<char>.Shared.Return(buffer);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return found;
        }

        return found;
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
