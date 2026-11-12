// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.NetworkRecovery;

namespace Axiom.Presentation;

/// <summary>
/// One place for truthful recovery wording. "Succeeded" always requires the service's read-back
/// verification; transport and authorization failures say explicitly that nothing was changed.
/// </summary>
public static class NetworkRecoveryText
{
    public static string DescribeCapture(NetworkRecoveryCaptureResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        return result.Status switch
        {
            NetworkRecoveryStatus.Succeeded =>
                $"Recovery baseline saved at {Format(result.CapturedUtc)} " +
                $"({result.AdapterCount} adapter(s), {result.RuleCount} Axiom rule(s), " +
                $"protection {(result.ProtectionWasActive ? "active" : "inactive")}).",

            NetworkRecoveryStatus.AlreadyCaptured =>
                $"A recovery baseline from {Format(result.CapturedUtc)} is already saved " +
                $"({result.AdapterCount} adapter(s), {result.RuleCount} rule(s)); it was not replaced.",

            NetworkRecoveryStatus.SnapshotCorrupt =>
                "The saved recovery baseline is corrupt and was not replaced. " + Problems(result.Problems),

            NetworkRecoveryStatus.NotAuthorized =>
                "The recovery baseline needs the installed Axiom service with administrator rights. Nothing was saved.",

            NetworkRecoveryStatus.Unavailable =>
                "The Axiom service is not available, so no recovery baseline was saved.",

            NetworkRecoveryStatus.Incompatible =>
                "The installed Axiom service does not support network recovery. Update or reinstall it.",

            _ => "The recovery baseline was not saved. " + Problems(result.Problems),
        };
    }

    public static string DescribeRestore(NetworkRecoveryRestoreResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        return result.Status switch
        {
            NetworkRecoveryStatus.Succeeded when result.AdaptersRestored == 0 && result.RulesRemoved == 0 =>
                "The saved state contained nothing to restore; the current configuration was verified.",

            NetworkRecoveryStatus.Succeeded =>
                $"Restored and verified {result.AdaptersRestored} adapter(s); " +
                $"removed {result.RulesRemoved} Axiom-owned rule(s).",

            NetworkRecoveryStatus.PartialFailure =>
                $"Restore incomplete: {result.AdaptersRestored} adapter(s) applied, " +
                $"{result.AdaptersVerified} verified, {result.RulesRemoved} rule(s) removed. " +
                Problems(result.Problems),

            NetworkRecoveryStatus.NoSnapshot =>
                "No saved network state is available. Nothing was changed.",

            NetworkRecoveryStatus.SnapshotCorrupt =>
                "The saved network state is corrupt and was refused. Nothing was changed.",

            NetworkRecoveryStatus.NotAuthorized =>
                "Restore requires the elevated Axiom service or an administrator recovery command. Nothing was changed.",

            NetworkRecoveryStatus.Unavailable =>
                "The Axiom service is not available. Nothing was changed.",

            NetworkRecoveryStatus.Incompatible =>
                "The installed Axiom service does not support network recovery. Update or reinstall it; nothing was changed.",

            NetworkRecoveryStatus.Busy =>
                "Another recovery operation is still running. Nothing was changed.",

            _ => "Restore failed. " + Problems(result.Problems) + " Nothing was verified.",
        };
    }

    public static string Problems(IReadOnlyList<NetworkRecoveryProblem> problems)
    {
        ArgumentNullException.ThrowIfNull(problems);

        if (problems.Count == 0)
        {
            return "No details were reported.";
        }

        return string.Join(
            " ",
            problems.Select(problem => string.IsNullOrWhiteSpace(problem.Item)
                ? problem.Message
                : $"{problem.Item}: {problem.Message}"));
    }

    private static string Format(DateTimeOffset? value) =>
        value is null
            ? "an earlier run"
            : value.Value.ToLocalTime().ToString("g", System.Globalization.CultureInfo.CurrentCulture);
}
