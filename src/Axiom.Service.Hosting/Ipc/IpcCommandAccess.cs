// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ipc;

namespace Axiom.Service.Hosting.Ipc;

/// <summary>
/// What an IPC command discloses or changes. Decided per command type by <see cref="IpcCommandAccess"/>;
/// the transport decides per connection which classes a caller may use (<see cref="IpcCaller"/>).
/// </summary>
public enum IpcCommandClass
{
    /// <summary>Narrow health information with no machine-wide activity: <c>serviceHealth</c>, <c>capabilities</c>.</summary>
    PublicRead = 0,

    /// <summary>Reads that disclose machine-wide activity (connections, history, DNS, diagnostics, settings, enforcement status and receipts).</summary>
    PrivateRead = 1,

    /// <summary>Changes machine-wide state (rules, Axiom Shield, Privacy Shield, threat sharing, recovery, enforcement evaluation with its receipt journal).</summary>
    Write = 2,
}

/// <summary>
/// Identity of an authenticated IPC client as seen by the dispatcher. Built by the transport that
/// authenticated the peer; this assembly offers no shortcut from an actor string, and neither
/// <paramref name="CanWrite"/> nor <paramref name="CanReadPrivate"/> has a default, so both grants
/// are always written out at the call site and a restricted caller cannot receive private read by
/// omission (Windows: <c>WindowsPipeCaller.Authenticated</c> in Axiom.Infrastructure.Windows).
/// </summary>
/// <param name="Actor">Audit-trail identity (Windows SID or <c>uid:N</c>).</param>
/// <param name="CanWrite">Whether <see cref="IpcCommandClass.Write"/> commands are allowed.</param>
/// <param name="CanReadPrivate">Whether <see cref="IpcCommandClass.PrivateRead"/> commands are allowed.</param>
/// <param name="WriteDenialReason">Message returned to the client for a denied write.</param>
/// <param name="ReadDenialReason">Message returned to the client for a denied private read.</param>
public sealed record IpcCaller(
    string Actor,
    bool CanWrite,
    bool CanReadPrivate,
    string? WriteDenialReason = null,
    string? ReadDenialReason = null)
{
    /// <summary>Pure per-command decision: public reads always, the other classes by the flags.</summary>
    public bool Permits(IpcCommandClass commandClass) => commandClass switch
    {
        IpcCommandClass.PublicRead => true,
        IpcCommandClass.PrivateRead => CanReadPrivate,
        _ => CanWrite,
    };

    /// <summary>The client-facing message for a command this caller may not use.</summary>
    public string DenialMessage(IpcCommandClass commandClass, string? commandType) =>
        (commandClass == IpcCommandClass.PrivateRead ? ReadDenialReason : WriteDenialReason)
        ?? $"Command '{commandType}' is not allowed for {Actor}.";
}

/// <summary>
/// Explicit classification of every IPC command into exactly one <see cref="IpcCommandClass"/>.
/// Anything not listed is treated as a write, so a new command is restricted until it is classified
/// here (a reflection test checks that every <see cref="IpcCommandTypes"/> constant is in exactly
/// one set). "Read-only" is not "harmless": snapshot, history, live events, DNS history and
/// diagnostics disclose machine-wide activity and are private; only <c>serviceHealth</c> and
/// <c>capabilities</c> are public, and <c>serviceHealth</c> is redacted for callers without private
/// read access (<see cref="RedactHealth"/>).
/// </summary>
public static class IpcCommandAccess
{
    public static IReadOnlySet<string> PublicReadCommands { get; } = new HashSet<string>(StringComparer.Ordinal)
    {
        IpcCommandTypes.Capabilities,
        IpcCommandTypes.ServiceHealth,
    };

    public static IReadOnlySet<string> PrivateReadCommands { get; } = new HashSet<string>(StringComparer.Ordinal)
    {
        IpcCommandTypes.Snapshot,
        IpcCommandTypes.LiveEvents,
        IpcCommandTypes.RuleVerify,
        IpcCommandTypes.RulesQuery,
        IpcCommandTypes.HistoryQuery,
        IpcCommandTypes.ThroughputHistory,
        IpcCommandTypes.PrivacyStatus,
        IpcCommandTypes.ConfigGet,
        IpcCommandTypes.DiagnosticsExport,
        IpcCommandTypes.ProtectionStatus,
        IpcCommandTypes.ThreatShareStatus,

        // Agent enforcement (upstream #322). Status carries the policy revision, agent/rule/
        // protected-resource counts, receipt counters and the policy error text (an I/O message
        // can name the policy path); receipts carry decisions, host adapter and version, action
        // kinds, indicator references and the hash chain. Neither is public health data.
        IpcCommandTypes.EnforcementStatus,
        IpcCommandTypes.EnforcementReceipts,
    };

    /// <summary>Public and private reads together (commands that change nothing).</summary>
    public static IReadOnlySet<string> ReadOnlyCommands { get; } =
        new HashSet<string>(PublicReadCommands.Concat(PrivateReadCommands), StringComparer.Ordinal);

    public static IReadOnlySet<string> WriteCommands { get; } = new HashSet<string>(StringComparer.Ordinal)
    {
        IpcCommandTypes.RuleApply,
        IpcCommandTypes.RuleRemove,
        IpcCommandTypes.PrivacyConfigure,
        IpcCommandTypes.PrivacySourcesUpdate,
        IpcCommandTypes.PrivacyHistoryClear,
        IpcCommandTypes.ConfigSet,
        IpcCommandTypes.ProtectionEnable,
        IpcCommandTypes.ProtectionDisable,
        IpcCommandTypes.ProtectionDecide,
        IpcCommandTypes.ProtectionDismiss,
        IpcCommandTypes.ProtectionLockdown,
        IpcCommandTypes.ThreatShareEnqueue,
        IpcCommandTypes.ThreatShareDismiss,
        IpcCommandTypes.ThreatShareRecord,
        IpcCommandTypes.NetworkRecoveryCapture,
        IpcCommandTypes.NetworkRecoveryRestore,

        // Every evaluate appends a receipt to the hash-chained journal (also for rejected
        // requests) and can add an entry to the request-id replay cache, and its verdict
        // discloses the matching rule: a state change, so it needs write access.
        IpcCommandTypes.EnforcementEvaluate,
    };

    /// <summary>The class of a command; unknown and null commands count as writes.</summary>
    public static IpcCommandClass Classify(string? commandType)
    {
        if (commandType is null)
        {
            return IpcCommandClass.Write;
        }

        if (PublicReadCommands.Contains(commandType))
        {
            return IpcCommandClass.PublicRead;
        }

        return PrivateReadCommands.Contains(commandType) ? IpcCommandClass.PrivateRead : IpcCommandClass.Write;
    }

    /// <summary>True unless the command is explicitly read-only (unknown commands count as writes).</summary>
    public static bool IsWrite(string? commandType) => Classify(commandType) == IpcCommandClass.Write;

    public const string HealthRedactedNote =
        "private fields redacted: this caller may read service health but not machine-wide activity";

    /// <summary>
    /// The public shape of <c>serviceHealth</c>: status, uptime, source kind and poll interval.
    /// Activity counts, capture time, limitations (which name paths and adapters) and the last
    /// error are withheld; the single limitation says so.
    /// </summary>
    public static ServiceHealth RedactHealth(ServiceHealth health)
    {
        ArgumentNullException.ThrowIfNull(health);
        return new ServiceHealth
        {
            Status = health.Status,
            UptimeSeconds = health.UptimeSeconds,
            SourceName = health.SourceName,
            PollIntervalSeconds = health.PollIntervalSeconds,
            LastCaptureUtc = null,
            ConnectionCount = 0,
            ProcessCount = 0,
            Limitations = [HealthRedactedNote],
            LastError = null,
        };
    }
}
