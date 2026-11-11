// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ipc;

namespace Axiom.Service.Hosting.Ipc;

/// <summary>Identity of an authenticated IPC client as seen by the dispatcher.</summary>
/// <param name="Actor">Audit-trail identity (Windows SID or <c>uid:N</c>).</param>
/// <param name="CanWrite">Whether commands in <see cref="IpcCommandAccess.WriteCommands"/> are allowed.</param>
/// <param name="WriteDenialReason">Message returned to the client for a denied write.</param>
public sealed record IpcCaller(string Actor, bool CanWrite, string? WriteDenialReason = null)
{
    public static IpcCaller FullAccess(string actor) => new(actor, true);
}

/// <summary>
/// Explicit read/write classification of every IPC command. Read-only commands return state;
/// write commands change machine-wide state (rules, Axiom Shield, Privacy Shield configuration,
/// threat sharing). Anything not listed as read-only is treated as a write, so a new command is
/// restricted until it is classified here (a test checks that every command is in exactly one list).
/// </summary>
public static class IpcCommandAccess
{
    public static IReadOnlySet<string> ReadOnlyCommands { get; } = new HashSet<string>(StringComparer.Ordinal)
    {
        IpcCommandTypes.Capabilities,
        IpcCommandTypes.ServiceHealth,
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
    };

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
    };

    /// <summary>True unless the command is explicitly read-only (unknown commands count as writes).</summary>
    public static bool IsWrite(string? commandType) =>
        commandType is null || !ReadOnlyCommands.Contains(commandType);
}
