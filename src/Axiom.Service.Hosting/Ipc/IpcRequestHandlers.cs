// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Contracts.History;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Contracts.Privacy;
using Axiom.Contracts.Protection;
using Axiom.Contracts.Threat;

namespace Axiom.Service.Hosting.Ipc;

/// <summary>
/// The named service commands the IPC endpoint may dispatch. A null handler means the command is
/// not available in this build and is reported as <c>not_supported</c>. The string argument of the
/// write handlers is the authenticated caller identity (Windows SID or <c>uid:N</c> on Unix).
/// </summary>
public sealed class IpcRequestHandlers
{
    public required Func<ConnectionSnapshot?> SnapshotProvider { get; init; }

    public required Func<ServiceHealth> HealthProvider { get; init; }

    public Func<HistoryQuery, CancellationToken, Task<HistoryPage>>? HistoryQuery { get; init; }

    public Func<ThroughputHistoryQuery, CancellationToken, Task<ThroughputHistory>>? ThroughputHistory { get; init; }

    public Func<CancellationToken, Task<FirewallRulesSnapshot>>? RulesQuery { get; init; }

    public Func<RuleSpec, string, CancellationToken, Task<RuleApplyResult>>? RuleApply { get; init; }

    public Func<Guid, string, CancellationToken, Task<RuleApplyResult>>? RuleRemove { get; init; }

    public Func<Guid, CancellationToken, Task<EffectiveRuleReport>>? RuleVerify { get; init; }

    public Func<CancellationToken, Task<PrivacyShieldStatus>>? PrivacyStatus { get; init; }

    public Func<PrivacyShieldSettings, CancellationToken, Task<PrivacyShieldStatus>>? PrivacyConfigure { get; init; }

    public Func<CancellationToken, Task<PrivacyShieldStatus>>? PrivacySourcesUpdate { get; init; }

    public Func<CancellationToken, Task<PrivacyShieldStatus>>? PrivacyHistoryClear { get; init; }

    public Func<CancellationToken, Task<ProtectionStatus>>? ProtectionStatus { get; init; }

    public Func<ProtectionEnableRequest, string, CancellationToken, Task<ProtectionStatus>>? ProtectionEnable { get; init; }

    public Func<string, CancellationToken, Task<ProtectionStatus>>? ProtectionDisable { get; init; }

    public Func<ProtectionDecideRequest, string, CancellationToken, Task<ProtectionStatus>>? ProtectionDecide { get; init; }

    public Func<ProtectionDismissRequest, CancellationToken, Task<ProtectionStatus>>? ProtectionDismiss { get; init; }

    public Func<ProtectionLockdownRequest, string, CancellationToken, Task<ProtectionStatus>>? ProtectionLockdown { get; init; }

    public Func<CancellationToken, Task<ThreatShareQueueStatus>>? ThreatShareStatus { get; init; }

    public Func<ThreatShareEnqueueRequest, CancellationToken, Task<ThreatShareQueueStatus>>? ThreatShareEnqueue { get; init; }

    public Func<ThreatShareDismissRequest, CancellationToken, Task<ThreatShareQueueStatus>>? ThreatShareDismiss { get; init; }

    public Func<ThreatShareRecordRequest, CancellationToken, Task<ThreatShareQueueStatus>>? ThreatShareRecord { get; init; }
}
