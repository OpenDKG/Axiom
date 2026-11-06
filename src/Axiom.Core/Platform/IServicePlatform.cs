// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Core.Firewall;

namespace Axiom.Core.Platform;

/// <summary>
/// The single platform seam of the service host. Windows keeps its named pipe, IP Helper and
/// Windows Firewall implementations; Unix hosts supply their own. Both sides use the same
/// transport-neutral <see cref="IpcRequestProcessor"/>, history and domain rules.
/// </summary>
public interface IServicePlatform
{
    /// <summary>Short name shown in diagnostics, for example "Windows (IP Helper)".</summary>
    string Name { get; }

    /// <summary>True only when the explicit write gate is open on this platform.</summary>
    bool FirewallWritesEnabled { get; }

    IConnectionSnapshotSource CreateSnapshotSource();

    IFirewallPolicyAdapter CreateFirewallAdapter();

    /// <summary>Actor identity recorded in the audit trail (Windows SID or Unix uid).</summary>
    string ResolveActorId();

    Task RunIpcServerAsync(IpcRequestProcessor processor, string actorId, CancellationToken cancellationToken);
}
