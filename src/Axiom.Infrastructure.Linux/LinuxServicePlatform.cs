// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Core.Firewall;
using Axiom.Core.Platform;
using Axiom.Infrastructure.Linux.Firewall;
using Axiom.Infrastructure.Linux.Ipc;
using Axiom.Infrastructure.Linux.ProcFs;

namespace Axiom.Infrastructure.Linux;

/// <summary>Linux composition of the platform seam: procfs inventory, Unix socket IPC, fail-closed firewall.</summary>
public sealed class LinuxServicePlatform : IServicePlatform
{
    public const string AllowedUidVariable = "AXIOM_ALLOWED_UID";

    public string Name => "Linux (procfs)";

    // Writes stay closed unless the operator opt-in gate is set; the adapter refuses too.
    public bool FirewallWritesEnabled => LinuxFirewallPolicyAdapter.IsWriteGateOpen;

    public IConnectionSnapshotSource CreateSnapshotSource() => new ProcConnectionSource();

    public IFirewallPolicyAdapter CreateFirewallAdapter() => new LinuxFirewallPolicyAdapter();

    public string ResolveActorId() =>
        string.Create(CultureInfo.InvariantCulture, $"uid:{ResolveAllowedUid()}");

    public Task RunIpcServerAsync(
        IpcRequestProcessor processor,
        string actorId,
        CancellationToken cancellationToken)
    {
        var server = new UnixSocketServer(
            IpcEndpoint.ResolveServerUnixSocketPath(),
            ResolveAllowedUid(),
            processor,
            message => Console.Error.WriteLine(message));

        return RunAndDisposeAsync(server, cancellationToken);
    }

    /// <summary>
    /// The only uid allowed to call the service. Defaults to the service's own uid; a system
    /// install sets it to the desktop user. Values that would silently widen access are rejected.
    /// </summary>
    public static uint ResolveAllowedUid()
    {
        var configured = Environment.GetEnvironmentVariable(AllowedUidVariable);
        if (string.IsNullOrWhiteSpace(configured))
        {
            return PosixIdentity.EffectiveUserId;
        }

        if (!uint.TryParse(configured.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var uid) ||
            uid == uint.MaxValue)
        {
            throw new InvalidOperationException(
                $"{AllowedUidVariable} must be a numeric uid other than the reserved 4294967295.");
        }

        return uid;
    }

    private static async Task RunAndDisposeAsync(UnixSocketServer server, CancellationToken cancellationToken)
    {
        await using (server.ConfigureAwait(false))
        {
            await server.RunAsync(cancellationToken).ConfigureAwait(false);
        }
    }
}
