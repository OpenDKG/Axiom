// SPDX-License-Identifier: GPL-3.0-or-later
using System.Security.Principal;
using Axiom.Contracts;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Core.Firewall;
using Axiom.Core.Platform;
using Axiom.Infrastructure.Windows.Firewall;
using Axiom.Infrastructure.Windows.IpHelper;
using Axiom.Infrastructure.Windows.Ipc;

namespace Axiom.Infrastructure.Windows;

/// <summary>Windows composition of the platform seam. Behaviour is unchanged from the WPF-era host.</summary>
public sealed class WindowsServicePlatform : IServicePlatform
{
    public string Name => "Windows (IP Helper)";

    public bool FirewallWritesEnabled => WindowsFirewallPolicyAdapter.IsWriteGateOpen;

    public IConnectionSnapshotSource CreateSnapshotSource() => new IpHelperConnectionSource();

    public IFirewallPolicyAdapter CreateFirewallAdapter() => new WindowsFirewallPolicyAdapter();

    public string ResolveActorId()
    {
        var configured = Environment.GetEnvironmentVariable("AXIOM_ALLOWED_SID")
                         ?? Environment.GetEnvironmentVariable(LegacyIdentity.ProductName + "_ALLOWED_SID");
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return configured.Trim();
        }

        return WindowsIdentity.GetCurrent().User?.Value
            ?? throw new InvalidOperationException("Cannot determine the allowed SID.");
    }

    public Task RunIpcServerAsync(
        IpcRequestProcessor processor,
        string actorId,
        CancellationToken cancellationToken) =>
        new PipeServer(
            IpcPipe.Name,
            actorId,
            processor,
            message => Console.Error.WriteLine(message)).RunAsync(cancellationToken);
}
