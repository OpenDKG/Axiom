// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;

namespace Axiom.Infrastructure.Linux.Nft;

/// <summary>
/// An optional enforcement layer fed by the same rule set and generation as the nftables table
/// (docs/LINUX_EBPF.md): the adapter calls <see cref="SyncAsync"/> after every successful publish.
/// nftables stays the primary boundary; a layer may be inactive (missing toolchain, kernel
/// without BTF, unit without the capabilities) and must say so in <see cref="Status"/>.
/// </summary>
public interface IVerdictLayer
{
    /// <summary>True while the layer enforces verdicts.</summary>
    bool Active { get; }

    /// <summary>One line for capabilities/doctor: what the layer does or why it is inactive.</summary>
    string Status { get; }

    /// <summary>Reconciles the layer's state with the enabled rules of this generation.</summary>
    Task SyncAsync(IReadOnlyList<ManagedRule> rules, long generation, CancellationToken ct);
}

/// <summary>A verdict layer with a daemon lifetime, driven by <see cref="NftEnforcementSupervisor"/>.</summary>
public interface IEnforcementLayer : IVerdictLayer
{
    /// <summary>Probes, loads and attaches; never throws — an unusable layer reports <see cref="IVerdictLayer.Status"/>.</summary>
    Task StartAsync(CancellationToken ct);

    /// <summary>Detaches and removes everything the layer created; idempotent.</summary>
    Task StopAsync();

    /// <summary>Streams the layer's flow events into the sink until cancelled (restarting its source on exit).</summary>
    Task RunEventsAsync(CancellationToken ct);
}
