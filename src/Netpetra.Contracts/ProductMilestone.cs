// SPDX-License-Identifier: GPL-3.0-or-later
namespace Netpetra.Contracts;

/// <summary>
/// Version of the product surface exposed to the UI. Kept separate from the assembly version so
/// that the shell can state exactly which milestone a build implements.
/// </summary>
public static class ProductMilestone
{
    public const string Current = "FND-005";

    /// <summary>True: TCP/UDP inventory comes from the local Windows owner tables.</summary>
    public const bool LiveInventory = true;

    /// <summary>True: the overview throughput chart is still a deterministic demo series (FND-004).</summary>
    public const bool DemoTrafficSeries = true;
}
