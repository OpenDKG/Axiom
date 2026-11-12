// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts;

/// <summary>
/// Version of the product surface exposed to the UI. Kept separate from the assembly version so
/// that the shell can state exactly which milestone a build implements.
/// </summary>
public static class ProductMilestone
{
    /// <summary>
    /// Build label derived from the shared product version (Directory.Build.props), so IPC
    /// capabilities, error text and every Settings page always agree with the shipped release.
    /// </summary>
    public static string Current { get; } = BuildLabel();

    private static string BuildLabel()
    {
        var assembly = typeof(ProductMilestone).Assembly;
        var informational = (Attribute.GetCustomAttribute(
            assembly,
            typeof(System.Reflection.AssemblyInformationalVersionAttribute))
            as System.Reflection.AssemblyInformationalVersionAttribute)?.InformationalVersion;
        var version = string.IsNullOrWhiteSpace(informational)
            ? assembly.GetName().Version?.ToString(3) ?? "dev"
            : informational.Split('+')[0];
        return $"Axiom {version}";
    }

    /// <summary>True: TCP/UDP inventory comes from the local Windows owner tables.</summary>
    public const bool LiveInventory = true;

    /// <summary>True: the overview throughput chart is still a deterministic demo series (FND-004).</summary>
    public const bool DemoTrafficSeries = true;
}
