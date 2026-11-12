// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Infrastructure.Unix;

/// <summary>
/// File-system layout shared by the Unix daemons. Every path derives from the machine data
/// directory and the run directory so tests can point both at a temp folder; the platform
/// records (<c>MacServicePaths</c>, <c>LinuxServicePaths</c>) add their OS-specific locations.
/// </summary>
public record UnixServicePaths(string MachineDataDirectory, string RunDirectory, string IpcSocketPath)
{
    public const string FilterSocketVariable = "AXIOM_FILTER_SOCKET";

    public string? FilterSocketOverride { get; init; }

    public string FilterDirectory => Path.Combine(MachineDataDirectory, "filter");

    /// <summary>Rule table published for the OS filter backend (AxiomFilter on macOS).</summary>
    public string RulesFile => Path.Combine(FilterDirectory, "rules.json");

    /// <summary>The daemon's own record of the rules it owns (the "OS state" of the adapter).</summary>
    public string ManagedRulesFile => Path.Combine(FilterDirectory, "managed-rules.json");

    public string FilterSocketPath => string.IsNullOrWhiteSpace(FilterSocketOverride)
        ? Path.Combine(RunDirectory, "filter.sock")
        : FilterSocketOverride.Trim();

    public string DnsBackupFile => Path.Combine(MachineDataDirectory, "privacy-shield-dns-backup.json");

    /// <summary>Upstream network recovery baseline (<c>network-recovery.txt</c>, 0600) in the machine data root.</summary>
    public string RecoverySnapshotFile => Path.Combine(
        MachineDataDirectory,
        Axiom.Contracts.NetworkRecovery.NetworkRecoverySnapshotStore.FileName);

    /// <summary>A test layout rooted in <paramref name="root"/>.</summary>
    public static UnixServicePaths ForRoot(string root) => new(
        Path.Combine(root, "data"),
        Path.Combine(root, "run"),
        Path.Combine(root, "run", "axiom.sock"));
}
