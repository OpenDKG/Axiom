// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts;
using Axiom.Contracts.Ipc;

namespace Axiom.Infrastructure.MacOS;

/// <summary>
/// File-system layout of the macOS daemon (docs/MACOS_ARCHITECTURE.md). Every path derives from
/// the machine data directory and the run directory so tests can point both at a temp folder.
/// </summary>
public sealed record MacServicePaths(string MachineDataDirectory, string RunDirectory, string IpcSocketPath)
{
    public const string DefaultRunDirectory = "/var/run/axiom";

    public const string FilterSocketVariable = "AXIOM_FILTER_SOCKET";

    public const string LaunchdLabel = "com.axiom.service";

    public const string LaunchDaemonPlistPath = "/Library/LaunchDaemons/com.axiom.service.plist";

    public const string LogDirectory = "/Library/Logs/Axiom";

    public const string LogFilePath = "/Library/Logs/Axiom/axiomd.log";

    /// <summary>Production layout, honouring <c>AXIOM_IPC_SOCKET</c> / <c>AXIOM_FILTER_SOCKET</c>.</summary>
    public static MacServicePaths Default { get; } = new(
        AxiomPaths.MachineDataDirectory,
        DefaultRunDirectory,
        IpcPipe.Endpoint)
    {
        FilterSocketOverride = Environment.GetEnvironmentVariable(FilterSocketVariable),
    };

    public string? FilterSocketOverride { get; init; }

    public string FilterDirectory => Path.Combine(MachineDataDirectory, "filter");

    /// <summary>Rule table read by the AxiomFilter system extension.</summary>
    public string RulesFile => Path.Combine(FilterDirectory, "rules.json");

    /// <summary>The daemon's own record of the rules it owns (the "OS state" of the adapter).</summary>
    public string ManagedRulesFile => Path.Combine(FilterDirectory, "managed-rules.json");

    public string FilterSocketPath => string.IsNullOrWhiteSpace(FilterSocketOverride)
        ? Path.Combine(RunDirectory, "filter.sock")
        : FilterSocketOverride.Trim();

    /// <summary>Last AxiomFilter instance (pid@start) the daemon saw; 0600, daemon-private.</summary>
    public string FilterInstanceMarkerFile => Path.Combine(MachineDataDirectory, "filter-instance");

    public string DnsBackupFile => Path.Combine(MachineDataDirectory, "privacy-shield-dns-backup.json");

    /// <summary>Upstream network recovery baseline (<c>network-recovery.txt</c>, 0600) in the machine data root.</summary>
    public string RecoverySnapshotFile => Path.Combine(
        MachineDataDirectory,
        Axiom.Contracts.NetworkRecovery.NetworkRecoverySnapshotStore.FileName);

    /// <summary>A test layout rooted in <paramref name="root"/>.</summary>
    public static MacServicePaths ForRoot(string root) => new(
        Path.Combine(root, "data"),
        Path.Combine(root, "run"),
        Path.Combine(root, "run", "axiom.sock"));
}
