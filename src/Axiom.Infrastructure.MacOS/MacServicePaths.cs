// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts;
using Axiom.Contracts.Ipc;
using Axiom.Infrastructure.Unix;

namespace Axiom.Infrastructure.MacOS;

/// <summary>
/// File-system layout of the macOS daemon (docs/MACOS_ARCHITECTURE.md). The shared Unix part
/// (data, run and filter paths) is <see cref="UnixServicePaths"/>; this record adds the launchd
/// label, plist and log locations.
/// </summary>
public sealed record MacServicePaths(string MachineDataDirectory, string RunDirectory, string IpcSocketPath)
    : UnixServicePaths(MachineDataDirectory, RunDirectory, IpcSocketPath)
{
    public const string DefaultRunDirectory = "/var/run/axiom";

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

    /// <summary>A test layout rooted in <paramref name="root"/>.</summary>
    public static new MacServicePaths ForRoot(string root) => new(
        Path.Combine(root, "data"),
        Path.Combine(root, "run"),
        Path.Combine(root, "run", "axiom.sock"));
}
