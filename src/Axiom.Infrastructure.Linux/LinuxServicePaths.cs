// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts;
using Axiom.Contracts.Ipc;
using Axiom.Infrastructure.Unix;

namespace Axiom.Infrastructure.Linux;

/// <summary>
/// File-system layout of the Linux daemon (docs/LINUX_ARCHITECTURE.md §2): state in
/// <c>/var/lib/axiom</c> (0700, <c>StateDirectory=</c>), sockets in <c>/run/axiom</c>
/// (<c>RuntimeDirectory=</c>), logs through journald with <c>/var/log/axiom</c> reserved
/// (<c>LogsDirectory=</c>), the root-owned image in <c>/usr/libexec/axiom</c> and the unit in
/// <c>/etc/systemd/system</c>. Development and non-root runs override the roots with
/// <c>AXIOM_DATA_ROOT</c>, <c>AXIOM_RUNTIME_DIR</c> and <c>AXIOM_IPC_SOCKET</c>.
/// </summary>
public sealed record LinuxServicePaths(string MachineDataDirectory, string RunDirectory, string IpcSocketPath)
    : UnixServicePaths(MachineDataDirectory, RunDirectory, IpcSocketPath)
{
    public const string DefaultRunDirectory = "/run/axiom";

    public const string LogDirectory = "/var/log/axiom";

    public const string ImageDirectory = "/usr/libexec/axiom";

    public const string UnitName = "axiomd.service";

    public const string UnitFilePath = "/etc/systemd/system/axiomd.service";

    public const string IpcSocketFileName = "axiom.sock";

    /// <summary>Overrides the run directory (sockets) for development and tests.</summary>
    public const string RuntimeDirectoryVariable = "AXIOM_RUNTIME_DIR";

    /// <summary>Set by systemd when the unit declares <c>RuntimeDirectory=axiom</c>.</summary>
    public const string SystemdRuntimeDirectoryVariable = "RUNTIME_DIRECTORY";

    /// <summary>Production layout, honouring the environment overrides.</summary>
    public static LinuxServicePaths Default { get; } = Resolve(
        AxiomPaths.MachineDataDirectory,
        Environment.GetEnvironmentVariable(RuntimeDirectoryVariable),
        Environment.GetEnvironmentVariable(SystemdRuntimeDirectoryVariable),
        Environment.GetEnvironmentVariable(IpcPipe.UnixSocketVariable)) with
    {
        FilterSocketOverride = Environment.GetEnvironmentVariable(FilterSocketVariable),
    };

    /// <summary>Daemon executable inside the protected image directory.</summary>
    public static string DaemonPath => Path.Combine(ImageDirectory, Unix.Install.ProtectedImageLayout.DaemonFileName);

    /// <summary>
    /// Pure resolution: <c>AXIOM_RUNTIME_DIR</c> wins over systemd's <c>RUNTIME_DIRECTORY</c>
    /// (first entry of its colon-separated list) over <c>/run/axiom</c>; the socket is
    /// <c>AXIOM_IPC_SOCKET</c> or <c>&lt;run&gt;/axiom.sock</c>.
    /// </summary>
    public static LinuxServicePaths Resolve(string machineDataDirectory, string? runtimeOverride, string? systemdRuntime, string? socketOverride)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(machineDataDirectory);

        var run = !string.IsNullOrWhiteSpace(runtimeOverride) ? runtimeOverride.Trim()
            : !string.IsNullOrWhiteSpace(systemdRuntime) ? systemdRuntime.Split(':', 2)[0].Trim()
            : DefaultRunDirectory;
        if (run.Length == 0)
        {
            run = DefaultRunDirectory;
        }

        var socket = string.IsNullOrWhiteSpace(socketOverride)
            ? Path.Combine(run, IpcSocketFileName)
            : socketOverride.Trim();
        return new LinuxServicePaths(machineDataDirectory, run, socket);
    }

    /// <summary>A test layout rooted in <paramref name="root"/>.</summary>
    public static new LinuxServicePaths ForRoot(string root) => new(
        Path.Combine(root, "data"),
        Path.Combine(root, "run"),
        Path.Combine(root, "run", IpcSocketFileName));
}
