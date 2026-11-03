// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;

namespace LocalFirewall.Infrastructure.Windows;

/// <summary>
/// Read-only facts about the host. Deliberately uses only <see cref="Environment"/> and
/// <see cref="RuntimeInformation"/>; FND-001 performs no P/Invoke and needs no privileges.
/// </summary>
public sealed record WindowsPlatformInfo
{
    public required string OsDescription { get; init; }

    public required Version OsVersion { get; init; }

    public required string ProcessArchitecture { get; init; }

    public required bool Is64BitOperatingSystem { get; init; }

    public required bool Is64BitProcess { get; init; }

    public static WindowsPlatformInfo Current { get; } = new()
    {
        OsDescription = RuntimeInformation.OSDescription,
        OsVersion = Environment.OSVersion.Version,
        ProcessArchitecture = RuntimeInformation.ProcessArchitecture.ToString(),
        Is64BitOperatingSystem = Environment.Is64BitOperatingSystem,
        Is64BitProcess = Environment.Is64BitProcess,
    };

    public override string ToString() =>
        $"{OsDescription} ({OsVersion}); process {ProcessArchitecture}; 64-bit OS={Is64BitOperatingSystem}, 64-bit process={Is64BitProcess}";
}
