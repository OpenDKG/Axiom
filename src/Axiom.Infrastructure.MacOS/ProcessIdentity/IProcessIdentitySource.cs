// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Infrastructure.MacOS.ProcessIdentity;

/// <summary>Process identity lookup used by the connection source (mockable in tests).</summary>
public interface IProcessIdentitySource
{
    MacProcessIdentity Resolve(int processId, string? knownPath);
}

/// <summary>Path-only identity (non-macOS hosts and tests).</summary>
public sealed class PathOnlyIdentitySource : IProcessIdentitySource
{
    public static PathOnlyIdentitySource Instance { get; } = new();

    public MacProcessIdentity Resolve(int processId, string? knownPath)
    {
        var path = knownPath ?? string.Empty;
        var bundle = MacBundleInfo.FindEnclosingBundle(path);
        return new MacProcessIdentity
        {
            ProcessId = processId,
            Path = path,
            DisplayName = bundle is not null
                ? Path.GetFileNameWithoutExtension(bundle)
                : path.Length > 0 ? Path.GetFileName(path) : string.Empty,
            BundlePath = bundle ?? string.Empty,
        };
    }
}
