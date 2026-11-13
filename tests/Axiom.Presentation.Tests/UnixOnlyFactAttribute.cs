// SPDX-License-Identifier: GPL-3.0-or-later
using Xunit;

namespace Axiom.Presentation.Tests;

/// <summary>
/// A fact that only runs on macOS/Linux. Used for macOS bundle-path tests whose inputs are POSIX
/// paths: Windows' Path.GetDirectoryName rewrites '/' to '\', so they cannot hold there.
/// </summary>
public sealed class UnixOnlyFactAttribute : FactAttribute
{
    public UnixOnlyFactAttribute()
    {
        if (OperatingSystem.IsWindows())
        {
            Skip = "POSIX bundle paths; runs on macOS/Linux only.";
        }
    }
}
