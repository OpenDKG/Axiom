// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Infrastructure.Linux.Tests;

internal static class TestBinaries
{
    public static string ExistingExecutable()
    {
        foreach (var candidate in new[] { "/usr/bin/env", "/bin/sh", "/usr/bin/true" })
        {
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new InvalidOperationException("No absolute executable is available for the test.");
    }
}
