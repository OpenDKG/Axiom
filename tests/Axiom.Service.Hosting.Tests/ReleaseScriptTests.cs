// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Xunit;

namespace Axiom.Service.Hosting.Tests;

/// <summary>
/// Axiom.Service targets net10.0-windows and net10.0. Any release or developer command that
/// publishes or runs it must pin the Windows framework; without <c>-f net10.0-windows</c> the
/// publish fails with NETSDK1129 (validated on Linux: the unqualified publish exits 1). This
/// check runs on every OS in the portable suite so the scripts cannot drift again.
/// </summary>
public sealed class ReleaseScriptTests
{
    public static TheoryData<string> WindowsServiceScripts => new(
        "scripts/build-release.ps1",
        "scripts/publish-setup.ps1",
        "scripts/build-msix.ps1",
        "scripts/run-service.ps1");

    [Theory]
    [MemberData(nameof(WindowsServiceScripts))]
    public void Windows_service_publish_and_run_commands_specify_the_framework(string relativePath)
    {
        var script = Path.Combine(RepositoryRoot(), relativePath.Replace('/', Path.DirectorySeparatorChar));
        Assert.True(File.Exists(script), $"missing {relativePath}");
        var text = File.ReadAllText(script)
            .Replace("`\r\n", " ", StringComparison.Ordinal)
            .Replace("`\n", " ", StringComparison.Ordinal);

        var commands = text.Split('\n')
            .Select(line => line.Trim())
            .Where(line => (line.Contains("Axiom.Service", StringComparison.Ordinal) ||
                            line.Contains("$serviceProject", StringComparison.Ordinal)) &&
                           (line.Contains("publish", StringComparison.Ordinal) ||
                            line.Contains("\"run\"", StringComparison.Ordinal)))
            .ToList();

        Assert.NotEmpty(commands);
        Assert.All(commands, line => Assert.Contains("net10.0-windows", line, StringComparison.Ordinal));
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Axiom.sln")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        return directory!.FullName;
    }
}
