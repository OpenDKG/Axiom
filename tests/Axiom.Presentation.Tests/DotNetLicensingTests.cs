// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;
using System.Text.RegularExpressions;
using Xunit;

namespace Axiom.Presentation.Tests;

/// <summary>The licensing documents must match how Windows releases are built and what they ship.</summary>
public sealed class DotNetLicensingTests
{
    private static readonly string Licensing = Flat(Read("docs", "LICENSING.md"));
    private static readonly string Notices = Flat(Read("THIRD_PARTY_NOTICES.md"));

    [Fact]
    public void Documents_do_not_call_the_whole_windows_runtime_mit()
    {
        Assert.DoesNotContain("runtime redistributed by the self-contained build is MIT", Licensing, StringComparison.Ordinal);
        Assert.DoesNotContain("which are MIT licensed", Notices, StringComparison.Ordinal);
        foreach (var document in new[] { Licensing, Notices })
        {
            Assert.Contains(".NET Library License", document, StringComparison.Ordinal);
            Assert.Contains("coreclr", document, StringComparison.Ordinal);
            Assert.Contains("licenses/dotnet/DOTNET-LIBRARY-LICENSE.txt", document, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Single_file_windows_builds_are_documented_with_the_open_compatibility_question()
    {
        // While any Windows release program is single-file, the documents must say what follows.
        Assert.Contains(
            "<PublishSingleFile>true</PublishSingleFile>",
            Read("src", "Axiom.Desktop.Avalonia.Windows", "Properties", "PublishProfiles", "win-x64-selfcontained.pubxml"),
            StringComparison.Ordinal);
        Assert.Contains("-p:PublishSingleFile=true", Read("scripts", "build-release.ps1"), StringComparison.Ordinal);
        Assert.Contains("-p:PublishSingleFile=true", Read("scripts", "publish-setup.ps1"), StringComparison.Ordinal);

        Assert.Contains("desktop app, the service and Setup are single-file", Licensing, StringComparison.Ordinal);
        Assert.Contains("needs review by the founders or a lawyer", Licensing, StringComparison.Ordinal);
        Assert.Contains("needs review by the founders or a lawyer", Notices, StringComparison.Ordinal);
    }

    [Fact]
    public void Every_recorded_native_binary_is_named_in_the_notices()
    {
        using var map = JsonDocument.Parse(Read("packaging", "licenses", "native-binaries.json"));
        Assert.Contains(map.RootElement.GetProperty("singleFileHost").GetProperty("notice").GetString()!, Notices, StringComparison.Ordinal);
        foreach (var binary in map.RootElement.GetProperty("binaries").EnumerateArray())
        {
            Assert.Contains($"`{binary.GetProperty("file").GetString()}`", Notices, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void The_library_license_text_is_present_and_no_build_ships_diasymreader()
    {
        Assert.Contains(
            "MICROSOFT .NET LIBRARY",
            Read("packaging", "licenses", "dotnet", "DOTNET-LIBRARY-LICENSE.txt"),
            StringComparison.Ordinal);
        var targets = Read("Directory.Build.targets");
        Assert.Contains("AfterTargets=\"ResolveRuntimePackAssets\"", targets, StringComparison.Ordinal);
        Assert.Contains("StartsWith('Microsoft.DiaSymReader.Native.')", targets, StringComparison.Ordinal);
        Assert.Contains("Microsoft.DiaSymReader.Native", Notices, StringComparison.Ordinal);
    }

    private static string Flat(string text) => Regex.Replace(text, @"\s+", " ");

    private static string Read(params string[] parts)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "PRIVACY.md")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        return File.ReadAllText(Path.Combine([directory.FullName, .. parts]));
    }
}
