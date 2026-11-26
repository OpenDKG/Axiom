// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class BundledLegalFilesTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("axiom-legal-").FullName;

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact]
    public void Install_copies_every_named_file_and_remove_leaves_other_files_alone()
    {
        var payload = Path.Combine(_root, "payload");
        var install = Path.Combine(_root, "install");
        foreach (var relative in BundledLegalFiles.RelativePaths)
        {
            Write(Path.Combine(payload, BundledLegalFiles.FolderName, relative), relative);
        }

        Write(Path.Combine(install, "LICENSE"), "the user's own file");
        Write(Path.Combine(install, "licenses", "mine.txt"), "the user's own file");

        Assert.Equal(BundledLegalFiles.RelativePaths.Count, BundledLegalFiles.Install(payload, install));
        Assert.All(BundledLegalFiles.RelativePaths, relative =>
            Assert.Equal(relative, File.ReadAllText(Path.Combine(install, "licenses", relative))));

        BundledLegalFiles.Remove(install);

        Assert.Equal("the user's own file", File.ReadAllText(Path.Combine(install, "LICENSE")));
        Assert.True(File.Exists(Path.Combine(install, "licenses", "mine.txt")));
        Assert.Single(Directory.EnumerateFileSystemEntries(Path.Combine(install, "licenses")));
    }

    [Fact]
    public void Remove_deletes_the_folder_it_filled()
    {
        var payload = Path.Combine(_root, "payload");
        var install = Path.Combine(_root, "install");
        Write(Path.Combine(payload, "licenses", "dotnet", "DOTNET-LIBRARY-LICENSE.txt"), "text");
        Assert.Equal(1, BundledLegalFiles.Install(payload, install));

        BundledLegalFiles.Remove(install);

        Assert.False(Directory.Exists(Path.Combine(install, "licenses")));
    }

    [Fact]
    public void A_payload_without_license_files_installs_nothing() =>
        Assert.Equal(0, BundledLegalFiles.Install(Path.Combine(_root, "empty"), Path.Combine(_root, "install")));

    private static void Write(string path, string text)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, text);
    }
}
