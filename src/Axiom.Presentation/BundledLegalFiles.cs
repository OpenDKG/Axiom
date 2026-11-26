// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

/// <summary>
/// The license and notice files Setup installs into <c>&lt;install folder&gt;/licenses</c>. Only these
/// named files are ever written or removed, so nothing else in a chosen install folder is touched.
/// </summary>
public static class BundledLegalFiles
{
    public const string FolderName = "licenses";

    /// <summary>Paths below <see cref="FolderName"/>, in the setup payload and in the install folder.</summary>
    public static IReadOnlyList<string> RelativePaths { get; } =
    [
        "LICENSE",
        "NOTICE",
        "AUTHORS.md",
        "THIRD_PARTY_NOTICES.md",
        Path.Combine("dotnet", "DOTNET-LIBRARY-LICENSE.txt"),
        Path.Combine("dotnet", "LICENSE.TXT"),
        Path.Combine("dotnet", "THIRD-PARTY-NOTICES.TXT"),
    ];

    /// <summary>Copies the files the payload carries and returns how many were copied.</summary>
    public static int Install(string payloadDirectory, string installDirectory)
    {
        var copied = 0;
        foreach (var relative in RelativePaths)
        {
            var source = Path.Combine(payloadDirectory, FolderName, relative);
            if (!File.Exists(source))
            {
                continue;
            }

            var destination = Path.Combine(installDirectory, FolderName, relative);
            ThrowIfLinked(destination);
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            File.Copy(source, destination, overwrite: true);
            copied++;
        }

        return copied;
    }

    /// <summary>Removes the named files, then the folders if nothing else is left in them.</summary>
    public static void Remove(string installDirectory)
    {
        var folder = Path.Combine(installDirectory, FolderName);
        if (!Directory.Exists(folder) || StorageSafety.IsReparsePointInPath(folder))
        {
            return;
        }

        foreach (var relative in RelativePaths)
        {
            var path = Path.Combine(folder, relative);
            if (File.Exists(path) && !StorageSafety.IsReparsePointInPath(path))
            {
                File.Delete(path);
            }
        }

        foreach (var directory in new[] { Path.Combine(folder, "dotnet"), folder })
        {
            if (Directory.Exists(directory) && !Directory.EnumerateFileSystemEntries(directory).Any())
            {
                Directory.Delete(directory);
            }
        }
    }

    private static void ThrowIfLinked(string path)
    {
        if (StorageSafety.IsReparsePointInPath(path))
        {
            throw new IOException("A license file path contains a junction or symbolic link: " + path);
        }
    }
}
