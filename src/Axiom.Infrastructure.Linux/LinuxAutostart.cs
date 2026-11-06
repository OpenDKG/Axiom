// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text;

namespace Axiom.Infrastructure.Linux;

/// <summary>
/// XDG autostart entry for the desktop host. Linux has no registry Run key; the equivalent is
/// <c>$XDG_CONFIG_HOME/autostart/*.desktop</c>. Only a file carrying our marker is ever deleted or
/// replaced, and a symlink at that path is refused.
/// </summary>
public static class LinuxAutostart
{
    public const string FileName = "axiom.desktop";

    public const string Marker = "X-Axiom-Managed=true";

    public static string ResolvePath(string? configHome = null)
    {
        var root = configHome ??
                   Environment.GetEnvironmentVariable("XDG_CONFIG_HOME");
        if (string.IsNullOrWhiteSpace(root))
        {
            root = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".config");
        }

        return Path.Combine(root, "autostart", FileName);
    }

    public static bool IsEnabled(string? configHome = null)
    {
        var path = ResolvePath(configHome);
        try
        {
            return File.Exists(path) &&
                   !new FileInfo(path).LinkTargetIsSymlink() &&
                   File.ReadAllText(path).Contains(Marker, StringComparison.Ordinal);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    public static void Enable(string executablePath, string? configHome = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        if (!Path.IsPathFullyQualified(executablePath))
        {
            throw new ArgumentException("The autostart executable must be an absolute path.", nameof(executablePath));
        }

        if (!File.Exists(executablePath))
        {
            throw new FileNotFoundException("The autostart executable does not exist.", executablePath);
        }

        var path = ResolvePath(configHome);
        var directory = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(directory);

        if (File.Exists(path) && new FileInfo(path).LinkTargetIsSymlink())
        {
            throw new IOException("Refusing to replace a symlinked autostart entry.");
        }

        if (File.Exists(path) && !File.ReadAllText(path).Contains(Marker, StringComparison.Ordinal))
        {
            throw new IOException("Refusing to replace an autostart entry that Axiom does not own.");
        }

        var content = new StringBuilder()
            .AppendLine("[Desktop Entry]")
            .AppendLine("Type=Application")
            .AppendLine("Name=Axiom")
            .AppendLine("Comment=Local network monitor and privacy guard")
            .Append("Exec=\"").Append(executablePath.Replace("\"", "\\\"", StringComparison.Ordinal)).AppendLine("\"")
            .AppendLine("Terminal=false")
            .AppendLine("X-GNOME-Autostart-enabled=true")
            .AppendLine(Marker)
            .ToString();

        var temporary = $"{path}.{Guid.NewGuid():N}.tmp";
        try
        {
            File.WriteAllText(temporary, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    public static void Disable(string? configHome = null)
    {
        var path = ResolvePath(configHome);
        if (!File.Exists(path))
        {
            return;
        }

        if (new FileInfo(path).LinkTargetIsSymlink() ||
            !File.ReadAllText(path).Contains(Marker, StringComparison.Ordinal))
        {
            return; // Never delete an entry another program owns.
        }

        File.Delete(path);
    }

    private static bool LinkTargetIsSymlink(this FileInfo info) => info.LinkTarget is not null || info.Attributes.HasFlag(FileAttributes.ReparsePoint);
}
