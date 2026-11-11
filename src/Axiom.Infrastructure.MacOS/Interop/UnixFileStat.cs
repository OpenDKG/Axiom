// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;

namespace Axiom.Infrastructure.MacOS.Interop;

/// <summary>Owner, group and mode of one file system entry (from <c>stat -f '%u %g %p %N'</c>).</summary>
public sealed record UnixFileEntry(string Path, uint Uid, uint Gid, int Mode)
{
    private const int TypeMask = 0xF000;

    private const int DirectoryType = 0x4000;

    private const int SocketType = 0xC000;

    /// <summary>Permission bits only (0777 mask), e.g. 0o755.</summary>
    public int Permissions => Mode & 0x1FF;

    public bool IsDirectory => (Mode & TypeMask) == DirectoryType;

    public bool IsSocket => (Mode & TypeMask) == SocketType;

    public bool IsGroupOrWorldWritable => (Mode & 0x012) != 0;

    public bool IsRootOwned => Uid == 0;

    public string PermissionsOctal => Convert.ToString(Permissions, 8).PadLeft(3, '0');

    public string Describe() => $"uid={Uid} gid={Gid} mode={PermissionsOctal}";
}

/// <summary>
/// Reads owner/group/mode of many paths with one <c>/usr/bin/stat</c> call. .NET exposes the mode
/// (<see cref="File.GetUnixFileMode(string)"/>) but not the owner, and the <c>struct stat</c>
/// layout differs per platform, so the tool is used instead of a P/Invoke. Testable through
/// <see cref="IProcessRunner"/>.
/// </summary>
public static class UnixFileStat
{
    public const string StatTool = "/usr/bin/stat";

    public const string Format = "%u %g %p %N";

    private const int ChunkSize = 200;

    private static readonly TimeSpan ToolTimeout = TimeSpan.FromSeconds(30);

    public static IReadOnlyList<UnixFileEntry> List(IProcessRunner runner, IReadOnlyList<string> paths)
    {
        ArgumentNullException.ThrowIfNull(runner);
        ArgumentNullException.ThrowIfNull(paths);

        var entries = new List<UnixFileEntry>(paths.Count);
        for (var offset = 0; offset < paths.Count; offset += ChunkSize)
        {
            var chunk = paths.Skip(offset).Take(ChunkSize).ToList();
            var arguments = new List<string> { "-f", Format };
            arguments.AddRange(chunk);
            var result = runner.Run(StatTool, arguments, ToolTimeout);
            entries.AddRange(Parse(result.StandardOutput));
        }

        return entries;
    }

    public static UnixFileEntry? Stat(IProcessRunner runner, string path)
    {
        var entries = List(runner, [path]);
        return entries.Count == 1 ? entries[0] : null;
    }

    /// <summary>Parses <c>stat -f '%u %g %p %N'</c> output; malformed lines are skipped.</summary>
    public static IReadOnlyList<UnixFileEntry> Parse(string output)
    {
        var entries = new List<UnixFileEntry>();
        foreach (var raw in (output ?? string.Empty).Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            var parts = line.Split(' ', 4, StringSplitOptions.None);
            if (parts.Length != 4 ||
                !uint.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var uid) ||
                !uint.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var gid) ||
                !TryParseOctal(parts[2], out var mode) ||
                parts[3].Length == 0)
            {
                continue;
            }

            entries.Add(new UnixFileEntry(parts[3], uid, gid, mode));
        }

        return entries;
    }

    private static bool TryParseOctal(string text, out int value)
    {
        value = 0;
        if (text.Length == 0)
        {
            return false;
        }

        foreach (var character in text)
        {
            if (character is < '0' or > '7')
            {
                return false;
            }

            value = (value << 3) | (character - '0');
        }

        return true;
    }
}
