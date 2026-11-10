// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Core.Protection;

/// <summary>
/// A stable identity for an executable across versioned install folders. Updates move
/// <c>GoogleUpdater\157.0.8089.0\updater.exe</c> to <c>158.x\updater.exe</c> and Codex uses a hash
/// folder, so a path-exact decision asked again after every update. The family key replaces version
/// and hash segments with <c>*</c> while keeping the executable name and the rest of the path.
/// </summary>
public static class ProtectionPathFamily
{
    public static string Key(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        var segments = path.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0)
        {
            return path;
        }

        for (var index = 0; index < segments.Length - 1; index++)
        {
            if (IsVersionSegment(segments[index]) ||
                IsHashSegment(segments[index]) ||
                IsPackageSegment(segments[index]))
            {
                segments[index] = "*";
            }
        }

        return string.Join('\\', segments);
    }

    private static bool IsVersionSegment(string segment)
    {
        if (segment.Length < 5 || !char.IsAsciiDigit(segment[0]))
        {
            return false;
        }

        var dots = 0;
        foreach (var character in segment)
        {
            if (character == '.')
            {
                dots++;
            }
            else if (!char.IsAsciiDigit(character))
            {
                return false;
            }
        }

        return dots >= 2;
    }

    private static bool IsHashSegment(string segment) =>
        segment.Length >= 16 && segment.All(char.IsAsciiHexDigit);

    private static bool IsPackageSegment(string segment) =>
        segment.Contains("_x64__", StringComparison.OrdinalIgnoreCase) ||
        segment.Contains("_arm64__", StringComparison.OrdinalIgnoreCase) ||
        segment.Contains("_x86__", StringComparison.OrdinalIgnoreCase);
}
