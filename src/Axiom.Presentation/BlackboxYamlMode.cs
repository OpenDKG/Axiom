// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

/// <summary>
/// Minimal, line-preserving editor for Blackbox's Hermes YAML mode. It changes only the scalar on
/// the existing plugins.entries.blackbox.mode line, so unrelated keys, comments, ordering and
/// indentation remain byte-identical.
/// </summary>
public static class BlackboxYamlMode
{
    public static string ReadMode(string yaml)
    {
        var lines = yaml.Split('\n');
        var index = FindModeLine(lines);
        return index < 0 ? "audit" : ExtractValue(lines[index]);
    }

    public static string? SetMode(string yaml, string mode)
    {
        if (mode is not ("audit" or "block"))
        {
            return null;
        }

        var lines = yaml.Split('\n');
        var index = FindModeLine(lines);
        if (index < 0)
        {
            return null;
        }

        var hadCarriageReturn = lines[index].EndsWith('\r');
        var line = lines[index].TrimEnd('\r');
        var colon = line.IndexOf(':');
        var afterColon = line[(colon + 1)..];
        var commentIndex = afterColon.IndexOf('#');
        var valuePart = commentIndex >= 0 ? afterColon[..commentIndex] : afterColon;
        var comment = commentIndex >= 0 ? afterColon[commentIndex..] : string.Empty;
        var leading = valuePart[..(valuePart.Length - valuePart.TrimStart().Length)];
        var trailing = valuePart[valuePart.TrimEnd().Length..];
        lines[index] = line[..(colon + 1)] + leading + mode + trailing + comment +
                       (hadCarriageReturn ? "\r" : string.Empty);
        return string.Join('\n', lines);
    }

    private static int FindModeLine(string[] lines)
    {
        var plugins = FindKey(lines, 0, -1, "plugins");
        if (plugins < 0)
        {
            return -1;
        }

        var entries = FindKey(lines, plugins + 1, Indent(lines[plugins]), "entries");
        if (entries < 0)
        {
            return -1;
        }

        var blackbox = FindKey(lines, entries + 1, Indent(lines[entries]), "blackbox");
        if (blackbox < 0)
        {
            return -1;
        }

        return FindKey(lines, blackbox + 1, Indent(lines[blackbox]), "mode");
    }

    private static int FindKey(string[] lines, int start, int parentIndent, string key)
    {
        for (var index = start; index < lines.Length; index++)
        {
            var line = lines[index].TrimEnd('\r');
            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed.StartsWith('#'))
            {
                continue;
            }

            var indent = Indent(line);
            if (indent <= parentIndent)
            {
                return -1;
            }

            if (trimmed.StartsWith(key + ":", StringComparison.Ordinal))
            {
                return index;
            }
        }

        return -1;
    }

    private static string ExtractValue(string line)
    {
        var colon = line.IndexOf(':');
        if (colon < 0)
        {
            return "audit";
        }

        var value = line[(colon + 1)..];
        var commentIndex = value.IndexOf('#');
        if (commentIndex >= 0)
        {
            value = value[..commentIndex];
        }

        return value.Trim().Trim('"', '\'');
    }

    private static int Indent(string line) =>
        line.TakeWhile(character => character == ' ').Count();
}
