// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

public sealed class SourceEncodingRegressionTests
{
    private static readonly string[] ForbiddenMojibake =
    [
        "\u00e2\u20ac", // â€ (UTF-8 punctuation decoded as cp1252)
        "\u00c3\u00a2", // Ã¢ (double-encoded cp1252)
        "\u00c2\u00b7", // Â· (UTF-8 middle dot decoded as cp1252/latin-1)
        "\u0393\u00c7", // ΓÇ (UTF-8 decoded as cp437)
        "\uFFFD",       // replacement character
        "\u009d",       // stray C1 control byte left by cp1252 roundtrip
    ];

    [Fact]
    public void Source_files_under_src_contain_no_mojibake_sequences()
    {
        var srcRoot = Path.Combine(FindRepoRoot(), "src");
        var extensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".cs", ".axaml", ".xaml" };
        var hits = new List<string>();

        foreach (var path in Directory.EnumerateFiles(srcRoot, "*", SearchOption.AllDirectories))
        {
            if (!extensions.Contains(Path.GetExtension(path)))
            {
                continue;
            }

            var lines = File.ReadAllLines(path, Encoding.UTF8);
            for (var index = 0; index < lines.Length; index++)
            {
                foreach (var marker in ForbiddenMojibake)
                {
                    if (lines[index].Contains(marker, StringComparison.Ordinal))
                    {
                        var relative = Path.GetRelativePath(srcRoot, path);
                        hits.Add($"{relative}:{index + 1}");
                        break;
                    }
                }
            }
        }

        Assert.Empty(hits);
    }

    private static string FindRepoRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "Axiom.sln")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate Axiom.sln above test directory.");
    }
}
