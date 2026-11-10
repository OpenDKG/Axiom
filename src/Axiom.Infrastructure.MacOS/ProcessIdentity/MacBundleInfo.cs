// SPDX-License-Identifier: GPL-3.0-or-later
using System.Xml;
using System.Xml.Linq;

namespace Axiom.Infrastructure.MacOS.ProcessIdentity;

/// <summary>Bundle facts from <c>Contents/Info.plist</c>.</summary>
public sealed record MacBundleInfo(string BundlePath, string BundleId, string Name, string Version)
{
    /// <summary>
    /// The outermost <c>.app</c> bundle containing <paramref name="executablePath"/>, so helpers
    /// inside <c>Foo.app/Contents/Frameworks/Bar.app</c> are attributed to <c>Foo.app</c>.
    /// </summary>
    public static string? FindEnclosingBundle(string? executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath) || !executablePath.StartsWith('/'))
        {
            return null;
        }

        var segments = executablePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        for (var index = 0; index < segments.Length - 1; index++)
        {
            if (segments[index].EndsWith(".app", StringComparison.OrdinalIgnoreCase))
            {
                return "/" + string.Join('/', segments.Take(index + 1));
            }
        }

        return null;
    }

    /// <summary>Parses an XML property list's top-level string keys (binary plists return null).</summary>
    public static IReadOnlyDictionary<string, string>? ParseXmlPlist(string text)
    {
        if (string.IsNullOrWhiteSpace(text) || !text.TrimStart().StartsWith('<'))
        {
            return null;
        }

        try
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Ignore,
                XmlResolver = null,
                MaxCharactersInDocument = 4 * 1024 * 1024,
            };
            using var reader = XmlReader.Create(new StringReader(text), settings);
            var document = XDocument.Load(reader);
            var dict = document.Root?.Element("dict");
            if (dict is null)
            {
                return null;
            }

            var result = new Dictionary<string, string>(StringComparer.Ordinal);
            string? key = null;
            foreach (var element in dict.Elements())
            {
                if (element.Name.LocalName == "key")
                {
                    key = element.Value;
                    continue;
                }

                if (key is not null && element.Name.LocalName == "string")
                {
                    result[key] = element.Value;
                }

                key = null;
            }

            return result;
        }
        catch (XmlException)
        {
            return null;
        }
    }

    public static MacBundleInfo FromPlist(string bundlePath, IReadOnlyDictionary<string, string> plist)
    {
        ArgumentNullException.ThrowIfNull(plist);

        string Value(string key) => plist.TryGetValue(key, out var value) ? value.Trim() : string.Empty;

        var name = Value("CFBundleDisplayName");
        if (name.Length == 0)
        {
            name = Value("CFBundleName");
        }

        if (name.Length == 0)
        {
            name = Path.GetFileNameWithoutExtension(bundlePath);
        }

        var version = Value("CFBundleShortVersionString");
        if (version.Length == 0)
        {
            version = Value("CFBundleVersion");
        }

        return new MacBundleInfo(bundlePath, Value("CFBundleIdentifier"), name, version);
    }
}
