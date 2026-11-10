// SPDX-License-Identifier: GPL-3.0-or-later
using System.Reflection;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Legal documents bundled into the assembly. Embedded copies keep the license, the notice and the
/// third-party list readable in an offline or single-file installation, without a browser and
/// without depending on a path next to the executable.
/// </summary>
public static class AxiomDocuments
{
    public const string SourceUrl = "https://github.com/a-51-50/Axiom";

    public const string CopyrightNotice = "Copyright (C) 2026 The Axiom contributors";

    /// <summary>
    /// Collectively held copyright, as recorded in NOTICE and the build properties. Naming the
    /// creator does not assign copyright; that needs the owner's explicit wording.
    /// </summary>
    public const string CopyrightLine = "\u00A9 2026 The Axiom contributors";

    public const string LicenseName = "GNU General Public License v3.0 or later (GPL-3.0-or-later)";

    /// <summary>Confirmed by the repository owner; the public GitHub account is used, not a legal name.</summary>
    public const string CreatorLabel = "a-51-50";

    public const string ContributorsLine = "dreddster, brxtrac";

    public const string AffiliationLabel = "OpenDKG Initiative";

    /// <summary>Approved affiliation wording. It states no ownership, copyright or publishing claim.</summary>
    public const string AffiliationText =
        "Axiom is an independent open-source project affiliated with the OpenDKG initiative.";

    private static readonly Lazy<string> LicenseDocument = new(() => Read("Axiom.Documents.LICENSE.txt"));

    private static readonly Lazy<string> NoticeDocument = new(() => Read("Axiom.Documents.NOTICE.txt"));

    private static readonly Lazy<string> ThirdPartyDocument =
        new(() => Read("Axiom.Documents.THIRD_PARTY_NOTICES.md"));

    private static readonly Lazy<string> AuthorsDocument = new(() => Read("Axiom.Documents.AUTHORS.md"));

    public static string License => LicenseDocument.Value;

    public static string Notice => NoticeDocument.Value;

    public static string ThirdPartyNotices => ThirdPartyDocument.Value;

    public static string Authors => AuthorsDocument.Value;

    /// <summary>The notice followed by the full GPL text, which is what "View license" shows.</summary>
    public static string LicenseBundle => Notice + "\n\n" + License;

    private static string Read(string resourceName)
    {
        var assembly = typeof(AxiomDocuments).Assembly;
        using var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream is null)
        {
            return $"The bundled document '{resourceName}' is missing from this build. " +
                   $"The license and notices are published with every release at {SourceUrl}.";
        }

        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
