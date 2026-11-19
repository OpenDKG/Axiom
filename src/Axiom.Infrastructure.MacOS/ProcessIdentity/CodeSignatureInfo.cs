// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Infrastructure.MacOS.ProcessIdentity;

/// <summary>Code-signing facts of an executable or bundle.</summary>
public sealed record CodeSignatureInfo(string SignerName, string TeamId, string Identifier, string Status)
{
    public static CodeSignatureInfo Unavailable { get; } = new(string.Empty, string.Empty, string.Empty, "Unavailable");

    /// <summary>
    /// Parses the stderr of <c>codesign -dv --verbose=2</c>. The first <c>Authority=</c> line is the
    /// leaf signer ("Developer ID Application: Name (TEAMID)", "Apple Mac OS Application Signing",
    /// "Software Signing" for platform binaries). <paramref name="verified"/> is the result of
    /// <c>codesign --verify</c> (null when not run).
    /// </summary>
    public static CodeSignatureInfo Parse(string output, bool? verified)
    {
        ArgumentNullException.ThrowIfNull(output);

        if (output.Contains("code object is not signed at all", StringComparison.OrdinalIgnoreCase))
        {
            return new CodeSignatureInfo(string.Empty, string.Empty, string.Empty, "Unsigned");
        }

        string signer = string.Empty, team = string.Empty, identifier = string.Empty;
        var adhoc = false;
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (signer.Length == 0 && line.StartsWith("Authority=", StringComparison.Ordinal))
            {
                signer = line["Authority=".Length..].Trim();
            }
            else if (line.StartsWith("TeamIdentifier=", StringComparison.Ordinal))
            {
                var value = line["TeamIdentifier=".Length..].Trim();
                team = string.Equals(value, "not set", StringComparison.OrdinalIgnoreCase) ? string.Empty : value;
            }
            else if (line.StartsWith("Identifier=", StringComparison.Ordinal))
            {
                identifier = line["Identifier=".Length..].Trim();
            }
            else if (line.StartsWith("Signature=adhoc", StringComparison.OrdinalIgnoreCase))
            {
                adhoc = true;
            }
        }

        if (adhoc && signer.Length == 0)
        {
            signer = "Ad hoc";
        }

        var status = verified switch
        {
            false => "Invalid",
            _ when adhoc => "AdHoc",
            true => "Valid",
            null => signer.Length > 0 ? "Signed" : "Unavailable",
        };

        return new CodeSignatureInfo(signer, team, identifier, status);
    }
}
