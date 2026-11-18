// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

/// <summary>Per-user permission for Axiom's manual reporting UI, independent of the Blackbox report switch.</summary>
public static class ThreatSharingConsent
{
    public const string ReporterTermsUrl =
        "https://github.com/umanitek/agent-blackbox/blob/main/plugins/blackbox/docs/REPORTER_TERMS.md";

    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Axiom",
        "manual-threat-sharing");

    public static bool HasConsent(string? path = null)
    {
        try
        {
            return string.Equals(File.ReadAllText(path ?? DefaultPath), "manual-v1", StringComparison.Ordinal);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    public static bool TrySetPermission(bool allowed, string? path = null)
    {
        var target = path ?? DefaultPath;
        var temporary = target + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            if (Path.GetDirectoryName(target) is { Length: > 0 } directory)
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(temporary, allowed ? "manual-v1" : "off");
            File.Move(temporary, target, overwrite: true);
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
        finally
        {
            try
            {
                File.Delete(temporary);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
            }
        }
    }
}
