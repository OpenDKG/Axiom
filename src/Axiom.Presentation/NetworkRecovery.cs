// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text;

namespace Axiom.Presentation;

/// <summary>DNS configuration of one adapter before Axiom changed it.</summary>
public sealed record NetworkAdapterDns(
    string AdapterId,
    string Description,
    bool UsesDhcp,
    IReadOnlyList<string> Servers);

/// <summary>
/// Last known-good network state captured before Axiom applies a DNS or firewall change. Restoring
/// the snapshot is the supported fallback when a user loses connectivity; it contains no secrets,
/// only adapter identifiers, DNS server addresses and Axiom-owned rule identifiers.
/// </summary>
public sealed record NetworkRecoverySnapshot(
    DateTimeOffset CapturedUtc,
    IReadOnlyList<NetworkAdapterDns> Adapters,
    IReadOnlyList<string> AxiomRuleIds,
    bool ProtectionWasActive)
{
    public static NetworkRecoverySnapshot Empty { get; } =
        new(DateTimeOffset.MinValue, [], [], false);

    public bool IsEmpty => Adapters.Count == 0 && AxiomRuleIds.Count == 0;
}

/// <summary>
/// Persists the snapshot as a small line-based file. The format is deliberately plain text so a
/// recovery tool can read it even when the UI or service cannot start, and so no serializer
/// features are required in a trimmed build.
/// </summary>
public static class NetworkRecoveryStore
{
    private const string Header = "axiom-network-recovery=1";

    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Axiom",
        "network-recovery.txt");

    public static NetworkRecoverySnapshot Load() => LoadFrom(DefaultPath);

    public static NetworkRecoverySnapshot LoadFrom(string path)
    {
        ArgumentNullException.ThrowIfNull(path);

        try
        {
            return !File.Exists(path) ? NetworkRecoverySnapshot.Empty : Parse(File.ReadAllText(path));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return NetworkRecoverySnapshot.Empty;
        }
    }

    public static void Save(NetworkRecoverySnapshot snapshot) => SaveTo(DefaultPath, snapshot);

    public static void SaveTo(string path, NetworkRecoverySnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(snapshot);

        try
        {
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(path, Serialize(snapshot));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Recovery data is best-effort; a read-only profile must not block protection changes.
        }
    }

    /// <summary>Stable text form; adapters and rules never contain a newline.</summary>
    public static string Serialize(NetworkRecoverySnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        var text = new StringBuilder();
        text.Append(Header).Append('\n');
        text.Append("captured=").Append(snapshot.CapturedUtc.ToString("O")).Append('\n');
        text.Append("active=").Append(snapshot.ProtectionWasActive ? "1" : "0").Append('\n');

        foreach (var adapter in snapshot.Adapters)
        {
            text.Append("adapter|")
                .Append(Clean(adapter.AdapterId)).Append('|')
                .Append(Clean(adapter.Description)).Append('|')
                .Append(adapter.UsesDhcp ? "1" : "0").Append('|')
                .Append(Clean(string.Join(';', adapter.Servers)))
                .Append('\n');
        }

        foreach (var rule in snapshot.AxiomRuleIds)
        {
            text.Append("rule|").Append(Clean(rule)).Append('\n');
        }

        return text.ToString();
    }

    /// <summary>Parses a stored snapshot; malformed lines are ignored, never guessed.</summary>
    public static NetworkRecoverySnapshot Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var lines = text.Replace("\r", string.Empty).Split('\n', StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length == 0 || !string.Equals(lines[0].Trim(), Header, StringComparison.Ordinal))
        {
            return NetworkRecoverySnapshot.Empty;
        }

        var captured = DateTimeOffset.MinValue;
        var active = false;
        var adapters = new List<NetworkAdapterDns>();
        var rules = new List<string>();

        for (var index = 1; index < lines.Length; index++)
        {
            var line = lines[index].Trim();
            if (line.StartsWith("captured=", StringComparison.Ordinal))
            {
                if (DateTimeOffset.TryParse(
                        line[9..],
                        System.Globalization.CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.RoundtripKind,
                        out var parsed))
                {
                    captured = parsed;
                }
            }
            else if (line.StartsWith("active=", StringComparison.Ordinal))
            {
                active = line[7..] == "1";
            }
            else if (line.StartsWith("adapter|", StringComparison.Ordinal))
            {
                var parts = line.Split('|');
                if (parts.Length == 5)
                {
                    adapters.Add(new NetworkAdapterDns(
                        parts[1],
                        parts[2],
                        parts[3] == "1",
                        parts[4].Split(';', StringSplitOptions.RemoveEmptyEntries)));
                }
            }
            else if (line.StartsWith("rule|", StringComparison.Ordinal) && line.Length > 5)
            {
                rules.Add(line[5..]);
            }
        }

        return new NetworkRecoverySnapshot(captured, adapters, rules, active);
    }

    private static string Clean(string value) =>
        value.Replace('|', '/').Replace('\n', ' ').Replace('\r', ' ');
}
