// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Axiom.Contracts.Firewall;

namespace Axiom.Contracts.NetworkRecovery;

/// <summary>
/// Plain-text store for the machine recovery snapshot. The format stays readable without the app,
/// but it is not accepted on trust: the file has a strict header, a SHA-256 checksum and a parser
/// that rejects unknown, duplicate or out-of-range entries. Restore therefore never guesses from a
/// truncated or hand-corrupted file.
/// </summary>
public static class NetworkRecoverySnapshotStore
{
    public const string FileName = "network-recovery.txt";

    private const string Header = "axiom-network-recovery=2";

    private const int MaxFileBytes = 64 * 1024;

    private const int MaxAdapters = 64;

    private const int MaxServersPerFamily = 16;

    private const int MaxRules = 512;

    private const int MaxTextLength = 256;

    private const int MaxGroupLength = 128;

    /// <summary>Machine-wide location written by the elevated service and the recovery command.</summary>
    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Axiom",
        FileName);

    public static NetworkRecoverySnapshotRead Read(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        try
        {
            if (!File.Exists(path))
            {
                return NetworkRecoverySnapshotRead.Missing;
            }

            if (new FileInfo(path).Length > MaxFileBytes)
            {
                return NetworkRecoverySnapshotRead.Corrupt(
                    $"The recovery snapshot is larger than {MaxFileBytes} bytes.");
            }

            return Parse(File.ReadAllText(path, Encoding.UTF8));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return NetworkRecoverySnapshotRead.Unreadable(
                $"The recovery snapshot could not be read: {exception.Message}");
        }
    }

    /// <summary>Validates and atomically replaces the snapshot. Nothing is written on invalid input.</summary>
    public static bool TryWrite(string path, NetworkRecoverySnapshot snapshot, out string? error)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(snapshot);

        if (!TryValidate(snapshot, out error))
        {
            return false;
        }

        string? temporary = null;
        try
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath(path));
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            File.WriteAllText(temporary, Serialize(snapshot), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            if (!OperatingSystem.IsWindows())
            {
                // Machine-wide state written by the root daemon: not readable by other local users.
                File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            File.Move(temporary, path, overwrite: true);
            temporary = null;
            return true;
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or NotSupportedException)
        {
            error = $"The recovery snapshot could not be written: {exception.Message}";
            return false;
        }
        finally
        {
            if (temporary is not null)
            {
                try
                {
                    File.Delete(temporary);
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    // A leftover temporary file is harmless; the next write uses a new name.
                }
            }
        }
    }

    public static string Serialize(NetworkRecoverySnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        var body = new StringBuilder();
        body.Append(Header).Append('\n');
        body.Append("captured=")
            .Append(snapshot.CapturedUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture))
            .Append('\n');
        body.Append("protection=").Append(snapshot.ProtectionWasActive ? "active" : "inactive").Append('\n');

        foreach (var adapter in snapshot.Adapters)
        {
            body.Append("adapter|")
                .Append(adapter.AdapterId.ToString("D")).Append('|')
                .Append(CleanText(adapter.InterfaceAlias, "adapter")).Append('|')
                .Append(CleanText(adapter.Description, string.Empty)).Append('|')
                .Append(ModeToken(adapter.Ipv4Mode)).Append('|')
                .Append(string.Join(';', adapter.Ipv4Servers.Select(NormalizeServer))).Append('|')
                .Append(ModeToken(adapter.Ipv6Mode)).Append('|')
                .Append(string.Join(';', adapter.Ipv6Servers.Select(NormalizeServer)))
                .Append('\n');
        }

        foreach (var rule in snapshot.Rules)
        {
            body.Append("rule|")
                .Append(rule.ManagedRuleId.ToString("D")).Append('|')
                .Append(DirectionToken(rule.Direction)).Append('|')
                .Append(CleanText(rule.OwnershipGroup, "Axiom"))
                .Append('\n');
        }

        var text = body.ToString();
        return string.Concat(text, "checksum=", ComputeChecksum(text), "\n");
    }

    public static NetworkRecoverySnapshotRead Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        if (Encoding.UTF8.GetByteCount(text) > MaxFileBytes)
        {
            return NetworkRecoverySnapshotRead.Corrupt(
                $"The recovery snapshot is larger than {MaxFileBytes} bytes.");
        }

        var normalized = text.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');
        var lines = normalized.Split('\n').ToList();
        if (lines.Count > 0 && lines[^1].Length == 0)
        {
            lines.RemoveAt(lines.Count - 1);
        }

        if (lines.Count < 4)
        {
            return NetworkRecoverySnapshotRead.Corrupt("The recovery snapshot is incomplete.");
        }

        if (lines.Any(line => line.Length == 0))
        {
            return NetworkRecoverySnapshotRead.Corrupt("The recovery snapshot contains a blank line.");
        }

        var checksumLine = lines[^1];
        if (!checksumLine.StartsWith("checksum=", StringComparison.Ordinal))
        {
            return NetworkRecoverySnapshotRead.Corrupt("The recovery snapshot has no checksum.");
        }

        var bodyLines = lines.Take(lines.Count - 1).ToList();
        var body = string.Join('\n', bodyLines) + "\n";
        if (!string.Equals(checksumLine[9..], ComputeChecksum(body), StringComparison.Ordinal))
        {
            return NetworkRecoverySnapshotRead.Corrupt(
                "The recovery snapshot checksum does not match; the file was changed or damaged.");
        }

        if (!string.Equals(bodyLines[0], Header, StringComparison.Ordinal))
        {
            return NetworkRecoverySnapshotRead.Corrupt("The recovery snapshot header is not supported.");
        }

        DateTimeOffset captured = default;
        bool? protection = null;
        var capturedSeen = false;
        var protectionSeen = false;
        var adapters = new List<NetworkAdapterDnsState>();
        var rules = new List<NetworkOwnedRuleState>();
        var adapterIds = new HashSet<Guid>();
        var ruleIds = new HashSet<(Guid Id, FirewallDirection Direction)>();

        for (var index = 1; index < bodyLines.Count; index++)
        {
            var line = bodyLines[index];

            if (line.StartsWith("captured=", StringComparison.Ordinal))
            {
                if (capturedSeen ||
                    !DateTimeOffset.TryParse(
                        line[9..],
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.RoundtripKind,
                        out captured))
                {
                    return NetworkRecoverySnapshotRead.Corrupt("The capture time is invalid.");
                }

                capturedSeen = true;
                continue;
            }

            if (line.StartsWith("protection=", StringComparison.Ordinal))
            {
                if (protectionSeen)
                {
                    return NetworkRecoverySnapshotRead.Corrupt("The protection flag is duplicated.");
                }

                protection = line[11..] switch
                {
                    "active" => true,
                    "inactive" => false,
                    _ => null,
                };
                if (protection is null)
                {
                    return NetworkRecoverySnapshotRead.Corrupt("The protection flag is invalid.");
                }

                protectionSeen = true;
                continue;
            }

            if (line.StartsWith("adapter|", StringComparison.Ordinal))
            {
                if (adapters.Count >= MaxAdapters)
                {
                    return NetworkRecoverySnapshotRead.Corrupt("The recovery snapshot has too many adapters.");
                }

                var parts = line.Split('|');
                if (parts.Length != 8 ||
                    !Guid.TryParseExact(parts[1], "D", out var adapterId) ||
                    adapterId == Guid.Empty ||
                    !adapterIds.Add(adapterId) ||
                    !TryReadText(parts[2], allowEmpty: false, out var alias) ||
                    !TryReadText(parts[3], allowEmpty: true, out var description) ||
                    !TryReadMode(parts[4], out var ipv4Mode) ||
                    !TryReadMode(parts[6], out var ipv6Mode) ||
                    !TryReadServers(parts[5], AddressFamily.InterNetwork, ipv4Mode, out var ipv4Servers) ||
                    !TryReadServers(parts[7], AddressFamily.InterNetworkV6, ipv6Mode, out var ipv6Servers))
                {
                    return NetworkRecoverySnapshotRead.Corrupt(
                        $"The adapter entry on line {index + 1} is invalid.");
                }

                adapters.Add(new NetworkAdapterDnsState
                {
                    AdapterId = adapterId,
                    InterfaceAlias = alias,
                    Description = description,
                    Ipv4Mode = ipv4Mode,
                    Ipv6Mode = ipv6Mode,
                    Ipv4Servers = ipv4Servers,
                    Ipv6Servers = ipv6Servers,
                });
                continue;
            }

            if (line.StartsWith("rule|", StringComparison.Ordinal))
            {
                if (rules.Count >= MaxRules)
                {
                    return NetworkRecoverySnapshotRead.Corrupt("The recovery snapshot has too many rules.");
                }

                var parts = line.Split('|');
                if (parts.Length != 4 ||
                    !Guid.TryParseExact(parts[1], "D", out var ruleId) ||
                    ruleId == Guid.Empty ||
                    !TryReadDirection(parts[2], out var direction) ||
                    !TryReadGroup(parts[3], out var group) ||
                    !ruleIds.Add((ruleId, direction)))
                {
                    return NetworkRecoverySnapshotRead.Corrupt(
                        $"The rule entry on line {index + 1} is invalid.");
                }

                rules.Add(new NetworkOwnedRuleState
                {
                    ManagedRuleId = ruleId,
                    Direction = direction,
                    OwnershipGroup = group,
                });
                continue;
            }

            return NetworkRecoverySnapshotRead.Corrupt(
                $"The recovery snapshot contains an unknown entry on line {index + 1}.");
        }

        if (!capturedSeen || protection is null || captured == default)
        {
            return NetworkRecoverySnapshotRead.Corrupt(
                "The recovery snapshot is missing its capture time or protection flag.");
        }

        var snapshot = new NetworkRecoverySnapshot
        {
            CapturedUtc = captured,
            ProtectionWasActive = protection.Value,
            Adapters = adapters,
            Rules = rules,
        };

        return TryValidate(snapshot, out var error)
            ? NetworkRecoverySnapshotRead.Valid(snapshot)
            : NetworkRecoverySnapshotRead.Corrupt(error ?? "The recovery snapshot is invalid.");
    }

    /// <summary>Validation shared by the writer and the parser; no filesystem access.</summary>
    public static bool TryValidate(NetworkRecoverySnapshot snapshot, out string? error)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        if (snapshot.FormatVersion != NetworkRecoverySnapshot.CurrentFormatVersion)
        {
            error = $"Unsupported recovery snapshot format {snapshot.FormatVersion}.";
            return false;
        }

        if (snapshot.CapturedUtc == default)
        {
            error = "The recovery snapshot has no capture time.";
            return false;
        }

        if (snapshot.Adapters.Count > MaxAdapters)
        {
            error = $"The recovery snapshot has more than {MaxAdapters} adapters.";
            return false;
        }

        if (snapshot.Rules.Count > MaxRules)
        {
            error = $"The recovery snapshot has more than {MaxRules} rules.";
            return false;
        }

        var adapterIds = new HashSet<Guid>();
        foreach (var adapter in snapshot.Adapters)
        {
            if (adapter.AdapterId == Guid.Empty || !adapterIds.Add(adapter.AdapterId))
            {
                error = "A recovery adapter entry has an empty or duplicate identifier.";
                return false;
            }

            if (string.IsNullOrWhiteSpace(adapter.InterfaceAlias) ||
                !IsValidText(adapter.InterfaceAlias) ||
                !IsValidText(adapter.Description))
            {
                error = "A recovery adapter entry has an invalid alias or description.";
                return false;
            }

            if (!Enum.IsDefined(adapter.Ipv4Mode) || !Enum.IsDefined(adapter.Ipv6Mode) ||
                !IsValidServers(adapter.Ipv4Servers, AddressFamily.InterNetwork, adapter.Ipv4Mode) ||
                !IsValidServers(adapter.Ipv6Servers, AddressFamily.InterNetworkV6, adapter.Ipv6Mode))
            {
                error = $"The DNS state for adapter '{adapter.InterfaceAlias}' is invalid.";
                return false;
            }
        }

        var ruleIds = new HashSet<(Guid Id, FirewallDirection Direction)>();
        foreach (var rule in snapshot.Rules)
        {
            if (rule.ManagedRuleId == Guid.Empty ||
                !Enum.IsDefined(rule.Direction) ||
                !ruleIds.Add((rule.ManagedRuleId, rule.Direction)))
            {
                error = "A recovery rule entry has an empty, duplicate or invalid identity.";
                return false;
            }

            if (!TryReadGroup(rule.OwnershipGroup, out _))
            {
                error = "A recovery rule entry has an invalid ownership group.";
                return false;
            }
        }

        error = null;
        return true;
    }

    private static bool TryReadServers(
        string value,
        AddressFamily family,
        NetworkDnsMode mode,
        out IReadOnlyList<string> servers)
    {
        servers = [];
        var parts = value.Length == 0
            ? new List<string>()
            : value.Split(';', StringSplitOptions.RemoveEmptyEntries).ToList();

        if (mode == NetworkDnsMode.Automatic && parts.Count != 0)
        {
            return false;
        }

        if (mode == NetworkDnsMode.Static && parts.Count == 0)
        {
            return false;
        }

        if (parts.Count > MaxServersPerFamily)
        {
            return false;
        }

        var parsed = new List<string>(parts.Count);
        foreach (var part in parts)
        {
            if (!IPAddress.TryParse(part, out var address) ||
                address.AddressFamily != family ||
                parsed.Contains(address.ToString(), StringComparer.OrdinalIgnoreCase))
            {
                return false;
            }

            parsed.Add(address.ToString());
        }

        servers = parsed;
        return true;
    }

    private static bool IsValidServers(
        IReadOnlyList<string> servers,
        AddressFamily family,
        NetworkDnsMode mode)
    {
        var parsed = TryReadServers(string.Join(';', servers.Select(NormalizeServer)), family, mode, out var read);
        return parsed && read.Count == servers.Count;
    }

    private static bool TryReadText(string value, bool allowEmpty, out string text)
    {
        text = value.Trim();
        if (text.Length == 0)
        {
            return allowEmpty;
        }

        return IsValidText(text);
    }

    private static bool IsValidText(string value) =>
        value.Length <= MaxTextLength &&
        !value.Contains('|') &&
        !value.Any(char.IsControl);

    private static bool TryReadGroup(string value, out string group)
    {
        group = value.Trim();
        return group.Length is > 0 and <= MaxGroupLength &&
               !group.Contains('|') &&
               !group.Any(char.IsControl);
    }

    private static bool TryReadMode(string value, out NetworkDnsMode mode)
    {
        switch (value)
        {
            case "auto":
                mode = NetworkDnsMode.Automatic;
                return true;
            case "static":
                mode = NetworkDnsMode.Static;
                return true;
            default:
                mode = default;
                return false;
        }
    }

    private static bool TryReadDirection(string value, out FirewallDirection direction)
    {
        switch (value)
        {
            case "OUT":
                direction = FirewallDirection.Outbound;
                return true;
            case "IN":
                direction = FirewallDirection.Inbound;
                return true;
            default:
                direction = default;
                return false;
        }
    }

    private static string ModeToken(NetworkDnsMode mode) => mode switch
    {
        NetworkDnsMode.Automatic => "auto",
        NetworkDnsMode.Static => "static",
        _ => throw new ArgumentOutOfRangeException(nameof(mode), mode, "Undefined DNS mode."),
    };

    private static string DirectionToken(FirewallDirection direction) => direction switch
    {
        FirewallDirection.Outbound => "OUT",
        FirewallDirection.Inbound => "IN",
        _ => throw new ArgumentOutOfRangeException(nameof(direction), direction, "Undefined direction."),
    };

    private static string NormalizeServer(string server)
    {
        if (string.IsNullOrWhiteSpace(server))
        {
            return string.Empty;
        }

        return IPAddress.TryParse(server.Trim(), out var address) ? address.ToString() : server.Trim();
    }

    private static string CleanText(string value, string fallback)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return fallback;
        }

        var cleaned = new StringBuilder(value.Length);
        foreach (var character in value.Trim())
        {
            cleaned.Append(character switch
            {
                '|' => '/',
                '\r' or '\n' => ' ',
                _ when char.IsControl(character) => ' ',
                _ => character,
            });
        }

        return cleaned.Length > MaxTextLength ? cleaned.ToString(0, MaxTextLength) : cleaned.ToString();
    }

    private static string ComputeChecksum(string body) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(body))).ToLowerInvariant();
}
