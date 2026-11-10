// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;

namespace Axiom.Infrastructure.Windows.Dns;

/// <summary>
/// Reads the adapter DNS snapshot the Privacy Shield helper saves before it changes an adapter.
/// The snapshot is the source of the fallback servers, so reading it back must be forgiving: a
/// missing, unreadable or malformed file simply yields no fallback instead of failing the change.
/// </summary>
public static class DnsAdapterSnapshot
{
    public static bool TryReadServerAddresses(
        string? backupPath,
        string interfaceAlias,
        out IReadOnlyList<string> addresses)
    {
        addresses = [];

        if (string.IsNullOrWhiteSpace(backupPath) ||
            string.IsNullOrWhiteSpace(interfaceAlias) ||
            !File.Exists(backupPath))
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(backupPath));
            if (!document.RootElement.TryGetProperty("interfaces", out var interfaces) ||
                interfaces.ValueKind != JsonValueKind.Array)
            {
                return false;
            }

            foreach (var entry in interfaces.EnumerateArray())
            {
                if (!entry.TryGetProperty("interfaceAlias", out var alias) ||
                    !string.Equals(alias.GetString(), interfaceAlias, StringComparison.OrdinalIgnoreCase) ||
                    !entry.TryGetProperty("serverAddresses", out var servers) ||
                    servers.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                addresses = servers
                    .EnumerateArray()
                    .Where(server => server.ValueKind == JsonValueKind.String)
                    .Select(server => server.GetString())
                    .Where(server => !string.IsNullOrWhiteSpace(server))
                    .Select(server => server!)
                    .ToArray();
                return true;
            }

            return false;
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            return false;
        }
    }
}
