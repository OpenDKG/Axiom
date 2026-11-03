// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Netrigil.Contracts.Monitoring;

namespace Netrigil.UI.ViewModels;

/// <summary>Aggregated view over observed sockets that share one executable identity.</summary>
public sealed record AppGroup(
    string Key,
    string Name,
    string Path,
    int SocketCount,
    int TcpCount,
    int UdpCount,
    string States,
    DateTimeOffset FirstSeenUtc);

public static class AppGrouping
{
    public static IReadOnlyList<AppGroup> Group(IEnumerable<ConnectionRow> rows)
    {
        ArgumentNullException.ThrowIfNull(rows);

        var groups = new Dictionary<string, (string Name, string Path, int Sockets, int Tcp, int Udp,
            Dictionary<string, int> States, DateTimeOffset FirstSeen)>(StringComparer.OrdinalIgnoreCase);

        foreach (var row in rows)
        {
            var source = row.Source;

            // PID 0 rows are TIME_WAIT/kernel leftovers without an owner; they stay visible in the
            // socket table but must not look like an executable in the app grouping.
            if (source.ProcessId == 0)
            {
                continue;
            }

            var key = source.AppPath.Length > 0
                ? source.AppPath
                : $"pid:{source.ProcessId}";

            var displayName = source.AppPath.Length > 0
                ? source.AppDisplayName
                : $"{source.AppDisplayName} · PID {source.ProcessId}";

            if (!groups.TryGetValue(key, out var group))
            {
                group = (
                    displayName,
                    source.AppPath,
                    Sockets: 0,
                    Tcp: 0,
                    Udp: 0,
                    States: new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase),
                    FirstSeen: source.FirstObservedUtc);
            }

            group.Sockets++;
            if (source.Protocol == TransportProtocol.Tcp)
            {
                group.Tcp++;
            }
            else
            {
                group.Udp++;
            }

            group.States.TryGetValue(source.State, out var stateCount);
            group.States[source.State] = stateCount + 1;

            if (source.FirstObservedUtc < group.FirstSeen)
            {
                group.FirstSeen = source.FirstObservedUtc;
            }

            groups[key] = group;
        }

        return groups
            .Select(pair => new AppGroup(
                pair.Key,
                pair.Value.Name,
                pair.Value.Path,
                pair.Value.Sockets,
                pair.Value.Tcp,
                pair.Value.Udp,
                FormatStates(pair.Value.States),
                pair.Value.FirstSeen))
            .OrderByDescending(group => group.SocketCount)
            .ThenBy(group => group.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static int CountUnowned(IEnumerable<ConnectionRow> rows)
    {
        ArgumentNullException.ThrowIfNull(rows);
        return rows.Count(row => row.Source.ProcessId == 0);
    }

    private static string FormatStates(Dictionary<string, int> states) =>
        string.Join(
            " · ",
            states
                .OrderByDescending(pair => pair.Value)
                .Take(3)
                .Select(pair => $"{pair.Key} {pair.Value.ToString(CultureInfo.InvariantCulture)}"));
}
