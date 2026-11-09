// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Monitoring;

namespace Axiom.Service;

/// <summary>
/// Accumulates per-connection TCP byte counters into per-application totals across polls. A socket
/// counter is cumulative for the connection lifetime, so only the delta since the previous poll is
/// added; totals survive when a connection closes because the last measured bytes stay counted.
/// </summary>
public sealed class AppTrafficAccumulator
{
    private const int MaxApps = 512;

    private readonly object _gate = new();

    private readonly Dictionary<string, SocketCursor> _sockets = new(StringComparer.Ordinal);

    private readonly Dictionary<string, AppTotals> _apps = new(StringComparer.OrdinalIgnoreCase);

    private DateTimeOffset _lastApplyUtc;

    public ConnectionSnapshot Apply(ConnectionSnapshot snapshot, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        lock (_gate)
        {
            var elapsedSeconds = _lastApplyUtc == default
                ? 0
                : Math.Max(0.1, (now - _lastApplyUtc).TotalSeconds);
            _lastApplyUtc = now;

            foreach (var totals in _apps.Values)
            {
                totals.SentRate = 0;
                totals.ReceivedRate = 0;
            }

            var live = new HashSet<string>(StringComparer.Ordinal);

            foreach (var connection in snapshot.Connections)
            {
                if (connection.ObservedBytesSent is not long sent ||
                    connection.ObservedBytesReceived is not long received)
                {
                    continue;
                }

                var socketKey = SocketKey(connection);
                if (!live.Add(socketKey))
                {
                    continue;
                }

                var hasPrevious = _sockets.TryGetValue(socketKey, out var previous);
                var deltaSent = hasPrevious && sent >= previous.Sent ? sent - previous.Sent : sent;
                var deltaReceived = hasPrevious && received >= previous.Received
                    ? received - previous.Received
                    : received;
                _sockets[socketKey] = new SocketCursor(sent, received);

                if (deltaSent == 0 && deltaReceived == 0)
                {
                    continue;
                }

                var appKey = connection.AppPath.Length > 0
                    ? connection.AppPath
                    : $"pid:{connection.ProcessId}";
                if (!_apps.TryGetValue(appKey, out var totals))
                {
                    totals = new AppTotals(connection.AppDisplayName, connection.AppPath, now);
                }

                totals.Sent += deltaSent;
                totals.Received += deltaReceived;
                if (elapsedSeconds > 0)
                {
                    totals.SentRate += deltaSent / elapsedSeconds;
                    totals.ReceivedRate += deltaReceived / elapsedSeconds;
                }

                totals.UpdatedUtc = now;
                _apps[appKey] = totals;
            }

            foreach (var key in _sockets.Keys.Where(key => !live.Contains(key)).ToList())
            {
                _sockets.Remove(key);
            }

            if (_apps.Count > MaxApps)
            {
                foreach (var key in _apps
                             .OrderBy(pair => pair.Value.UpdatedUtc)
                             .Take(_apps.Count - MaxApps)
                             .Select(pair => pair.Key)
                             .ToList())
                {
                    _apps.Remove(key);
                }
            }

            var traffic = _apps
                .Select(pair => new AppTrafficTotals(
                    pair.Key,
                    pair.Value.AppName,
                    pair.Value.AppPath,
                    pair.Value.Sent,
                    pair.Value.Received,
                    pair.Value.SinceUtc,
                    pair.Value.UpdatedUtc)
                {
                    SentBytesPerSecond = pair.Value.SentRate,
                    ReceivedBytesPerSecond = pair.Value.ReceivedRate,
                })
                .OrderByDescending(item => item.TotalBytes)
                .ThenBy(item => item.AppName, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            return snapshot with { AppTraffic = traffic };
        }
    }

    private static string SocketKey(LiveConnection connection) =>
        $"{connection.Protocol}|{connection.LocalEndpoint}|{connection.RemoteEndpoint}|{connection.ProcessId}";

    private readonly record struct SocketCursor(long Sent, long Received);

    private sealed class AppTotals(string appName, string appPath, DateTimeOffset sinceUtc)
    {
        public string AppName { get; } = appName;

        public string AppPath { get; } = appPath;

        public DateTimeOffset SinceUtc { get; } = sinceUtc;

        public DateTimeOffset UpdatedUtc { get; set; } = sinceUtc;

        public long Sent { get; set; }

        public long Received { get; set; }

        public double SentRate { get; set; }

        public double ReceivedRate { get; set; }
    }
}
