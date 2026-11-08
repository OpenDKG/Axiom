// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ai;
using Axiom.Contracts.History;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;

namespace Axiom.Presentation;

/// <summary>
/// Aggregated local flow history used as a baseline for the AI evidence package. It is derived from
/// the service's SQLite history and never contains packet payloads or byte counts.
/// </summary>
public sealed record AiEvidenceBaseline(
    int WindowDays,
    int RowsConsidered,
    int TotalCount,
    bool Truncated,
    string Note,
    IReadOnlyDictionary<string, AiEvidenceBaselineFlow> Flows,
    IReadOnlyDictionary<string, AiEvidenceBaselineApp> Apps);

public sealed record AiEvidenceBaselineFlow(
    int Rows,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc);

public sealed record AiEvidenceBaselineApp(
    int Rows,
    IReadOnlyList<string> TypicalRemotes);

public static class AiEvidenceBaselineCollector
{
    public const int WindowDays = 30;
    private const int MaxRows = 5000;

    public static async Task<AiEvidenceBaseline?> TryLoadAsync(
        IServiceRequestClient? client,
        IReadOnlyList<LiveConnection> connections,
        CancellationToken cancellationToken)
    {
        if (client is null || connections.Count == 0)
        {
            return null;
        }

        try
        {
            var now = DateTimeOffset.UtcNow;
            var query = new HistoryQuery
            {
                FromUtc = now.AddDays(-WindowDays),
                ToUtc = now,
                Limit = 1,
                IncludeBaseline = true,
            };
            var page = await client
                .SendAsync<HistoryPage>(
                    IpcCommandTypes.HistoryQuery,
                    query,
                    cancellationToken)
                .ConfigureAwait(false);

            if (page.Baseline is { } baseline)
            {
                return FromAggregate(baseline);
            }

            // Older services ignore IncludeBaseline; fall back to a bounded row query.
            var rowsPage = await client
                .SendAsync<HistoryPage>(
                    IpcCommandTypes.HistoryQuery,
                    new HistoryQuery
                    {
                        FromUtc = now.AddDays(-WindowDays),
                        ToUtc = now,
                        Limit = MaxRows,
                    },
                    cancellationToken)
                .ConfigureAwait(false);
            return Build(rowsPage);
        }
#pragma warning disable CA1031 // Baseline history is optional; an unavailable service must not block analysis.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            return new AiEvidenceBaseline(
                WindowDays,
                0,
                0,
                false,
                "Local flow history was unavailable for this analysis: " + exception.Message,
                new Dictionary<string, AiEvidenceBaselineFlow>(StringComparer.OrdinalIgnoreCase),
                new Dictionary<string, AiEvidenceBaselineApp>(StringComparer.OrdinalIgnoreCase));
        }
    }

    private static AiEvidenceBaseline FromAggregate(HistoryBaseline baseline)
    {
        var flows = baseline.Flows.ToDictionary(
            flow => FlowKey(flow.AppKey, flow.Protocol, flow.RemoteEndpoint, flow.Direction),
            flow => new AiEvidenceBaselineFlow(
                flow.FlowRows,
                flow.FirstSeenUtc,
                flow.LastSeenUtc),
            StringComparer.OrdinalIgnoreCase);
        var apps = baseline.Apps.ToDictionary(
            app => app.AppKey,
            app => new AiEvidenceBaselineApp(app.FlowRows, app.TypicalRemotes),
            StringComparer.OrdinalIgnoreCase);

        return new AiEvidenceBaseline(
            WindowDays,
            baseline.TotalFlows,
            baseline.TotalFlows,
            false,
            baseline.Note,
            flows,
            apps);
    }

    public static AiEvidenceBaseline Build(HistoryPage page)
    {
        ArgumentNullException.ThrowIfNull(page);

        var flows = new Dictionary<string, FlowAccumulator>(StringComparer.OrdinalIgnoreCase);
        var apps = new Dictionary<string, AppAccumulator>(StringComparer.OrdinalIgnoreCase);

        foreach (var row in page.Rows)
        {
            var appKey = AppKey(row.AppPath, row.AppDisplayName, row.ProcessId);
            var flowKey = FlowKey(appKey, row.Protocol, row.RemoteEndpoint, row.Direction);

            if (!flows.TryGetValue(flowKey, out var flow))
            {
                flow = new FlowAccumulator(row.FirstSeenUtc, row.LastSeenUtc);
                flows[flowKey] = flow;
            }
            else
            {
                flow.Add(row.FirstSeenUtc, row.LastSeenUtc);
            }

            if (!apps.TryGetValue(appKey, out var app))
            {
                app = new AppAccumulator();
                apps[appKey] = app;
            }

            app.Add(row.RemoteEndpoint);
        }

        var truncated = page.TotalCount > page.Rows.Count;
        var note = truncated
            ? $"Local flow history baseline over {WindowDays} days; only {page.Rows.Count} of " +
              $"{page.TotalCount} rows were considered."
            : $"Local flow history baseline over {WindowDays} days; {page.Rows.Count} row(s) considered. " +
              "It records flow observations, not packet counts or payloads.";

        return new AiEvidenceBaseline(
            WindowDays,
            page.Rows.Count,
            page.TotalCount,
            truncated,
            note,
            flows.ToDictionary(
                pair => pair.Key,
                pair => new AiEvidenceBaselineFlow(
                    pair.Value.Rows,
                    pair.Value.FirstSeenUtc,
                    pair.Value.LastSeenUtc),
                StringComparer.OrdinalIgnoreCase),
            apps.ToDictionary(
                pair => pair.Key,
                pair => new AiEvidenceBaselineApp(
                    pair.Value.Rows,
                    pair.Value.Remotes
                        .OrderByDescending(entry => entry.Value)
                        .ThenBy(entry => entry.Key, StringComparer.Ordinal)
                        .Take(3)
                        .Select(entry => entry.Key)
                        .ToArray()),
                StringComparer.OrdinalIgnoreCase));
    }

    public static string AppKey(string path, string displayName, int processId) =>
        !string.IsNullOrWhiteSpace(path)
            ? path.Trim()
            : $"pid:{processId}:{displayName.Trim()}";

    public static string FlowKey(string appKey, string protocol, string remoteEndpoint, string direction) =>
        $"{appKey}|{protocol}|{remoteEndpoint}|{direction}";

    private sealed class FlowAccumulator(DateTimeOffset firstSeenUtc, DateTimeOffset lastSeenUtc)
    {
        public int Rows { get; private set; } = 1;

        public DateTimeOffset FirstSeenUtc { get; private set; } = firstSeenUtc;

        public DateTimeOffset LastSeenUtc { get; private set; } = lastSeenUtc;

        public void Add(DateTimeOffset firstSeenUtc, DateTimeOffset lastSeenUtc)
        {
            Rows++;
            if (firstSeenUtc < FirstSeenUtc)
            {
                FirstSeenUtc = firstSeenUtc;
            }

            if (lastSeenUtc > LastSeenUtc)
            {
                LastSeenUtc = lastSeenUtc;
            }
        }
    }

    private sealed class AppAccumulator
    {
        public int Rows { get; private set; }

        public Dictionary<string, int> Remotes { get; } = new(StringComparer.Ordinal);

        public void Add(string remoteEndpoint)
        {
            Rows++;
            if (string.IsNullOrWhiteSpace(remoteEndpoint))
            {
                return;
            }

            Remotes[remoteEndpoint] = Remotes.TryGetValue(remoteEndpoint, out var count)
                ? count + 1
                : 1;
        }
    }
}
