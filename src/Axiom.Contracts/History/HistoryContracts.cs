// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.History;

/// <summary>Time-window query over stored connection observations. All times are UTC.</summary>
public sealed record HistoryQuery
{
    public required DateTimeOffset FromUtc { get; init; }

    public required DateTimeOffset ToUtc { get; init; }

    /// <summary>Matches app name, path, remote endpoint or PID.</summary>
    public string? Search { get; init; }

    public int Limit { get; init; } = 200;

    public int Offset { get; init; }

    /// <summary>
    /// When true, the store also returns aggregated 30-day baseline data instead of transferring
    /// every flow row. The normal row query is still bounded by <see cref="Limit"/>.
    /// </summary>
    public bool IncludeBaseline { get; init; }
}

public sealed record HistoryRow
{
    public required string AppDisplayName { get; init; }

    public required string AppPath { get; init; }

    public required int ProcessId { get; init; }

    public required string Protocol { get; init; }

    public required string LocalEndpoint { get; init; }

    public required string RemoteEndpoint { get; init; }

    public required string Direction { get; init; }

    public required string State { get; init; }

    public required string Quality { get; init; }

    public required DateTimeOffset FirstSeenUtc { get; init; }

    public required DateTimeOffset LastSeenUtc { get; init; }
}

public sealed record HistoryPage
{
    public required IReadOnlyList<HistoryRow> Rows { get; init; }

    public required int TotalCount { get; init; }

    public required string DatabasePath { get; init; }

    public required DateTimeOffset QueriedUtc { get; init; }

    /// <summary>Aggregated baseline, present only when <see cref="HistoryQuery.IncludeBaseline"/> is set.</summary>
    public HistoryBaseline? Baseline { get; init; }
}

public sealed record HistoryBaseline(
    IReadOnlyList<HistoryBaselineApp> Apps,
    IReadOnlyList<HistoryBaselineFlow> Flows,
    int TotalFlows,
    DateTimeOffset GeneratedUtc,
    string Note);

public sealed record HistoryBaselineApp(
    string AppKey,
    string DisplayName,
    string ExecutablePath,
    int FlowRows,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc,
    IReadOnlyList<string> TypicalRemotes);

public sealed record HistoryBaselineFlow(
    string AppKey,
    string Protocol,
    string RemoteEndpoint,
    string Direction,
    int FlowRows,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc);
