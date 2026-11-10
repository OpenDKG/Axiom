// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Concurrent;
using System.Text.Json;
using Axiom.Contracts.Privacy;
using Axiom.Contracts.Threat;

namespace Axiom.Service;

/// <summary>
/// Holds the indicator candidates Axiom proposes to share and records what happened to each one.
/// Only malware indicators an agent actually fetched (and high-confidence AI Analyst IOCs) enter
/// the queue. The service never runs the reporter or writes to the graph: Blackbox and the user's
/// DKG identity live in the user's own session, so the desktop submits and reports the outcome.
/// </summary>
public sealed class ThreatShareController : IAsyncDisposable
{
    private readonly ThreatShareStore _store;
    private readonly ConcurrentQueue<ThreatShareEnqueueRequest> _incoming = new();
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly HashSet<string> _knownIds = new(StringComparer.Ordinal);
    private readonly List<ThreatShareItem> _items;

    public ThreatShareController(ThreatShareStore? store = null)
    {
        _store = store ?? new ThreatShareStore();

        _items = _store.Load().ToList();
        foreach (var item in _items)
        {
            _knownIds.Add(item.Candidate.Id);
        }
    }

    public string StorePath => _store.StorePath;

    /// <summary>
    /// Called from the DNS block path, so it only decides and enqueues; it never touches disk.
    /// </summary>
    public void ObserveBlocked(PrivacyShieldBlockedEvent blocked)
    {
        if (CreateFromBlocked(blocked) is { } request)
        {
            _incoming.Enqueue(request);
        }
    }

    /// <summary>
    /// A blocked malware domain is only shareable when an agent actually fetched it: directly, or
    /// through a tool process it spawned. Only then is the Blackbox "fetched-by-tool" context true.
    /// Ads, tracking and telemetry never qualify.
    /// </summary>
    public static ThreatShareEnqueueRequest? CreateFromBlocked(PrivacyShieldBlockedEvent blocked)
    {
        if (!blocked.Category.HasFlag(PrivacyCategory.Malware))
        {
            return null;
        }

        var fetchedDirectly = AgentProcessMatcher.IsAgentProcess(blocked.AppName, blocked.AppPath);
        var fetchedByTool = AgentProcessMatcher.IsAgentProcess(blocked.AgentName, blocked.AgentPath);
        if (!fetchedDirectly && !fetchedByTool)
        {
            return null;
        }

        if (ThreatShareVocabulary.Normalize("domain", blocked.Domain) is null)
        {
            return null;
        }

        var via = fetchedDirectly
            ? blocked.AppDisplay
            : $"{blocked.AppDisplay} via {blocked.AgentDisplay}";

        return new ThreatShareEnqueueRequest
        {
            IndicatorType = "domain",
            Value = blocked.Domain,
            Reason = "malware-delivery",
            Context = "fetched-by-tool",
            Source = ThreatShareSource.PrivacyShield,
            Detail = $"Blocked for {via} by the malware list.",
            ObservedUtc = blocked.BlockedUtc,
        };
    }

    public void Enqueue(ThreatShareEnqueueRequest request) => _incoming.Enqueue(request);

    /// <summary>Persists queued observations without contacting anything else.</summary>
    public Task FlushAsync(CancellationToken cancellationToken) =>
        FlushIncomingAsync(cancellationToken);

    public async Task<ThreatShareQueueStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        await FlushIncomingAsync(cancellationToken).ConfigureAwait(false);
        return await SnapshotAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<ThreatShareQueueStatus> DismissAsync(string id, CancellationToken cancellationToken)
    {
        await FlushIncomingAsync(cancellationToken).ConfigureAwait(false);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var index = _items.FindIndex(item =>
                string.Equals(item.Candidate.Id, id, StringComparison.Ordinal));
            if (index >= 0 && _items[index].State == ThreatShareState.Pending)
            {
                _items[index] = _items[index] with
                {
                    State = ThreatShareState.Dismissed,
                    Outcome = "dismissed by the user",
                    AttemptedUtc = DateTimeOffset.UtcNow,
                };
                _store.Save(_items);
            }
        }
        finally
        {
            _gate.Release();
        }

        return await SnapshotAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Records the outcome the desktop got from the Blackbox reporter.</summary>
    public async Task<ThreatShareQueueStatus> RecordAsync(
        ThreatShareRecordRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        await FlushIncomingAsync(cancellationToken).ConfigureAwait(false);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var index = _items.FindIndex(item =>
                string.Equals(item.Candidate.Id, request.Id, StringComparison.Ordinal));
            if (index >= 0)
            {
                _items[index] = _items[index] with
                {
                    State = request.Submitted ? ThreatShareState.Submitted : ThreatShareState.Rejected,
                    Outcome = Trim(request.Outcome, 200),
                    AttemptedUtc = DateTimeOffset.UtcNow,
                };
                _store.Save(_items);
            }
        }
        finally
        {
            _gate.Release();
        }

        return await SnapshotAsync(cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            _store.Save(_items);
        }
        finally
        {
            _gate.Release();
            _gate.Dispose();
        }
    }

    private async Task FlushIncomingAsync(CancellationToken cancellationToken)
    {
        if (_incoming.IsEmpty)
        {
            return;
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var changed = false;
            while (_incoming.TryDequeue(out var request))
            {
                var type = (request.IndicatorType ?? string.Empty).Trim().ToLowerInvariant();
                var reason = (request.Reason ?? string.Empty).Trim().ToLowerInvariant();
                var context = (request.Context ?? string.Empty).Trim().ToLowerInvariant();
                if (!ThreatShareVocabulary.IsSupported(type, reason, context))
                {
                    continue;
                }

                if (ThreatShareVocabulary.Normalize(type, request.Value) is not { } value)
                {
                    continue;
                }

                var id = ThreatShareVocabulary.BuildId(type, value);
                if (!_knownIds.Add(id))
                {
                    continue;
                }

                _items.Add(new ThreatShareItem(
                    new ThreatShareCandidate
                    {
                        Id = id,
                        IndicatorType = type,
                        Value = value,
                        Reason = reason,
                        Context = context,
                        Source = request.Source,
                        Detail = Trim(request.Detail, 200),
                        ObservedUtc = request.ObservedUtc,
                    },
                    ThreatShareState.Pending,
                    string.Empty,
                    null));
                changed = true;
            }

            if (changed)
            {
                if (_items.Count > ThreatShareStore.MaxItems)
                {
                    _items.RemoveRange(0, _items.Count - ThreatShareStore.MaxItems);
                }

                _store.Save(_items);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<ThreatShareQueueStatus> SnapshotAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var today = DateTimeOffset.UtcNow.UtcDateTime.Date;
            var items = _items
                .OrderByDescending(item => item.State == ThreatShareState.Pending)
                .ThenByDescending(item => item.Candidate.ObservedUtc)
                .Take(100)
                .ToArray();

            var pending = _items.Count(item => item.State == ThreatShareState.Pending);
            var submitted = _items.Count(item => item.State == ThreatShareState.Submitted);
            var todaySubmitted = _items.Count(item =>
                item.State == ThreatShareState.Submitted &&
                item.AttemptedUtc is { } attempted &&
                attempted.UtcDateTime.Date == today);

            return new ThreatShareQueueStatus
            {
                Pending = pending,
                Submitted = submitted,
                TodaySubmitted = todaySubmitted,
                DailyLimit = ThreatShareVocabulary.MaxDailySubmissions,
                Detail = pending == 0
                    ? "No indicator is waiting for review."
                    : $"{pending} indicator(s) wait for your review; the desktop sends one only when you press Share or Send now.",
                Items = items,
            };
        }
        finally
        {
            _gate.Release();
        }
    }

    private static string Trim(string? value, int max)
    {
        var text = (value ?? string.Empty).Trim();
        return text.Length <= max ? text : text[..(max - 3)] + "...";
    }
}
