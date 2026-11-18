// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Concurrent;
using System.Text.Json;
using Axiom.Contracts.Threat;

namespace Axiom.Service;

/// <summary>
/// Holds the indicator candidates Axiom proposes to share and records what happened to each one.
/// Only high-confidence AI Analyst IOCs that match evidence Axiom observed enter the queue; public
/// list matches stay local so they are not mistaken for independent sightings. The service never
/// runs the reporter or writes to the graph: Blackbox and the user's DKG identity live in the
/// user's own session, so the desktop submits and reports the outcome.
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
            if (index >= 0 &&
                _items[index].State is ThreatShareState.Pending or ThreatShareState.Deferred)
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

    /// <summary>Marks a previously submitted report as retracted locally after CLI confirmation.</summary>
    public Task<ThreatShareQueueStatus> RetractAsync(
        string id,
        string outcome,
        CancellationToken cancellationToken) =>
        RecordAsync(
            new ThreatShareRecordRequest
            {
                Id = id,
                Submitted = false,
                Retracted = true,
                Outcome = string.IsNullOrWhiteSpace(outcome)
                    ? "retraction submitted; existing CC0 replicas may persist"
                    : outcome,
            },
            cancellationToken);

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
                var current = _items[index];
                var now = DateTimeOffset.UtcNow;
                var attempts = current.Attempts + 1;
                var submissionKey = string.IsNullOrWhiteSpace(current.SubmissionKey)
                    ? Guid.NewGuid().ToString("N")
                    : current.SubmissionKey;
                _items[index] = request.Retracted
                    ? current with
                    {
                        State = ThreatShareState.Retracted,
                        Outcome = string.IsNullOrWhiteSpace(request.Outcome)
                            ? "retraction submitted; existing CC0 replicas may persist"
                            : Trim(request.Outcome, 200),
                        AttemptedUtc = now,
                        Attempts = attempts,
                        NextAttemptUtc = null,
                        SubmissionKey = submissionKey,
                    }
                    : request.Submitted
                        ? current with
                        {
                            State = ThreatShareState.Submitted,
                            Outcome = Trim(request.Outcome, 200),
                            AttemptedUtc = now,
                            Attempts = attempts,
                            NextAttemptUtc = null,
                            SubmissionKey = submissionKey,
                        }
                        : request.Ambiguous
                            ? current with
                            {
                                State = ThreatShareState.Unverified,
                                Outcome = Trim(request.Outcome, 200),
                                AttemptedUtc = now,
                                Attempts = attempts,
                                NextAttemptUtc = null,
                                SubmissionKey = submissionKey,
                            }
                            : request.Deferred
                                ? current with
                                {
                                    State = ThreatShareState.Deferred,
                                    Outcome = Trim(request.Outcome, 200),
                                    AttemptedUtc = now,
                                    Attempts = attempts,
                                    NextAttemptUtc = now.AddMinutes(BackoffMinutes(attempts)),
                                    SubmissionKey = submissionKey,
                                }
                                : current with
                                {
                                    State = ThreatShareState.Rejected,
                                    Outcome = Trim(request.Outcome, 200),
                                    AttemptedUtc = now,
                                    Attempts = attempts,
                                    NextAttemptUtc = null,
                                    SubmissionKey = submissionKey,
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

                var severity = ThreatShareVocabulary.NormalizeSeverity(request.Severity);
                var assessment = ResolveAssessment(request, type, value, reason);

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
                        Severity = severity,
                        EvidenceClass = request.EvidenceClass,
                        ProofGrade = request.ProofGrade,
                        PublicationEligibility = assessment.Eligibility,
                        NoveltyStatus = request.NoveltyStatus,
                        EligibilityReasonCode = assessment.ReasonCode,
                        EligibilityExplanation = assessment.Explanation,
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
                    var expired = _items.Count - ThreatShareStore.MaxItems;
                    for (var index = 0; index < expired; index++)
                    {
                        _knownIds.Remove(_items[index].Candidate.Id);
                    }

                    _items.RemoveRange(0, expired);
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
                .ThenByDescending(item => item.State == ThreatShareState.Deferred)
                .ThenByDescending(item => item.Candidate.ObservedUtc)
                .Take(100)
                .ToArray();

            var pending = _items.Count(item => item.State == ThreatShareState.Pending);
            var deferred = _items.Count(item => item.State == ThreatShareState.Deferred);
            var unverified = _items.Count(item => item.State == ThreatShareState.Unverified);
            var submitted = _items.Count(item => item.State == ThreatShareState.Submitted);
            var todaySubmitted = _items.Count(item =>
                item.State == ThreatShareState.Submitted &&
                item.AttemptedUtc is { } attempted &&
                attempted.UtcDateTime.Date == today);

            return new ThreatShareQueueStatus
            {
                Pending = pending,
                Deferred = deferred,
                Unverified = unverified,
                Submitted = submitted,
                TodaySubmitted = todaySubmitted,
                DailyLimit = ThreatShareVocabulary.MaxDailySubmissions,
                Detail = pending == 0 && deferred == 0 && unverified == 0
                    ? "No indicator is waiting for review."
                    : $"{pending} waiting for your review, {deferred} deferred after a transient failure; " +
                      "the desktop sends one only when you press Share or Send now.",
                Items = items,
            };
        }
        finally
        {
            _gate.Release();
        }
    }

    private static ThreatShareEligibilityAssessment ResolveAssessment(
        ThreatShareEnqueueRequest request,
        string type,
        string value,
        string reason)
    {
        var evaluated = ThreatShareVocabulary.EvaluatePublicationEligibility(
            type,
            value,
            reason,
            request.EvidenceClass,
            request.ProofGrade,
            listDerived: request.EvidenceClass == ThreatShareEvidenceClass.PublicFeedMatch);

        if (!string.IsNullOrWhiteSpace(request.EligibilityReasonCode) &&
            request.PublicationEligibility < evaluated.Eligibility)
        {
            return new(
                request.PublicationEligibility,
                Trim(request.EligibilityReasonCode, 64),
                Trim(request.EligibilityExplanation, 200));
        }

        return evaluated;
    }

    private static double BackoffMinutes(int attempts) =>
        Math.Min(5 * Math.Pow(2, Math.Max(0, attempts - 1)), 360);

    private static string Trim(string? value, int max)
    {
        var text = (value ?? string.Empty).Trim();
        return text.Length <= max ? text : text[..(max - 3)] + "...";
    }
}
