// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Axiom.Contracts.Blackbox;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Contracts.Threat;
using Axiom.Presentation;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

public sealed class ThreatSharingControlTests
{
    [Fact]
    public async Task Turning_blackbox_automatic_sharing_off_keeps_toggle_visible_and_allows_re_enabling()
    {
        var reportState = true;
        var handler = new StubBlackboxHandler(
            () => reportState,
            value => reportState = value);
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://127.0.0.1:9700/") };
        using var blackbox = new BlackboxDashboardClient(http);
        var ui = new StubUserInteraction(confirmResult: true);
        var dialogs = new StubBlackboxDialogs();
        var service = new StubThreatShareService();
        var timers = new StubTimerFactory();
        using var security = new SecurityPageViewModel(
            ui, new StubSecurityDialogs(), new StubProtector(), timers, new StubShellActions());
        using var agents = new AgentsPageViewModel(
            security,
            agentSessions: null,
            ui,
            dialogs,
            timers,
            service,
            blackbox);

        await agents.RefreshAllCommand.ExecuteAsync(null);
        Assert.True(agents.BlackboxAutomaticSharing);
        Assert.True(agents.CanToggleBlackboxAutomaticSharing);
        Assert.Equal("Turn off Blackbox automatic sharing", agents.BlackboxAutomaticSharingButtonText);

        await agents.ToggleBlackboxAutomaticSharingCommand.ExecuteAsync(null);
        Assert.False(reportState);
        Assert.False(agents.BlackboxAutomaticSharing);
        Assert.True(agents.CanToggleBlackboxAutomaticSharing);
        Assert.Equal("Turn on Blackbox automatic sharing", agents.BlackboxAutomaticSharingButtonText);

        // Turning it back on asks for explicit confirmation and restores ON state.
        await agents.ToggleBlackboxAutomaticSharingCommand.ExecuteAsync(null);
        Assert.True(reportState);
        Assert.True(agents.BlackboxAutomaticSharing);
        Assert.True(agents.CanToggleBlackboxAutomaticSharing);
        Assert.Equal("Turn off Blackbox automatic sharing", agents.BlackboxAutomaticSharingButtonText);
        Assert.Single(ui.Confirmations);
    }

    [Fact]
    public async Task Adding_and_verifying_manual_threat_indicators_updates_queue_through_ipc()
    {
        var reportState = false;
        var handler = new StubBlackboxHandler(
            () => reportState,
            value => reportState = value);
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://127.0.0.1:9700/") };
        using var blackbox = new BlackboxDashboardClient(http);
        var ui = new StubUserInteraction(confirmResult: true);
        var service = new StubThreatShareService();
        var aiCandidate = new ThreatShareCandidate
        {
            Id = "ioc:domain:suspect-c2.net",
            IndicatorType = "domain",
            Value = "suspect-c2.net",
            Reason = "unknown",
            Context = ThreatShareVocabulary.ObservedNetworkContext,
            Source = ThreatShareSource.AiAnalyst,
            Detail = "Observed by AI Analyst",
            ObservedUtc = DateTimeOffset.UtcNow,
            Severity = "high",
            EvidenceClass = ThreatShareEvidenceClass.HeuristicOrAiSuspected,
            ProofGrade = ThreatShareProofGrade.Observed,
            PublicationEligibility = ThreatSharePublicationEligibility.NeedsEvidence,
            EligibilityReasonCode = "UNSPECIFIED_THREAT_REASON",
            EligibilityExplanation = "Classify before publishing.",
        };
        service.SeedPending(aiCandidate);

        var dialogs = new StubBlackboxDialogs
        {
            ManualIndicator = new ThreatShareEnqueueRequest
            {
                IndicatorType = "domain",
                Value = "manual-c2.net",
                Reason = "command-and-control",
                Context = "fetched-by-tool",
                Source = ThreatShareSource.Operator,
                Detail = "Verified locally.",
                ObservedUtc = DateTimeOffset.UtcNow,
                Severity = "high",
                EvidenceClass = ThreatShareEvidenceClass.ReproducibleAttackArtifact,
                ProofGrade = ThreatShareProofGrade.Reproduced,
                PublicationEligibility = ThreatSharePublicationEligibility.NeedsOperatorReview,
            },
            VerifyRequest = new ThreatShareVerifyRequest
            {
                Id = aiCandidate.Id,
                Reason = "command-and-control",
                Context = "fetched-by-tool",
                Severity = "critical",
                Detail = "Confirmed C2 traffic.",
            },
        };

        var timers = new StubTimerFactory();
        using var security = new SecurityPageViewModel(
            ui, new StubSecurityDialogs(), new StubProtector(), timers, new StubShellActions());
        using var agents = new AgentsPageViewModel(
            security,
            agentSessions: null,
            ui,
            dialogs,
            timers,
            service,
            blackbox);

        await agents.RefreshAllCommand.ExecuteAsync(null);
        Assert.True(agents.CanAddThreatShareIndicator);
        var initialRow = Assert.Single(agents.ThreatShareCandidates);
        Assert.True(initialRow.CanVerify);
        Assert.False(initialRow.Candidate.CanPublishToCommunity);

        await agents.VerifyThreatShareItemCommand.ExecuteAsync(initialRow);
        var verifiedRow = Assert.Single(agents.ThreatShareCandidates, row => row.Candidate.Id == aiCandidate.Id);
        Assert.False(verifiedRow.CanVerify);
        Assert.True(verifiedRow.Candidate.CanPublishToCommunity);

        await agents.AddThreatShareIndicatorCommand.ExecuteAsync(null);
        Assert.Contains(agents.ThreatShareCandidates, row =>
            row.Candidate.Value == "manual-c2.net" && row.Candidate.CanPublishToCommunity);
    }

    private sealed class StubBlackboxHandler(Func<bool> getReport, Action<bool> setReport) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var path = request.RequestUri?.AbsolutePath ?? string.Empty;
            if (request.Method == HttpMethod.Get && path == "/api/session")
            {
                return JsonResponse("""{"token":"test-token"}""");
            }

            if (request.Method == HttpMethod.Post && path == "/api/settings")
            {
                var body = request.Content is null
                    ? string.Empty
                    : await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                var patch = JsonNode.Parse(body) as JsonObject;
                if (patch?["report"] is JsonValue val && val.TryGetValue<bool>(out var enabled))
                {
                    setReport(enabled);
                }

                var reportLiteral = getReport() ? "true" : "false";
                return JsonResponse($$$"""{"ok":true,"settings":{"mode":"block","report":{{{reportLiteral}}}}}""");
            }

            if (path == "/api/settings")
            {
                var reportLiteral = getReport() ? "true" : "false";
                return JsonResponse($$$"""{"mode":"block","block_severity":"critical","report":{{{reportLiteral}}},"protected_paths":[],"categories":{}}""");
            }

            if (path == "/api/graph-status")
            {
                return JsonResponse("""{"mode":"block","node_reachable":true,"curated":10,"community":0,"findings_logged":0}""");
            }

            if (path == "/api/verified-sync")
            {
                return JsonResponse("""{"state":"ready","verified_rules":10,"lookups":{"state":"ready","label":"Ready","text":""}}""");
            }

            if (path == "/api/audit")
            {
                return JsonResponse("""{"entries":[],"total":0}""");
            }

            if (path == "/api/findings")
            {
                return JsonResponse("""{"findings":[],"total":0}""");
            }

            if (path == "/api/graph")
            {
                return JsonResponse("""{"threats":[],"total":0,"partial":false}""");
            }

            return JsonResponse("{}");
        }

        private static HttpResponseMessage JsonResponse(string json) =>
            new(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            };
    }

    private sealed class StubThreatShareService : IServiceRequestClient
    {
        private readonly List<ThreatShareItem> _items = [];

        public void SeedPending(ThreatShareCandidate candidate) =>
            _items.Add(new ThreatShareItem(candidate, ThreatShareState.Pending, string.Empty, null));

        public Task<TResult> SendAsync<TResult>(string commandType, object? payload, CancellationToken cancellationToken)
        {
            if (commandType == IpcCommandTypes.ThreatShareEnqueue && payload is ThreatShareEnqueueRequest enqueue)
            {
                var normalized = ThreatShareVocabulary.Normalize(enqueue.IndicatorType, enqueue.Value) ?? enqueue.Value;
                var id = ThreatShareVocabulary.BuildId(enqueue.IndicatorType, normalized);
                var assessment = ThreatShareVocabulary.EvaluatePublicationEligibility(
                    enqueue.IndicatorType, normalized, enqueue.Reason, enqueue.EvidenceClass, enqueue.ProofGrade);
                _items.Add(new ThreatShareItem(
                    new ThreatShareCandidate
                    {
                        Id = id,
                        IndicatorType = enqueue.IndicatorType,
                        Value = normalized,
                        Reason = enqueue.Reason,
                        Context = enqueue.Context,
                        Source = enqueue.Source,
                        Detail = enqueue.Detail,
                        ObservedUtc = enqueue.ObservedUtc,
                        Severity = enqueue.Severity,
                        EvidenceClass = enqueue.EvidenceClass,
                        ProofGrade = enqueue.ProofGrade,
                        PublicationEligibility = assessment.Eligibility,
                        EligibilityReasonCode = assessment.ReasonCode,
                        EligibilityExplanation = assessment.Explanation,
                    },
                    ThreatShareState.Pending,
                    string.Empty,
                    null));
            }
            else if (commandType == IpcCommandTypes.ThreatShareVerify && payload is ThreatShareVerifyRequest verify)
            {
                var idx = _items.FindIndex(item => item.Candidate.Id == verify.Id);
                if (idx >= 0)
                {
                    var current = _items[idx];
                    var assessment = ThreatShareVocabulary.EvaluatePublicationEligibility(
                        current.Candidate.IndicatorType,
                        current.Candidate.Value,
                        verify.Reason,
                        ThreatShareEvidenceClass.ReproducibleAttackArtifact,
                        ThreatShareProofGrade.Reproduced);
                    _items[idx] = current with
                    {
                        Candidate = current.Candidate with
                        {
                            Reason = verify.Reason,
                            Context = verify.Context,
                            Severity = verify.Severity,
                            Detail = verify.Detail,
                            EvidenceClass = ThreatShareEvidenceClass.ReproducibleAttackArtifact,
                            ProofGrade = ThreatShareProofGrade.Reproduced,
                            PublicationEligibility = assessment.Eligibility,
                            EligibilityReasonCode = assessment.ReasonCode,
                            EligibilityExplanation = assessment.Explanation,
                        },
                    };
                }
            }

            if (typeof(TResult) == typeof(ThreatShareQueueStatus))
            {
                var status = new ThreatShareQueueStatus
                {
                    Pending = _items.Count,
                    Submitted = 0,
                    TodaySubmitted = 0,
                    Items = _items.ToArray(),
                };
                return Task.FromResult((TResult)(object)status);
            }

            throw new ServiceUnavailableException(IpcErrorCodes.NotSupported, $"Command not stubbed in test: {commandType}");
        }
    }

    private sealed class StubBlackboxDialogs : IBlackboxDialogService
    {
        public ThreatShareEnqueueRequest? ManualIndicator { get; set; }

        public ThreatShareVerifyRequest? VerifyRequest { get; set; }

        public Task ShowSettingsAsync(BlackboxDashboardClient client, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task ShowLogAsync(string title, string text, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<ThreatShareEnqueueRequest?> PromptManualThreatIndicatorAsync(CancellationToken cancellationToken) =>
            Task.FromResult(ManualIndicator);

        public Task<ThreatShareVerifyRequest?> PromptVerifyThreatCandidateAsync(
            ThreatShareCandidate candidate,
            CancellationToken cancellationToken) =>
            Task.FromResult(VerifyRequest);
    }

    private sealed class StubUserInteraction(bool confirmResult) : IUserInteraction
    {
        public List<string> Confirmations { get; } = [];

        public Task<bool> ConfirmAsync(
            string title,
            string message,
            string confirmLabel,
            bool destructive,
            CancellationToken cancellationToken)
        {
            Confirmations.Add(title);
            return Task.FromResult(confirmResult);
        }

        public Task ShowMessageAsync(string title, string message, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task ShowDocumentAsync(string title, string document, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<string?> PickSaveFileAsync(string suggestedFileName, string extension, string typeName, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);

        public Task<string?> PickOpenFileAsync(string title, string extension, string typeName, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);

        public Task<string?> PickFolderAsync(string title, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);

        public Task CopyTextAsync(string text, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task OpenExternalAsync(string url, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    private sealed class StubSecurityDialogs : ISecurityDialogService
    {
        public Task<ReputationSettings?> EditReputationAsync(
            ReputationSettings current,
            CancellationToken cancellationToken) =>
            Task.FromResult<ReputationSettings?>(null);

        public Task<CommunityFeedSettings?> EditCommunityAsync(
            CommunityFeedSettings current,
            CancellationToken cancellationToken) =>
            Task.FromResult<CommunityFeedSettings?>(null);

        public Task<bool?> ChooseAgentHookInstallationAsync(CancellationToken cancellationToken) =>
            Task.FromResult<bool?>(null);
    }

    private sealed class StubProtector : IApiKeyProtector
    {
        public string Protect(string plaintext) => plaintext;

        public string Unprotect(string ciphertext) => ciphertext;
    }

    private sealed class StubShellActions : IShellActions
    {
        public void Restart()
        {
        }

        public void Shutdown()
        {
        }
    }

    private sealed class StubTimerFactory : IUiTimerFactory
    {
        public IUiTimer Create(TimeSpan interval) => new StubTimer(interval);

        private sealed class StubTimer(TimeSpan interval) : IUiTimer
        {
            public TimeSpan Interval { get; set; } = interval;

            public bool IsEnabled { get; private set; }

            event EventHandler? IUiTimer.Tick
            {
                add { }
                remove { }
            }

            public void Start() => IsEnabled = true;

            public void StopTimer() => IsEnabled = false;

            public void Dispose() => StopTimer();
        }
    }
}
