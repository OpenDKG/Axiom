// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Axiom.Contracts;
using Axiom.Contracts.Agents;
using Axiom.Contracts.Blackbox;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Threat;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Agent protection page. It owns the focused Blackbox control-center reads (settings, health,
/// audit) and keeps the existing SecurityViewModel probe/timer for module installation state.
/// Polling is active only while this page is selected.
/// </summary>
public sealed partial class AgentsPageViewModel : PageViewModel, IActivatablePage, IDisposable
{
    private const int ActivityPageSize = 500;

    private const int ActivityMax = 20_000;

    private const int VerifiedGraphPageSize = 80;

    private const int VerifiedGraphPreviewSize = 12;

    private static readonly TimeSpan ActivityRefreshInterval = TimeSpan.FromSeconds(15);

    private static readonly TimeSpan VerifiedGraphRefreshInterval = TimeSpan.FromSeconds(60);

    private static readonly TimeSpan AutoSyncInterval = TimeSpan.FromMinutes(15);

    private static readonly Regex SecretPattern = new(
        @"(?i)\b(token|secret|password|passwd|api[_-]?key|authorization)\b\s*[:=]\s*(""[^""]*""|'[^']*'|[^\s,}\]]+)",
        RegexOptions.Compiled);

    private static readonly Regex BearerPattern = new(
        @"(?i)\bBearer\s+[A-Za-z0-9._~+/\-]+=*",
        RegexOptions.Compiled);

    private static readonly Regex LongHexPattern = new(
        @"\b[A-Fa-f0-9]{32,}\b",
        RegexOptions.Compiled);

    private readonly BlackboxDashboardClient _client;

    private readonly BlackboxAutoSyncStore _autoSyncStore = new();

    private readonly AgentEvidenceStore _agentEvidence = new();

    private readonly VerifiedGraphPeerRelay _peerRelay = new();

    private readonly IAgentSessionSource? _agentSessions;

    private DateTimeOffset _lastSessionRefresh = DateTimeOffset.MinValue;

    private readonly IUiTimer _timer;
    private readonly IUserInteraction _ui;
    private readonly IBlackboxDialogService _dialogs;
    private readonly IServiceRequestClient? _serviceClient;
    private readonly ThreatShareCli _cli = new();
    private ThreatShareQueueStatus? _threatShareStatus;
    private bool _threatShareSubmitting;

    private readonly List<BlackboxAuditEntry> _allActivity = [];

    private readonly List<BlackboxFinding> _allFindings = [];

    private bool _refreshing;

    private bool _preservingActivitySelection;

    private bool _preservingFindingSelection;

    private string? _selectedActivityIdentity;

    private bool _activityInitialized;

    private int _activityTotal;

    private DateTimeOffset _lastActivityRefresh = DateTimeOffset.MinValue;

    private DateTimeOffset _lastVerifiedGraphRefresh = DateTimeOffset.MinValue;

    private bool _verifiedGraphInitialized;

    private bool _pageActive;

    private bool _autoSyncRunning;

    private DateTimeOffset _lastAutoSyncAttempt = DateTimeOffset.MinValue;

    private DateTimeOffset? _latestEvidenceUtc;

    private DateTimeOffset? _latestSessionUtc;

    private bool _hasLiveSession;

    public AgentsPageViewModel(
        SecurityPageViewModel security,
        IAgentSessionSource? agentSessions,
        IUserInteraction ui,
        IBlackboxDialogService dialogs,
        IUiTimerFactory timers,
        IServiceRequestClient? serviceClient = null,
        BlackboxDashboardClient? blackboxClient = null)
        : base("Agent Protection", "Hooks, DKG and Blackbox protection for local AI agents", "\uE99A")
    {
        Security = security ?? throw new ArgumentNullException(nameof(security));
        ArgumentNullException.ThrowIfNull(ui);
        ArgumentNullException.ThrowIfNull(dialogs);
        ArgumentNullException.ThrowIfNull(timers);
        _agentSessions = agentSessions;
        _ui = ui;
        _dialogs = dialogs;
        _serviceClient = serviceClient;
        _client = blackboxClient ?? new BlackboxDashboardClient();
        if (!IsAvailable)
        {
            _threatShareQueueText = "Indicator preview is unavailable in Store builds.";
        }

        var autoSync = _autoSyncStore.Load();
        _isAutoSyncEnabled = autoSync.Enabled;
        _lastAutoSyncAttempt = autoSync.LastAttemptUtc;
        _autoSyncStatusText = autoSync.Enabled
            ? string.IsNullOrWhiteSpace(autoSync.LastStatus)
                ? "Auto-sync is on; checks every 15 minutes for new verified assets."
                : autoSync.LastStatus
            : "Auto-sync is off.";

        _timer = timers.Create(TimeSpan.FromSeconds(8));
        _timer.Tick += async (_, _) =>
        {
            if (_pageActive)
            {
                await RefreshAsync().ConfigureAwait(true);
            }

            await MaybeAutoSyncAsync().ConfigureAwait(true);
        };
    }

    public SecurityPageViewModel Security { get; }

    public bool IsAvailable => !DistributionContext.IsStorePackage;

    /// <summary>Truthful enforcement status shown above the host list.</summary>
    [ObservableProperty]
    private EnforcementSurfaceState _enforcement = EnforcementSurfaceState.Current;

    public IReadOnlyList<string> ActivityFilters { get; } =
        ["All Activity", "Sessions", "API calls", "Tool calls", "Installs", "File access", "Threats"];

    public IReadOnlyList<string> AgentFilters { get; } =
        ["All agents", "Hermes", "OpenClaw", "OpenCode", "OpenChamber", "Codex", "Claude", "Cursor", "Copilot", "Gemini", "Windsurf", "Cline", "ZCode", "DeepSeek", "Unknown"];

    public IReadOnlyList<string> SeverityFilters { get; } =
        ["All severities", "Info", "Low", "Medium", "High", "Critical"];

    public ObservableCollection<BlackboxAuditEntry> Activity { get; } = [];

    public ObservableCollection<BlackboxFinding> Findings { get; } = [];

    public ObservableCollection<AgentEvidenceEvent> HookEvidence { get; } = [];

    public ObservableCollection<AgentSessionGroup> SessionGroups { get; } = [];

    public ObservableCollection<ActivityDetailRow> SelectedActivityDetails { get; } = [];

    [ObservableProperty]
    private BlackboxAuditEntry? _selectedActivity;

    [ObservableProperty]
    private BlackboxFinding? _selectedFinding;

    [ObservableProperty]
    private bool _hasSelectedFinding;

    [ObservableProperty]
    private AgentEvidenceEvent? _selectedHookEvidence;

    [ObservableProperty]
    private string _selectedActivityTitle = "Select an activity row to see details.";

    [ObservableProperty]
    private string _selectedActivityRawText = string.Empty;

    [ObservableProperty]
    private bool _hasSelectedActivity;

    [ObservableProperty]
    private bool _canLoadMoreActivity;

    [ObservableProperty]
    private string _activityBreakdownText = "No activity loaded.";

    [ObservableProperty]
    private int _sessionCount;

    [ObservableProperty]
    private int _apiCallCount;

    [ObservableProperty]
    private int _toolCallCount;

    [ObservableProperty]
    private int _installCount;

    [ObservableProperty]
    private int _fileAccessCount;

    [ObservableProperty]
    private int _threatCount;

    /// <summary>Blocked guard decisions by agent, built from the local evidence store.</summary>
    [ObservableProperty]
    private AgentBlockSummary _blockSummary = AgentBlockSummary.Empty;

    public string BlockSummaryText => BlockSummary.HasBlocks
        ? $"{BlockSummary.Blocked:N0} blocked of {BlockSummary.TotalEvents:N0} guard decisions across {BlockSummary.ByHarness.Count} agent(s)"
        : "No blocked guard decisions recorded yet.";

    partial void OnBlockSummaryChanged(AgentBlockSummary value) =>
        OnPropertyChanged(nameof(BlockSummaryText));

    [ObservableProperty]
    private int _findingCount;

    [ObservableProperty]
    private int _blockedFindingCount;

    [ObservableProperty]
    private int _flaggedFindingCount;

    [ObservableProperty]
    private string _selectedActivityFilter = "All Activity";

    [ObservableProperty]
    private string _selectedAgentFilter = "All agents";

    [ObservableProperty]
    private string _selectedSeverityFilter = "All severities";

    [ObservableProperty]
    private string _activityStatusText = "Select the Agents page to load local Blackbox activity.";

    [ObservableProperty]
    private bool _hasStaleAgentActivity;

    [ObservableProperty]
    private string _activityFreshnessText = string.Empty;

    [ObservableProperty]
    private string _healthStatusText = "Blackbox health is not loaded yet.";

    [ObservableProperty]
    private string _blackboxHealthText = "Dashboard: unknown";

    [ObservableProperty]
    private string _threatSharingStatusText = "checking…";

    [ObservableProperty]
    private bool _threatSharingEnabled;

    [ObservableProperty]
    private bool _canToggleThreatSharing;

    public string ThreatSharingButtonText =>
        ThreatSharingEnabled ? "Disable threat sharing" : "Enable threat sharing";

    partial void OnThreatSharingEnabledChanged(bool value) =>
        OnPropertyChanged(nameof(ThreatSharingButtonText));

    /// <summary>Indicators Axiom proposes to share; nothing is sent until sharing is on.</summary>
    public ObservableCollection<ThreatShareItem> ThreatShareCandidates { get; } = [];

    /// <summary>Recently shared reports that the operator may explicitly retract.</summary>
    public ObservableCollection<ThreatShareItem> SubmittedThreatShares { get; } = [];

    [ObservableProperty]
    private string _threatShareQueueText = "Loading the indicator preview...";

    [ObservableProperty]
    private string _threatShareReporterText = string.Empty;

    [ObservableProperty]
    private bool _hasThreatShareCandidates;

    [ObservableProperty]
    private bool _hasSubmittedThreatShares;

    [ObservableProperty]
    private bool _canSubmitThreatShare;

    /// <summary>Per-row action availability; an unverified row must still be retryable on purpose.</summary>
    [ObservableProperty]
    private bool _canShareThreatShareItem;

    [ObservableProperty]
    private string _threatShareActionText = string.Empty;

    [ObservableProperty]
    private string _dkgHealthText = "DKG: unknown";

    [ObservableProperty]
    private string _axiomDkgHealthText = "Axiom DKG: unknown";

    [ObservableProperty]
    private string _graphHealthText = "Verified graph: unknown";

    [ObservableProperty]
    private string _verifiedSyncState = "Unknown";

    [ObservableProperty]
    private string _verifiedSyncStateDetail = "Verified graph sync has not been loaded yet.";

    [ObservableProperty]
    private double _verifiedSyncPercent;

    [ObservableProperty]
    private string _verifiedSyncProgressText = "—";

    [ObservableProperty]
    private string _verifiedSyncCountsText = "Downloaded — · compiled — · verified rules —";

    [ObservableProperty]
    private string _verifiedSyncLookupText = "Verified-answer lookups: unknown";

    [ObservableProperty]
    private string _verifiedGraphListStatus = "No verified threats loaded.";

    [ObservableProperty]
    private IReadOnlyList<BlackboxGraphThreat> _verifiedGraphThreats = [];

    [ObservableProperty]
    private IReadOnlyList<BlackboxGraphThreat> _verifiedGraphPreview = [];

    [ObservableProperty]
    private IReadOnlyDictionary<string, int> _verifiedGraphCategoryTotals =
        new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

    [ObservableProperty]
    private int _verifiedGraphTotal;

    [ObservableProperty]
    private BlackboxGraphThreat? _selectedThreat;

    [ObservableProperty]
    private string _selectedThreatTitle = "Select a verified threat to see details.";

    [ObservableProperty]
    private string _selectedThreatDetail = string.Empty;

    partial void OnSelectedThreatChanged(BlackboxGraphThreat? value)
    {
        if (value is null)
        {
            SelectedThreatTitle = "Select a verified threat to see details.";
            SelectedThreatDetail = string.Empty;
            return;
        }

        SelectedThreatTitle = value.DisplayName;
        SelectedThreatDetail =
            $"Identifier: {value.Identifier}\n" +
            $"Category: {value.CategoryLabel}\n" +
            $"Severity: {value.SeverityLabel}\n" +
            $"Ecosystems: {(string.IsNullOrWhiteSpace(value.Ecosystems) ? "unknown" : value.Ecosystems)}\n" +
            $"Source: {(string.IsNullOrWhiteSpace(value.Source) ? "unknown" : value.Source)}";
    }

    [ObservableProperty]
    private bool _isVerifiedSyncRunning;

    [ObservableProperty]
    private bool _isAutoSyncEnabled;

    [ObservableProperty]
    private string _autoSyncStatusText = "Auto-sync is off.";

    [ObservableProperty]
    private string _summaryText = "No activity has been loaded.";

    [ObservableProperty]
    private string _lastBlockedText = "No blocked action observed.";

    [ObservableProperty]
    private string _protectedPathViolationsText = "0 protected-path findings";

    [ObservableProperty]
    private string _unresolvedText = "0 unresolved findings";

    [ObservableProperty]
    private string _protectionTestText = "Protection test has not run.";

    [ObservableProperty]
    private string _sessionStatusText = "No host session data loaded.";

    public void Activate()
    {
        if (!IsAvailable)
        {
            return;
        }

        _pageActive = true;
        _timer.Start();
        _lastSessionRefresh = DateTimeOffset.MinValue;
        _lastActivityRefresh = DateTimeOffset.MinValue;
        _ = RefreshAsync();
    }

    public void Deactivate()
    {
        _pageActive = false;
        if (!IsAutoSyncEnabled)
        {
            _timer.StopTimer();
        }
    }

    public void Dispose()
    {
        _timer.StopTimer();
        _timer.Dispose();
        _client.Dispose();
        _peerRelay.Dispose();
    }

    [RelayCommand]
    private async Task RefreshAsync()
    {
        if (!IsAvailable)
        {
            ThreatShareQueueText = "Indicator preview is unavailable in Store builds.";
            HasThreatShareCandidates = false;
            CanSubmitThreatShare = false;
            return;
        }

        if (_refreshing)
        {
            return;
        }

        _refreshing = true;
        var now = DateTimeOffset.UtcNow;
        try
        {
            var shouldRefreshActivity = !_activityInitialized ||
                                       now - _lastActivityRefresh >= ActivityRefreshInterval;
            var shouldRefreshVerifiedGraph = !_verifiedGraphInitialized ||
                                            now - _lastVerifiedGraphRefresh >= VerifiedGraphRefreshInterval;
            var settingsTask = _client.GetSettingsAsync(CancellationToken.None);
            var graphTask = _client.GetGraphStatusAsync(CancellationToken.None);
            var verifiedSyncTask = TryGetVerifiedSyncAsync();
            var verifiedGraphTask = shouldRefreshVerifiedGraph
                ? TryGetVerifiedGraphAsync()
                : Task.FromResult<BlackboxGraphPage?>(null);
            var auditTask = shouldRefreshActivity
                ? LoadActivityAsync(full: !_activityInitialized)
                : Task.FromResult<BlackboxAuditPage?>(null);
            var findingsTask = _client.GetFindingsAsync(100, 0, CancellationToken.None);

            // These two are optional dashboard reads. Apply them independently so a slow audit
            // history or a missing endpoint cannot hide the verified-graph state.
            var verifiedSync = await verifiedSyncTask.ConfigureAwait(true);
            var graphPage = await verifiedGraphTask.ConfigureAwait(true);
            var localRules = verifiedSync?.VerifiedRules ?? 0;
            if (localRules > 0 && graphPage is { Threats.Count: > 0 })
            {
                _peerRelay.PublishInMemory(verifiedSync!, graphPage);
            }

            if (localRules == 0 ||
                (shouldRefreshVerifiedGraph && (verifiedSync?.IsSyncing == true || graphPage?.Threats.Count == 0)))
            {
                if (await _peerRelay.TryFetchFromPeersAsync(localRules, CancellationToken.None).ConfigureAwait(true) is { } peerSnapshot)
                {
                    verifiedSync = peerSnapshot.Sync;
                    graphPage = peerSnapshot.Graph;
                }
            }

            ApplyVerifiedSync(verifiedSync);
            if (graphPage is not null)
            {
                ApplyVerifiedGraph(graphPage);
                _lastVerifiedGraphRefresh = now;
                _verifiedGraphInitialized = true;
            }

            await Task.WhenAll(
                settingsTask,
                graphTask,
                auditTask,
                findingsTask).ConfigureAwait(true);

            if (auditTask.Result is { } auditPage)
            {
                if (_activityInitialized)
                {
                    MergeActivity(auditPage);
                }
                else
                {
                    ApplyActivity(auditPage);
                    _activityInitialized = true;
                }

                _lastActivityRefresh = now;
            }

            ApplyFindings(findingsTask.Result);
            ApplyHealth(settingsTask.Result, graphTask.Result);
            ApplyHookEvidence();
            await RefreshEnforcementAsync(
                guardAvailable: true,
                ReadString(settingsTask.Result, "mode")).ConfigureAwait(true);
            await RefreshSessionsAsync().ConfigureAwait(true);
        }
        catch (Exception exception) when (exception is
            HttpRequestException or TaskCanceledException or InvalidDataException or System.Text.Json.JsonException)
        {
            ActivityStatusText = $"Blackbox is unavailable: {exception.Message}";
            HealthStatusText = "Blackbox dashboard is offline or not responding.";
            SummaryText = "No live Blackbox data is available.";
            ThreatSharingStatusText = "offline · dashboard unavailable";
            CanToggleThreatSharing = false;
            ApplyHookEvidence();
            await RefreshEnforcementAsync(guardAvailable: false, hookMode: null).ConfigureAwait(true);
        }

        try
        {
            await RefreshThreatShareAsync().ConfigureAwait(true);
        }
        finally
        {
            _refreshing = false;
        }
    }

    [RelayCommand]
    private async Task RefreshAllAsync()
    {
        await Security.RefreshCommand.ExecuteAsync(null).ConfigureAwait(true);
        _activityInitialized = false;
        _lastActivityRefresh = DateTimeOffset.MinValue;
        await RefreshAsync().ConfigureAwait(true);
    }

    [RelayCommand(CanExecute = nameof(CanSyncVerifiedGraph))]
    private async Task SyncVerifiedGraphAsync()
    {
        if (!IsAvailable || IsVerifiedSyncRunning)
        {
            return;
        }

        IsVerifiedSyncRunning = true;
        VerifiedSyncState = "SYNCING";
        VerifiedSyncStateDetail = "Requesting a verified-graph sync from the local Blackbox dashboard…";
        try
        {
            var result = await _client.RequestSyncAsync(CancellationToken.None).ConfigureAwait(true);
            if (!result.Ok)
            {
                VerifiedSyncState = "SYNC FAILED";
                VerifiedSyncStateDetail = result.Message;
                return;
            }

            VerifiedSyncStateDetail = result.Message;
            _verifiedGraphInitialized = false;
            _lastVerifiedGraphRefresh = DateTimeOffset.MinValue;
            await Task.Delay(TimeSpan.FromSeconds(2)).ConfigureAwait(true);
            await RefreshAsync().ConfigureAwait(true);
        }
        catch (Exception exception) when (exception is
            HttpRequestException or TaskCanceledException or InvalidDataException or System.Text.Json.JsonException)
        {
            VerifiedSyncState = "SYNC FAILED";
            VerifiedSyncStateDetail = $"Could not request a verified-graph sync: {exception.Message}";
        }
        finally
        {
            IsVerifiedSyncRunning = false;
        }
    }

    private bool CanSyncVerifiedGraph() => IsAvailable && !IsVerifiedSyncRunning;

    partial void OnIsVerifiedSyncRunningChanged(bool value) =>
        SyncVerifiedGraphCommand.NotifyCanExecuteChanged();

    partial void OnIsAutoSyncEnabledChanged(bool value)
    {
        AutoSyncStatusText = value
            ? "Auto-sync is on; checks every 15 minutes for new verified assets."
            : "Auto-sync is off.";

        if (value)
        {
            _timer.Start();
        }
        else if (!_pageActive)
        {
            _timer.StopTimer();
        }

        PersistAutoSync();
    }

    private async Task MaybeAutoSyncAsync()
    {
        if (!IsAutoSyncEnabled || _autoSyncRunning || !IsAvailable)
        {
            return;
        }

        if (IsVerifiedSyncRunning ||
            string.Equals(VerifiedSyncState, "SYNCING", StringComparison.Ordinal) ||
            string.Equals(VerifiedSyncState, "NODE OFFLINE", StringComparison.Ordinal) ||
            string.Equals(VerifiedSyncState, "UNAVAILABLE", StringComparison.Ordinal))
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        if (now - _lastAutoSyncAttempt < AutoSyncInterval)
        {
            return;
        }

        _autoSyncRunning = true;
        _lastAutoSyncAttempt = now;
        AutoSyncStatusText = "Auto-sync: checking for new verified assets…";
        PersistAutoSync();
        try
        {
            var result = await _client.RequestSyncAsync(CancellationToken.None).ConfigureAwait(true);
            if (!result.Ok)
            {
                AutoSyncStatusText = $"Auto-sync: {result.Message}";
                return;
            }

            AutoSyncStatusText = "Auto-sync requested; existing assets stay local and only new data is fetched.";
            await Task.Delay(TimeSpan.FromSeconds(2)).ConfigureAwait(true);
            if (_pageActive)
            {
                await RefreshAsync().ConfigureAwait(true);
            }
        }
        catch (Exception exception) when (exception is
            HttpRequestException or TaskCanceledException or InvalidDataException or System.Text.Json.JsonException)
        {
            AutoSyncStatusText = $"Auto-sync could not reach the dashboard: {exception.Message}";
        }
        finally
        {
            _autoSyncRunning = false;
            PersistAutoSync();
        }
    }

    private void PersistAutoSync()
    {
        try
        {
            _autoSyncStore.Save(new BlackboxAutoSyncSettings(
                IsAutoSyncEnabled,
                _lastAutoSyncAttempt,
                AutoSyncStatusText));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            AutoSyncStatusText = $"Auto-sync setting could not be saved: {exception.Message}";
        }
    }

    [RelayCommand]
    private async Task LoadMoreActivityAsync()
    {
        if (!CanLoadMoreActivity || !_activityInitialized)
        {
            return;
        }

        try
        {
            var page = await _client.GetAuditAsync(
                ActivityPageSize,
                _allActivity.Count,
                CancellationToken.None).ConfigureAwait(true);
            MergeActivity(page);
        }
        catch (Exception exception) when (exception is
            HttpRequestException or TaskCanceledException or InvalidDataException or System.Text.Json.JsonException)
        {
            ActivityStatusText = $"Could not load older activity: {exception.Message}";
        }
    }

    private async Task<BlackboxAuditPage?> LoadActivityAsync(bool full)
    {
        if (!full)
        {
            return await _client.GetAuditAsync(
                ActivityPageSize,
                0,
                CancellationToken.None).ConfigureAwait(true);
        }

        var entries = new List<BlackboxAuditEntry>();
        var offset = 0;
        var total = 0;
        while (entries.Count < ActivityMax)
        {
            var page = await _client.GetAuditAsync(
                Math.Min(ActivityPageSize, ActivityMax - entries.Count),
                offset,
                CancellationToken.None).ConfigureAwait(true);
            total = page.Total;
            if (page.Entries.Count == 0)
            {
                break;
            }

            entries.AddRange(page.Entries);
            offset += page.Entries.Count;
            if (offset >= total)
            {
                break;
            }
        }

        return new BlackboxAuditPage(entries, total);
    }

    private static T? ResolveCopyTarget<T>(T? explicitItem, T? currentSelection, Action<T?> selectItem) where T : class
    {
        var target = explicitItem ?? currentSelection;
        if (target is null)
        {
            return null;
        }

        if (!ReferenceEquals(currentSelection, target))
        {
            selectItem(target);
        }

        return target;
    }

    [RelayCommand]
    private void CopyActivityEvent(BlackboxAuditEntry? entry = null)
    {
        if (ResolveCopyTarget(entry, SelectedActivity, value => SelectedActivity = value) is not { } target)
        {
            return;
        }

        CopyToClipboard(string.Join(
            Environment.NewLine,
            $"Time: {target.DateTimeText}",
            $"Agent: {target.Agent}",
            $"Event: {target.EventLabel} ({target.Event})",
            $"Details: {target.ActionSummary}",
            $"Session: {target.SessionFull}",
            $"Severity: {target.Severity}",
            $"Decision: {target.Decision}",
            $"Security: {target.SecurityOutcomeDetail}"));
    }

    [RelayCommand]
    private void CopyActivityDetails(BlackboxAuditEntry? entry = null)
    {
        if (ResolveCopyTarget(entry, SelectedActivity, value => SelectedActivity = value) is null)
        {
            return;
        }

        var lines = SelectedActivityDetails
            .Select(row => $"{row.Label}: {row.Value}")
            .ToList();
        if (!string.IsNullOrWhiteSpace(SelectedActivityRawText))
        {
            lines.Add(string.Empty);
            lines.Add("Raw event:");
            lines.Add(SelectedActivityRawText);
        }

        CopyToClipboard(string.Join(Environment.NewLine, lines));
    }

    [RelayCommand]
    private void CopyActivityJson(BlackboxAuditEntry? entry = null)
    {
        if (ResolveCopyTarget(entry, SelectedActivity, value => SelectedActivity = value) is null)
        {
            return;
        }

        CopyToClipboard(SelectedActivityRawText);
    }

    [RelayCommand]
    private void CopyFinding(BlackboxFinding? finding = null)
    {
        if (ResolveCopyTarget(finding, SelectedFinding, value => SelectedFinding = value) is not { } target)
        {
            return;
        }

        CopyToClipboard(string.Join(
            Environment.NewLine,
            $"Time: {target.TimeText}",
            $"Agent: {target.Agent}",
            $"Category: {target.Category}",
            $"Severity: {target.Severity}",
            $"Identifier: {target.Identifier}",
            $"Title: {target.Title}",
            $"Decision: {target.Decision}",
            $"Session: {target.Session}",
            $"Security: {target.SecurityOutcome}"));
    }

    [RelayCommand]
    private void CopyHookEvidence(AgentEvidenceEvent? evidence = null)
    {
        if (ResolveCopyTarget(evidence, SelectedHookEvidence, value => SelectedHookEvidence = value) is not { } target)
        {
            return;
        }

        CopyToClipboard(string.Join(
            Environment.NewLine,
            $"Time: {target.Timestamp:O}",
            $"Framework: {target.Framework}",
            $"Event: {target.EventType}",
            $"Tool: {target.Tool}",
            $"Decision: {target.Decision}",
            $"Guard status: {target.GuardStatus}",
            $"Duration: {target.DurationMs} ms",
            $"Error: {target.ErrorCode}",
            $"Session: {target.Session}",
            $"Call: {target.Call}"));
    }

    [RelayCommand]
    private void CopySessionDetails(AgentSessionRow? session)
    {
        if (session is null)
        {
            return;
        }

        CopyToClipboard(string.Join(
            Environment.NewLine,
            $"Provider: {session.Provider}",
            $"Session: {session.Title}",
            $"Workspace: {session.Workspace}",
            $"Last seen: {session.LastSeen}",
            $"Live: {(session.Live ? "yes" : "no")}"));
    }

    [RelayCommand]
    private void CopyText(string? value) => CopyToClipboard(value ?? string.Empty);

    private void CopyToClipboard(string text) => _ = CopyToClipboardAsync(text);

    private async Task CopyToClipboardAsync(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return;
        }

        try
        {
            await _ui.CopyTextAsync(text, CancellationToken.None).ConfigureAwait(true);
        }
        catch (Exception exception) when (exception is
                     InvalidOperationException or NotSupportedException or System.Runtime.InteropServices.ExternalException)
        {
            ActivityStatusText = "Clipboard is temporarily unavailable.";
        }
    }

    [RelayCommand]
    private async Task TestProtectionAsync()
    {
        var confirmed = await _ui.ConfirmAsync(
            "Test Blackbox protection",
            "Run a harmless protected-file canary test?\n\n" +
            "Axiom creates a temporary file, adds it to Blackbox protected paths, calls the local " +
            "Blackbox guard, then removes the temporary file and restores the original paths. " +
            "No credentials, wallet files or destructive command are used.",
            "Run test",
            destructive: false,
            CancellationToken.None).ConfigureAwait(true);
        if (!confirmed)
        {
            return;
        }

        ProtectionTestText = "Testing…";
        try
        {
            var settings = await _client.GetSettingsAsync(CancellationToken.None).ConfigureAwait(true);
            if (!string.Equals(ReadString(settings, "mode"), "block", StringComparison.OrdinalIgnoreCase))
            {
                ProtectionTestText = "INCONCLUSIVE — Blackbox is in audit mode. Switch to Block, then retry.";
                return;
            }

            var originalPaths = (settings["protected_paths"] as JsonArray)?
                .Select(node => node?.GetValue<string>() ?? string.Empty)
                .Where(path => path.Length > 0)
                .ToArray() ?? [];

            var canary = Path.Combine(
                Path.GetTempPath(),
                $"axiom-protection-test-{Guid.NewGuid():N}.txt");
            await File.WriteAllTextAsync(canary, "AXIOM SECURITY TEST").ConfigureAwait(true);

            try
            {
                var withCanary = new JsonArray(
                    originalPaths.Select(path => (JsonNode?)JsonValue.Create(path))
                        .Append(JsonValue.Create(canary))
                        .ToArray());
                var save = await _client.SaveSettingsAsync(
                    new JsonObject { ["protected_paths"] = withCanary },
                    CancellationToken.None).ConfigureAwait(true);
                if (!save.Ok)
                {
                    ProtectionTestText = "FAIL — could not add the canary to protected paths: " +
                        string.Join("; ", save.Errors);
                    return;
                }

                var decision = await RunGuardAsync(canary).ConfigureAwait(true);
                var action = ReadString(decision, "action");
                var message = ReadString(decision, "message");
                ProtectionTestText = string.Equals(action, "block", StringComparison.OrdinalIgnoreCase)
                    ? "PASS (guard-level) — Blackbox rejected the canary read. Agent hook execution was not exercised."
                    : $"FAIL/INCONCLUSIVE — the guard did not block the canary read. {message}".Trim();
            }
            finally
            {
                var cleanupError = await RemoveCanaryPathAsync(canary).ConfigureAwait(true);
                File.Delete(canary);
                if (cleanupError is not null)
                {
                    ProtectionTestText += $" Cleanup issue: {cleanupError}";
                }
            }
        }
        catch (Exception exception) when (exception is
            HttpRequestException or TaskCanceledException or InvalidDataException or
            System.Text.Json.JsonException or IOException or InvalidOperationException or
            TimeoutException or System.ComponentModel.Win32Exception)
        {
            ProtectionTestText = $"INCONCLUSIVE — {exception.Message}";
        }
        finally
        {
            await RefreshAsync().ConfigureAwait(true);
        }
    }

    private async Task<string?> RemoveCanaryPathAsync(string canary)
    {
        try
        {
            // Re-read immediately before cleanup so a concurrent user edit is preserved.
            var current = await _client.GetSettingsAsync(CancellationToken.None).ConfigureAwait(true);
            var currentPaths = (current["protected_paths"] as JsonArray)?
                .Select(node => node?.GetValue<string>() ?? string.Empty)
                .Where(path => path.Length > 0)
                .ToArray() ?? [];

            var remaining = currentPaths
                .Where(path => !string.Equals(path, canary, StringComparison.OrdinalIgnoreCase))
                .ToArray();

            if (remaining.Length == currentPaths.Length)
            {
                return null;
            }

            var patch = new JsonObject
            {
                ["protected_paths"] = new JsonArray(
                    remaining.Select(path => (JsonNode?)JsonValue.Create(path)).ToArray()),
            };
            var result = await _client.SaveSettingsAsync(patch, CancellationToken.None).ConfigureAwait(true);
            return result.Ok ? null : string.Join("; ", result.Errors);
        }
        catch (Exception exception) when (exception is
            HttpRequestException or TaskCanceledException or InvalidDataException or System.Text.Json.JsonException)
        {
            return $"could not remove the canary path: {exception.Message}";
        }
    }

    private async Task<JsonObject?> RunGuardAsync(string path)
    {
        var root = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Axiom",
            "modules",
            "blackbox",
            "agent-blackbox");
        var python = Path.Combine(root, "venv", "Scripts", "python.exe");
        var bridge = Path.Combine(root, "axiom-guard-bridge.py");
        if (!File.Exists(python) || !File.Exists(bridge))
        {
            throw new InvalidOperationException("Blackbox guard bridge is not installed.");
        }

        var startInfo = new ProcessStartInfo(python)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = root,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        startInfo.ArgumentList.Add(bridge);

        using var process = Process.Start(startInfo) ??
                            throw new InvalidOperationException("Could not start the Blackbox guard bridge.");
        await process.StandardInput.WriteAsync(new JsonObject
        {
            ["framework"] = "axiom-test",
            ["tool"] = "read",
            ["args"] = new JsonObject { ["path"] = path },
            ["session"] = "axiom-protection-test",
            ["call"] = Guid.NewGuid().ToString("N"),
        }.ToJsonString()).ConfigureAwait(true);
        process.StandardInput.Close();

        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();
        var exitTask = process.WaitForExitAsync();
        var completed = await Task.WhenAny(exitTask, Task.Delay(TimeSpan.FromSeconds(15))).ConfigureAwait(true);
        if (completed != exitTask)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
#pragma warning disable CA1031 // The timeout path must still report the timeout.
            catch (Exception)
#pragma warning restore CA1031
            {
            }

            throw new TimeoutException("Blackbox guard timed out.");
        }

        await exitTask.ConfigureAwait(true);
        var output = await outputTask.ConfigureAwait(true);
        _ = await errorTask.ConfigureAwait(true);
        return JsonNode.Parse(output) as JsonObject;
    }

    [RelayCommand]
    private async Task ToggleThreatSharingAsync()
    {
        if (!CanToggleThreatSharing)
        {
            return;
        }

        var enable = !ThreatSharingEnabled;
        if (enable)
        {
            var confirmed = await _ui.ConfirmAsync(
                "Enable threat sharing",
                "Allow Blackbox to send signed, redacted threat indicators to the community verified graph?\n\n" +
                "It never sends prompts, commands, file paths, credentials, model content or raw session ids. " +
                "Threat sharing is off by default.",
                "Enable sharing",
                destructive: false,
                CancellationToken.None).ConfigureAwait(true);

            if (!confirmed)
            {
                return;
            }
        }

        CanToggleThreatSharing = false;
        try
        {
            var result = await _client
                .SaveSettingsAsync(
                    new JsonObject { ["report"] = enable },
                    CancellationToken.None)
                .ConfigureAwait(true);

            if (!result.Ok)
            {
                ThreatSharingStatusText = "failed · " + (result.Errors.Count == 0
                    ? "Blackbox rejected the update."
                    : string.Join("; ", result.Errors));
                return;
            }

            var settings = result.Settings ??
                           await _client.GetSettingsAsync(CancellationToken.None).ConfigureAwait(true);
            var saved = ReadBool(settings, "report", enable);
            ThreatSharingEnabled = saved;
            ThreatSharingStatusText = saved ? "on · signed, redacted" : "off · opt in";
            HealthStatusText = saved
                ? "Threat sharing enabled, persisted and verified."
                : "Threat sharing disabled and verified.";
        }
        catch (Exception exception) when (exception is
                     HttpRequestException or TaskCanceledException or InvalidDataException or
                     System.Text.Json.JsonException)
        {
            ThreatSharingStatusText = "failed · " + exception.Message;
        }
        finally
        {
            CanToggleThreatSharing = true;
        }
    }

    /// <summary>
    /// Loads Axiom's own indicator preview from the service. The service only holds candidates for
    /// malware indicators an agent fetched plus high-confidence AI Analyst IOCs; it never sends them
    /// here, it only reports what is queued and what the last submission did.
    /// </summary>
    private async Task RefreshThreatShareAsync()
    {
        if (_serviceClient is null)
        {
            ThreatShareQueueText = "Indicator preview needs the local Axiom service.";
            HasThreatShareCandidates = false;
            CanSubmitThreatShare = false;
            return;
        }

        try
        {
            var status = await _serviceClient
                .SendAsync<ThreatShareQueueStatus>(
                    IpcCommandTypes.ThreatShareStatus,
                    null,
                    CancellationToken.None)
                .ConfigureAwait(true);
            ApplyThreatShareStatus(status);
        }
        catch (Exception exception) when (exception is
                     ServiceUnavailableException or TimeoutException or
                     System.Text.Json.JsonException or System.IO.IOException)
        {
            ThreatShareQueueText = "Indicator preview is unavailable: " + exception.Message;
            HasThreatShareCandidates = false;
            CanSubmitThreatShare = false;
        }
    }

    private void ApplyThreatShareStatus(ThreatShareQueueStatus status)
    {
        _threatShareStatus = status;
        ThreatShareReporterText = ThreatShareCli.DescribeReporterProfile();
        var pending = status.Items
            .Where(item => item.State is ThreatShareState.Pending or ThreatShareState.Deferred
                or ThreatShareState.Unverified)
            .Take(8)
            .Select(item =>
            {
                var novelty = ThreatShareCli.InspectLocalGraphNovelty(item.Candidate.Id);
                return novelty == item.Candidate.NoveltyStatus
                    ? item
                    : item with { Candidate = item.Candidate with { NoveltyStatus = novelty } };
            })
            .ToList();

        ThreatShareCandidates.Clear();
        foreach (var item in pending)
        {
            ThreatShareCandidates.Add(item);
        }

        var submittedItems = status.Items
            .Where(item => item.State == ThreatShareState.Submitted)
            .OrderByDescending(item => item.AttemptedUtc ?? item.Candidate.ObservedUtc)
            .Take(5)
            .ToList();
        SubmittedThreatShares.Clear();
        foreach (var item in submittedItems)
        {
            SubmittedThreatShares.Add(item);
        }

        HasThreatShareCandidates = pending.Count > 0;
        HasSubmittedThreatShares = submittedItems.Count > 0;
        CanSubmitThreatShare = pending.Any(item => IsReady(item) && item.Candidate.CanPublishToCommunity) &&
                               ThreatSharingEnabled &&
                               status.TodaySubmitted < status.DailyLimit;
        CanShareThreatShareItem = pending.Count > 0 &&
                                  ThreatSharingEnabled &&
                                  status.TodaySubmitted < status.DailyLimit;

        var consent = ThreatShareCli.ConsentPresent()
            ? string.Empty
            : " Blackbox still needs the reporter terms accepted in its own settings.";

        var deferred = status.Deferred > 0
            ? $" {status.Deferred} deferred after a transient failure; retry when it is due."
            : string.Empty;

        var unverified = status.Unverified > 0
            ? $" {status.Unverified} awaiting confirmation: the reporter outcome was unknown, so retry only after you check."
            : string.Empty;

        var sandboxNote = ThreatShareCli.IsSandboxModeEnabled()
            ? "Sandbox mode is active."
            : "Shared statements are signed under CC0 1.0 and replicated; curators exclusively decide novelty.";

        ThreatShareQueueText =
            $"{status.Pending} waiting for your review, {status.Submitted} shared in total, " +
            $"{status.TodaySubmitted}/{status.DailyLimit} today.{deferred}{unverified} " +
            (ThreatSharingEnabled
                ? $"Sharing is on; every share is checked locally (reporter terms, signing key, category, novelty) before anything is signed. {sandboxNote}"
                : $"Sharing is off; nothing is signed or sent. {sandboxNote}") +
            consent;
    }

    [RelayCommand]
    private Task SubmitThreatShareAsync()
    {
        if (_threatShareStatus is not { } status)
        {
            return Task.CompletedTask;
        }

        var pending = ThreatShareCandidates
            .Where(item => IsReady(item) && item.Candidate.CanPublishToCommunity)
            .Take(Math.Max(0, status.DailyLimit - status.TodaySubmitted))
            .ToList();
        if (pending.Count == 0 && ThreatShareCandidates.Any(IsReady))
        {
            var reason = ThreatShareCandidates.First(IsReady).Candidate.EligibilityExplanation;
            ThreatShareActionText = string.IsNullOrWhiteSpace(reason)
                ? "Queued candidates require stronger evidence before community publication."
                : reason;
            return Task.CompletedTask;
        }

        return SubmitThreatShareItemsAsync(pending);
    }

    [RelayCommand]
    private Task ShareThreatShareItemAsync(ThreatShareItem? item)
    {
        if (item is null)
        {
            return Task.CompletedTask;
        }

        if (item.State == ThreatShareState.Submitted)
        {
            return RetractThreatShareItemAsync(item);
        }

        if (!item.Candidate.CanPublishToCommunity)
        {
            ThreatShareActionText = string.IsNullOrWhiteSpace(item.Candidate.EligibilityExplanation)
                ? "This indicator is kept local until stronger evidence is attached."
                : item.Candidate.EligibilityExplanation;
            return Task.CompletedTask;
        }

        if (item.State == ThreatShareState.Unverified)
        {
            // The row says "Retry": the user has seen that the previous attempt may have published.
            return SubmitThreatShareItemsAsync([item]);
        }

        if (!IsReady(item))
        {
            ThreatShareActionText =
                $"This indicator is deferred after a transient failure. Retry after " +
                $"{item.NextAttemptUtc?.ToLocalTime():HH:mm}.";
            return Task.CompletedTask;
        }

        return SubmitThreatShareItemsAsync([item]);
    }

    [RelayCommand]
    private Task RetractThreatShareAsync(ThreatShareItem? item) =>
        item is null || item.State != ThreatShareState.Submitted
            ? Task.CompletedTask
            : RetractThreatShareItemAsync(item);

    private async Task RetractThreatShareItemAsync(ThreatShareItem item)
    {
        if (_serviceClient is null || _threatShareSubmitting)
        {
            return;
        }

        var confirmed = await _ui.ConfirmAsync(
            "Retract community report",
            $"Send a signed retraction for {item.Candidate.Id}?\n\n" +
            "Conforming Blackbox nodes stop counting your report, though existing CC0 replicas on the network cannot be erased.",
            "Retract report",
            destructive: true,
            CancellationToken.None).ConfigureAwait(true);
        if (!confirmed)
        {
            return;
        }

        _threatShareSubmitting = true;
        ThreatShareActionText = $"Submitting retraction for {item.Candidate.Value}...";
        try
        {
            var result = await _cli.RetractAsync(item.Candidate.Id, CancellationToken.None).ConfigureAwait(true);
            if (result.Status != ThreatShareReportStatus.Retracted)
            {
                ThreatShareActionText = $"Retraction status: {result.Outcome}";
                return;
            }

            var latest = await _serviceClient
                .SendAsync<ThreatShareQueueStatus>(
                    IpcCommandTypes.ThreatShareRecord,
                    new ThreatShareRecordRequest
                    {
                        Id = item.Candidate.Id,
                        Submitted = false,
                        Retracted = true,
                        Outcome = result.Outcome,
                    },
                    CancellationToken.None)
                .ConfigureAwait(true);
            ApplyThreatShareStatus(latest);
            ThreatShareActionText = $"Retracted {item.Candidate.Value}. {result.Outcome}";
        }
        catch (Exception exception) when (exception is
                     ServiceUnavailableException or TimeoutException or
                     System.Text.Json.JsonException or System.IO.IOException)
        {
            ThreatShareActionText = "Retraction failed: " + exception.Message;
        }
        finally
        {
            _threatShareSubmitting = false;
        }
    }

    private static bool IsReady(ThreatShareItem item) =>
        item.State == ThreatShareState.Pending ||
        (item.State == ThreatShareState.Deferred &&
         (item.NextAttemptUtc is null || item.NextAttemptUtc <= DateTimeOffset.UtcNow));

    private async Task SubmitThreatShareItemsAsync(List<ThreatShareItem> items)
    {
        if (_serviceClient is null || _threatShareSubmitting)
        {
            return;
        }

        if (!ThreatSharingEnabled)
        {
            ThreatShareActionText = "Turn threat sharing on before sharing indicators.";
            return;
        }

        if (_threatShareStatus is { } status && status.TodaySubmitted >= status.DailyLimit)
        {
            ThreatShareActionText = "The daily sharing cap is reached; nothing was sent.";
            return;
        }

        var publishable = items.Where(item => item.Candidate.CanPublishToCommunity).ToList();
        var heldLocal = items.Count - publishable.Count;
        if (publishable.Count == 0)
        {
            ThreatShareActionText = heldLocal > 0
                ? $"Kept {heldLocal} item(s) local: {items[0].Candidate.EligibilityExplanation}"
                : "Nothing is waiting for review.";
            return;
        }

        _threatShareSubmitting = true;
        CanSubmitThreatShare = false;
        ThreatShareActionText = "Submitting through the Blackbox reporter...";
        var ruleset = ThreatShareCli.ReadRuleset();
        var consent = ThreatShareCli.ConsentPresent();
        var key = ThreatShareCli.ReporterKeyPresent();
        var blocked = new List<string>();
        try
        {
            var shared = 0;
            var deferred = 0;
            var unverified = 0;
            var rejected = 0;
            var capReached = false;
            ThreatShareQueueStatus? latest = null;
            foreach (var item in publishable)
            {
                var preflight = ThreatSharePreflight.Evaluate(
                    item.Candidate, ThreatSharingEnabled, consent, key, ruleset);
                if (!preflight.Ready)
                {
                    blocked.Add($"{item.Candidate.Value} ({preflight.FailureText})");
                    continue;
                }

                var result = await _cli
                    .ReportAsync(item.Candidate, CancellationToken.None)
                    .ConfigureAwait(true);

                // The cap is not an outcome for this indicator: leave it pending for tomorrow.
                if (result.Status == ThreatShareReportStatus.CapReached)
                {
                    capReached = true;
                    break;
                }

                latest = await _serviceClient
                    .SendAsync<ThreatShareQueueStatus>(
                        IpcCommandTypes.ThreatShareRecord,
                        new ThreatShareRecordRequest
                        {
                            Id = item.Candidate.Id,
                            Submitted = result.Submitted,
                            Deferred = result.Status == ThreatShareReportStatus.RetryableFailure,
                            Ambiguous = result.Ambiguous,
                            Outcome = result.Outcome,
                        },
                        CancellationToken.None)
                    .ConfigureAwait(true);

                switch (result.Status)
                {
                    case ThreatShareReportStatus.Shared:
                    case ThreatShareReportStatus.AlreadyShared:
                        shared++;
                        break;
                    case ThreatShareReportStatus.RetryableFailure:
                        deferred++;
                        break;
                    case ThreatShareReportStatus.UnknownOutcome:
                        unverified++;
                        break;
                    default:
                        rejected++;
                        break;
                }
            }

            if (latest is not null)
            {
                ApplyThreatShareStatus(latest);
            }

            ThreatShareActionText =
                $"Submitted {shared}, deferred {deferred}, awaiting confirmation {unverified}, rejected {rejected}." +
                (capReached
                    ? " The daily cap is reached; the remaining indicators stay queued."
                    : string.Empty) +
                (blocked.Count > 0
                    ? $" {blocked.Count} not sent: {string.Join("; ", blocked.Take(3))}."
                    : string.Empty);
        }
        catch (Exception exception) when (exception is
                     ServiceUnavailableException or TimeoutException or
                     System.Text.Json.JsonException or System.IO.IOException)
        {
            ThreatShareActionText = "Submission failed: " + exception.Message;
        }
        finally
        {
            _threatShareSubmitting = false;
        }
    }

    [RelayCommand]
    private async Task DismissThreatShareAsync(ThreatShareItem? item)
    {
        if (_serviceClient is null || item is null)
        {
            return;
        }

        try
        {
            var status = await _serviceClient
                .SendAsync<ThreatShareQueueStatus>(
                    IpcCommandTypes.ThreatShareDismiss,
                    new ThreatShareDismissRequest { Id = item.Candidate.Id },
                    CancellationToken.None)
                .ConfigureAwait(true);
            ApplyThreatShareStatus(status);
            ThreatShareActionText = $"Dismissed {item.Candidate.Value}.";
        }
        catch (Exception exception) when (exception is
                     ServiceUnavailableException or TimeoutException or
                     System.Text.Json.JsonException or System.IO.IOException)
        {
            ThreatShareActionText = "Could not dismiss the indicator: " + exception.Message;
        }
    }
    [RelayCommand]
    private async Task SetBlackboxModeAsync(string? mode)
    {
        if (mode is not ("audit" or "block"))
        {
            return;
        }

        try
        {
            var result = await _client.SaveSettingsAsync(
                new JsonObject { ["mode"] = mode },
                CancellationToken.None).ConfigureAwait(true);

            if (!result.Ok || result.Settings is null)
            {
                HealthStatusText = "Mode change failed: " + (result.Errors.Count == 0
                    ? "Blackbox rejected the update."
                    : string.Join("; ", result.Errors));
                return;
            }

            var savedMode = ReadString(result.Settings, "mode");
            if (!string.Equals(savedMode, mode, StringComparison.OrdinalIgnoreCase))
            {
                HealthStatusText = "Mode verification failed: Blackbox did not persist the requested mode.";
                return;
            }

            HealthStatusText = $"Mode changed to {mode} and verified at {DateTimeOffset.Now:HH:mm:ss}.";
            await Security.RefreshCommand.ExecuteAsync(null).ConfigureAwait(true);
            await RefreshAsync().ConfigureAwait(true);
        }
        catch (Exception exception) when (exception is
            HttpRequestException or TaskCanceledException or InvalidDataException or System.Text.Json.JsonException)
        {
            HealthStatusText = $"Mode change failed: {exception.Message}";
        }
    }

    [RelayCommand]
    private async Task InstallHooksAsync()
    {
        await Security.InstallAgentHooksCommand.ExecuteAsync(null).ConfigureAwait(true);
        await RefreshAllAsync().ConfigureAwait(true);
    }

    [RelayCommand]
    private async Task ConfigureAsync()
    {
        await _dialogs.ShowSettingsAsync(_client, CancellationToken.None).ConfigureAwait(true);
        await RefreshAsync().ConfigureAwait(true);
    }

    [RelayCommand]
    private async Task ViewDkgLogAsync()
    {
        var candidates = new[]
        {
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Axiom",
                "modules",
                "dkg-home",
                "daemon.log"),
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "hermes",
                "blackbox",
                "dkg",
                "daemon.log"),
        };

        var path = candidates.FirstOrDefault(File.Exists);
        var text = path is null
            ? "No DKG daemon.log was found at:\n" + string.Join("\n", candidates)
            : ReadBoundedLog(path);

        await _dialogs.ShowLogAsync("DKG daemon log", text, CancellationToken.None).ConfigureAwait(true);
    }

    private static string ReadBoundedLog(string path)
    {
        try
        {
            var lines = File.ReadLines(path).TakeLast(200).ToArray();
            var text = string.Join('\n', lines);
            if (text.Length > 64 * 1024)
            {
                text = text[^Math.Min(text.Length, 64 * 1024)..];
            }

            text = Regex.Replace(
                text,
                @"(?i)(token|secret|password|api[_-]?key)\s*[:=]\s*\S+",
                "$1=[redacted]");
            return Regex.Replace(text, @"[A-Fa-f0-9]{32,}", "[redacted-hex]");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return $"Could not read {path}: {exception.Message}";
        }
    }

    [RelayCommand]
    private async Task OpenDashboardAsync()
    {
        try
        {
            await _ui.OpenExternalAsync("http://127.0.0.1:9700", CancellationToken.None).ConfigureAwait(true);
        }
        catch (Exception exception) when (exception is
                     System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException)
        {
            ActivityStatusText = $"Could not open the Blackbox dashboard: {exception.Message}";
        }
    }

    [RelayCommand]
    private void SetActivityFilter(string? filter)
    {
        SelectedActivityFilter = filter ?? "All Activity";
        ApplyFilters();
    }

    [RelayCommand]
    private void SetAgentFilter(string? filter)
    {
        SelectedAgentFilter = filter ?? "All agents";
        ApplyFilters();
    }

    [RelayCommand]
    private void SetSeverityFilter(string? filter)
    {
        SelectedSeverityFilter = filter ?? "All severities";
        ApplyFilters();
    }

    partial void OnSelectedActivityFilterChanged(string value) => ApplyFilters();

    partial void OnSelectedAgentFilterChanged(string value) => ApplyFilters();

    partial void OnSelectedSeverityFilterChanged(string value) => ApplyFilters();

    internal void ApplyActivity(BlackboxAuditPage page)
    {
        _allActivity.Clear();
        _allActivity.AddRange(NormalizeActivity(page.Entries, ReadFrameworkMap()));
        _activityTotal = Math.Max(page.Total, _allActivity.Count);
        UpdateActivitySummary();
        ApplyFilters();
    }

    internal void MergeActivity(BlackboxAuditPage page)
    {
        _activityTotal = Math.Max(page.Total, _allActivity.Count);
        var incoming = NormalizeActivity(page.Entries, ReadFrameworkMap());
        var seen = _allActivity
            .Select(ActivityIdentity)
            .ToHashSet(StringComparer.Ordinal);
        var added = incoming
            .Where(entry => seen.Add(ActivityIdentity(entry)))
            .ToList();

        if (added.Count > 0)
        {
            _allActivity.AddRange(added);
            _allActivity.Sort((left, right) =>
                (right.Timestamp ?? DateTimeOffset.MinValue)
                .CompareTo(left.Timestamp ?? DateTimeOffset.MinValue));
        }

        UpdateActivitySummary();
        if (added.Count > 0)
        {
            ApplyFilters();
        }
    }

    private static List<BlackboxAuditEntry> NormalizeActivity(
        IEnumerable<BlackboxAuditEntry> entries,
        Dictionary<string, string> frameworkBySession)
    {
        var source = entries.ToList();
        var toolActions = source
            .Where(entry => entry.Event == "pre_tool_call" &&
                            entry.Detail?.ToolCallId is { Length: > 0 } &&
                            entry.Action.Length > 0)
            .GroupBy(entry => entry.Detail!.ToolCallId, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.First().Action, StringComparer.Ordinal);

        var normalized = new List<BlackboxAuditEntry>(source.Count);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var original in source)
        {
            var entry = original;
            if (entry.Event == "post_tool_call" &&
                entry.Detail?.ToolCallId is { Length: > 0 } toolCallId &&
                toolActions.TryGetValue(toolCallId, out var toolAction))
            {
                entry = entry with { Action = toolAction };
            }

            if (string.Equals(entry.Agent, "hermes", StringComparison.OrdinalIgnoreCase) &&
                frameworkBySession.TryGetValue(entry.SessionFull, out var framework) &&
                !string.Equals(framework, "hermes", StringComparison.OrdinalIgnoreCase))
            {
                entry = entry with { Agent = framework };
            }

            var key = ActivityIdentity(entry);
            if (seen.Add(key))
            {
                normalized.Add(entry);
            }
        }

        return normalized;
    }

    private Dictionary<string, string> ReadFrameworkMap()
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var item in _agentEvidence.ReadRecent(4000).OrderBy(item => item.Timestamp))
        {
            if (!string.IsNullOrWhiteSpace(item.Session) && !string.IsNullOrWhiteSpace(item.Framework))
            {
                map[item.Session] = item.Framework;
            }
        }

        return map;
    }

    private void UpdateActivitySummary()
    {
        var sessions = _allActivity.Count(entry => entry.Category == "sessions");
        var apiCalls = _allActivity.Count(entry => entry.Category == "api");
        var toolCalls = _allActivity.Count(entry => entry.Category == "tools");
        var installs = _allActivity.Count(entry => entry.Category == "installs");
        var files = _allActivity.Count(entry => entry.Category == "file");
        var threats = _allActivity.Count(entry => entry.IsThreat);

        SessionCount = sessions;
        ApiCallCount = apiCalls;
        ToolCallCount = toolCalls;
        InstallCount = installs;
        FileAccessCount = files;
        ThreatCount = threats;
        BlockSummary = AgentBlockSummaryBuilder.Build(_agentEvidence.ReadRecent(4000));

        ActivityBreakdownText =
            $"{sessions} sessions · {apiCalls} API calls · {toolCalls} tool calls · " +
            $"{installs} installs · {files} file accesses · {threats} threats";
        CanLoadMoreActivity = _allActivity.Count < _activityTotal && _allActivity.Count < ActivityMax;
        ActivityStatusText = _allActivity.Count == 0
            ? "No recorded agent activity yet."
            : _allActivity.Count >= _activityTotal
                ? $"Showing all {_allActivity.Count} recorded event(s)."
                : $"Showing {_allActivity.Count} of {_activityTotal} recorded event(s).";

        UpdateActivityFreshness();
    }

    private void UpdateActivityFreshness()
    {
        var newest = _allActivity.Count == 0
            ? (DateTimeOffset?)null
            : _allActivity.Max(entry => entry.Timestamp);
        if (_latestEvidenceUtc is { } evidenceUtc && (newest is null || evidenceUtc > newest))
        {
            newest = evidenceUtc;
        }

        if (_latestSessionUtc is { } sessionUtc && (newest is null || sessionUtc > newest))
        {
            newest = sessionUtc;
        }

        var now = DateTimeOffset.UtcNow;
        HasStaleAgentActivity = ActivityFreshness.IsStale(newest, now, _hasLiveSession);
        ActivityFreshnessText = ActivityFreshness.Describe(newest, now, _hasLiveSession);
    }

    internal void ApplyFindings(BlackboxFindingPage page)
    {
        var selected = SelectedFinding;
        _allFindings.Clear();
        _allFindings.AddRange(page.Findings.OrderByDescending(finding => finding.Timestamp));

        // The audit refreshes every 15 seconds. Sync in place instead of calling Clear(), so row
        // containers stay attached across refreshes while preserving the active selection.
        if (!Findings.SequenceEqual(_allFindings))
        {
            var selectedKey = selected is null ? null : FindingIdentity(selected);
            _preservingFindingSelection = true;
            CollectionSync.SyncInPlace(Findings, _allFindings);

            _preservingFindingSelection = false;
            SelectedFinding = selectedKey is null
                ? null
                : Findings.FirstOrDefault(finding => FindingIdentity(finding) == selectedKey);
            HasSelectedFinding = SelectedFinding is not null;
        }

        var blocked = _allFindings.Count(finding => finding.IsBlocked);
        var flagged = _allFindings.Count(finding => finding.IsFlagged);
        var fileAccess = _allFindings.Count(finding =>
            string.Equals(finding.Category, "fileaccess", StringComparison.OrdinalIgnoreCase));
        var unresolved = _allFindings.Count(finding => !finding.IsBlocked);

        FindingCount = _allFindings.Count;
        BlockedFindingCount = blocked;
        FlaggedFindingCount = flagged;

        ProtectedPathViolationsText = $"{fileAccess} protected-path finding(s)";
        UnresolvedText = $"{unresolved} unresolved or unverified finding(s)";
        SummaryText = $"{_allFindings.Count} finding(s): {blocked} blocked, {flagged} flagged.";

        var lastBlocked = _allFindings
            .Where(finding => finding.IsBlocked)
            .OrderByDescending(finding => finding.Timestamp)
            .FirstOrDefault();
        LastBlockedText = lastBlocked is null
            ? "No blocked action observed."
            : $"{lastBlocked.TimeText} · {lastBlocked.Agent} · {lastBlocked.Tool} · {lastBlocked.Identifier}";
    }

    private static string FindingIdentity(BlackboxFinding finding) =>
        $"{finding.Timestamp?.UtcTicks}|{finding.Identifier}|{finding.Agent}|{finding.Title}";

    partial void OnSelectedFindingChanged(BlackboxFinding? value)
    {
        if (value is null && _preservingFindingSelection)
        {
            return;
        }

        HasSelectedFinding = value is not null;
    }

    private async Task<BlackboxVerifiedSync?> TryGetVerifiedSyncAsync()
    {
        try
        {
            var dashboard = await _client.GetVerifiedSyncAsync(CancellationToken.None).ConfigureAwait(true);
            var local = BlackboxLocalState.TryReadSync();
            if (local is not null && local.VerifiedRules > dashboard.VerifiedRules)
            {
                return local;
            }

            return dashboard;
        }
        catch (Exception exception) when (exception is
            HttpRequestException or TaskCanceledException or InvalidDataException or System.Text.Json.JsonException)
        {
            return BlackboxLocalState.TryReadSync();
        }
    }

    private async Task<BlackboxGraphPage?> TryGetVerifiedGraphAsync()
    {
        try
        {
            return await _client.GetVerifiedGraphAsync(
                VerifiedGraphPageSize,
                0,
                CancellationToken.None).ConfigureAwait(true);
        }
        catch (Exception exception) when (exception is
            HttpRequestException or TaskCanceledException or InvalidDataException or System.Text.Json.JsonException)
        {
            return BlackboxLocalState.TryReadGraph();
        }
    }

    private void ApplyVerifiedSync(BlackboxVerifiedSync? sync)
    {
        if (sync is null)
        {
            VerifiedSyncState = "UNAVAILABLE";
            VerifiedSyncStateDetail =
                "The local Blackbox dashboard did not return verified-sync state. " +
                "Local rules may still protect, but verified graph coverage is unknown.";
            VerifiedSyncPercent = 0;
            VerifiedSyncProgressText = "—";
            VerifiedSyncCountsText = "Downloaded — · compiled — · verified rules —";
            VerifiedSyncLookupText = "Verified-answer lookups: unknown";
            return;
        }

        var state = sync.State.Trim().ToLowerInvariant();
        var hasCompiledRules = sync.VerifiedRules > 0 || (sync.CompiledAssets ?? 0) > 0;
        var nodeUnavailableWithRules = sync.IsOffline && hasCompiledRules;
        VerifiedSyncState = state switch
        {
            "synced" => "SYNCED",
            "syncing" => "SYNCING",
            "unavailable" => nodeUnavailableWithRules ? "DEGRADED" : "NODE OFFLINE",
            "unknown" => "UNKNOWN",
            _ => state.Length == 0 ? "UNKNOWN" : state.ToUpperInvariant(),
        };

        VerifiedSyncPercent = sync.DisplayPercent;
        VerifiedSyncProgressText = sync.PercentCompiled is { } compiled
            ? $"{compiled.ToString("0.0", CultureInfo.InvariantCulture)}% compiled"
            : "compiled —";
        VerifiedSyncCountsText =
            $"{CountText(sync.DownloadedAssets)} / {CountText(sync.GraphAssets)} downloaded · " +
            $"{CountText(sync.CompiledAssets)} / {CountText(sync.GraphAssets)} compiled · " +
            $"{CountText(sync.DownloadedTriples)} triples · " +
            $"{CountText(sync.VerifiedRules)} verified rules";

        VerifiedSyncLookupText = string.IsNullOrWhiteSpace(sync.Lookups.Label)
            ? "Verified-answer lookups: unknown"
            : $"Verified-answer lookups: {sync.Lookups.Label}";

        var detail = sync.IsOffline
            ? nodeUnavailableWithRules
                ? "The node probe timed out, but the last compiled verified rules remain loaded. The graph may be catching up."
                : "The local DKG node is not answering. Downloaded data is not synchronized, so verified graph coverage is not available."
            : sync.IsSyncing
                ? (string.IsNullOrWhiteSpace(sync.PhaseText)
                    ? "The local dashboard is syncing the verified graph."
                    : sync.PhaseText)
                : string.Equals(state, "synced", StringComparison.Ordinal)
                    ? (string.Equals(sync.Phase, "peer-ram", StringComparison.OrdinalIgnoreCase) &&
                       !string.IsNullOrWhiteSpace(sync.PhaseText)
                        ? sync.PhaseText
                        : $"The local graph holds {CountText(sync.VerifiedRules)} compiled verified rule(s).")
                    : string.IsNullOrWhiteSpace(sync.PhaseText)
                        ? $"The dashboard reports verified-graph state '{sync.State}'."
                        : sync.PhaseText;

        if (!string.IsNullOrWhiteSpace(sync.CheckedAt))
        {
            detail += $" Last checked {sync.CheckedAt}.";
        }

        VerifiedSyncStateDetail = detail;
    }

    private void ApplyVerifiedGraph(BlackboxGraphPage page)
    {
        var threats = page.Threats
            .Take(VerifiedGraphPageSize)
            .ToList();

        VerifiedGraphThreats = threats;
        VerifiedGraphPreview = threats.Take(VerifiedGraphPreviewSize).ToList();
        VerifiedGraphCategoryTotals = page.CategoryTotals;
        VerifiedGraphTotal = page.Total;

        if (page.Total == 0 && threats.Count == 0)
        {
            VerifiedGraphListStatus = VerifiedSyncState switch
            {
                "NODE OFFLINE" => "The verified graph is not loaded while the local DKG node is offline.",
                "DEGRADED" => "The graph sample could not be read while the node probe timed out.",
                _ => "The verified graph currently contains no threats.",
            };
            return;
        }

        VerifiedGraphListStatus = page.Partial || page.Total > VerifiedGraphPreview.Count
            ? $"Showing {VerifiedGraphPreview.Count} of {page.Total} verified threat(s); the graph above uses {threats.Count} loaded node(s)."
            : $"Showing all {page.Total} verified threat(s).";
    }

    private static string CountText(int value) =>
        value.ToString("N0", CultureInfo.InvariantCulture);

    private static string CountText(int? value) =>
        value is { } number ? CountText(number) : "—";

    private static string CountText(long? value) =>
        value is { } number ? number.ToString("N0", CultureInfo.InvariantCulture) : "—";

    private void ApplyHealth(JsonObject settings, JsonObject graph)
    {
        var mode = ReadString(settings, "mode") ?? "unknown";
        var report = ReadBool(settings, "report", false);
        BlackboxHealthText = $"Dashboard online · mode {mode} · community sharing {(report ? "ON" : "off")}";
        ThreatSharingEnabled = report;
        ThreatSharingStatusText = report ? "on · signed, redacted" : "off · opt in";
        CanToggleThreatSharing = true;

        var dkgUrl = ReadString(graph, "dkg_url") ?? "unknown";
        var reachable = ReadBool(graph, "node_reachable", false);
        DkgHealthText = $"Blackbox DKG: {dkgUrl} · {(reachable ? "reachable" : "offline")}";

        var dkgModule = Security.Modules.FirstOrDefault(module => module.Name == "OriginTrail DKG");
        AxiomDkgHealthText = dkgModule is null
            ? "DKG: unknown"
            : $"DKG: {dkgModule.Status} · {dkgModule.Detail}";

        var ruleset = graph["ruleset"] as JsonObject;
        var verified = ReadInt(ruleset, "injection") + ReadInt(ruleset, "escalation") +
                       ReadInt(ruleset, "dependency") + ReadInt(ruleset, "fileaccess") +
                       ReadInt(ruleset, "skill") + ReadInt(ruleset, "ioc");
        var community = ReadInt(graph, "community");
        GraphHealthText = $"Verified graph: {verified} rule(s) · community: {community}";

        var lastSync = ReadString(graph, "last_sync");
        HealthStatusText = reachable
            ? $"Blackbox dashboard and DKG are reachable. Last sync: {lastSync ?? "not reported"}."
            : "Dashboard is online, but its configured DKG node is offline. Local rules may still protect; verified graph coverage is not synchronized.";
    }

    private async Task RefreshSessionsAsync()
    {
        if (_agentSessions is null)
        {
            SessionStatusText = "Host session metadata is unavailable in this build.";
            return;
        }

        if (DateTimeOffset.UtcNow - _lastSessionRefresh < TimeSpan.FromSeconds(15))
        {
            return;
        }

        _lastSessionRefresh = DateTimeOffset.UtcNow;
        var sessions = await Task.Run(_agentSessions.Read).ConfigureAwait(true);
        _latestSessionUtc = sessions.Count == 0
            ? null
            : sessions.Max(item => (DateTimeOffset?)item.LastSeenUtc);
        _hasLiveSession = sessions.Any(item => item.HostLive);

        SessionGroups.Clear();
        foreach (var group in sessions
                     .GroupBy(item => item.Framework, StringComparer.OrdinalIgnoreCase)
                     .OrderBy(group => group.Key, StringComparer.OrdinalIgnoreCase))
        {
            var rows = group
                .OrderByDescending(item => item.LastSeenUtc)
                .Take(8)
                .Select(item =>
                {
                    var workspace = item.Workspace.TrimEnd('\\', '/');
                    var title = string.IsNullOrWhiteSpace(item.Title)
                        ? Path.GetFileName(workspace)
                        : item.Title;
                    if (string.IsNullOrWhiteSpace(title))
                    {
                        title = "Untitled session";
                    }

                    var local = item.LastSeenUtc.ToLocalTime();
                    var when = local.Date == DateTime.Today
                        ? local.ToString("HH:mm", CultureInfo.InvariantCulture)
                        : local.ToString("MM-dd HH:mm", CultureInfo.InvariantCulture);
                    return new AgentSessionRow(
                        ProviderLabel(item.Framework),
                        title,
                        workspace,
                        when,
                        item.HostLive);
                })
                .ToArray();
            if (rows.Length > 0)
            {
                SessionGroups.Add(new AgentSessionGroup(ProviderLabel(group.Key), rows));
            }
        }

        SessionStatusText = SessionGroups.Count == 0
            ? "No Claude Code, Codex, Antigravity or OpenCode/OpenChamber sessions were found. Hooks can still be installed and trusted."
            : $"{SessionGroups.Sum(group => group.Sessions.Count)} host session(s) from Claude Code, Codex, Antigravity and OpenCode/OpenChamber metadata. 'Not running' is a historical session, not an error.";
        UpdateActivityFreshness();
    }

    private static string ProviderLabel(string framework) =>
        framework.ToLowerInvariant() switch
        {
            "claude" or "claude-code" => "Claude Code",
            "codex" => "Codex",
            "antigravity" => "Antigravity",
            "opencode" or "openchamber" => "OpenCode / OpenChamber",
            _ => framework,
        };

    private void ApplyHookEvidence()
    {
        var recent = _agentEvidence.ReadRecent(60)
            .OrderByDescending(entry => entry.Timestamp)
            .Take(30)
            .ToList();

        if (!HookEvidence.SequenceEqual(recent))
        {
            var selected = SelectedHookEvidence;
            CollectionSync.SyncInPlace(HookEvidence, recent);

            SelectedHookEvidence = selected is null
                ? null
                : HookEvidence.FirstOrDefault(item =>
                    item.Timestamp == selected.Timestamp &&
                    string.Equals(item.Framework, selected.Framework, StringComparison.Ordinal) &&
                    string.Equals(item.EventType, selected.EventType, StringComparison.Ordinal) &&
                    string.Equals(item.Tool, selected.Tool, StringComparison.Ordinal) &&
                    string.Equals(item.Decision, selected.Decision, StringComparison.Ordinal));
        }

        _latestEvidenceUtc = HookEvidence.Count == 0
            ? null
            : HookEvidence.Max(item => (DateTimeOffset?)item.Timestamp);
        UpdateActivityFreshness();
    }

    private async Task RefreshEnforcementAsync(bool guardAvailable, string? hookMode)
    {
        EnforcementStatusDto? status = null;
        EnforcementReceiptsSnapshotDto? receipts = null;

        if (_serviceClient is not null)
        {
            try
            {
                status = await _serviceClient
                    .SendAsync<EnforcementStatusDto>(IpcCommandTypes.EnforcementStatus, null, CancellationToken.None)
                    .ConfigureAwait(true);
                receipts = await _serviceClient
                    .SendAsync<EnforcementReceiptsSnapshotDto>(IpcCommandTypes.EnforcementReceipts, null, CancellationToken.None)
                    .ConfigureAwait(true);
            }
            catch (Exception exception) when (exception is
                ServiceUnavailableException or TimeoutException or System.Text.Json.JsonException or IOException)
            {
                // Leave controller telemetry null when the service pipe is absent or busy.
            }
        }

        var normalizedMode = hookMode?.Trim().ToLowerInvariant() is "audit" or "block"
            ? hookMode.Trim().ToLowerInvariant()
            : Security.BlackboxModeText?.Trim().ToLowerInvariant() is "audit" or "block"
                ? Security.BlackboxModeText.Trim().ToLowerInvariant()
                : null;
        var localHookDenies = HookEvidence.Count(entry =>
            string.Equals(entry.EffectiveChannel, "HOST_DENY_SENT", StringComparison.Ordinal));

        Enforcement = EnforcementSurfaceState.FromReceiptsAndStatus(
            status,
            receipts,
            guardAvailable,
            normalizedMode,
            localHookDenies);
    }

    partial void OnSelectedActivityChanged(BlackboxAuditEntry? value)
    {
        if (value is null && _preservingActivitySelection)
        {
            return;
        }

        var identity = value is null ? null : ActivityIdentity(value);
        if (value is not null && HasSelectedActivity && identity == _selectedActivityIdentity)
        {
            return;
        }

        _selectedActivityIdentity = identity;
        UpdateSelectedActivityDetails();
    }

    private void ApplyFilters()
    {
        var severityFilter = SelectedSeverityFilter == "All severities"
            ? null
            : SelectedSeverityFilter.ToLowerInvariant();
        var filtered = new List<BlackboxAuditEntry>();
        foreach (var entry in _allActivity)
        {
            if (!MatchesActivityFilter(entry, SelectedActivityFilter))
            {
                continue;
            }

            if (SelectedAgentFilter != "All agents" &&
                !string.Equals(entry.Agent, SelectedAgentFilter, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (severityFilter is not null &&
                !string.Equals(entry.Severity, severityFilter, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            filtered.Add(entry);
        }

        if (Activity.SequenceEqual(filtered))
        {
            return;
        }

        var selectedKey = SelectedActivity is null ? null : ActivityIdentity(SelectedActivity);
        _preservingActivitySelection = true;
        CollectionSync.SyncInPlace(Activity, filtered);

        _preservingActivitySelection = false;
        SelectedActivity = selectedKey is null
            ? null
            : Activity.FirstOrDefault(entry => ActivityIdentity(entry) == selectedKey);
        if (SelectedActivity is null && (HasSelectedActivity || SelectedActivityDetails.Count > 0))
        {
            UpdateSelectedActivityDetails();
        }
    }

    private void UpdateSelectedActivityDetails()
    {
        SelectedActivityDetails.Clear();
        if (SelectedActivity is not { } entry)
        {
            HasSelectedActivity = false;
            SelectedActivityTitle = "Select an activity row to see details.";
            SelectedActivityRawText = string.Empty;
            return;
        }

        HasSelectedActivity = true;
        SelectedActivityTitle = $"{entry.EventLabel} · {entry.Agent}";
        AddActivityDetail("Agent", entry.Agent);
        AddActivityDetail("Event", $"{entry.EventLabel} ({entry.Event})");
        AddActivityDetail("Time", entry.DateTimeText);
        AddActivityDetail("Workspace", entry.Detail?.Workspace);
        AddActivityDetail("Session", entry.SessionFull);
        AddActivityDetail("Task", entry.Detail?.TaskId);
        AddActivityDetail("Tool", entry.Tool);
        AddActivityDetail("Command", entry.Detail?.Command);
        AddActivityDetail("Path", entry.Detail?.Path);
        AddActivityDetail("Mode", entry.Detail?.Mode);
        AddActivityDetail("URL", entry.Detail?.Url);
        AddActivityDetail("Query", entry.Detail?.Query);
        AddActivityDetail("Provider", entry.Detail?.Provider);
        AddActivityDetail("Model", entry.Detail?.Model);
        AddActivityDetail("Package", entry.Detail?.PackageText);
        AddActivityDetail("Result", entry.Detail?.ResultStatus);
        AddActivityDetail("Output", entry.Detail?.ResultText);
        if (entry.Detail?.DurationMs is > 0)
        {
            AddActivityDetail("Duration", FormatDuration(entry.Detail.DurationMs.Value));
        }

        AddActivityDetail("Security", entry.SecurityOutcomeDetail);
        AddActivityDetail("Decision", entry.Decision);
        AddActivityDetail("Severity", entry.Severity);
        AddActivityDetail("Identifier", entry.Identifier);
        AddActivityDetail("Finding", entry.Detail?.FindingTitle);
        AddActivityDetail("Category", entry.Detail?.FindingCategory);
        AddActivityDetail("Evidence", entry.Detail?.FindingEvidence);
        AddActivityDetail("Summary", entry.Details);
        SelectedActivityRawText = RedactAndClamp(entry.RawJson, 20_000);
    }

    private void AddActivityDetail(string label, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        SelectedActivityDetails.Add(new ActivityDetailRow(label, RedactAndClamp(value, 8_000)));
    }

    private static bool MatchesActivityFilter(BlackboxAuditEntry entry, string filter) =>
        filter switch
        {
            "Sessions" => entry.Category == "sessions",
            "API calls" => entry.Category == "api",
            "Tool calls" => entry.Category == "tools",
            "Installs" => entry.Category == "installs",
            "File access" => entry.Category == "file",
            "Threats" => entry.IsThreat,
            _ => true,
        };

    private static string ActivityIdentity(BlackboxAuditEntry entry) =>
        entry.RawJson.Length > 0
            ? entry.RawJson
            : string.Join(
                '|',
                entry.Timestamp?.ToUnixTimeMilliseconds(),
                entry.Event,
                entry.Agent,
                entry.Session,
                entry.Tool,
                entry.Identifier,
                entry.Action);

    private static string RedactAndClamp(string value, int limit)
    {
        var redacted = SecretPattern.Replace(value, "$1=[redacted]");
        redacted = BearerPattern.Replace(redacted, "Bearer [redacted]");
        redacted = LongHexPattern.Replace(redacted, "[redacted-hex]");
        return redacted.Length <= limit ? redacted : redacted[..limit] + "\n… (truncated)";
    }

    private static string FormatDuration(long milliseconds) => milliseconds switch
    {
        < 1000 => $"{milliseconds} ms",
        < 60_000 => $"{milliseconds / 1000.0:0.0} s",
        _ => $"{milliseconds / 60_000.0:0.0} min",
    };

    private static string? ReadString(JsonObject? element, string propertyName) =>
        element?[propertyName] is JsonValue value && value.TryGetValue<string>(out var text)
            ? text
            : null;

    private static bool ReadBool(JsonObject? element, string propertyName, bool fallback) =>
        element?[propertyName] is JsonValue value && value.TryGetValue<bool>(out var result)
            ? result
            : fallback;

    private static int ReadInt(JsonObject? element, string propertyName) =>
        element?[propertyName] is JsonValue value && value.TryGetValue<int>(out var result)
            ? result
            : 0;
}

public sealed record AgentSessionRow(
    string Provider,
    string Title,
    string Workspace,
    string LastSeen,
    bool Live)
{
    public string LiveText => Live ? "live" : "not running";

    public string LiveTooltip => Live
        ? "Session data was updated within the last 5 minutes, or its host process is running."
        : "Historical session: no update in the last 5 minutes and no visible host process. The session data is kept.";
}

public sealed record AgentSessionGroup(string Provider, IReadOnlyList<AgentSessionRow> Sessions);

public sealed record ActivityDetailRow(string Label, string Value);
