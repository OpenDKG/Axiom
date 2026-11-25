// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Axiom.Contracts.Ai;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Contracts.Privacy;
using Axiom.Contracts.Threat;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

public sealed record AiProviderOption(AiProviderKind Value, string Label)
{
    public override string ToString() => Label;
}

/// <summary>
/// Manual, bounded AI investigation. It uses the existing local monitor snapshot, sends only
/// explicit evidence to the configured provider (if enabled), and has no firewall or shell action.
/// </summary>
public sealed partial class AiAnalystPageViewModel : PageViewModel, IActivatablePage, IDisposable
{
    private readonly ConnectionMonitor _monitor;
    private readonly AiAnalystClient _client = new();
    private readonly AiAnalystSettingsStore _settingsStore;
    private readonly IUserInteraction _ui;
    private readonly IServiceRequestClient? _serviceClient;
    private readonly AiFindingStore _findingStore = new();
    private readonly IUiTimer _autoTimer;
    private readonly IUiTimer _busyTimer;
    private readonly HashSet<string> _autoSeen = new(StringComparer.Ordinal);
    private readonly Queue<DateTimeOffset> _requestTimes = new();
    private DateTimeOffset _lastAutoAttempt = DateTimeOffset.MinValue;
    private DateTimeOffset _analysisStartedUtc;
    private CancellationTokenSource? _analysisCts;
    private bool _disposed;

    private string _apiKey = string.Empty;
    private bool _apiKeyDirty;

    public AiAnalystPageViewModel(
        ConnectionMonitor monitor,
        IApiKeyProtector protector,
        IUiTimerFactory timers,
        IUserInteraction ui,
        IServiceRequestClient? serviceClient = null)
        : base("AI Analyst", "Optional, evidence-based investigation with no enforcement", "I")
    {
        _monitor = monitor ?? throw new ArgumentNullException(nameof(monitor));
        ArgumentNullException.ThrowIfNull(protector);
        ArgumentNullException.ThrowIfNull(timers);
        _ui = ui ?? throw new ArgumentNullException(nameof(ui));
        _serviceClient = serviceClient;
        _settingsStore = new AiAnalystSettingsStore(protector);

        Providers =
        [
            .. AiProviderCompliancePolicy.GetPresets()
                .Select(preset => new AiProviderOption(preset.Kind, preset.Label)),
        ];

        _autoTimer = timers.Create(TimeSpan.FromSeconds(60));
        _autoTimer.Tick += (_, _) => _ = AutomaticTickAsync();
        _busyTimer = timers.Create(TimeSpan.FromSeconds(1));
        _busyTimer.Tick += (_, _) => OnPropertyChanged(nameof(BusyText));
        var (settings, key) = _settingsStore.Load();
        _apiKey = key;
        Enabled = settings.Enabled;
        Provider = Providers.FirstOrDefault(option => option.Value == settings.Provider) ?? Providers[0];
        Endpoint = settings.Endpoint;
        Model = settings.Model;
        if (settings.Provider == AiProviderKind.OpenChamberLocal &&
            !Endpoint.StartsWith("opencode://", StringComparison.OrdinalIgnoreCase) &&
            AiProviderCompliancePolicy.TryGetPreset(AiProviderKind.OpenChamberLocal, out var openCodePreset))
        {
            Endpoint = openCodePreset.Endpoint;
            Model = string.IsNullOrWhiteSpace(Model)
                ? openCodePreset.DefaultModel
                : Model;
        }
        RedactPaths = settings.RedactPaths;
        MaxConnections = settings.MaxConnections;
        MaxTokens = settings.MaxTokens;
        AutomaticAnalysis = settings.AutomaticAnalysis;
        AnalysisIntervalMinutes = settings.AnalysisIntervalMinutes;
        MaxRequestsPerHour = settings.MaxRequestsPerHour;
        VerifierModel = settings.VerifierModel;
        StartAutomaticTimer();

        foreach (var finding in _findingStore.LoadRecent())
        {
            History.Add(finding);
        }

        History.CollectionChanged += (_, _) => OnPropertyChanged(nameof(HasHistory));

        SelectedFinding = History.FirstOrDefault();
        UpdateCredentialsText();
        UpdateStatus();
    }

    public IReadOnlyList<AiProviderOption> Providers { get; }

    public ObservableCollection<AiFinding> History { get; } = [];

    public bool HasHistory => History.Count > 0;

    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(Model) &&
        (IsOpenCodeProvider || !string.IsNullOrWhiteSpace(Endpoint));

    public bool IsOpenCodeProvider => Provider?.Value == AiProviderKind.OpenChamberLocal;

    public bool CanAnalyze => !IsBusy;

    public bool CanCancel => IsBusy;

    public bool CanCopyResult => SelectedFinding is not null;

    public string BusyText => IsBusy
        ? $"Agent is analyzing… {Math.Max(0, (int)(DateTimeOffset.UtcNow - _analysisStartedUtc).TotalSeconds)} s"
        : string.Empty;

    public string CredentialsText => IsOpenCodeProvider
        ? "Uses your authorized OpenCode CLI setup. Third-party consumer logins (Claude Pro/Max, Antigravity, Gemini CLI, Copilot) are blocked to protect your accounts."
        : string.IsNullOrWhiteSpace(_apiKey)
            ? "No API key stored. A local endpoint may not require one."
            : $"API key is stored with {PlatformText.SecretStore}; it is never shown or logged.";

    public string ProviderComplianceText => Provider is { } selected
        ? AiProviderCompliancePolicy.GetComplianceNote(selected.Value)
        : string.Empty;

    public string PrivacyText =>
        "Evidence is bounded and contains process names, PIDs, parent process chains, executable " +
        "metadata (signer, product, version), sanitised command lines, endpoints, direction, state, " +
        "quality and a local 30-day flow baseline. Local paths are reduced to file names when redaction " +
        "is enabled. Packet contents, credentials, browser cookies, agent histories and arbitrary files " +
        "are never sent.";

    public string AutomaticText =>
        "Automatic analysis is opt-in. When enabled, only new non-loopback destinations are considered, " +
        "deduplicated, and bounded by the interval and hourly request limit. No event is sent while " +
        "the analyst is disabled.";

    [ObservableProperty]
    private bool _enabled;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsOpenCodeProvider))]
    [NotifyPropertyChangedFor(nameof(IsConfigured))]
    [NotifyPropertyChangedFor(nameof(CredentialsText))]
    [NotifyPropertyChangedFor(nameof(ProviderComplianceText))]
    private AiProviderOption _provider;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsConfigured))]
    private string _endpoint = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsConfigured))]
    private string _model = string.Empty;

    [ObservableProperty]
    private string _apiKeyInput = string.Empty;

    [ObservableProperty]
    private bool _redactPaths = true;

    [ObservableProperty]
    private int _maxConnections = 25;

    [ObservableProperty]
    private int _maxTokens = 1200;

    [ObservableProperty]
    private bool _automaticAnalysis;

    [ObservableProperty]
    private int _analysisIntervalMinutes = 15;

    [ObservableProperty]
    private int _maxRequestsPerHour = 6;

    [ObservableProperty]
    private string _verifierModel = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanAnalyze))]
    [NotifyPropertyChangedFor(nameof(CanCancel))]
    private bool _isBusy;

    [ObservableProperty]
    private string _statusText = "AI analyst is disabled.";

    [ObservableProperty]
    private string _settingsStatus = "No provider request has been made.";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanCopyResult))]
    private AiFinding? _selectedFinding;

    private bool _suppressApiKeyInputChanged;

    partial void OnApiKeyInputChanged(string value)
    {
        if (_suppressApiKeyInputChanged)
        {
            return;
        }

        _apiKey = value;
        _apiKeyDirty = true;
        UpdateCredentialsText();
    }

    partial void OnProviderChanged(AiProviderOption value)
    {
        if (value is not null && AiProviderCompliancePolicy.TryGetPreset(value.Value, out var preset))
        {
            Endpoint = preset.Endpoint;
            Model = preset.DefaultModel;
        }

        UpdateStatus();
    }

    partial void OnIsBusyChanged(bool value)
    {
        if (value)
        {
            _analysisStartedUtc = DateTimeOffset.UtcNow;
            _busyTimer.Start();
        }
        else
        {
            _busyTimer.StopTimer();
        }

        OnPropertyChanged(nameof(BusyText));
        OnPropertyChanged(nameof(CanCancel));
    }

    partial void OnAutomaticAnalysisChanged(bool value)
    {
        if (!value)
        {
            _autoTimer.StopTimer();
        }
    }

    partial void OnEnabledChanged(bool value)
    {
        if (!value)
        {
            _autoTimer.StopTimer();
        }
    }

    public void Activate() => UpdateStatus();

    public void Deactivate()
    {
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _autoTimer.StopTimer();
        _autoTimer.Dispose();
        _busyTimer.StopTimer();
        _busyTimer.Dispose();
        try
        {
            _analysisCts?.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }

        _client.Dispose();
    }

    [RelayCommand]
    private void SaveSettings()
    {
        var settings = BuildSettings();
        if (!_settingsStore.Save(settings, _apiKeyDirty ? _apiKey : null))
        {
            SettingsStatus = "Could not save AI analyst settings.";
            return;
        }

        _apiKeyDirty = false;
        _suppressApiKeyInputChanged = true;
        try
        {
            ApiKeyInput = string.Empty;
        }
        finally
        {
            _suppressApiKeyInputChanged = false;
        }
        SettingsStatus = settings.Enabled &&
                         !AiProviderCompliancePolicy.ValidateRequest(settings, _apiKey, out var complianceError)
            ? $"Settings saved locally. Compliance check: {complianceError}"
            : $"Settings saved locally. The API key is protected with {PlatformText.SecretStore}.";
        UpdateCredentialsText();
        OnPropertyChanged(nameof(ProviderComplianceText));
        UpdateStatus();
        StartAutomaticTimer();
    }

    [RelayCommand]
    private Task AnalyzeAsync() => RunAnalysisAsync(automatic: false, connections: null);

    [RelayCommand]
    private void ClearHistory()
    {
        _findingStore.Clear();
        History.Clear();
        SelectedFinding = null;
        StatusText = "Local AI finding history cleared.";
    }

    /// <summary>
    /// Prompt the user can send to an already signed-in official agent client so it connects
    /// safely to Axiom's read-only MCP server or configures a compliant API key / local model.
    /// </summary>
    public string AgentSetupPrompt =>
        "Connect this official client (Claude Code, Antigravity, Codex, or Gemini CLI) to Axiom safely: " +
        "register Axiom's read-only local stdio MCP server (Axiom.McpServer, see docs/MCP.md) so this session " +
        "can inspect Axiom observations directly, OR in Axiom > AI Analyst configure an official API key " +
        "provider (Anthropic Console, Google AI Studio, OpenAI Platform, or OpenRouter) or a local Ollama " +
        "endpoint. Do not reuse any consumer OAuth login or paste API keys into chat.";

    [RelayCommand]
    private Task CopyAgentSetupPromptAsync() =>
        CopyTextAsync(AgentSetupPrompt, "Agent setup prompt copied to the clipboard.");

    [RelayCommand]
    private Task CopyResultAsync() => SelectedFinding is { } finding
        ? CopyTextAsync(FormatFinding(finding), "Analysis result copied to the clipboard.")
        : Task.CompletedTask;

    [RelayCommand]
    private Task CopyAllResultsAsync() => History.Count == 0
        ? Task.CompletedTask
        : CopyTextAsync(
            string.Join(
                Environment.NewLine + Environment.NewLine,
                History.Select(FormatFinding)),
            $"{History.Count} analysis result(s) copied to the clipboard.");

    [RelayCommand]
    private void CancelAnalysis()
    {
        if (_disposed)
        {
            return;
        }

        try
        {
            _analysisCts?.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }

        StatusText = "Cancelling the AI analysis…";
    }

    private async Task CopyTextAsync(string text, string successMessage)
    {
        try
        {
            await _ui.CopyTextAsync(text, CancellationToken.None).ConfigureAwait(true);
            StatusText = successMessage;
        }
#pragma warning disable CA1031 // Clipboard access can fail when another process owns it.
        catch (Exception)
#pragma warning restore CA1031
        {
            StatusText = "Clipboard is unavailable. Select the text manually and copy it.";
        }
    }

    private static string FormatFinding(AiFinding finding)
    {
        var text = new StringBuilder();
        text.AppendLine("Axiom AI Analyst");
        text.AppendLine("Finding: " + finding.FindingId);
        text.AppendLine("Analyzed: " + finding.AnalysisTimestampUtc.ToString("O"));
        text.AppendLine("Model: " + finding.Model);
        if (!string.IsNullOrWhiteSpace(finding.VerifierModel))
        {
            text.AppendLine("Verifier model: " + finding.VerifierModel);
            text.AppendLine("Verifier status: " + finding.VerifierStatus);
            if (!string.IsNullOrWhiteSpace(finding.VerifierSummary))
            {
                text.AppendLine("Verifier summary: " + finding.VerifierSummary);
            }
        }

        text.AppendLine("Status: " + finding.Status);
        text.AppendLine("Severity: " + finding.Severity);
        text.AppendLine("Confidence: " + finding.Confidence);
        text.AppendLine("Human reviewed: " + (finding.HumanReviewed ? "yes" : "no"));
        if (!string.IsNullOrWhiteSpace(finding.Error))
        {
            text.AppendLine("Error: " + finding.Error);
        }

        text.AppendLine();
        text.AppendLine("Summary:");
        text.AppendLine(finding.Summary);
        AppendSection(text, "Observations", finding.Observations);
        AppendSection(text, "Evidence references", finding.EvidenceReferences);
        AppendSection(text, "Alternative explanations", finding.AlternativeExplanations);
        AppendSection(text, "Missing evidence", finding.MissingEvidence);
        AppendSection(text, "Recommended actions (text only; nothing is applied)", finding.RecommendedActions);
        return text.ToString().TrimEnd();
    }

    private static void AppendSection(StringBuilder text, string title, IReadOnlyList<string> values)
    {
        if (values.Count == 0)
        {
            return;
        }

        text.AppendLine();
        text.AppendLine(title + ":");
        foreach (var value in values)
        {
            text.AppendLine("- " + value);
        }
    }

    private async Task RunAnalysisAsync(
        bool automatic,
        IReadOnlyList<LiveConnection>? connections)
    {
        if (_disposed || IsBusy)
        {
            return;
        }

        var settings = BuildSettings();
        if (!settings.Enabled)
        {
            StatusText = "Enable the AI analyst and save provider settings first.";
            return;
        }

        if (!IsConfigured)
        {
            StatusText = "Endpoint and model are required.";
            return;
        }

        if (!IsOpenCodeProvider &&
            Endpoint.Contains(":4096", StringComparison.Ordinal) &&
            Endpoint.Contains("/v1/chat/completions", StringComparison.OrdinalIgnoreCase))
        {
            StatusText =
                "Port 4096 is OpenChamber's UI, not an OpenAI-compatible API. " +
                "Use a local Ollama/LM Studio endpoint or choose a cloud provider.";
            return;
        }

        var sourceConnections = connections ??
                                _monitor.Connections.Select(row => row.Source).ToArray();
        if (sourceConnections.Count == 0)
        {
            StatusText = "No live connection is available to analyze. Start monitoring or refresh the page.";
            return;
        }

        if (!ReserveRequest(settings, automatic))
        {
            return;
        }

        if (!_settingsStore.Save(settings, _apiKeyDirty ? _apiKey : null))
        {
            StatusText = "Could not save AI analyst settings before analysis.";
            return;
        }

        _apiKeyDirty = false;
        using var analysisCts = new CancellationTokenSource();
        _analysisCts = analysisCts;
        IsBusy = true;
        StatusText = automatic
            ? "Automatic analysis of new non-loopback activity is running..."
            : "Preparing bounded evidence and requesting analysis...";
        try
        {
            var baseline = await AiEvidenceBaselineCollector
                .TryLoadAsync(_serviceClient, sourceConnections, analysisCts.Token)
                .ConfigureAwait(true);
            var evidence = AiEvidenceBuilder.Build(
                sourceConnections,
                _monitor.SourceName,
                _monitor.Limitations,
                settings.MaxConnections,
                settings.RedactPaths,
                baseline);
            var finding = await _client
                .AnalyzeAsync(settings, _apiKey, evidence, analysisCts.Token)
                .ConfigureAwait(true);

            if (analysisCts.IsCancellationRequested)
            {
                StatusText = "Analysis cancelled. No finding was saved.";
                return;
            }

            _findingStore.Save(finding);
            History.Insert(0, finding);
            while (History.Count > AiFindingStore.MaxFindings)
            {
                History.RemoveAt(History.Count - 1);
            }

            SelectedFinding = finding;
            StatusText = finding.Error is null
                ? (automatic
                    ? "Automatic analysis completed. Review evidence and uncertainty before acting."
                    : "Analysis completed. Review evidence and uncertainty before acting.")
                : "Analysis returned no reliable result: " + finding.Error;
            UpdateStatus();

            // Only a high-confidence malicious finding proposes indicators, and only values Axiom
            // itself observed. They go into the Agents-page review list; nothing leaves the machine
            // until the user presses Share or Send now.
            if (!_disposed)
            {
                await QueueThreatShareCandidatesAsync(finding, evidence).ConfigureAwait(true);
            }
        }
        catch (Exception exception) when (exception is OperationCanceledException ||
                                          (_disposed && exception is ObjectDisposedException))
        {
            if (!_disposed)
            {
                StatusText = "Analysis cancelled. No finding was saved.";
            }
        }
        finally
        {
            _analysisCts = null;
            IsBusy = false;
        }
    }

    private async Task QueueThreatShareCandidatesAsync(
        AiFinding finding,
        AiEvidencePackage evidence)
    {
        if (_serviceClient is null || finding.Error is not null)
        {
            return;
        }

        try
        {
            var (available, listDerived) = await ListDerivedValuesAsync().ConfigureAwait(true);
            if (!available)
            {
                StatusText += " Threat-share candidates were not queued because local list " +
                              "provenance is unavailable; independence cannot be established.";
                return;
            }

            foreach (var candidate in ThreatShareIocExtractor.Extract(
                         finding,
                         evidence,
                         listDerived,
                         provenanceAvailable: true))
            {
                await _serviceClient
                    .SendAsync<ThreatShareQueueStatus>(
                        IpcCommandTypes.ThreatShareEnqueue,
                        candidate,
                        CancellationToken.None)
                    .ConfigureAwait(true);
            }
        }
        catch (Exception exception) when (exception is
                     ServiceUnavailableException or TimeoutException or
                     System.Text.Json.JsonException or System.IO.IOException)
        {
            // The preview list is optional; an offline service must not affect the analyst result.
        }
    }

    /// <summary>
    /// Values that local public-list blocks already contain, plus whether the lookup itself worked.
    /// The analyst must not present the same public-list match as an independent sighting; if the
    /// service cannot answer, the caller fails closed and queues nothing.
    /// </summary>
    private async Task<(bool Available, IReadOnlySet<string> Values)> ListDerivedValuesAsync()
    {
        var empty = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (_serviceClient is null)
        {
            return (false, empty);
        }

        try
        {
            var status = await _serviceClient
                .SendAsync<PrivacyShieldStatus>(
                    IpcCommandTypes.PrivacyStatus,
                    null,
                    CancellationToken.None)
                .ConfigureAwait(true);

            var values = status.BlockedHistory
                .Where(item => item.Category.HasFlag(PrivacyCategory.Malware))
                .SelectMany(item => new[] { item.Domain, item.MatchedRule })
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(value => value.TrimEnd('.').ToLowerInvariant())
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            return (true, values);
        }
        catch (Exception exception) when (exception is
                     ServiceUnavailableException or TimeoutException or
                     System.Text.Json.JsonException or System.IO.IOException)
        {
            return (false, empty);
        }
    }

    private async Task AutomaticTickAsync()
    {
        if (_disposed || !AutomaticAnalysis || !Enabled || !IsConfigured || IsBusy)
        {
            return;
        }

        var interval = TimeSpan.FromMinutes(Math.Clamp(AnalysisIntervalMinutes, 5, 60));
        var now = DateTimeOffset.UtcNow;
        if (now - _lastAutoAttempt < interval)
        {
            return;
        }

        _lastAutoAttempt = now;
        var candidates = _monitor.Connections
            .Where(row => row.Source.IsNew &&
                          !row.Source.IsLoopback &&
                          !string.IsNullOrWhiteSpace(row.Source.RemoteEndpoint))
            .Select(row => row.Source)
            .Take(Math.Clamp(MaxConnections, 1, 50))
            .Where(connection => _autoSeen.Add(
                $"{connection.ProcessId}|{connection.Protocol}|{connection.RemoteEndpoint}"))
            .ToArray();

        if (candidates.Length == 0)
        {
            return;
        }

        if (_autoSeen.Count > 5000)
        {
            _autoSeen.Clear();
        }

        await RunAnalysisAsync(automatic: true, connections: candidates).ConfigureAwait(true);
    }

    private bool ReserveRequest(AiAnalystSettings settings, bool automatic)
    {
        var now = DateTimeOffset.UtcNow;
        while (_requestTimes.Count > 0 && now - _requestTimes.Peek() > TimeSpan.FromHours(1))
        {
            _requestTimes.Dequeue();
        }

        if (automatic && _requestTimes.Count >= Math.Clamp(settings.MaxRequestsPerHour, 1, 60))
        {
            StatusText = "Automatic analysis hourly request limit reached; no request was sent.";
            return false;
        }

        _requestTimes.Enqueue(now);
        return true;
    }

    private void StartAutomaticTimer()
    {
        _autoTimer.StopTimer();
        if (AutomaticAnalysis && Enabled)
        {
            _autoTimer.Start();
        }
    }

    private AiAnalystSettings BuildSettings() => new()
    {
        Enabled = Enabled,
        Provider = Provider?.Value ?? AiProviderKind.OpenAiCompatible,
        Endpoint = Endpoint.Trim(),
        Model = Model.Trim(),
        RedactPaths = RedactPaths,
        MaxConnections = Math.Clamp(MaxConnections, 1, 50),
        MaxTokens = Math.Clamp(MaxTokens, 256, 4000),
        AutomaticAnalysis = AutomaticAnalysis,
        AnalysisIntervalMinutes = Math.Clamp(AnalysisIntervalMinutes, 5, 60),
        MaxRequestsPerHour = Math.Clamp(MaxRequestsPerHour, 1, 60),
        VerifierModel = VerifierModel.Trim(),
    };

    private void UpdateCredentialsText() => OnPropertyChanged(nameof(CredentialsText));

    private void UpdateStatus()
    {
        if (!Enabled)
        {
            StatusText = "AI analyst is disabled. No data leaves this device.";
        }
        else if (!IsConfigured)
        {
            StatusText = "AI analyst is enabled but endpoint/model is incomplete.";
        }
        else if (!IsOpenCodeProvider &&
                 Endpoint.Contains(":4096", StringComparison.Ordinal) &&
                 Endpoint.Contains("/v1/chat/completions", StringComparison.OrdinalIgnoreCase))
        {
            StatusText =
                "Port 4096 is OpenChamber's UI, not an OpenAI-compatible API. " +
                "Set an Ollama/LM Studio endpoint or choose a cloud provider.";
        }
        else
        {
            StatusText = AutomaticAnalysis
                ? "Ready. Automatic analysis is opt-in and limited to new non-loopback activity."
                : "Ready for an explicit manual analysis. No automatic request is made.";
        }

        OnPropertyChanged(nameof(IsConfigured));
        OnPropertyChanged(nameof(CanAnalyze));
    }
}
