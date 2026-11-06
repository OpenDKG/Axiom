// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Netpetra.Contracts.Ai;
using Netpetra.UI.Services;

namespace Netpetra.UI.ViewModels;

public sealed record AiProviderOption(AiProviderKind Value, string Label)
{
    public override string ToString() => Label;
}

/// <summary>
/// Manual, bounded AI investigation. It uses the existing local monitor snapshot, sends only
/// explicit evidence to the configured provider (if enabled), and has no firewall or shell action.
/// </summary>
public sealed partial class AiAnalystViewModel : PageViewModel, IActivatablePage, IDisposable
{
    private readonly ConnectionMonitor _monitor;

    private readonly AiAnalystClient _client = new();

    private readonly AiAnalystSettingsStore _settingsStore = new();

    private readonly AiFindingStore _findingStore = new();

    private readonly DispatcherTimer _autoTimer = new() { Interval = TimeSpan.FromSeconds(60) };

    private readonly HashSet<string> _autoSeen = new(StringComparer.Ordinal);

    private readonly Queue<DateTimeOffset> _requestTimes = new();

    private DateTimeOffset _lastAutoAttempt = DateTimeOffset.MinValue;

    private string _apiKey = string.Empty;
    private bool _apiKeyDirty;

    public AiAnalystViewModel(ConnectionMonitor monitor)
        : base("AI Analyst", "Optional, evidence-based investigation with no enforcement", "\uE9D9")
    {
        _monitor = monitor ?? throw new ArgumentNullException(nameof(monitor));
        Providers =
        [
            new(AiProviderKind.OpenAiCompatible, "OpenAI-compatible / cloud"),
            new(AiProviderKind.LocalOpenAiCompatible, "OpenAI-compatible / local (HTTP loopback)"),
        ];

        _autoTimer.Tick += (_, _) => _ = AutomaticTickAsync();
        var (settings, key) = _settingsStore.Load();
        _apiKey = key;
        Enabled = settings.Enabled;
        Provider = Providers.FirstOrDefault(option => option.Value == settings.Provider) ?? Providers[0];
        Endpoint = settings.Endpoint;
        Model = settings.Model;
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

        SelectedFinding = History.FirstOrDefault();
        UpdateCredentialsText();
        UpdateStatus();
    }

    public IReadOnlyList<AiProviderOption> Providers { get; }

    public ObservableCollection<AiFinding> History { get; } = [];

    public bool IsConfigured => !string.IsNullOrWhiteSpace(Endpoint) && !string.IsNullOrWhiteSpace(Model);

    public bool CanAnalyze => !IsBusy;

    public string CredentialsText => string.IsNullOrWhiteSpace(_apiKey)
        ? "No API key stored. A local endpoint may not require one."
        : "API key is stored with Windows DPAPI; it is never shown or logged.";

    public string PrivacyText =>
        "Evidence is bounded and contains process names, PIDs, endpoints, direction, state and " +
        "quality. Local paths are reduced to file names when redaction is enabled. Packet contents, " +
        "credentials, browser cookies, agent histories and arbitrary files are never sent.";

    public string AutomaticText =>
        "Automatic analysis is opt-in. When enabled, only new non-loopback destinations are considered, " +
        "deduplicated, and bounded by the interval and hourly request limit. No event is sent while " +
        "the analyst is disabled.";

    [ObservableProperty]
    private bool _enabled;

    [ObservableProperty]
    private AiProviderOption _provider;

    [ObservableProperty]
    private string _endpoint = string.Empty;

    [ObservableProperty]
    private string _model = string.Empty;

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
    private bool _isBusy;

    [ObservableProperty]
    private string _statusText = "AI analyst is disabled.";

    [ObservableProperty]
    private string _settingsStatus = "No provider request has been made.";

    [ObservableProperty]
    private AiFinding? _selectedFinding;

    partial void OnAutomaticAnalysisChanged(bool value)
    {
        if (!value)
        {
            _autoTimer.Stop();
        }
    }

    partial void OnEnabledChanged(bool value)
    {
        if (!value)
        {
            _autoTimer.Stop();
        }
    }

    public void Activate() => UpdateStatus();

    public void Deactivate()
    {
    }

    public void Dispose()
    {
        _autoTimer.Stop();
        _client.Dispose();
    }

    public void SetApiKey(string value)
    {
        _apiKey = value;
        _apiKeyDirty = true;
        UpdateCredentialsText();
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
        SettingsStatus = "Settings saved locally. The API key is protected with Windows DPAPI.";
        UpdateCredentialsText();
        UpdateStatus();
        StartAutomaticTimer();
    }

    [RelayCommand]
    private Task AnalyzeAsync() => RunAnalysisAsync(automatic: false, connections: null);

    private async Task RunAnalysisAsync(
        bool automatic,
        IReadOnlyList<Netpetra.Contracts.Monitoring.LiveConnection>? connections)
    {
        if (IsBusy)
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
        IsBusy = true;
        StatusText = automatic
            ? "Automatic analysis of new non-loopback activity is running..."
            : "Preparing bounded evidence and requesting analysis...";
        try
        {
            var evidence = AiEvidenceBuilder.Build(
                sourceConnections,
                _monitor.SourceName,
                _monitor.Limitations,
                settings.MaxConnections,
                settings.RedactPaths);
            var finding = await _client
                .AnalyzeAsync(settings, _apiKey, evidence, CancellationToken.None)
                .ConfigureAwait(true);

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
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task AutomaticTickAsync()
    {
        if (!AutomaticAnalysis || !Enabled || !IsConfigured || IsBusy)
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
        _autoTimer.Stop();
        if (AutomaticAnalysis && Enabled)
        {
            _autoTimer.Start();
        }
    }

    [RelayCommand]
    private void ClearHistory()
    {
        _findingStore.Clear();
        History.Clear();
        SelectedFinding = null;
        StatusText = "Local AI finding history cleared.";
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
        else
        {
            StatusText = AutomaticAnalysis
                ? "Ready. Automatic analysis is opt-in and limited to new non-loopback activity."
                : "Ready for an explicit manual analysis. No automatic request is made.";
        }

        OnPropertyChanged(nameof(IsConfigured));
    }
}
