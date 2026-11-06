// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
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

        var (settings, key) = _settingsStore.Load();
        _apiKey = key;
        Enabled = settings.Enabled;
        Provider = Providers.FirstOrDefault(option => option.Value == settings.Provider) ?? Providers[0];
        Endpoint = settings.Endpoint;
        Model = settings.Model;
        RedactPaths = settings.RedactPaths;
        MaxConnections = settings.MaxConnections;
        MaxTokens = settings.MaxTokens;

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
        "Automatic background analysis is not enabled in this build. Analysis is an explicit button " +
        "action; no event is sent to a provider without it.";

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
    [NotifyPropertyChangedFor(nameof(CanAnalyze))]
    private bool _isBusy;

    [ObservableProperty]
    private string _statusText = "AI analyst is disabled.";

    [ObservableProperty]
    private string _settingsStatus = "No provider request has been made.";

    [ObservableProperty]
    private AiFinding? _selectedFinding;

    public void Activate()
    {
        UpdateStatus();
    }

    public void Deactivate()
    {
    }

    public void Dispose() => _client.Dispose();

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
    }

    [RelayCommand]
    private async Task AnalyzeAsync()
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

        if (_monitor.Connections.Count == 0)
        {
            StatusText = "No live connection is available to analyze. Start monitoring or refresh the page.";
            return;
        }

        if (!_settingsStore.Save(settings, _apiKeyDirty ? _apiKey : null))
        {
            StatusText = "Could not save AI analyst settings before analysis.";
            return;
        }

        _apiKeyDirty = false;
        IsBusy = true;
        StatusText = "Preparing bounded evidence and requesting analysis...";
        try
        {
            var evidence = AiEvidenceBuilder.Build(
                _monitor.Connections.Select(row => row.Source).ToArray(),
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
                ? "Analysis completed. Review evidence and uncertainty before acting."
                : "Analysis returned no reliable result: " + finding.Error;
            UpdateStatus();
        }
        finally
        {
            IsBusy = false;
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
            StatusText = "Ready for an explicit manual analysis. No automatic request is made.";
        }

        OnPropertyChanged(nameof(IsConfigured));
    }
}
