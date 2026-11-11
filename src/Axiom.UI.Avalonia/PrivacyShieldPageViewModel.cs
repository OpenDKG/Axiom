// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Privacy;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

public sealed record PrivacyShieldProfileOption(PrivacyShieldProfile Value, string Label)
{
    public override string ToString() => Label;
}

public sealed record PrivacyShieldAdapterOption(
    string Name,
    string Description,
    string DnsText,
    bool HasDefaultRoute,
    bool UsesResolver = false,
    bool HasFallback = false)
{
    public string DisplayName => HasDefaultRoute
        ? $"{Name} — default route · DNS {DnsText}"
        : $"{Name} — DNS {DnsText}";

    public override string ToString() => DisplayName;
}

public sealed partial class PrivacyShieldSourceRow : ObservableObject
{
    public PrivacyShieldSourceRow(PrivacyShieldSourceInfo source)
    {
        Id = source.Id;
        Name = source.Name;
        License = source.License;
        Description = source.Description;
    }

    public string Id { get; }

    public string Name { get; }

    public string License { get; }

    public string Description { get; }

    [ObservableProperty]
    private bool _enabled;

    [ObservableProperty]
    private int _entries;

    [ObservableProperty]
    private string _updatedText = "not downloaded";

    [ObservableProperty]
    private string _errorText = string.Empty;
}

/// <summary>A blocked DNS event with the current allow/block action for that domain.</summary>
public sealed class BlockedEventRow(PrivacyShieldBlockedEvent blocked, bool isAllowed)
{
    public string Domain => blocked.Domain;

    public string AppDisplay => blocked.AppDisplay;

    public string AppPath => blocked.AppPath;

    public string CategoryText => blocked.CategoryText;

    public DateTimeOffset TimestampUtc => blocked.BlockedUtc;

    public bool IsAllowed => isAllowed;

    public bool CanAllow => !isAllowed;

    public bool CanBlock => isAllowed;

    public string StateText => isAllowed ? "allowed" : "blocked";

    public string Tooltip => string.IsNullOrWhiteSpace(blocked.AppPath)
        ? $"{blocked.Domain}\nBlocked app: {blocked.AppDisplay}\nCategory: {blocked.CategoryText}"
        : $"{blocked.Domain}\nBlocked app: {blocked.AppDisplay}\nPath: {blocked.AppPath}\nCategory: {blocked.CategoryText}";
}

/// <summary>One (domain, app) pair in the live list, so a chatty app cannot flood the page.</summary>
public sealed class RecentBlockedGroup(
    string domain,
    string appDisplay,
    string categoryText,
    int count,
    DateTimeOffset lastUtc,
    BlockedEventRow latest)
{
    public string Domain => domain;

    public string AppDisplay => appDisplay;

    public string CategoryText => categoryText;

    public int Count => count;

    public string CountText => count > 1 ? $"{count}x" : string.Empty;

    public DateTimeOffset LastUtc => lastUtc;

    public BlockedEventRow Latest => latest;

    public bool CanAllow => latest.CanAllow;

    public bool CanBlock => latest.CanBlock;

    public string Tooltip => $"{latest.Tooltip}\nSeen {count} time(s) in the live window.";
}

/// <summary>One domain inside an application's retained history group.</summary>
public sealed class BlockedHistoryDomainRow(
    string domain,
    string categoryText,
    int count,
    DateTimeOffset lastUtc,
    BlockedEventRow latest)
{
    public string Domain => domain;

    public string CategoryText => categoryText;

    public int Count => count;

    public string CountText => count > 1 ? $"{count}x" : string.Empty;

    public DateTimeOffset LastUtc => lastUtc;

    public BlockedEventRow Latest => latest;

    public bool CanAllow => latest.CanAllow;

    public bool CanBlock => latest.CanBlock;

    public string Tooltip => $"{latest.Tooltip}\nSeen {count} time(s) in the retained history.";
}

/// <summary>One application in the retained history, expandable to its blocked domains.</summary>
public sealed class BlockedHistoryAppGroup(
    string appDisplay,
    string appPath,
    IReadOnlyList<BlockedHistoryDomainRow> domains,
    DateTimeOffset lastUtc) : INotifyPropertyChanged
{
    private bool _isExpanded;

    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>
    /// Bound two-way to the Expander. The page refreshes every two seconds and rebuilds this list,
    /// so the open/closed state has to live on the item instead of the control, otherwise a group
    /// collapses while the user is reading it.
    /// </summary>
    public bool IsExpanded
    {
        get => _isExpanded;
        set
        {
            if (_isExpanded == value)
            {
                return;
            }

            _isExpanded = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsExpanded)));
        }
    }

    public string AppDisplay => appDisplay;

    public string AppPath => appPath;

    public IReadOnlyList<BlockedHistoryDomainRow> Domains => domains;

    public int TotalBlocks => domains.Sum(domain => domain.Count);

    public int DomainCount => domains.Count;

    public DateTimeOffset LastUtc => lastUtc;

    public string SummaryText => $"{TotalBlocks} blocks · {DomainCount} domains";

    public string Tooltip => string.IsNullOrWhiteSpace(appPath)
        ? appDisplay
        : $"{appDisplay}\n{appPath}";
}

/// <summary>
/// Privacy Shield is a local DNS filter. Complete installation enables the resolver; a partial
/// installation leaves it opt-in. The service never changes adapter DNS settings; the user must
/// point Windows at the displayed loopback resolver explicitly.
/// </summary>
public sealed partial class PrivacyShieldPageViewModel : PageViewModel, IActivatablePage, IDisposable
{
    private readonly IServiceRequestClient? _client;
    private readonly IUserInteraction _ui;
    private readonly IDnsAdapterHelper _dnsHelper;
    private readonly IUiTimer? _statsTimer;
    private bool _updating;
    private bool _resolverActive;

    /// <summary>True while the service reports the resolver as running (Overview wording).</summary>
    public bool IsResolverActive => _resolverActive;
    private bool _statsRefreshing;
    private readonly HashSet<string> _expandedHistoryApps = new(StringComparer.OrdinalIgnoreCase);
    private string? _blockedHistorySignature;

    public PrivacyShieldPageViewModel(
        IServiceRequestClient? serviceClient,
        IUserInteraction ui,
        IDnsAdapterHelper dnsHelper,
        IUiTimerFactory timers)
        : base("Privacy Shield", "Local DNS filtering · complete installation enables the resolver", "P")
    {
        ArgumentNullException.ThrowIfNull(ui);
        ArgumentNullException.ThrowIfNull(dnsHelper);
        ArgumentNullException.ThrowIfNull(timers);
        _client = serviceClient;
        _ui = ui;
        _dnsHelper = dnsHelper;

        Profiles =
        [
            new(PrivacyShieldProfile.Basic, "Basic · Windows telemetry"),
            new(PrivacyShieldProfile.Balanced, "Balanced · telemetry, ads, tracking"),
            new(PrivacyShieldProfile.Strict, "Strict · all categories"),
        ];
        _selectedProfile = Profiles[1];
        ApplyProfileCategories(PrivacyShieldProfile.Balanced);
        Adapters = new ObservableCollection<PrivacyShieldAdapterOption>(BuildAdapterOptions());
        _selectedAdapter = Adapters.FirstOrDefault();

        if (_client is null)
        {
            StatusBadge = "SERVICE REQUIRED";
            StatusText = "Privacy Shield runs in the local Axiom service. Start this host with --service.";
            DetailText = "No DNS settings were changed.";
        }
        else
        {
            _statsTimer = timers.Create(TimeSpan.FromSeconds(2));
            _statsTimer.Tick += (_, _) => _ = RefreshStatsAsync();
            _ = RefreshAsync();
        }
    }

    public bool IsSupported => _client is not null;

    public IReadOnlyList<PrivacyShieldProfileOption> Profiles { get; }

    public ObservableCollection<PrivacyShieldTopDomain> TopBlocked { get; } = [];

    public ObservableCollection<BlockedEventRow> RecentBlocked { get; } = [];

    public ObservableCollection<BlockedHistoryAppGroup> BlockedHistoryGroups { get; } = [];

    [ObservableProperty]
    private string _blockedHistorySummary = "No blocked query history yet.";

    [ObservableProperty]
    private bool _hasDnsOutageRisk;

    [ObservableProperty]
    private string _dnsOutageWarningText = string.Empty;

    /// <summary>Grouped live list: one row per (domain, app), newest first, bounded.</summary>
    public ObservableCollection<RecentBlockedGroup> RecentBlockedGroups { get; } = [];

    [ObservableProperty]
    private bool _showAllRecentBlocked;

    [ObservableProperty]
    private string _recentBlockedSummary = "No blocked queries in the live window.";

    private List<RecentBlockedGroup> _recentGroups = [];

    private bool _dnsOutageAlerted;

    public string RecentBlockedToggleText => ShowAllRecentBlocked ? "Show top" : "Show all";

    partial void OnShowAllRecentBlockedChanged(bool value)
    {
        ApplyRecentGroupView();
        OnPropertyChanged(nameof(RecentBlockedToggleText));
    }

    [RelayCommand]
    private void ToggleRecentBlocked() => ShowAllRecentBlocked = !ShowAllRecentBlocked;

    public ObservableCollection<PrivacyShieldSourceRow> Sources { get; } =
        new(PrivacyShieldSourceCatalog.All.Select(source => new PrivacyShieldSourceRow(source)));

    public ObservableCollection<PrivacyShieldAdapterOption> Adapters { get; }

    [ObservableProperty]
    private PrivacyShieldAdapterOption? _selectedAdapter;

    [ObservableProperty]
    private string _dnsHelperStatusText = "No adapter DNS change has been made.";

    partial void OnSelectedAdapterChanged(PrivacyShieldAdapterOption? value)
    {
        if (value is null)
        {
            return;
        }

        var already = $"Adapter '{value.Name}' already sends DNS to the Privacy Shield resolver at 127.0.0.1.";
        if (value.UsesResolver && DnsHelperStatusText == "No adapter DNS change has been made.")
        {
            DnsHelperStatusText = already;
        }
        else if (!value.UsesResolver && DnsHelperStatusText == already)
        {
            DnsHelperStatusText = "No adapter DNS change has been made.";
        }
    }

    public string StarterRulesText =>
        $"{PrivacyShieldPolicy.StarterRulesAll.Count} starter rules (manually reviewed, not a third-party list)";

    public string ManualSetupText => OperatingSystem.IsMacOS()
        ? "The Axiom daemon points the DNS servers of every network service at 127.0.0.1 while the " +
          "Privacy Shield resolver runs, saves the previous servers first, and restores them when the " +
          "resolver stops, the service stops or Axiom is uninstalled. No manual change or password " +
          "prompt is needed. This is DNS filtering only: applications still connect directly to " +
          "destination IPs; traffic is not routed or proxied through Axiom."
        : ManualSetupTextWindows;

    private static string ManualSetupTextWindows =>
        $"The Axiom service never changes adapter DNS silently. The optional {PlatformText.ElevationName} helper changes " +
        $"only the selected adapter after you confirm {PlatformText.ElevationPrompt}; it saves the previous DNS, " +
        "keeps it behind the resolver as a fallback, and can restore it. If you do not use the helper, " +
        "set the adapter DNS to 127.0.0.1 (port 53) and keep the router's DNS as the second entry " +
        $"manually. Until {PlatformText.OsName} DNS points at this resolver, normal traffic bypasses it " +
        "and the counters stay at zero. This is DNS filtering only: applications still connect " +
        "directly to destination IPs; traffic is not routed or proxied through Axiom.";

    public string BypassText =>
        "Privacy Shield is a DNS filter, not a VPN or traffic proxy. It does not block hardcoded IPs, " +
        "DoH/DoT/DoQ, VPN tunnels or answers cached before activation. A blocked query is not proof " +
        "that a connection was prevented.";

    [ObservableProperty]
    private PrivacyShieldProfileOption _selectedProfile;

    [ObservableProperty]
    private bool _enabled;

    [ObservableProperty]
    private bool _telemetry = true;

    [ObservableProperty]
    private bool _ads = true;

    [ObservableProperty]
    private bool _tracking = true;

    [ObservableProperty]
    private bool _analytics = true;

    [ObservableProperty]
    private bool _malware;

    [ObservableProperty]
    private string _portText = "53";

    [ObservableProperty]
    private string _upstreamText = string.Empty;

    [ObservableProperty]
    private string _allowedDomainsText = string.Empty;

    [ObservableProperty]
    private string _blockedDomainsText = string.Empty;

    [ObservableProperty]
    private string _statusBadge = "DISABLED";

    [ObservableProperty]
    private string _statusText = "Privacy Shield is disabled. No DNS query is observed or filtered.";

    [ObservableProperty]
    private string _detailText = string.Empty;

    [ObservableProperty]
    private string _statsText = "No queries observed.";

    [ObservableProperty]
    private string _statsHintText = string.Empty;

    [ObservableProperty]
    private bool _hasStatsHint;

    [ObservableProperty]
    private string _lastUpdatedText = "Not refreshed.";

    [ObservableProperty]
    private string _lastErrorText = string.Empty;

    [ObservableProperty]
    private bool _isBusy;

    partial void OnSelectedProfileChanged(PrivacyShieldProfileOption value)
    {
        if (_updating || value is null)
        {
            return;
        }

        ApplyProfileCategories(value.Value);
    }

    public void Activate()
    {
        RefreshAdapters();
        _statsTimer?.Start();
        _ = RefreshAsync();
    }

    public void Deactivate() => _statsTimer?.StopTimer();

    public void Dispose()
    {
        _statsTimer?.StopTimer();
        _statsTimer?.Dispose();
    }

    [RelayCommand]
    private async Task RefreshAsync()
    {
        if (_client is null || IsBusy)
        {
            return;
        }

        IsBusy = true;
        try
        {
            RefreshAdapters();
            var status = await _client
                .SendAsync<PrivacyShieldStatus>(IpcCommandTypes.PrivacyStatus, null, CancellationToken.None)
                .ConfigureAwait(true);
            ApplyStatus(status);
        }
        catch (ServiceUnavailableException exception)
        {
            StatusBadge = "UNAVAILABLE";
            StatusText = exception.Message;
            DetailText = "No DNS query is observed while the service is unavailable.";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task RefreshStatsAsync()
    {
        if (_client is null || IsBusy || _statsRefreshing)
        {
            return;
        }

        _statsRefreshing = true;
        try
        {
            var status = await _client
                .SendAsync<PrivacyShieldStatus>(IpcCommandTypes.PrivacyStatus, null, CancellationToken.None)
                .ConfigureAwait(true);
            ApplyStats(status);
        }
        catch (ServiceUnavailableException exception)
        {
            StatusBadge = "UNAVAILABLE";
            StatusText = exception.Message;
        }
        finally
        {
            _statsRefreshing = false;
        }
    }

    [RelayCommand]
    private async Task ApplyAsync()
    {
        if (_client is null || IsBusy)
        {
            return;
        }

        IsBusy = true;
        try
        {
            var settings = BuildSettings();
            if (!ValidateSettingsSize(settings))
            {
                return;
            }

            var status = await _client
                .SendAsync<PrivacyShieldStatus>(
                    IpcCommandTypes.PrivacyConfigure,
                    settings,
                    CancellationToken.None)
                .ConfigureAwait(true);
            ApplyStatus(status);
        }
        catch (ServiceUnavailableException exception)
        {
            StatusBadge = "UNAVAILABLE";
            StatusText = exception.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task DisableAsync()
    {
        if (_client is null || IsBusy)
        {
            return;
        }

        IsBusy = true;
        try
        {
            var settings = BuildSettings() with { Enabled = false };
            if (!ValidateSettingsSize(settings))
            {
                return;
            }

            var status = await _client
                .SendAsync<PrivacyShieldStatus>(
                    IpcCommandTypes.PrivacyConfigure,
                    settings,
                    CancellationToken.None)
                .ConfigureAwait(true);
            ApplyStatus(status);
        }
        catch (ServiceUnavailableException exception)
        {
            StatusBadge = "UNAVAILABLE";
            StatusText = exception.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task UpdateSourcesAsync()
    {
        if (_client is null || IsBusy)
        {
            return;
        }

        IsBusy = true;
        try
        {
            var settings = BuildSettings();
            if (!ValidateSettingsSize(settings))
            {
                return;
            }

            await _client
                .SendAsync<PrivacyShieldStatus>(
                    IpcCommandTypes.PrivacyConfigure,
                    settings,
                    CancellationToken.None)
                .ConfigureAwait(true);
            var status = await _client
                .SendAsync<PrivacyShieldStatus>(
                    IpcCommandTypes.PrivacySourcesUpdate,
                    null,
                    CancellationToken.None)
                .ConfigureAwait(true);
            ApplyStatus(status);
        }
        catch (ServiceUnavailableException exception)
        {
            StatusBadge = "UNAVAILABLE";
            StatusText = exception.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private const string MacDnsNote =
        "On macOS the Axiom daemon switches system DNS to Privacy Shield automatically while the resolver " +
        "runs and restores the previous DNS servers when it stops. No manual change is needed.";

    [RelayCommand]
    private async Task EnableSystemDnsAsync()
    {
        if (OperatingSystem.IsMacOS())
        {
            // The macOS daemon points system DNS at the resolver itself and restores it on stop.
            DnsHelperStatusText = MacDnsNote;
            return;
        }

        if (!_resolverActive)
        {
            DnsHelperStatusText = "Start the Privacy Shield resolver on port 53 first.";
            return;
        }

        if (SelectedAdapter is null)
        {
            DnsHelperStatusText = "Select a network adapter first.";
            return;
        }

        var confirmed = await _ui.ConfirmAsync(
            "Change adapter DNS",
            $"Point adapter '{SelectedAdapter.Name}' at the Privacy Shield loopback resolver 127.0.0.1?\n\n" +
            "The adapter keeps its current DNS servers behind the resolver as a fallback, so a stopped " +
            $"resolver cannot take the network down. {PlatformText.OsName} will ask for elevation. The previous DNS " +
            "settings are saved and can be restored.",
            "Change DNS",
            destructive: true,
            CancellationToken.None).ConfigureAwait(true);
        if (!confirmed)
        {
            DnsHelperStatusText = "Adapter DNS change cancelled.";
            return;
        }

        DnsHelperStatusText = $"Waiting for {(OperatingSystem.IsMacOS() ? "the macOS administrator prompt" : "the Windows elevation prompt")}...";
        try
        {
            var exitCode = await _dnsHelper
                .EnableAsync(SelectedAdapter.Name, "127.0.0.1", CancellationToken.None)
                .ConfigureAwait(true);
            DnsHelperStatusText = exitCode == 0
                ? $"Adapter '{SelectedAdapter.Name}' now uses 127.0.0.1, with its previous DNS kept as fallback. Original settings were saved."
                : $"The elevated DNS helper exited with code {exitCode}.";
        }
        catch (Exception exception) when (exception is
                     System.ComponentModel.Win32Exception or InvalidOperationException or IOException or NotSupportedException)
        {
            DnsHelperStatusText = "Elevation was cancelled or the DNS helper failed: " + exception.Message;
        }

        RefreshAdapters();
    }

    [RelayCommand]
    private async Task RestoreSystemDnsAsync()
    {
        if (OperatingSystem.IsMacOS())
        {
            // The macOS daemon points system DNS at the resolver itself and restores it on stop.
            DnsHelperStatusText = MacDnsNote;
            return;
        }

        var confirmed = await _ui.ConfirmAsync(
            "Restore adapter DNS",
            $"Restore the adapter DNS settings saved by the Privacy Shield helper? {PlatformText.OsName} will ask for elevation.",
            "Restore DNS",
            destructive: false,
            CancellationToken.None).ConfigureAwait(true);
        if (!confirmed)
        {
            DnsHelperStatusText = "DNS restore cancelled.";
            return;
        }

        DnsHelperStatusText = $"Waiting for {(OperatingSystem.IsMacOS() ? "the macOS administrator prompt" : "the Windows elevation prompt")}...";
        try
        {
            var exitCode = await _dnsHelper
                .RestoreAsync(CancellationToken.None)
                .ConfigureAwait(true);
            DnsHelperStatusText = exitCode == 0
                ? "Original adapter DNS settings were restored."
                : $"The elevated restore helper exited with code {exitCode}.";
        }
        catch (Exception exception) when (exception is
                     System.ComponentModel.Win32Exception or InvalidOperationException or IOException or NotSupportedException)
        {
            DnsHelperStatusText = "Elevation was cancelled or the DNS restore failed: " + exception.Message;
        }

        RefreshAdapters();
    }

    [RelayCommand]
    private async Task ImportBlocklistAsync()
    {
        var path = await _ui
            .PickOpenFileAsync("Import a local domain blocklist", ".txt", "Domain lists", CancellationToken.None)
            .ConfigureAwait(true);
        if (path is null)
        {
            return;
        }

        try
        {
            var info = new FileInfo(path);
            if (info.Length > 8 * 1024 * 1024)
            {
                LastErrorText = "The list is larger than the 8 MB import limit.";
                return;
            }

            var domains = PrivacyShieldPolicy.ParseList(await File.ReadAllTextAsync(path).ConfigureAwait(true));
            if (domains.Count == 0)
            {
                LastErrorText = "No valid domains were found in the selected file.";
                return;
            }

            var existing = PrivacyShieldPolicy.ParseList(BlockedDomainsText).ToList();
            var seen = existing.ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var domain in domains)
            {
                if (seen.Add(domain))
                {
                    existing.Add(domain);
                }
            }

            BlockedDomainsText = string.Join(Environment.NewLine, existing);
            LastErrorText = $"Imported {domains.Count} unique domain(s) into the custom blocklist.";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            LastErrorText = "Could not read the selected list: " + exception.Message;
        }
    }

    [RelayCommand]
    private void ClearDomains()
    {
        AllowedDomainsText = string.Empty;
        BlockedDomainsText = string.Empty;
        LastErrorText = "Custom allow/block lists cleared in the form. Apply to save.";
    }

    [RelayCommand]
    private Task AllowBlockedDomainAsync(BlockedEventRow? row) => SetBlockedDomainDecisionAsync(row, allow: true);

    [RelayCommand]
    private Task BlockBlockedDomainAsync(BlockedEventRow? row) => SetBlockedDomainDecisionAsync(row, allow: false);

    private async Task SetBlockedDomainDecisionAsync(BlockedEventRow? row, bool allow)
    {
        if (row is null || _client is null || IsBusy)
        {
            return;
        }

        var allowed = PrivacyShieldPolicy.ParseList(AllowedDomainsText).ToList();
        var blocked = PrivacyShieldPolicy.ParseList(BlockedDomainsText).ToList();
        if (allow)
        {
            if (!allowed.Contains(row.Domain, StringComparer.OrdinalIgnoreCase))
            {
                allowed.Add(row.Domain);
            }

            blocked.RemoveAll(domain => string.Equals(domain, row.Domain, StringComparison.OrdinalIgnoreCase));
        }
        else
        {
            blocked.RemoveAll(domain => string.Equals(domain, row.Domain, StringComparison.OrdinalIgnoreCase));
            blocked.Add(row.Domain);
            allowed.RemoveAll(domain => string.Equals(domain, row.Domain, StringComparison.OrdinalIgnoreCase));
        }

        AllowedDomainsText = string.Join(Environment.NewLine, allowed);
        BlockedDomainsText = string.Join(Environment.NewLine, blocked);
        await ApplyAsync().ConfigureAwait(true);
        if (string.IsNullOrWhiteSpace(LastErrorText))
        {
            LastErrorText = allow
                ? $"{row.Domain}: allowed. Use Block to block it again."
                : $"{row.Domain}: blocked in the custom list. Allow removes this custom block.";
        }
    }

    [RelayCommand]
    private async Task ClearBlockedHistoryAsync()
    {
        if (_client is null || IsBusy)
        {
            return;
        }

        IsBusy = true;
        try
        {
            var status = await _client
                .SendAsync<PrivacyShieldStatus>(
                    IpcCommandTypes.PrivacyHistoryClear,
                    null,
                    CancellationToken.None)
                .ConfigureAwait(true);
            ApplyStatus(status);
        }
        catch (ServiceUnavailableException exception)
        {
            StatusBadge = "UNAVAILABLE";
            StatusText = exception.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private PrivacyShieldSettings BuildSettings()
    {
        var categories = PrivacyCategory.Custom;
        if (Telemetry)
        {
            categories |= PrivacyCategory.Telemetry;
        }

        if (Ads)
        {
            categories |= PrivacyCategory.Ads;
        }

        if (Tracking)
        {
            categories |= PrivacyCategory.Tracking;
        }

        if (Analytics)
        {
            categories |= PrivacyCategory.Analytics;
        }

        if (Malware)
        {
            categories |= PrivacyCategory.Malware;
        }

        return new PrivacyShieldSettings
        {
            Enabled = Enabled,
            Profile = SelectedProfile?.Value ?? PrivacyShieldProfile.Balanced,
            Categories = categories,
            Port = int.TryParse(PortText, out var port) ? port : 53,
            UpstreamDns = UpstreamText.Trim(),
            AllowedDomains = PrivacyShieldPolicy.ParseList(
                AllowedDomainsText,
                PrivacyShieldPolicy.MaxSettingsDomains),
            BlockedDomains = PrivacyShieldPolicy.ParseList(
                BlockedDomainsText,
                PrivacyShieldPolicy.MaxSettingsDomains),
            EnabledSourceIds = Sources
                .Where(source => source.Enabled)
                .Select(source => source.Id)
                .ToArray(),
        };
    }

    private bool ValidateSettingsSize(PrivacyShieldSettings settings)
    {
        var characters = settings.AllowedDomains.Sum(domain => domain.Length) +
                         settings.BlockedDomains.Sum(domain => domain.Length);
        if (characters <= 180_000)
        {
            return true;
        }

        LastErrorText =
            "The allow/block lists are too large for the local IPC settings message. " +
            $"Keep the combined list under 180,000 characters (currently {characters:N0}).";
        return false;
    }

    private void ApplyStatus(PrivacyShieldStatus status)
    {
        _updating = true;
        try
        {
            _resolverActive = status.Running;
            var settings = status.Settings;
            Enabled = settings.Enabled;
            SelectedProfile = Profiles.FirstOrDefault(profile => profile.Value == settings.Profile)
                              ?? Profiles[1];
            Telemetry = (settings.Categories & PrivacyCategory.Telemetry) != 0;
            Ads = (settings.Categories & PrivacyCategory.Ads) != 0;
            Tracking = (settings.Categories & PrivacyCategory.Tracking) != 0;
            Analytics = (settings.Categories & PrivacyCategory.Analytics) != 0;
            Malware = (settings.Categories & PrivacyCategory.Malware) != 0;
            PortText = settings.Port.ToString(CultureInfo.InvariantCulture);
            UpstreamText = settings.UpstreamDns;
            AllowedDomainsText = string.Join(Environment.NewLine, settings.AllowedDomains);
            BlockedDomainsText = string.Join(Environment.NewLine, settings.BlockedDomains);
            foreach (var source in Sources)
            {
                var state = status.Sources.FirstOrDefault(item =>
                    string.Equals(item.Id, source.Id, StringComparison.OrdinalIgnoreCase));
                source.Enabled = settings.EnabledSourceIds.Contains(
                    source.Id,
                    StringComparer.OrdinalIgnoreCase);
                source.Entries = state?.Entries ?? 0;
                source.UpdatedText = state?.UpdatedUtc is { } updated
                    ? $"updated {updated.ToLocalTime():MM-dd HH:mm} · {state.Entries:N0} entries"
                    : "not downloaded";
                source.ErrorText = state?.Error ?? string.Empty;
            }
        }
        finally
        {
            _updating = false;
        }

        ApplyStats(status);
    }

    private void ApplyStats(PrivacyShieldStatus status)
    {
        _resolverActive = status.Running;
        StatusBadge = status.Running ? "ACTIVE" : status.Enabled ? "ERROR" : "DISABLED";
        StatusText = status.Running
            ? $"Listening on {status.BindAddress}:{status.Port}; upstream {status.Upstream}."
            : status.Detail;
        DetailText = $"{status.RuleCount:N0} active rules · {status.Allowed:N0} allowed · " +
                     $"{status.Blocked:N0} blocked · {status.Errors:N0} errors. " +
                     "Counts are in memory and reset when the resolver restarts.";
        StatsText = status.Running
            ? $"{status.Queries:N0} queries observed."
            : "No queries observed.";
        UpdateStatsHint(status);
        if (SelectedAdapter is { UsesResolver: true } activeAdapter &&
            DnsHelperStatusText == "No adapter DNS change has been made.")
        {
            DnsHelperStatusText =
                $"Adapter '{activeAdapter.Name}' already sends DNS to the Privacy Shield resolver at 127.0.0.1.";
        }

        LastUpdatedText = $"Updated {DateTimeOffset.Now:HH:mm:ss}";
        LastErrorText = status.LastError ?? string.Empty;

        TopBlocked.Clear();
        foreach (var domain in status.TopBlocked)
        {
            TopBlocked.Add(domain);
        }

        var allowedDomains = status.Settings.AllowedDomains.ToHashSet(StringComparer.OrdinalIgnoreCase);

        RecentBlocked.Clear();
        foreach (var blocked in status.RecentBlocked)
        {
            RecentBlocked.Add(new BlockedEventRow(blocked, allowedDomains.Contains(blocked.Domain)));
        }

        // Viber and similar apps can emit dozens of blocks a minute. Group by domain and app so the
        // page shows what is happening instead of a growing wall of identical rows.
        _recentGroups = RecentBlocked
            .GroupBy(row => (row.Domain, row.AppDisplay))
            .Select(group => new RecentBlockedGroup(
                group.Key.Domain,
                group.Key.AppDisplay,
                group.First().CategoryText,
                group.Count(),
                group.Max(row => row.TimestampUtc),
                group.OrderByDescending(row => row.TimestampUtc).First()))
            .OrderByDescending(group => group.Count)
            .ThenByDescending(group => group.LastUtc)
            .ToList();
        ApplyRecentGroupView();

        var historyRows = status.BlockedHistory
            .Select(blocked => new BlockedEventRow(blocked, allowedDomains.Contains(blocked.Domain)))
            .ToList();

        UpdateBlockedHistory(historyRows);
        RefreshAdapters();
    }

    /// <summary>
    /// Rebuilds the grouped retained history only when its content changed, and restores the groups
    /// the user opened. Rebuilding on every two-second tick replaced the items, so every Expander
    /// closed again and a list could not be read while blocked queries were still arriving.
    /// </summary>
    private void UpdateBlockedHistory(List<BlockedEventRow> historyRows)
    {
        var signature = BuildBlockedHistorySignature(historyRows);
        if (string.Equals(signature, _blockedHistorySignature, StringComparison.Ordinal))
        {
            return;
        }

        _blockedHistorySignature = signature;
        BlockedHistoryGroups.Clear();

        var knownApps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var appGroup in historyRows
                     .GroupBy(row => row.AppDisplay, StringComparer.OrdinalIgnoreCase)
                     .OrderByDescending(group => group.Count())
                     .ThenByDescending(group => group.Max(row => row.TimestampUtc)))
        {
            var domains = appGroup
                .GroupBy(row => row.Domain, StringComparer.OrdinalIgnoreCase)
                .Select(domainGroup => new BlockedHistoryDomainRow(
                    domainGroup.Key,
                    domainGroup.First().CategoryText,
                    domainGroup.Count(),
                    domainGroup.Max(row => row.TimestampUtc),
                    domainGroup.OrderByDescending(row => row.TimestampUtc).First()))
                .OrderByDescending(domain => domain.Count)
                .ThenByDescending(domain => domain.LastUtc)
                .ToList();

            var group = new BlockedHistoryAppGroup(
                appGroup.Key,
                appGroup.Select(row => row.AppPath).FirstOrDefault(path => !string.IsNullOrWhiteSpace(path))
                ?? string.Empty,
                domains,
                appGroup.Max(row => row.TimestampUtc));
            group.IsExpanded = _expandedHistoryApps.Contains(group.AppDisplay);
            group.PropertyChanged += OnBlockedHistoryGroupPropertyChanged;
            knownApps.Add(group.AppDisplay);
            BlockedHistoryGroups.Add(group);
        }

        _expandedHistoryApps.RemoveWhere(app => !knownApps.Contains(app));

        BlockedHistorySummary = historyRows.Count == 0
            ? "No blocked query history yet."
            : $"{historyRows.Count} blocks from {BlockedHistoryGroups.Count} apps; open an app to see its domains.";
    }

    private void OnBlockedHistoryGroupPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(BlockedHistoryAppGroup.IsExpanded) ||
            sender is not BlockedHistoryAppGroup group)
        {
            return;
        }

        if (group.IsExpanded)
        {
            _expandedHistoryApps.Add(group.AppDisplay);
        }
        else
        {
            _expandedHistoryApps.Remove(group.AppDisplay);
        }
    }

    private static string BuildBlockedHistorySignature(List<BlockedEventRow> rows)
    {
        if (rows.Count == 0)
        {
            return string.Empty;
        }

        var builder = new StringBuilder();
        foreach (var row in rows
                     .OrderBy(row => row.AppDisplay, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(row => row.Domain, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(row => row.TimestampUtc.UtcTicks)
                     .ThenBy(row => row.CategoryText, StringComparer.Ordinal))
        {
            builder.Append(row.AppDisplay).Append('\u001f')
                .Append(row.AppPath).Append('\u001f')
                .Append(row.Domain).Append('\u001f')
                .Append(row.CategoryText).Append('\u001f')
                .Append(row.CanAllow ? '1' : '0').Append('\u001f')
                .Append(row.TimestampUtc.UtcTicks).Append('\u001e');
        }

        return builder.ToString();
    }


    private static readonly TimeSpan MacDnsOutageGrace = TimeSpan.FromSeconds(8);
    private DateTimeOffset? _dnsOutageFirstSeenUtc;

    /// <summary>
    /// A stopped resolver while an adapter points at 127.0.0.1 means names stop resolving unless
    /// the adapter kept a fallback server. Say which of the two is true instead of leaving the user
    /// with a dead LAN and no explanation.
    /// </summary>
    private void UpdateDnsOutageWarning()
    {
        var risky = Adapters.FirstOrDefault(adapter => adapter.UsesResolver);
        if (_resolverActive || risky is null)
        {
            HasDnsOutageRisk = false;
            DnsOutageWarningText = string.Empty;
            _dnsOutageAlerted = false;
            _dnsOutageFirstSeenUtc = null;
            return;
        }

        // On macOS the daemon restores system DNS right after it stops the resolver, and the
        // system resolver configuration reaches this process a moment later. Only warn when the
        // adapter still points at 127.0.0.1 after a short grace period, so a normal Disable does
        // not raise a false "DNS is not answering" alert.
        if (OperatingSystem.IsMacOS())
        {
            var now = DateTimeOffset.UtcNow;
            _dnsOutageFirstSeenUtc ??= now;
            if (now - _dnsOutageFirstSeenUtc.Value < MacDnsOutageGrace)
            {
                return;
            }
        }

        HasDnsOutageRisk = true;
        if (risky.HasFallback)
        {
            DnsOutageWarningText =
                $"Adapter '{risky.Name}' sends DNS to 127.0.0.1 first, but the Privacy Shield resolver " +
                "is not running. Its fallback DNS server still answers, so names keep resolving, but " +
                "filtering is bypassed until you start Privacy Shield.";

            if (!_dnsOutageAlerted)
            {
                _dnsOutageAlerted = true;
                AxiomAlertService.Show(
                    "Privacy Shield resolver is stopped",
                    $"{risky.Name} falls back to its saved DNS server. The network still works, but " +
                    "Privacy Shield filtering is bypassed.",
                    force: false,
                    page: typeof(PrivacyShieldPageViewModel));
            }

            return;
        }

        DnsOutageWarningText =
            $"Adapter '{risky.Name}' sends DNS to 127.0.0.1, but the Privacy Shield resolver is not " +
            "running. Names will not resolve on that adapter until you start Privacy Shield or " +
            "restore the saved DNS.";

        if (!_dnsOutageAlerted)
        {
            _dnsOutageAlerted = true;
            AxiomAlertService.Show(
                "Privacy Shield DNS is not answering",
                $"{risky.Name} points at 127.0.0.1 while the resolver is stopped. Restore the saved DNS " +
                "or start Privacy Shield.",
                force: true,
                page: typeof(PrivacyShieldPageViewModel));
        }
    }

    private void ApplyRecentGroupView()
    {
        RecentBlockedGroups.Clear();
        var limit = ShowAllRecentBlocked ? 40 : 6;
        foreach (var group in _recentGroups.Take(limit))
        {
            RecentBlockedGroups.Add(group);
        }

        if (_recentGroups.Count == 0)
        {
            RecentBlockedSummary = "No blocked queries in the live window.";
            return;
        }

        var total = _recentGroups.Sum(group => group.Count);
        RecentBlockedSummary = _recentGroups.Count <= limit
            ? $"{total} blocks across {_recentGroups.Count} domain/app pairs."
            : $"{total} blocks across {_recentGroups.Count} domain/app pairs; showing the top {limit}.";
    }

    private void UpdateStatsHint(PrivacyShieldStatus status)
    {
        if (!status.Running || status.Queries > 0)
        {
            StatsHintText = string.Empty;
            HasStatsHint = false;
            return;
        }

        var pointed = Adapters
            .Where(adapter => adapter.UsesResolver)
            .Select(adapter => adapter.Name)
            .ToArray();
        StatsHintText = pointed.Length > 0
            ? $"No DNS query yet. {string.Join(", ", pointed)} already sends DNS to 127.0.0.1, " +
              "so the next query will appear here. Counters reset when the resolver restarts."
            : "The resolver is running but nothing uses it: no adapter DNS points at 127.0.0.1. " +
              "Select the default-route adapter below and press \"Point adapter at resolver\" " +
              "(Windows asks for elevation). Until then Windows bypasses Privacy Shield and these " +
              "counters stay at zero.";
        HasStatsHint = true;
    }

    private static PrivacyShieldAdapterOption[] BuildAdapterOptions() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .Where(network => network.OperationalStatus == OperationalStatus.Up &&
                              network.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .Select(network =>
            {
                var properties = network.GetIPProperties();
                var usesResolver = properties.DnsAddresses.Any(IPAddress.IsLoopback);
                var resolverAddress = properties.DnsAddresses
                    .Where(IPAddress.IsLoopback)
                    .OrderBy(address => address.AddressFamily == AddressFamily.InterNetwork ? 0 : 1)
                    .Select(address => address.ToString())
                    .FirstOrDefault();
                var otherDns = properties.DnsAddresses
                    .Where(address => !IPAddress.IsLoopback(address))
                    .Select(address => address.ToString())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                var dnsText = usesResolver
                    ? $"{resolverAddress} · Privacy Shield" +
                      (otherDns.Length == 0 ? string.Empty : ", " + string.Join(", ", otherDns))
                    : otherDns.Length == 0
                        ? "automatic"
                        : string.Join(", ", otherDns);

                var hasDefaultRoute = properties.GatewayAddresses.Any(gateway =>
                    !gateway.Address.Equals(IPAddress.Any) &&
                    !gateway.Address.Equals(IPAddress.IPv6Any) &&
                    !IPAddress.IsLoopback(gateway.Address));
                return new PrivacyShieldAdapterOption(
                    network.Name,
                    network.Description,
                    dnsText,
                    hasDefaultRoute,
                    usesResolver,
                    otherDns.Length > 0);
            })
            .OrderByDescending(adapter => adapter.HasDefaultRoute)
            .ThenBy(adapter => adapter.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private void RefreshAdapters()
    {
        var selectedName = SelectedAdapter?.Name;
        var options = BuildAdapterOptions();
        if (!Adapters.SequenceEqual(options))
        {
            Adapters.Clear();
            foreach (var option in options)
            {
                Adapters.Add(option);
            }

            SelectedAdapter = Adapters.FirstOrDefault(adapter =>
                                  string.Equals(adapter.Name, selectedName, StringComparison.OrdinalIgnoreCase))
                              ?? Adapters.FirstOrDefault();
        }

        UpdateDnsOutageWarning();
    }

    private void ApplyProfileCategories(PrivacyShieldProfile profile)
    {
        var categories = PrivacyShieldCategories.ForProfile(profile);
        _updating = true;
        try
        {
            Telemetry = (categories & PrivacyCategory.Telemetry) != 0;
            Ads = (categories & PrivacyCategory.Ads) != 0;
            Tracking = (categories & PrivacyCategory.Tracking) != 0;
            Analytics = (categories & PrivacyCategory.Analytics) != 0;
            Malware = (categories & PrivacyCategory.Malware) != 0;
        }
        finally
        {
            _updating = false;
        }
    }
}
