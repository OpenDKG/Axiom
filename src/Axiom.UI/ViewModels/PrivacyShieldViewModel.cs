// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Privacy;
using Axiom.UI.Services;

namespace Axiom.UI.ViewModels;

public sealed record PrivacyShieldProfileOption(PrivacyShieldProfile Value, string Label)
{
    public override string ToString() => Label;
}

public sealed record PrivacyShieldAdapterOption(
    string Name,
    string Description,
    string DnsText,
    bool HasDefaultRoute)
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

/// <summary>
/// Privacy Shield is a local DNS filter. Complete installation enables the resolver; a partial
/// installation leaves it opt-in. It never changes adapter DNS settings; the user
/// must point Windows at the displayed loopback resolver explicitly.
/// </summary>
public sealed partial class PrivacyShieldViewModel : PageViewModel, IActivatablePage, IDisposable
{
    private readonly ServicePipeClient? _client;

    private readonly System.Windows.Threading.DispatcherTimer _statsTimer = new()
    {
        Interval = TimeSpan.FromSeconds(2),
    };

    private bool _updating;
    private bool _resolverActive;
    private bool _statsRefreshing;

    public PrivacyShieldViewModel(bool serviceMode)
        : base("Privacy Shield", "Local DNS filtering · complete installation enables the resolver", "\uE72E")
    {
        _client = serviceMode ? new ServicePipeClient() : null;
        Profiles =
        [
            new(PrivacyShieldProfile.Basic, "Basic · Windows telemetry"),
            new(PrivacyShieldProfile.Balanced, "Balanced · telemetry, ads, tracking"),
            new(PrivacyShieldProfile.Strict, "Strict · all categories"),
        ];
        _selectedProfile = Profiles[1];
        ApplyProfileCategories(PrivacyShieldProfile.Balanced);
        Adapters = new ObservableCollection<PrivacyShieldAdapterOption>(
            NetworkInterface.GetAllNetworkInterfaces()
                .Where(network => network.OperationalStatus == OperationalStatus.Up &&
                                  network.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .Select(network =>
                {
                    var properties = network.GetIPProperties();
                    var dns = properties.DnsAddresses
                        .Where(address => !IPAddress.IsLoopback(address))
                        .Select(address => address.ToString())
                        .Distinct()
                        .ToArray();
                    var hasDefaultRoute = properties.GatewayAddresses.Any(gateway =>
                        !gateway.Address.Equals(IPAddress.Any) &&
                        !gateway.Address.Equals(IPAddress.IPv6Any) &&
                        !IPAddress.IsLoopback(gateway.Address));
                    return new PrivacyShieldAdapterOption(
                        network.Name,
                        network.Description,
                        dns.Length == 0 ? "automatic" : string.Join(", ", dns),
                        hasDefaultRoute);
                })
                .OrderByDescending(adapter => adapter.HasDefaultRoute)
                .ThenBy(adapter => adapter.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray());
        _selectedAdapter = Adapters.FirstOrDefault();
        if (!serviceMode)
        {
            StatusBadge = "SERVICE REQUIRED";
            StatusText = "Privacy Shield runs in the local Axiom service. Start Axiom with --service.";
            DetailText = "No DNS settings were changed.";
        }
        else
        {
            _statsTimer.Tick += (_, _) => _ = RefreshStatsAsync();
            _ = RefreshAsync();
        }
    }

    public bool IsSupported => _client is not null;

    public IReadOnlyList<PrivacyShieldProfileOption> Profiles { get; }

    public ObservableCollection<PrivacyShieldTopDomain> TopBlocked { get; } = [];

    public ObservableCollection<PrivacyShieldBlockedEvent> RecentBlocked { get; } = [];

    public ObservableCollection<PrivacyShieldBlockedEvent> BlockedHistory { get; } = [];

    public ObservableCollection<PrivacyShieldSourceRow> Sources { get; } =
        new(PrivacyShieldSourceCatalog.All.Select(source => new PrivacyShieldSourceRow(source)));

    public ObservableCollection<PrivacyShieldAdapterOption> Adapters { get; }

    [ObservableProperty]
    private PrivacyShieldAdapterOption? _selectedAdapter;

    [ObservableProperty]
    private string _dnsHelperStatusText = "No adapter DNS change has been made.";

    public string StarterRulesText =>
        $"{PrivacyShieldPolicy.StarterRulesAll.Count} starter rules (manually reviewed, not a third-party list)";

    public string ManualSetupText =>
        "The Axiom service never changes adapter DNS silently. The optional UAC helper changes " +
        "only the selected adapter after you confirm Windows elevation; it saves the previous DNS " +
        "and can restore it. If you do not use the helper, set the adapter DNS to 127.0.0.1 " +
        "(port 53) manually. Until Windows DNS points at this resolver, normal traffic bypasses it " +
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
        _statsTimer.Start();
        _ = RefreshAsync();
    }

    public void Deactivate() => _statsTimer.Stop();

    public void Dispose() => _statsTimer.Stop();

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

            var status = await _client
                .SendAsync<PrivacyShieldStatus>(
                    IpcCommandTypes.PrivacyConfigure,
                    settings,
                    CancellationToken.None)
                .ConfigureAwait(true);
            status = await _client
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

    [RelayCommand]
    private async Task EnableSystemDnsAsync()
    {
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

        DnsHelperStatusText = "Waiting for the Windows elevation prompt...";
        try
        {
            var exitCode = await PrivacyShieldDnsHelper
                .EnableAsync(SelectedAdapter.Name, "127.0.0.1", CancellationToken.None)
                .ConfigureAwait(true);
            DnsHelperStatusText = exitCode == 0
                ? $"Adapter '{SelectedAdapter.Name}' now uses 127.0.0.1. Original settings were saved."
                : $"The elevated DNS helper exited with code {exitCode}.";
        }
        catch (Exception exception) when (exception is
                     System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            DnsHelperStatusText = "Elevation was cancelled or the DNS helper failed: " + exception.Message;
        }
    }

    [RelayCommand]
    private async Task RestoreSystemDnsAsync()
    {
        DnsHelperStatusText = "Waiting for the Windows elevation prompt...";
        try
        {
            var exitCode = await PrivacyShieldDnsHelper
                .RestoreAsync(CancellationToken.None)
                .ConfigureAwait(true);
            DnsHelperStatusText = exitCode == 0
                ? "Original adapter DNS settings were restored."
                : $"The elevated restore helper exited with code {exitCode}.";
        }
        catch (Exception exception) when (exception is
                     System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            DnsHelperStatusText = "Elevation was cancelled or the DNS restore failed: " + exception.Message;
        }
    }

    [RelayCommand]
    private void ImportBlocklist()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Import a local domain blocklist",
            Filter = "Domain lists (*.txt;*.list;*.hosts)|*.txt;*.list;*.hosts|All files (*.*)|*.*",
            Multiselect = false,
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            var info = new FileInfo(dialog.FileName);
            if (info.Length > 8 * 1024 * 1024)
            {
                LastErrorText = "The list is larger than the 8 MB import limit.";
                return;
            }

            var domains = PrivacyShieldPolicy.ParseList(File.ReadAllText(dialog.FileName));
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
            PortText = settings.Port.ToString(System.Globalization.CultureInfo.InvariantCulture);
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
        LastUpdatedText = $"Updated {DateTimeOffset.Now:HH:mm:ss}";
        LastErrorText = status.LastError ?? string.Empty;

        TopBlocked.Clear();
        foreach (var domain in status.TopBlocked)
        {
            TopBlocked.Add(domain);
        }

        RecentBlocked.Clear();
        foreach (var blocked in status.RecentBlocked)
        {
            RecentBlocked.Add(blocked);
        }

        BlockedHistory.Clear();
        foreach (var blocked in status.BlockedHistory)
        {
            BlockedHistory.Add(blocked);
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
