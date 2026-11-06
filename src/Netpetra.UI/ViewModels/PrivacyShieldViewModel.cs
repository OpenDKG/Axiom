// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using Netpetra.Contracts.Ipc;
using Netpetra.Contracts.Privacy;
using Netpetra.UI.Services;

namespace Netpetra.UI.ViewModels;

public sealed record PrivacyShieldProfileOption(PrivacyShieldProfile Value, string Label)
{
    public override string ToString() => Label;
}

/// <summary>
/// Privacy Shield is an opt-in local DNS filter. It never changes adapter DNS settings; the user
/// must point Windows at the displayed loopback resolver explicitly.
/// </summary>
public sealed partial class PrivacyShieldViewModel : PageViewModel, IActivatablePage
{
    private readonly ServicePipeClient? _client;

    private bool _updating;

    public PrivacyShieldViewModel(bool serviceMode)
        : base("Privacy Shield", "Optional local DNS filtering; disabled by default", "\uE72E")
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
        if (!serviceMode)
        {
            StatusBadge = "SERVICE REQUIRED";
            StatusText = "Privacy Shield runs in the local Netpetra service. Start Netpetra with --service.";
            DetailText = "No DNS settings were changed.";
        }
        else
        {
            _ = RefreshAsync();
        }
    }

    public bool IsSupported => _client is not null;

    public IReadOnlyList<PrivacyShieldProfileOption> Profiles { get; }

    public ObservableCollection<PrivacyShieldTopDomain> TopBlocked { get; } = [];

    public string StarterRulesText =>
        $"{PrivacyShieldPolicy.StarterRulesAll.Count} starter rules (manually reviewed, not a third-party list)";

    public string ManualSetupText =>
        "This page never changes adapter DNS settings. To filter this PC, use the elevated " +
        "scripts/privacy-shield-dns.ps1 helper: Save, then Enable -InterfaceAlias, and Restore " +
        "if resolution fails. Without the helper, set the adapter DNS to 127.0.0.1 (port 53) " +
        "with administrator rights and keep the previous values. A resolver on any other port is " +
        "for testing only; the Windows DNS client always uses port 53.";

    public string BypassText =>
        "DNS filtering does not block hardcoded IPs, DoH/DoT/DoQ, VPN tunnels or answers cached " +
        "before activation. A blocked query is not proof that a connection was prevented.";

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

    public void Activate() => _ = RefreshAsync();

    public void Deactivate()
    {
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
        }
        finally
        {
            _updating = false;
        }

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
        LastErrorText = status.LastError ?? string.Empty;

        TopBlocked.Clear();
        foreach (var domain in status.TopBlocked)
        {
            TopBlocked.Add(domain);
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
