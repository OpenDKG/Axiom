// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using Netpetra.Contracts.Community;
using Netpetra.Contracts.Files;
using Netpetra.Contracts.Modules;
using Netpetra.Contracts.Reputation;
using Netpetra.UI.Services;
using Netpetra.UI.Views;

namespace Netpetra.UI.ViewModels;

/// <summary>One loopback probe sample for the activity strip.</summary>
public sealed record ModuleActivity(DateTimeOffset At, bool DkgConnected, bool BlackboxConnected);

/// <summary>Status of one optional security or intelligence module.</summary>
public sealed record SecurityModule(
    string Name,
    string Status,
    string Detail,
    string Glyph,
    bool IsConnected = false,
    bool CanAct = false,
    string ActionLabel = "Install",
    bool CanUninstall = false,
    bool CanSetMode = false);

public sealed partial class FileScanRow : ObservableObject
{
    public FileScanRow(FileScanEntry entry)
    {
        Path = entry.Path;
        Name = System.IO.Path.GetFileName(entry.Path);
        SizeBytes = entry.SizeBytes;
        Sha256 = entry.Sha256;
        SkippedReason = entry.SkippedReason;
    }

    public string Path { get; }

    public string Name { get; }

    public long SizeBytes { get; }

    public string? Sha256 { get; }

    public string? SkippedReason { get; }

    public bool HasHash => Sha256 is not null;

    public string SizeText => $"{SizeBytes:N0} B";

    public string HashText => Sha256 ?? SkippedReason ?? "—";

    public string StatusText => Sha256 is null ? "SKIPPED" : "HASHED";

    [ObservableProperty]
    private string _verdictText = "Not checked";
}

public sealed record CommunityFeedRow(string Sha256, string Name, string Verdict, string Source);

/// <summary>
/// Security page. Optional modules are read-only status probes; install buttons launch the official
/// third-party installer only after an explicit warning. Netpetra does not stop or control a module.
/// </summary>
public sealed partial class SecurityViewModel : PageViewModel, IDisposable
{
    private readonly OptionalModuleProbe _probe = new();

    private readonly OptionalModuleInstaller _installer = new();

    private readonly OptionalModuleUninstaller _uninstaller = new();

    private readonly BlackboxModeStore _blackboxMode = new();

    private readonly BoundedHistory<ModuleActivity> _activityHistory = new(30);

    private readonly ReputationSettingsStore _reputationStore = new();

    private readonly VirusTotalClient _virusTotal = new();

    private readonly CommunityFeedSettingsStore _communityStore = new();

    private readonly CommunityFeedClient _communityClient = new();

    private ReputationSettings _reputationSettings = new(false, string.Empty);

    private CommunityFeedSettings _communitySettings = new(false, string.Empty, string.Empty);

    private bool _communityConnected;

    private readonly DispatcherTimer _activityTimer;

    public SecurityViewModel()
        : base("Security", "Optional intelligence and protection modules", "\uE8D7")
    {
        _reputationSettings = _reputationStore.Load();
        _communitySettings = _communityStore.Load();
        _communityConnected = IsBundledStarterAvailable();
        _blackboxModeText = _blackboxMode.GetMode();
        Modules = [];
        SeedCheckingState();

        if (_communitySettings.Enabled && !string.IsNullOrWhiteSpace(_communitySettings.Url))
        {
            _ = RefreshCommunityAsync();
        }

        _activityTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
        _activityTimer.Tick += (_, _) => _ = RefreshAsync();
        _activityTimer.Start();

        _ = RefreshAsync();
    }

    public ObservableCollection<SecurityModule> Modules { get; }

    public ObservableCollection<ModuleActivity> Activity { get; } = [];

    public ObservableCollection<FileScanRow> FileScanResults { get; } = [];

    public ObservableCollection<CommunityFeedRow> CommunityEntries { get; } = [];

    [ObservableProperty]
    private string _fileScanStatus = "No folder scanned.";

    [ObservableProperty]
    private string _communityStatusText = "Not configured.";

    [ObservableProperty]
    private bool _isScanning;

    [ObservableProperty]
    private bool _isFetchingCommunity;

    [ObservableProperty]
    private bool _isCheckingHash;

    private string ReputationStatus => _reputationSettings.Enabled && !string.IsNullOrWhiteSpace(_reputationSettings.ApiKey)
        ? "CONFIGURED"
        : "NOT CONFIGURED";

    private string ReputationDetail => _reputationSettings.Enabled && !string.IsNullOrWhiteSpace(_reputationSettings.ApiKey)
        ? "Hash-only lookups enabled; the API key is stored with Windows DPAPI."
        : "No external reputation lookup is enabled. Unknown is shown as unknown.";

    private bool IsCommunityConfigured =>
        _communitySettings.Enabled && !string.IsNullOrWhiteSpace(_communitySettings.Url);

    private bool IsStarterFeed =>
        string.Equals(_communitySettings.Url, CommunityFeedSettingsStore.StarterFeedUrl, StringComparison.OrdinalIgnoreCase);

    private bool IsBundledStarterAvailable() =>
        IsCommunityConfigured &&
        IsStarterFeed &&
        File.Exists(Path.Combine(AppContext.BaseDirectory, "community", "feed.json"));

    private string CommunityStatus => _communityConnected
        ? "CONNECTED"
        : IsCommunityConfigured ? "CONFIGURED" : "NOT CONFIGURED";

    private string CommunityDetail => _communityConnected
        ? IsStarterFeed
            ? "Bundled starter feed loaded; entries are evidence, not a verdict."
            : "HTTPS feed loaded; entries are evidence, not a verdict."
        : IsCommunityConfigured
            ? IsStarterFeed
                ? "Bundled starter feed configured; waiting for the first refresh."
                : "HTTPS feed configured; entries are evidence, not a verdict."
            : "No community report is fetched, verified or published.";

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private string _lastCheckedText = "Not checked yet";

    [ObservableProperty]
    private string _installStatusText = string.Empty;

    [ObservableProperty]
    private string _blackboxModeText = "audit";

    public string StatusTitle
    {
        get
        {
            var connected = Modules.Count(module => module.IsConnected);
            return connected switch
            {
                0 => "Optional modules are off by design",
                1 => "1 optional module connected",
                _ => $"{connected} optional modules connected",
            };
        }
    }

    public string StatusBadge => Modules.Any(module => module.IsConnected) ? "CONNECTED" : "OFFLINE";

    public string StatusText => Modules.Any(module => module.IsConnected)
        ? "Netpetra reads loopback status. Install buttons open the official third-party installer only after confirmation."
        : "The standard build is local and offline. Use Install to open the official third-party installer after confirmation.";

    public void Dispose()
    {
        _activityTimer.Stop();
        _probe.Dispose();
        _virusTotal.Dispose();
        _communityClient.Dispose();
    }

    [RelayCommand]
    private async Task RefreshAsync()
    {
        if (IsBusy)
        {
            return;
        }

        IsBusy = true;

        try
        {
            var dkgTask = _probe.ProbeDkgAsync(CancellationToken.None);
            var blackboxTask = _probe.ProbeBlackboxAsync(CancellationToken.None);

            await Task.WhenAll(dkgTask, blackboxTask).ConfigureAwait(true);

            Rebuild(dkgTask.Result, blackboxTask.Result);
            LastCheckedText = $"Checked {DateTimeOffset.Now:HH:mm:ss}";

            _activityHistory.Add(new ModuleActivity(
                DateTimeOffset.Now,
                dkgTask.Result.IsConnected,
                blackboxTask.Result.IsConnected));

            Activity.Clear();
            foreach (var sample in _activityHistory.Items)
            {
                Activity.Add(sample);
            }
        }
        finally
        {
            IsBusy = false;
            OnPropertyChanged(nameof(StatusTitle));
            OnPropertyChanged(nameof(StatusBadge));
            OnPropertyChanged(nameof(StatusText));
        }
    }

    [RelayCommand]
    private async Task ActOnModuleAsync(string? module)
    {
        if (string.IsNullOrWhiteSpace(module))
        {
            return;
        }

        if (module.Equals("File scanning", StringComparison.Ordinal))
        {
            await ScanFilesAsync().ConfigureAwait(true);
            return;
        }

        if (module.Equals("Reputation provider", StringComparison.Ordinal))
        {
            await SetupReputationAsync().ConfigureAwait(true);
            return;
        }

        if (module.Equals("Community feed", StringComparison.Ordinal))
        {
            await SetupCommunityAsync().ConfigureAwait(true);
            return;
        }

        if (module.Equals("Blackbox", StringComparison.Ordinal))
        {
            if (_uninstaller.IsBlackboxInstalled)
            {
                var started = _installer.StartBlackboxDashboard();
                InstallStatusText = started
                    ? "Blackbox dashboard start requested. Checking again in a few seconds."
                    : "Blackbox venv is missing. Reinstall Blackbox to repair it.";

                if (started)
                {
                    await Task.Delay(3000).ConfigureAwait(true);
                    await RefreshAsync().ConfigureAwait(true);
                }

                return;
            }

            var confirmation = MessageBox.Show(
                "This downloads and runs Umanitek's official Windows installer with the Oxigraph " +
                "backend (no Docker).\n\nIt installs Python packages, clones the repository and may " +
                "register a scheduled task. Review the installer; continue only if you trust it.",
                "Install Blackbox",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (confirmation != MessageBoxResult.Yes)
            {
                return;
            }

            _installer.InstallBlackbox();
            InstallStatusText = "Blackbox installer opened in PowerShell. Complete it, then click Check again.";
            return;
        }

        if (module.StartsWith("OriginTrail", StringComparison.Ordinal))
        {
            var confirmation = MessageBox.Show(
                "This installs @origintrail-official/dkg into %LOCALAPPDATA%\\Netpetra\\modules, " +
                "opens the official testnet setup and starts the node.\n\nIt needs Node.js/npm. Continue?",
                "Install OriginTrail DKG",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (confirmation != MessageBoxResult.Yes)
            {
                return;
            }

            _installer.InstallDkg();
            InstallStatusText = "DKG installer opened in PowerShell. Complete the prompts, then click Check again.";
        }
    }

    [RelayCommand]
    private async Task CheckHashAsync(FileScanRow? row)
    {
        if (row?.Sha256 is null)
        {
            return;
        }

        if (!_reputationSettings.Enabled || string.IsNullOrWhiteSpace(_reputationSettings.ApiKey))
        {
            await SetupReputationAsync().ConfigureAwait(true);
            return;
        }

        IsCheckingHash = true;
        row.VerdictText = "Checking…";

        try
        {
            var report = await _virusTotal
                .LookupHashAsync(row.Sha256, _reputationSettings.ApiKey, CancellationToken.None)
                .ConfigureAwait(true);

            row.VerdictText = report.Summary;
        }
        catch (Exception exception) when (exception is HttpRequestException or InvalidOperationException or TaskCanceledException or System.Text.Json.JsonException)
        {
            row.VerdictText = $"Lookup failed: {exception.Message}";
        }
        finally
        {
            IsCheckingHash = false;
        }
    }

    private async Task SetupReputationAsync()
    {
        var window = new ReputationSetupWindow(_reputationSettings)
        {
            Owner = Application.Current.MainWindow,
        };

        if (window.ShowDialog() != true)
        {
            return;
        }

        _reputationSettings = window.Settings;
        _reputationStore.Save(_reputationSettings);
        await RefreshAsync().ConfigureAwait(true);
    }

    private async Task SetupCommunityAsync()
    {
        var window = new CommunitySetupWindow(_communitySettings)
        {
            Owner = Application.Current.MainWindow,
        };

        if (window.ShowDialog() != true)
        {
            return;
        }

        _communitySettings = window.Settings;
        _communityStore.Save(_communitySettings);
        await RefreshCommunityAsync().ConfigureAwait(true);
    }

    [RelayCommand]
    private async Task RefreshCommunityAsync()
    {
        if (!IsCommunityConfigured)
        {
            _communityConnected = false;
            ReplaceCommunityModule();
            CommunityStatusText = "Not configured.";
            return;
        }

        IsFetchingCommunity = true;
        CommunityStatusText = "Fetching feed…";

        try
        {
            var result = await _communityClient
                .FetchAsync(_communitySettings.Url, _communitySettings.Token, CancellationToken.None)
                .ConfigureAwait(true);

            CommunityEntries.Clear();
            foreach (var entry in result.Entries)
            {
                CommunityEntries.Add(new CommunityFeedRow(
                    entry.Sha256,
                    entry.Name ?? "—",
                    entry.Verdict ?? "—",
                    entry.Source ?? "—"));
            }

            _communityConnected = true;
            ReplaceCommunityModule();
            CommunityStatusText = $"{result.Entries.Count} entries fetched at {result.FetchedUtc:HH:mm:ss}.";
        }
        catch (Exception exception) when (exception is
            HttpRequestException or InvalidDataException or System.Text.Json.JsonException or
            TaskCanceledException or ArgumentException or FileNotFoundException)
        {
            _communityConnected = false;
            ReplaceCommunityModule();
            CommunityStatusText = $"Feed failed: {exception.Message}";
        }
        finally
        {
            IsFetchingCommunity = false;
        }
    }

    [RelayCommand]
    private async Task ScanFilesAsync()
    {
        var dialog = new OpenFolderDialog
        {
            Title = "Select a folder to hash locally",
            Multiselect = false,
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        IsScanning = true;
        FileScanStatus = "Scanning selected folder…";
        FileScanResults.Clear();

        try
        {
            var entries = await FileScanner.ScanAsync(dialog.FolderName).ConfigureAwait(true);
            foreach (var entry in entries)
            {
                FileScanResults.Add(new FileScanRow(entry));
            }

            FileScanStatus = $"{entries.Count} file(s) scanned locally. Hashes are not uploaded.";
        }
#pragma warning disable CA1031 // The UI must show a scan failure instead of crashing.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            FileScanStatus = $"Scan failed: {exception.Message}";
        }
        finally
        {
            IsScanning = false;
        }
    }

    [RelayCommand]
    private async Task UninstallModuleAsync(string? module)
    {
        if (string.IsNullOrWhiteSpace(module))
        {
            return;
        }

        var message = module switch
        {
            "Blackbox" =>
                "Remove the Blackbox folder, its shortcut, .hermes\\blackbox and the Agent Blackbox DKG scheduled task? Other Hermes data and global packages are kept.",
            "OriginTrail DKG" =>
                "Remove the local DKG package and its testnet home? No global npm package is removed.",
            "Reputation provider" =>
                "Delete the stored VirusTotal API key and disable the provider?",
            "Community feed" =>
                "Delete the stored community feed URL and token?",
            _ => null,
        };

        if (message is null)
        {
            return;
        }

        var confirmation = MessageBox.Show(
            message,
            "Uninstall optional module",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirmation != MessageBoxResult.Yes)
        {
            return;
        }

        switch (module)
        {
            case "Blackbox":
                _uninstaller.UninstallBlackbox();
                InstallStatusText = "Blackbox uninstall started in PowerShell.";
                break;
            case "OriginTrail DKG":
                _uninstaller.UninstallDkg();
                InstallStatusText = "DKG uninstall started in PowerShell.";
                break;
            case "Reputation provider":
                _uninstaller.RemoveReputationSettings();
                _reputationSettings = new ReputationSettings(false, string.Empty);
                InstallStatusText = "VirusTotal key removed.";
                break;
            case "Community feed":
                _uninstaller.RemoveCommunitySettings();
                _communitySettings = new CommunityFeedSettings(false, string.Empty, string.Empty);
                InstallStatusText = "Community feed settings removed.";
                break;
        }

        await Task.Delay(500).ConfigureAwait(true);
        await RefreshAsync().ConfigureAwait(true);
    }

    [RelayCommand]
    private async Task SetBlackboxModeAsync(string? mode)
    {
        if (mode is not ("audit" or "block"))
        {
            return;
        }

        var success = _blackboxMode.SetMode(mode);
        BlackboxModeText = mode;
        InstallStatusText = success
            ? $"Blackbox mode set to {mode}."
            : "Could not update the Blackbox mode. Is the Blackbox venv present?";

        await RefreshAsync().ConfigureAwait(true);
    }

    [RelayCommand]
    private void Restart()
    {
        var executable = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executable))
        {
            return;
        }

        var arguments = Environment.GetCommandLineArgs().Skip(1).Select(QuoteArgument);
        using var process = Process.Start(new ProcessStartInfo(executable, string.Join(' ', arguments))
        {
            UseShellExecute = true,
        });

        Application.Current.Shutdown();
    }

    private static string QuoteArgument(string value) =>
        $"\"{value.Replace("\"", "\\\"", StringComparison.Ordinal)}\"";

    private void SeedCheckingState()
    {
        Modules.Add(new SecurityModule(
            "Reputation provider",
            ReputationStatus,
            ReputationDetail,
            "\uE9D9",
            false,
            true,
            "Setup",
            _reputationSettings.Enabled || !string.IsNullOrWhiteSpace(_reputationSettings.ApiKey)));
        Modules.Add(new SecurityModule(
            "Blackbox",
            "CHECKING",
            "Looking for a local Blackbox dashboard on 127.0.0.1:9700.",
            "\uE7BA",
            false,
            !_uninstaller.IsBlackboxInstalled,
            "Install",
            _uninstaller.IsBlackboxInstalled,
            _blackboxMode.IsAvailable));
        Modules.Add(new SecurityModule(
            "OriginTrail DKG",
            "CHECKING",
            "Looking for a local DKG node on 127.0.0.1:9200.",
            "\uE968",
            false,
            !_uninstaller.IsDkgInstalled,
            "Install",
            _uninstaller.IsDkgInstalled));
        Modules.Add(CreateCommunityModule());
        Modules.Add(new SecurityModule(
            "File scanning",
            "NOT ENABLED",
            "No file is scanned, uploaded, quarantined or deleted.",
            "\uE8A5",
            false,
            true,
            "Scan"));
    }

    private SecurityModule CreateCommunityModule() => new(
        "Community feed",
        CommunityStatus,
        CommunityDetail,
        "\uE774",
        _communityConnected,
        true,
        "Setup",
        IsCommunityConfigured);

    private void ReplaceCommunityModule()
    {
        for (var index = 0; index < Modules.Count; index++)
        {
            if (Modules[index].Name == "Community feed")
            {
                Modules[index] = CreateCommunityModule();
                break;
            }
        }

        OnPropertyChanged(nameof(StatusTitle));
        OnPropertyChanged(nameof(StatusBadge));
        OnPropertyChanged(nameof(StatusText));
    }

    private void Rebuild(OptionalModuleStatus dkg, OptionalModuleStatus blackbox)
    {
        Modules.Clear();
        Modules.Add(new SecurityModule(
            "Reputation provider",
            ReputationStatus,
            ReputationDetail,
            "\uE9D9",
            false,
            true,
            "Setup",
            _reputationSettings.Enabled || !string.IsNullOrWhiteSpace(_reputationSettings.ApiKey)));
        var blackboxInstalled = _uninstaller.IsBlackboxInstalled;
        Modules.Add(new SecurityModule(
            "Blackbox",
            blackbox.Status,
            $"{blackbox.Detail} Mode: {BlackboxModeText}.",
            "\uE7BA",
            blackbox.IsConnected,
            !blackboxInstalled || !blackbox.IsConnected,
            blackboxInstalled ? "Start" : "Install",
            blackboxInstalled,
            _blackboxMode.IsAvailable));
        Modules.Add(new SecurityModule(
            "OriginTrail DKG",
            dkg.Status,
            dkg.Detail,
            "\uE968",
            dkg.IsConnected,
            !_uninstaller.IsDkgInstalled,
            "Install",
            _uninstaller.IsDkgInstalled));
        Modules.Add(CreateCommunityModule());
        Modules.Add(new SecurityModule(
            "File scanning",
            "NOT ENABLED",
            "No file is scanned, uploaded, quarantined or deleted.",
            "\uE8A5",
            false,
            true,
            "Scan"));
    }
}
