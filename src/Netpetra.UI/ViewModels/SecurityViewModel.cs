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
    string ActionLabel = "Install");

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

/// <summary>
/// Security page. Optional modules are read-only status probes; install buttons launch the official
/// third-party installer only after an explicit warning. Netpetra does not stop or control a module.
/// </summary>
public sealed partial class SecurityViewModel : PageViewModel, IDisposable
{
    private readonly OptionalModuleProbe _probe = new();

    private readonly OptionalModuleInstaller _installer = new();

    private readonly BoundedHistory<ModuleActivity> _activityHistory = new(30);

    private readonly ReputationSettingsStore _reputationStore = new();

    private readonly VirusTotalClient _virusTotal = new();

    private ReputationSettings _reputationSettings = new(false, string.Empty);

    private readonly DispatcherTimer _activityTimer;

    public SecurityViewModel()
        : base("Security", "Optional intelligence and protection modules", "\uE8D7")
    {
        _reputationSettings = _reputationStore.Load();
        Modules = [];
        SeedCheckingState();

        _activityTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
        _activityTimer.Tick += (_, _) => _ = RefreshAsync();
        _activityTimer.Start();

        _ = RefreshAsync();
    }

    public ObservableCollection<SecurityModule> Modules { get; }

    public ObservableCollection<ModuleActivity> Activity { get; } = [];

    public ObservableCollection<FileScanRow> FileScanResults { get; } = [];

    [ObservableProperty]
    private string _fileScanStatus = "No folder scanned.";

    [ObservableProperty]
    private bool _isScanning;

    [ObservableProperty]
    private bool _isCheckingHash;

    private string ReputationStatus => _reputationSettings.Enabled && !string.IsNullOrWhiteSpace(_reputationSettings.ApiKey)
        ? "CONFIGURED"
        : "NOT CONFIGURED";

    private string ReputationDetail => _reputationSettings.Enabled && !string.IsNullOrWhiteSpace(_reputationSettings.ApiKey)
        ? "Hash-only lookups enabled; the API key is stored with Windows DPAPI."
        : "No external reputation lookup is enabled. Unknown is shown as unknown.";

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private string _lastCheckedText = "Not checked yet";

    [ObservableProperty]
    private string _installStatusText = string.Empty;

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

        if (module.Equals("Blackbox", StringComparison.Ordinal))
        {
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
            "Setup"));
        Modules.Add(new SecurityModule(
            "Blackbox",
            "CHECKING",
            "Looking for a local Blackbox dashboard on 127.0.0.1:9700.",
            "\uE7BA",
            false,
            true));
        Modules.Add(new SecurityModule(
            "OriginTrail DKG",
            "CHECKING",
            "Looking for a local DKG node on 127.0.0.1:9200.",
            "\uE968",
            false,
            true));
        Modules.Add(new SecurityModule(
            "Community feed",
            "NOT CONFIGURED",
            "No community report is fetched, verified or published.",
            "\uE774"));
        Modules.Add(new SecurityModule(
            "File scanning",
            "NOT ENABLED",
            "No file is scanned, uploaded, quarantined or deleted.",
            "\uE8A5",
            false,
            true,
            "Scan"));
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
            "Setup"));
        Modules.Add(new SecurityModule(
            "Blackbox",
            blackbox.Status,
            blackbox.Detail,
            "\uE7BA",
            blackbox.IsConnected,
            !blackbox.IsConnected,
            "Install"));
        Modules.Add(new SecurityModule(
            "OriginTrail DKG",
            dkg.Status,
            dkg.Detail,
            "\uE968",
            dkg.IsConnected,
            !dkg.IsConnected,
            "Install"));
        Modules.Add(new SecurityModule(
            "Community feed",
            "NOT CONFIGURED",
            "No community report is fetched, verified or published.",
            "\uE774"));
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
