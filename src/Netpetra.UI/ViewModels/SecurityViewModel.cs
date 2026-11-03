// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Netpetra.Contracts.Modules;

namespace Netpetra.UI.ViewModels;

/// <summary>Status of one optional security or intelligence module.</summary>
public sealed record SecurityModule(
    string Name,
    string Status,
    string Detail,
    string Glyph,
    bool IsConnected = false);

/// <summary>
/// Security page. Optional modules are never started or controlled by Netpetra; the page only
/// reads their loopback status and reports an honest not-running/unavailable state.
/// </summary>
public sealed partial class SecurityViewModel : PageViewModel, IDisposable
{
    private readonly OptionalModuleProbe _probe = new();

    public SecurityViewModel()
        : base("Security", "Optional intelligence and protection modules", "\uE8D7")
    {
        Modules = [];
        SeedCheckingState();
        _ = RefreshAsync();
    }

    public ObservableCollection<SecurityModule> Modules { get; }

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private string _lastCheckedText = "Not checked yet";

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
        ? "Netpetra only reads loopback status. It never starts, stops or controls these modules."
        : "The standard build is local and offline. Blackbox and OriginTrail DKG are not running.";

    public void Dispose() => _probe.Dispose();

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
        }
        finally
        {
            IsBusy = false;
            OnPropertyChanged(nameof(StatusTitle));
            OnPropertyChanged(nameof(StatusBadge));
            OnPropertyChanged(nameof(StatusText));
        }
    }

    private void SeedCheckingState()
    {
        Modules.Add(new SecurityModule(
            "Reputation provider",
            "NOT CONFIGURED",
            "No external reputation lookup is enabled. Unknown is shown as unknown.",
            "\uE9D9"));
        Modules.Add(new SecurityModule(
            "Blackbox",
            "CHECKING",
            "Looking for a local Blackbox dashboard on 127.0.0.1:9700.",
            "\uE7BA"));
        Modules.Add(new SecurityModule(
            "OriginTrail DKG",
            "CHECKING",
            "Looking for a local DKG node on 127.0.0.1:9200.",
            "\uE968"));
        Modules.Add(new SecurityModule(
            "Community feed",
            "NOT CONFIGURED",
            "No community report is fetched, verified or published.",
            "\uE774"));
        Modules.Add(new SecurityModule(
            "File scanning",
            "NOT ENABLED",
            "No file is scanned, uploaded, quarantined or deleted.",
            "\uE8A5"));
    }

    private void Rebuild(OptionalModuleStatus dkg, OptionalModuleStatus blackbox)
    {
        Modules.Clear();
        Modules.Add(new SecurityModule(
            "Reputation provider",
            "NOT CONFIGURED",
            "No external reputation lookup is enabled. Unknown is shown as unknown.",
            "\uE9D9"));
        Modules.Add(new SecurityModule(
            "Blackbox",
            blackbox.Status,
            blackbox.Detail,
            "\uE7BA",
            blackbox.IsConnected));
        Modules.Add(new SecurityModule(
            "OriginTrail DKG",
            dkg.Status,
            dkg.Detail,
            "\uE968",
            dkg.IsConnected));
        Modules.Add(new SecurityModule(
            "Community feed",
            "NOT CONFIGURED",
            "No community report is fetched, verified or published.",
            "\uE774"));
        Modules.Add(new SecurityModule(
            "File scanning",
            "NOT ENABLED",
            "No file is scanned, uploaded, quarantined or deleted.",
            "\uE8A5"));
    }
}
