// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Netpetra.Contracts.Firewall;
using Netpetra.Contracts.Ipc;
using Netpetra.UI.Services;

namespace Netpetra.UI.ViewModels;

/// <summary>One owned Windows Firewall rule, read-only.</summary>
public sealed class FirewallRuleRow(ManagedRule rule)
{
    public Guid ManagedRuleId => rule.ManagedRuleId;

    public string OsRuleName => rule.OsRuleName;

    public string Application => rule.Spec.AppPath.Length == 0
        ? "—"
        : Path.GetFileName(rule.Spec.AppPath);

    public string DirectionText => rule.Spec.Direction == FirewallDirection.Outbound ? "Out" : "In";

    public string ActionText => rule.Spec.Action == FirewallAction.Block ? "Block" : "Allow";

    public string ProfilesText => rule.Spec.Profiles switch
    {
        FirewallProfile.All => "Domain, Private, Public",
        FirewallProfile.None => "None",
        _ => string.Join(", ", new[]
        {
            rule.Spec.Profiles.HasFlag(FirewallProfile.Domain) ? "Domain" : null,
            rule.Spec.Profiles.HasFlag(FirewallProfile.Private) ? "Private" : null,
            rule.Spec.Profiles.HasFlag(FirewallProfile.Public) ? "Public" : null,
        }.Where(part => part is not null)),
    };

    public string ProtocolText => rule.Spec.Protocol switch
    {
        NetworkProtocol.Tcp => "TCP",
        NetworkProtocol.Udp => "UDP",
        _ => "Any",
    };

    public string PortsText => string.IsNullOrWhiteSpace(rule.Spec.RemotePorts) ? "any" : rule.Spec.RemotePorts;

    public string EnabledText => rule.Spec.Enabled ? "yes" : "no";

    public string StateText => rule.State.ToString();

    public string Tooltip =>
        $"{rule.Spec.AppPath}\nRule: {rule.OsRuleName}\nCreated by: {rule.Spec.CreatedBy}";
}

/// <summary>
/// Firewall page. It reads the capability and owned rules through the service. It never offers a
/// write action in this build.
/// </summary>
public sealed partial class FirewallRulesViewModel : PageViewModel, IDisposable
{
    private readonly ServicePipeClient? _client;

    public FirewallRulesViewModel(bool serviceMode)
        : base("Firewall", "Owned rules read through the local service", "\uE72E")
    {
        if (!serviceMode)
        {
            CapabilityStatusText = "Service required";
            CapabilityDetail = "Firewall policy is read through the local service. Start the app with --service.";
            OwnedRuleCountText = "—";
            StatusText = "No Windows Firewall policy was read in in-process mode.";
            IsEmpty = true;
            return;
        }

        _client = new ServicePipeClient();
        CanRecheck = true;
        _ = RefreshAsync();
    }

    public ObservableCollection<FirewallRuleRow> Rules { get; } = [];

    [ObservableProperty]
    private string _capabilityStatusText = "Checking…";

    [ObservableProperty]
    private string _capabilityDetail = string.Empty;

    [ObservableProperty]
    private string _ownedRuleCountText = "—";

    [ObservableProperty]
    private string _statusText = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RemoveRuleCommand))]
    private bool _isBusy;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RemoveRuleCommand))]
    [NotifyPropertyChangedFor(nameof(NoticeText))]
    [NotifyPropertyChangedFor(nameof(NoticeBadgeText))]
    private bool _writesEnabled;

    public string NoticeText => WritesEnabled
        ? "Rules are read through the service with the documented INetFwPolicy2 COM objects. Writes are enabled for this test session; each change requires confirmation and is audited."
        : "Rules are read through the service with the documented INetFwPolicy2 COM objects. This session is read-only.";

    public string NoticeBadgeText => WritesEnabled ? "TEST VM" : "READ-ONLY";

    [ObservableProperty]
    private string _writePathText = "disabled";

    [ObservableProperty]
    private bool _isEmpty;

    [ObservableProperty]
    private bool _hasError;

    [ObservableProperty]
    private bool _canRecheck;

    public void Dispose()
    {
    }

    [RelayCommand(CanExecute = nameof(CanRemoveRule))]
    private async Task RemoveRuleAsync(FirewallRuleRow? row)
    {
        if (_client is null || row is null || !WritesEnabled)
        {
            return;
        }

        var confirmation = MessageBox.Show(
            $"Remove the owned Windows Firewall rule for {row.Application}?\n\n" +
            "Only this Axiom rule is removed; other Windows Firewall rules are not touched.",
            "Axiom firewall write",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirmation != MessageBoxResult.Yes)
        {
            return;
        }

        try
        {
            var result = await _client
                .SendAsync<RuleApplyResult>(
                    IpcCommandTypes.RuleRemove,
                    new RuleReference { ManagedRuleId = row.ManagedRuleId },
                    CancellationToken.None)
                .ConfigureAwait(true);

            StatusText = result.Success
                ? $"Removed {row.OsRuleName}."
                : $"Remove failed: {result.ErrorCode} — {result.ErrorMessage}";

            if (result.Success)
            {
                await RefreshAsync().ConfigureAwait(true);
            }
        }
        catch (ServiceUnavailableException exception)
        {
            StatusText = exception.Message;
        }
#pragma warning disable CA1031 // The UI must show an IPC failure instead of crashing.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            StatusText = $"Remove failed: {exception.Message}";
        }
    }

    private bool CanRemoveRule() => WritesEnabled && !IsBusy;

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
            var snapshot = await _client
                .SendAsync<FirewallRulesSnapshot>(IpcCommandTypes.RulesQuery, null, CancellationToken.None)
                .ConfigureAwait(true);

            Rules.Clear();
            foreach (var rule in snapshot.Rules)
            {
                Rules.Add(new FirewallRuleRow(rule));
            }

            CapabilityStatusText = snapshot.Capability.Status switch
            {
                FirewallCapabilityStatus.Available => "Available",
                FirewallCapabilityStatus.Degraded => "Degraded",
                FirewallCapabilityStatus.Unavailable => "Unavailable",
                _ => "Unknown",
            };
            CapabilityDetail = snapshot.Capability.Reason
                ?? "Windows Firewall COM policy is readable. No rule is changed by this page.";
            OwnedRuleCountText = snapshot.Rules.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
            IsEmpty = snapshot.Rules.Count == 0;
            WritesEnabled = snapshot.WritesEnabled;
            WritePathText = snapshot.WritesEnabled ? "enabled (test VM only)" : "disabled";
            HasError = snapshot.Capability.Status == FirewallCapabilityStatus.Unavailable;
            StatusText = snapshot.Rules.Count == 0
                ? "0 owned rules. Axiom has not created any Windows Firewall rule on this host."
                : $"{snapshot.Rules.Count} owned rules read at {DateTimeOffset.Now:HH:mm:ss}.";
        }
        catch (ServiceUnavailableException exception)
        {
            Rules.Clear();
            CapabilityStatusText = "Service offline";
            CapabilityDetail = exception.Message;
            OwnedRuleCountText = "—";
            IsEmpty = true;
            HasError = true;
            StatusText = exception.Message;
        }
#pragma warning disable CA1031 // The page must not stay busy on an unexpected IPC error.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            Rules.Clear();
            CapabilityStatusText = "Query failed";
            CapabilityDetail = exception.Message;
            OwnedRuleCountText = "—";
            IsEmpty = true;
            HasError = true;
            StatusText = $"Firewall query failed: {exception.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }
}
