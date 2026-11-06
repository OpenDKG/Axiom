// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.Win32;
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

    private readonly FirewallDefaultsStore _defaultsStore = FirewallDefaultsStore.Shared;

    public FirewallRulesViewModel(bool serviceMode)
        : base("Firewall", "Owned rules, defaults and rule editor", "\uE72E")
    {
        ApplyDefaults(_defaultsStore.Load());
        CopyDefaultsToNewRule();

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

    public IReadOnlyList<string> ProtocolOptions { get; } = ["Any", "TCP", "UDP"];

    public IReadOnlyList<string> DirectionOptions { get; } = ["Outbound", "Inbound"];

    public IReadOnlyList<string> ActionOptions { get; } = ["Block", "Allow"];

    [ObservableProperty]
    private bool _defaultDomain = true;

    [ObservableProperty]
    private bool _defaultPrivate = true;

    [ObservableProperty]
    private bool _defaultPublic = true;

    [ObservableProperty]
    private string _defaultProtocolText = "Any";

    [ObservableProperty]
    private string _defaultPortsText = string.Empty;

    [ObservableProperty]
    private string _defaultAddressesText = string.Empty;

    [ObservableProperty]
    private string _defaultsStatusText = "Defaults apply to new block rules created from Applications.";

    [ObservableProperty]
    private string _newRulePath = string.Empty;

    [ObservableProperty]
    private string _newRuleDirectionText = "Outbound";

    [ObservableProperty]
    private string _newRuleActionText = "Block";

    [ObservableProperty]
    private bool _newRuleDomain = true;

    [ObservableProperty]
    private bool _newRulePrivate = true;

    [ObservableProperty]
    private bool _newRulePublic = true;

    [ObservableProperty]
    private string _newRuleProtocolText = "Any";

    [ObservableProperty]
    private string _newRulePortsText = string.Empty;

    [ObservableProperty]
    private string _newRuleAddressesText = string.Empty;

    [ObservableProperty]
    private bool _newRuleEnabled = true;

    [ObservableProperty]
    private string _newRuleStatusText = "Writes are disabled; the rule editor is read-only until the test-VM write gate is enabled.";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ApplyNewRuleCommand))]
    private bool _isApplyingRule;

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
    [NotifyCanExecuteChangedFor(nameof(ApplyNewRuleCommand))]
    private bool _isBusy;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RemoveRuleCommand))]
    [NotifyCanExecuteChangedFor(nameof(ApplyNewRuleCommand))]
    [NotifyPropertyChangedFor(nameof(NoticeText))]
    [NotifyPropertyChangedFor(nameof(NoticeBadgeText))]
    [NotifyPropertyChangedFor(nameof(NewRuleWriteHint))]
    private bool _writesEnabled;

    public string NoticeText => WritesEnabled
        ? "Rules are read through the service with the documented INetFwPolicy2 COM objects. Writes are enabled for this test session; each change requires confirmation and is audited."
        : "Rules are read through the service with the documented INetFwPolicy2 COM objects. This session is read-only.";

    public string NoticeBadgeText => WritesEnabled ? "TEST VM" : "READ-ONLY";

    public string NewRuleWriteHint => WritesEnabled
        ? "Writes are enabled for this test session. Each change requires confirmation and is audited."
        : "Writes are disabled by design. Start the service with NETPETRA_ENABLE_FIREWALL_WRITES=1 and NETPETRA_FIREWALL_WRITE_CONFIRM=yes on an isolated test VM, then recheck.";

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

    [RelayCommand]
    private void SaveDefaults()
    {
        var profiles = BuildProfiles(DefaultDomain, DefaultPrivate, DefaultPublic);
        if (profiles == FirewallProfile.None)
        {
            DefaultsStatusText = "Select at least one profile for the defaults.";
            return;
        }

        var defaults = new FirewallDefaults(
            profiles,
            ParseProtocol(DefaultProtocolText),
            DefaultPortsText.Trim(),
            DefaultAddressesText.Trim());

        DefaultsStatusText = _defaultsStore.Save(defaults)
            ? "Defaults saved. New rules created from Applications will use this scope."
            : "Defaults could not be saved. Check the per-user data folder.";
        CopyDefaultsToNewRule();
    }

    [RelayCommand]
    private void ResetDefaults()
    {
        ApplyDefaults(FirewallDefaults.Default);
        CopyDefaultsToNewRule();
        DefaultsStatusText = "Defaults reset to all profiles, any protocol and any address.";
    }

    [RelayCommand]
    private void BrowseNewRuleExecutable()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select an executable for the Axiom firewall rule",
            Filter = "Executables (*.exe)|*.exe|All files (*.*)|*.*",
            CheckFileExists = true,
            Multiselect = false,
        };

        if (dialog.ShowDialog() == true)
        {
            NewRulePath = dialog.FileName;
        }
    }

    private bool CanApplyNewRule() => WritesEnabled && !IsBusy && !IsApplyingRule;

    [RelayCommand(CanExecute = nameof(CanApplyNewRule))]
    private async Task ApplyNewRuleAsync()
    {
        if (_client is null)
        {
            NewRuleStatusText = "Firewall writes require the local service.";
            return;
        }

        var path = NewRulePath.Trim();
        if (path.Length == 0 || !Path.IsPathFullyQualified(path))
        {
            NewRuleStatusText = "Select an absolute executable path first.";
            return;
        }

        var profiles = BuildProfiles(NewRuleDomain, NewRulePrivate, NewRulePublic);
        if (profiles == FirewallProfile.None)
        {
            NewRuleStatusText = "Select at least one network profile.";
            return;
        }

        var direction = string.Equals(NewRuleDirectionText, "Inbound", StringComparison.OrdinalIgnoreCase)
            ? FirewallDirection.Inbound
            : FirewallDirection.Outbound;
        var action = string.Equals(NewRuleActionText, "Allow", StringComparison.OrdinalIgnoreCase)
            ? FirewallAction.Allow
            : FirewallAction.Block;
        var addresses = NewRuleAddressesText.Split(
            [',', ';', ' '],
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var spec = new RuleSpec
        {
            ManagedRuleId = RuleIdentity.ForApp(path, direction),
            AppPath = path,
            Direction = direction,
            Action = action,
            Profiles = profiles,
            Protocol = ParseProtocol(NewRuleProtocolText),
            RemoteAddresses = addresses,
            RemotePorts = string.IsNullOrWhiteSpace(NewRulePortsText) ? null : NewRulePortsText.Trim(),
            Enabled = NewRuleEnabled,
            CreatedBy = Environment.UserName,
            Description = $"Axiom {action.ToString().ToLowerInvariant()} for {Path.GetFileName(path)}",
        };

        var confirmation = MessageBox.Show(
            $"Create or update the Axiom-owned {action.ToString().ToLowerInvariant()} rule for:\n{path}\n\n" +
            "Only this rule is changed. Other Windows Firewall rules are not touched. Continue only on an isolated test VM.",
            "Axiom firewall write",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirmation != MessageBoxResult.Yes)
        {
            NewRuleStatusText = "Rule change cancelled.";
            return;
        }

        IsApplyingRule = true;
        try
        {
            var result = await _client
                .SendAsync<RuleApplyResult>(IpcCommandTypes.RuleApply, spec, CancellationToken.None)
                .ConfigureAwait(true);

            NewRuleStatusText = result.Success
                ? $"Rule applied and verified at {result.VerifiedUtc?.ToString("HH:mm:ss", CultureInfo.InvariantCulture) ?? "unknown"}."
                : $"Rule apply failed: {result.ErrorCode} - {result.ErrorMessage}";

            if (result.Success)
            {
                await RefreshAsync().ConfigureAwait(true);
            }
        }
        catch (ServiceUnavailableException exception)
        {
            NewRuleStatusText = exception.Message;
        }
#pragma warning disable CA1031 // The UI must show an IPC failure instead of crashing.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            NewRuleStatusText = $"Rule apply failed: {exception.Message}";
        }
        finally
        {
            IsApplyingRule = false;
        }
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

    private static FirewallProfile BuildProfiles(bool domain, bool privateProfile, bool publicProfile)
    {
        var profiles = FirewallProfile.None;
        if (domain) profiles |= FirewallProfile.Domain;
        if (privateProfile) profiles |= FirewallProfile.Private;
        if (publicProfile) profiles |= FirewallProfile.Public;
        return profiles;
    }

    private static NetworkProtocol ParseProtocol(string value) => value switch
    {
        "TCP" => NetworkProtocol.Tcp,
        "UDP" => NetworkProtocol.Udp,
        _ => NetworkProtocol.Any,
    };

    private void ApplyDefaults(FirewallDefaults defaults)
    {
        DefaultDomain = defaults.Profiles.HasFlag(FirewallProfile.Domain);
        DefaultPrivate = defaults.Profiles.HasFlag(FirewallProfile.Private);
        DefaultPublic = defaults.Profiles.HasFlag(FirewallProfile.Public);
        DefaultProtocolText = defaults.Protocol switch
        {
            NetworkProtocol.Tcp => "TCP",
            NetworkProtocol.Udp => "UDP",
            _ => "Any",
        };
        DefaultPortsText = defaults.RemotePorts;
        DefaultAddressesText = defaults.RemoteAddresses;
    }

    private void CopyDefaultsToNewRule()
    {
        NewRuleDomain = DefaultDomain;
        NewRulePrivate = DefaultPrivate;
        NewRulePublic = DefaultPublic;
        NewRuleProtocolText = DefaultProtocolText;
        NewRulePortsText = DefaultPortsText;
        NewRuleAddressesText = DefaultAddressesText;
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
