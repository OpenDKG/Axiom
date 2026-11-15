// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.IO;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Axiom.Contracts;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>One selectable crypto wallet entry backed by Trader Shield packs.</summary>
public sealed partial class TraderShieldWalletOption : ObservableObject
{
    public TraderShieldWalletOption(string id, string displayName, bool isSelected)
    {
        Id = id;
        DisplayName = displayName;
        _isSelected = isSelected;
    }

    public string Id { get; }

    public string DisplayName { get; }

    [ObservableProperty]
    private bool _isSelected;
}

/// <summary>
/// Manages Blackbox Trader Shield configuration (enable switch, protected wallet checkboxes,
/// local EVM public addresses) and runs the real bridge self-test.
/// </summary>
public sealed partial class TraderShieldSectionViewModel : ObservableObject
{
    private static readonly Dictionary<string, string> WalletDisplayNames =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["metamask"] = "MetaMask",
            ["phantom"] = "Phantom",
            ["exodus"] = "Exodus",
            ["electrum"] = "Electrum",
            ["solana-cli"] = "Solana CLI",
            ["rabby"] = "Rabby",
            ["coinbase-wallet"] = "Coinbase Wallet",
            ["trust-wallet"] = "Trust Wallet",
            ["okx-wallet"] = "OKX Wallet",
            ["keplr"] = "Keplr",
            ["solflare"] = "Solflare",
        };

    private readonly string _configPath;
    private readonly Func<string, bool> _fileExists;
    private readonly Func<string, string?> _readFile;
    private readonly Func<string, string, bool> _writeFile;
    private readonly Func<IReadOnlyList<ProtectionCheckResult>> _selfTestRunner;

    [ObservableProperty]
    private bool _isEnabled;

    [ObservableProperty]
    private string _newAddressInput = string.Empty;

    [ObservableProperty]
    private string _statusText = "Trader Shield status not loaded.";

    [ObservableProperty]
    private string _selfTestStatusText = "Not tested yet. Runs a synthetic seed-phrase write and wallet keystore read through the local Blackbox guard.";

    [ObservableProperty]
    private bool _isTesting;

    public TraderShieldSectionViewModel(
        string? configPath = null,
        Func<string, bool>? fileExists = null,
        Func<string, string?>? readFile = null,
        Func<string, string, bool>? writeFile = null,
        Func<IReadOnlyList<ProtectionCheckResult>>? selfTestRunner = null)
    {
        _configPath = configPath ?? TraderShieldProvisioner.ResolveConfigPath();
        _fileExists = fileExists ?? File.Exists;
        _readFile = readFile ?? DefaultReadFile;
        _writeFile = writeFile ?? DefaultWriteFile;
        _selfTestRunner = selfTestRunner ?? (() => ProtectionProvisioner.RunTraderShieldSelfTest());

        foreach (var walletId in TraderShieldProvisioner.SupportedWallets)
        {
            var label = WalletDisplayNames.TryGetValue(walletId, out var display) ? display : walletId;
            Wallets.Add(new TraderShieldWalletOption(walletId, label, isSelected: true));
        }

        Addresses.CollectionChanged += OnAddressesChanged;
        Reload();
    }

    public bool IsAvailable => !DistributionContext.IsStorePackage;

    public ObservableCollection<TraderShieldWalletOption> Wallets { get; } = [];

    public ObservableCollection<string> Addresses { get; } = [];

    public bool HasAddresses => Addresses.Count > 0;

    public bool HasNoAddresses => Addresses.Count == 0;

    [RelayCommand]
    public void Reload()
    {
        if (!_fileExists(_configPath))
        {
            ApplySettings(new TraderShieldSettings(false, TraderShieldProvisioner.SupportedWallets, []));
            StatusText = "Hermes config not found yet — install Blackbox on Agents to persist Trader Shield.";
            return;
        }

        var yaml = _readFile(_configPath);
        if (yaml is null)
        {
            StatusText = "Could not read Hermes config; Trader Shield settings may be locked.";
            return;
        }

        var settings = TraderShieldProvisioner.Read(yaml);
        ApplySettings(settings);
        StatusText = BuildSummaryStatus(settings);
    }

    [RelayCommand]
    private void AddAddress()
    {
        var candidate = (NewAddressInput ?? string.Empty).Trim();
        if (!TraderShieldProvisioner.IsWalletAddress(candidate))
        {
            StatusText = "Enter a valid EVM address (0x followed by 40 hex characters).";
            return;
        }

        var normalized = candidate.ToLowerInvariant();
        if (Addresses.Contains(normalized, StringComparer.OrdinalIgnoreCase))
        {
            StatusText = $"{normalized} is already listed.";
            NewAddressInput = string.Empty;
            return;
        }

        Addresses.Add(normalized);
        NewAddressInput = string.Empty;
        SaveSettings();
    }

    [RelayCommand]
    private void RemoveAddress(string? address)
    {
        if (string.IsNullOrWhiteSpace(address))
        {
            return;
        }

        var match = Addresses.FirstOrDefault(item => string.Equals(item, address, StringComparison.OrdinalIgnoreCase));
        if (match is null)
        {
            return;
        }

        Addresses.Remove(match);
        SaveSettings();
    }

    [RelayCommand]
    public void SaveSettings()
    {
        if (!_fileExists(_configPath))
        {
            StatusText = "Hermes config not found — install Blackbox before saving Trader Shield settings.";
            return;
        }

        var current = _readFile(_configPath);
        if (current is null)
        {
            StatusText = "Could not read Hermes config before saving.";
            return;
        }

        var selectedWallets = Wallets.Where(wallet => wallet.IsSelected).Select(wallet => wallet.Id).ToArray();
        var updated = TraderShieldProvisioner.Apply(current, IsEnabled, Addresses, selectedWallets);
        if (!_writeFile(_configPath, updated))
        {
            StatusText = "Failed to save Trader Shield settings to Hermes config.";
            return;
        }

        var verified = TraderShieldProvisioner.Read(updated);
        ApplySettings(verified);
        StatusText = "Saved — " + BuildSummaryStatus(verified);
    }

    [RelayCommand]
    private async Task RunSelfTestAsync()
    {
        if (IsTesting)
        {
            return;
        }

        IsTesting = true;
        SelfTestStatusText = "Running synthetic seed-phrase write and keystore read checks…";
        try
        {
            var results = await Task.Run(_selfTestRunner).ConfigureAwait(true);
            SelfTestStatusText = FormatSelfTestResults(results);
        }
        finally
        {
            IsTesting = false;
        }
    }

    private void ApplySettings(TraderShieldSettings settings)
    {
        IsEnabled = settings.Enabled;
        var chosen = new HashSet<string>(settings.Wallets, StringComparer.OrdinalIgnoreCase);
        foreach (var wallet in Wallets)
        {
            wallet.IsSelected = chosen.Contains(wallet.Id);
        }

        Addresses.Clear();
        foreach (var address in settings.Addresses)
        {
            Addresses.Add(address);
        }
    }

    private void OnAddressesChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        OnPropertyChanged(nameof(HasAddresses));
        OnPropertyChanged(nameof(HasNoAddresses));
    }

    private static string BuildSummaryStatus(TraderShieldSettings settings)
    {
        var walletCount = settings.Wallets.Count;
        var addressCount = settings.Addresses.Count;
        return settings.Enabled
            ? $"Enabled — guarding {walletCount}/{TraderShieldProvisioner.SupportedWallets.Count} wallets, {addressCount} local address(es)."
            : $"Disabled — {walletCount}/{TraderShieldProvisioner.SupportedWallets.Count} wallets ticked, {addressCount} local address(es).";
    }

    private static string FormatSelfTestResults(IReadOnlyList<ProtectionCheckResult> results)
    {
        if (results.Count == 0)
        {
            return "INCONCLUSIVE — self-test produced no checks.";
        }

        var prefix = AgentProtectionSelfTest.AllPassed(results) ? "PASS — " : "FAIL/INCONCLUSIVE — ";
        return prefix + AgentProtectionSelfTest.Summary(results);
    }

    private static string? DefaultReadFile(string path)
    {
        try
        {
            if (StorageSafety.IsReparsePointInPath(path))
            {
                return null;
            }

            return File.ReadAllText(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static bool DefaultWriteFile(string path, string content)
    {
        try
        {
            if (StorageSafety.IsReparsePointInPath(path))
            {
                return false;
            }

            if (File.Exists(path))
            {
                StorageSafety.BackupFile(path);
            }

            File.WriteAllText(path, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}
