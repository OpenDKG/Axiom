// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Axiom.UI.Services;

namespace Axiom.UI.ViewModels;

/// <summary>Optional, external-only support for the open-source Axiom project.</summary>
public sealed partial class SupportViewModel : PageViewModel
{
    private readonly DonationConfig _config;

    public SupportViewModel()
        : base("Support", "How to use Axiom, report issues and support the project", "\uE897")
    {
        _config = DonationDestinations.Load();

        HasBuyMeACoffee = DonationDestinations.IsValidPage(
            _config.BuyMeACoffeeUrl, DonationPlatform.BuyMeACoffee);
        HasPayPal = DonationDestinations.IsValidPage(_config.PaypalUrl, DonationPlatform.PayPal);
        HasGitHubSponsors = DonationDestinations.IsValidPage(
            _config.GithubSponsorsUrl, DonationPlatform.GitHubSponsors);

        CryptoOptions = (_config.Crypto ?? [])
            .OfType<CryptoDonationConfig>()
            .Where(DonationDestinations.IsValidCrypto)
            .Select(option => new CryptoDonationRow(
                option.Currency.ToUpperInvariant(), option.Network, option.Address))
            .ToList();

        CryptoEmptyText = CryptoOptions.Count == 0
            ? "No verified public receiving addresses are configured in this build."
            : $"Available receiving addresses: {CryptoOptions.Count}. Always match the exact network before sending.";
        SetupNote = HasBuyMeACoffee || HasPayPal || HasGitHubSponsors || CryptoOptions.Count > 0
            ? "Donation destinations are bundled by the Axiom maintainer. Verify the recipient independently before paying."
            : "Donation options are not yet configured by the project maintainer. No payments can be made from this screen.";
    }

    public IReadOnlyList<UsageStep> UsageSteps { get; } =
    [
        new(
            "1. See what is happening",
            "Use Overview, Connections and Applications to inspect live sockets, remote endpoints and per-application activity. These pages are read-only."),
        new(
            "2. Review firewall rules",
            "Open Firewall to see only rules owned by Axiom. Writes are disabled by default; the explicit test-VM gate is required before any rule can be created or removed."),
        new(
            "3. Make one deliberate change",
            "On Applications, select a process and choose Block outbound only when you understand the effect. Verify connectivity and remove the owned rule from Firewall if needed."),
        new(
            "4. Filter DNS only if needed",
            "Privacy Shield is opt-in. It starts a loopback resolver; adapter DNS changes require the separate UAC helper and can break name resolution."),
        new(
            "5. Inspect local files and optional modules",
            "Security provides a local SHA-256 file scan and optional reputation/community features. DKG, Blackbox and agent hooks are separate third-party integrations and are never installed silently."),
        new(
            "6. Check agents and settings",
            "Agents shows hook and workspace status; an installed hook is not proof of blocking. Settings controls themes and per-user startup."),
    ];

    public bool HasBuyMeACoffee { get; }

    public bool HasPayPal { get; }

    public bool HasGitHubSponsors { get; }

    public IReadOnlyList<CryptoDonationRow> CryptoOptions { get; }

    public bool HasCrypto => CryptoOptions.Count != 0;

    public string CryptoEmptyText { get; }

    public string SetupNote { get; }

    public string BuyMeACoffeeStatus => HasBuyMeACoffee ? "External creator page" : "Not configured";

    public string PayPalStatus => HasPayPal ? "External PayPal.Me page" : "Not configured";

    public string GitHubSponsorsStatus => HasGitHubSponsors ? "External sponsor page" : "Not configured";

    [ObservableProperty]
    private string _actionStatus = "All donations are optional. Axiom remains free.";

    [RelayCommand]
    private void OpenGitHubIssues() => OpenExternal("https://github.com/a-51-50/Axiom/issues/new/choose");

    [RelayCommand]
    private void OpenGitHubRepository() => OpenExternal("https://github.com/a-51-50/Axiom");

    [RelayCommand]
    private void OpenDonationPage(string? provider)
    {
        string? target = provider switch
        {
            "coffee" when HasBuyMeACoffee => _config.BuyMeACoffeeUrl,
            "paypal" when HasPayPal => _config.PaypalUrl,
            "github" when HasGitHubSponsors => _config.GithubSponsorsUrl,
            _ => null,
        };

        if (target is null)
        {
            ActionStatus = "This donation destination is not configured.";
            return;
        }

        // Validate again at the actual launch boundary, not just at card render.
        var platform = provider switch
        {
            "coffee" => DonationPlatform.BuyMeACoffee,
            "paypal" => DonationPlatform.PayPal,
            "github" => DonationPlatform.GitHubSponsors,
            _ => (DonationPlatform)(-1),
        };

        if (!DonationDestinations.IsValidPage(target, platform))
        {
            ActionStatus = "This donation link did not pass validation.";
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo(target) { UseShellExecute = true });
            ActionStatus = "The external donation page was requested in your default browser. Axiom never processes payments.";
        }
        catch (Win32Exception)
        {
            ActionStatus = "Windows could not open the donation page.";
        }
        catch (InvalidOperationException)
        {
            ActionStatus = "No suitable browser handler is available for the donation link.";
        }
    }

    [RelayCommand]
    private void CopyCryptoAddress(CryptoDonationRow? option)
    {
        if (option is null ||
            !CryptoOptions.Any(row =>
                string.Equals(row.Currency, option.Currency, StringComparison.Ordinal) &&
                string.Equals(row.Network, option.Network, StringComparison.Ordinal) &&
                string.Equals(row.Address, option.Address, StringComparison.Ordinal)))
        {
            ActionStatus = "No validated wallet address was selected.";
            return;
        }

        try
        {
            Clipboard.SetText(option.Address);
            ActionStatus = $"Copied {option.Currency} public receive address ({option.Network}). Verify the network and recipient before sending.";
        }
        catch (ExternalException)
        {
            ActionStatus = "Clipboard is busy. Select and copy the address manually.";
        }
    }

    private static void OpenExternal(string target)
    {
        try
        {
            Process.Start(new ProcessStartInfo(target) { UseShellExecute = true });
        }
        catch (Win32Exception)
        {
        }
        catch (InvalidOperationException)
        {
        }
    }
}

public sealed record UsageStep(string Title, string Detail);

public sealed record CryptoDonationRow(string Currency, string Network, string Address)
{
    public string Heading => $"{Currency} · {Network}";

    public string NetworkWarning => Currency == "USDC"
        ? $"Only send USDC using {Network}. Other networks and token contracts are not interchangeable."
        : $"Use {Network} only. Verify the recipient's public address before transferring.";
}
