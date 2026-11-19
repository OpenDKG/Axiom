// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>Optional, external-only support for the open-source Axiom project.</summary>
public sealed partial class SupportPageViewModel : PageViewModel
{
    private readonly DonationConfig _config;
    private readonly IUserInteraction _ui;

    public SupportPageViewModel(IUserInteraction ui)
        : base("Help & Support", "How to use Axiom, report issues and support the project", "S")
    {
        _ui = ui ?? throw new ArgumentNullException(nameof(ui));
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
            "Open Firewall to see only rules owned by Axiom. Writes are off until you consent: complete installation enables Axiom Shield during setup, while partial installation leaves it off. The explicit test-VM gate is still required before any rule can be created or removed."),
        new(
            "3. Make one deliberate change",
            "On Applications, select a process and choose Block outbound only when you understand the effect. Verify connectivity and remove the owned rule from Firewall if needed."),
        new(
            "4. Filter DNS only if needed",
            "Privacy Shield runs a loopback resolver. Complete installation enables it; partial installation leaves it off. Adapter DNS changes require the separate UAC helper and can break name resolution."),
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
    private Task OpenGitHubIssuesAsync() => OpenExternalAsync(ProjectLinks.NewIssue);

    [RelayCommand]
    private Task OpenGitHubRepositoryAsync() => OpenExternalAsync(ProjectLinks.Repository);

    [RelayCommand]
    private async Task OpenDonationPageAsync(string? provider)
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

        // Validate again at the actual launch boundary, not only when the card is rendered.
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
            await _ui.OpenExternalAsync(target, CancellationToken.None).ConfigureAwait(true);
            ActionStatus = "The external donation page was requested in your default browser. Axiom never processes payments.";
        }
        catch (Exception exception) when (exception is
                     System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException)
        {
            ActionStatus = "Windows could not open the donation page.";
        }
    }

    [RelayCommand]
    private async Task CopyCryptoAddressAsync(CryptoDonationRow? option)
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
            await _ui.CopyTextAsync(option.Address, CancellationToken.None).ConfigureAwait(true);
            ActionStatus = $"Copied {option.Currency} public receive address ({option.Network}). Verify the network and recipient before sending.";
        }
        catch (Exception exception) when (exception is
                     System.Runtime.InteropServices.ExternalException or InvalidOperationException or NotSupportedException)
        {
            ActionStatus = "Clipboard is busy. Select and copy the address manually.";
        }
    }

    private async Task OpenExternalAsync(string target)
    {
        try
        {
            await _ui.OpenExternalAsync(target, CancellationToken.None).ConfigureAwait(true);
        }
        catch (Exception exception) when (exception is
                     System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException)
        {
            ActionStatus = "Windows could not open the link.";
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
