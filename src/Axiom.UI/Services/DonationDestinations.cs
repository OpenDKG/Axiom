// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Axiom.UI.Services;

/// <summary>
/// Read-only recipient configuration compiled into the UI assembly.
/// The application never accepts payment credentials, signs transactions, or writes recipient details.
/// The maintainer must verify every recipient before a release; empty values remain disabled.
/// </summary>
public static partial class DonationDestinations
{
    private const string ResourceName = "Axiom.UI.Resources.support-links.json";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    public static DonationConfig Load()
    {
        using var stream = typeof(DonationDestinations).Assembly.GetManifestResourceStream(ResourceName);
        if (stream is null)
        {
            return new DonationConfig();
        }

        try
        {
            return JsonSerializer.Deserialize<DonationConfig>(stream, JsonOptions) ?? new DonationConfig();
        }
        catch (JsonException)
        {
            // Invalid bundled donation settings should never block the security monitor from opening.
            return new DonationConfig();
        }
        catch (IOException)
        {
            return new DonationConfig();
        }
    }

    public static bool IsValidPage(string? value, DonationPlatform platform)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            !Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            !uri.IsDefaultPort ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Query) ||
            !string.IsNullOrEmpty(uri.Fragment))
        {
            return false;
        }

        var host = uri.IdnHost.ToLowerInvariant();
        var segments = uri.AbsolutePath.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0)
        {
            return false;
        }

        return platform switch
        {
            DonationPlatform.BuyMeACoffee =>
                (host is "buymeacoffee.com" or "www.buymeacoffee.com") &&
                segments.Length == 1 && IsSafeSegment(segments[0]),
            DonationPlatform.PayPal =>
                (host is "paypal.me" or "www.paypal.me") &&
                segments.Length == 1 && IsSafeSegment(segments[0]),
            DonationPlatform.GitHubSponsors =>
                host == "github.com" && segments.Length == 2 &&
                string.Equals(segments[0], "sponsors", StringComparison.OrdinalIgnoreCase) &&
                IsSafeSegment(segments[1]),
            _ => false,
        };
    }

    public static bool IsValidCrypto(CryptoDonationConfig option)
    {
        ArgumentNullException.ThrowIfNull(option);

        // Wallet addresses are *public receive addresses*, never private keys or recovery phrases.
        // Networks must be explicit to avoid misdirected transfers, particularly for USDC.
        var currency = option.Currency;
        var network = option.Network;
        var address = option.Address;

        if (string.IsNullOrWhiteSpace(network) || string.IsNullOrWhiteSpace(address))
        {
            return false;
        }

        if (string.Equals(currency, "BTC", StringComparison.OrdinalIgnoreCase))
        {
            var bech32 = address.StartsWith("bc1", StringComparison.OrdinalIgnoreCase);
            var consistentCase = !bech32 ||
                string.Equals(address, address.ToLowerInvariant(), StringComparison.Ordinal) ||
                string.Equals(address, address.ToUpperInvariant(), StringComparison.Ordinal);
            return consistentCase &&
                string.Equals(network, "Bitcoin mainnet", StringComparison.OrdinalIgnoreCase) &&
                BitcoinAddressRegex().IsMatch(address);
        }

        if (string.Equals(currency, "ETH", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(currency, "USDC", StringComparison.OrdinalIgnoreCase))
        {
            return (network is "Ethereum mainnet" or "Base mainnet" or "Polygon PoS") &&
                EvmAddressRegex().IsMatch(address);
        }

        return false;
    }

    private static bool IsSafeSegment(string value) =>
        SafePathSegmentRegex().IsMatch(value);

    [GeneratedRegex(@"^[A-Za-z0-9_-]{1,64}$", RegexOptions.CultureInvariant)]
    private static partial Regex SafePathSegmentRegex();

    [GeneratedRegex(@"^(?:bc1[ac-hj-np-z02-9]{11,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex BitcoinAddressRegex();

    [GeneratedRegex(@"^0x[0-9a-fA-F]{40}$", RegexOptions.CultureInvariant)]
    private static partial Regex EvmAddressRegex();
}

public enum DonationPlatform
{
    BuyMeACoffee,
    PayPal,
    GitHubSponsors,
}

public sealed class DonationConfig
{
    public string BuyMeACoffeeUrl { get; init; } = string.Empty;

    public string PaypalUrl { get; init; } = string.Empty;

    public string GithubSponsorsUrl { get; init; } = string.Empty;

    public CryptoDonationConfig[] Crypto { get; init; } = [];
}

public sealed class CryptoDonationConfig
{
    public string Currency { get; init; } = string.Empty;

    public string Network { get; init; } = string.Empty;

    public string Address { get; init; } = string.Empty;
}
