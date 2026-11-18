// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Axiom.UI.Services;
using Axiom.UI.ViewModels;
using Xunit;

namespace Axiom.UI.Tests;

public sealed class DonationDestinationsTests
{
    [Theory]
    [InlineData("https://buymeacoffee.com/axiom", DonationPlatform.BuyMeACoffee, true)]
    [InlineData("https://www.buymeacoffee.com/axiom", DonationPlatform.BuyMeACoffee, true)]
    [InlineData("https://paypal.me/axiom", DonationPlatform.PayPal, true)]
    [InlineData("https://www.paypal.me/axiom", DonationPlatform.PayPal, true)]
    [InlineData("https://github.com/sponsors/axiom", DonationPlatform.GitHubSponsors, true)]
    [InlineData("http://buymeacoffee.com/axiom", DonationPlatform.BuyMeACoffee, false)]
    [InlineData("https://buymeacoffee.com:444/axiom", DonationPlatform.BuyMeACoffee, false)]
    [InlineData("https://buymeacoffee.com/axiom?redirect=https://evil.example", DonationPlatform.BuyMeACoffee, false)]
    [InlineData("https://buymeacoffee.com/axiom#fragment", DonationPlatform.BuyMeACoffee, false)]
    [InlineData("https://user@buymeacoffee.com/axiom", DonationPlatform.BuyMeACoffee, false)]
    [InlineData("https://buymeacoffee.com.evil.example/axiom", DonationPlatform.BuyMeACoffee, false)]
    [InlineData("https://evil.example/buymeacoffee.com/axiom", DonationPlatform.BuyMeACoffee, false)]
    [InlineData("https://buymeacoffee.com/axiom/extra", DonationPlatform.BuyMeACoffee, false)]
    [InlineData("https://paypal.me/axiom/extra", DonationPlatform.PayPal, false)]
    [InlineData("https://github.com/Axiom", DonationPlatform.GitHubSponsors, false)]
    [InlineData("https://github.com/sponsors/axiom/extra", DonationPlatform.GitHubSponsors, false)]
    [InlineData("https://github.com/sponsors/../evil", DonationPlatform.GitHubSponsors, false)]
    [InlineData("https://github.com.evil.example/sponsors/axiom", DonationPlatform.GitHubSponsors, false)]
    [InlineData("", DonationPlatform.PayPal, false)]
    public void ValidatesOnlyExactHttpsProviderPages(
        string value,
        DonationPlatform platform,
        bool expected)
    {
        Assert.Equal(expected, DonationDestinations.IsValidPage(value, platform));
    }

    [Theory]
    [InlineData("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "Bitcoin mainnet", true)]
    [InlineData("BC1QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZWF5MDQ", "Bitcoin mainnet", true)]
    [InlineData("1BoatSLRHtKNngkdXEeobR76b53LETtpyT", "Bitcoin mainnet", true)]
    [InlineData("bc1Qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "Bitcoin mainnet", false)]
    [InlineData("1BoatSLRHtKNngkdXEeobR76b53LETtpyT", "Ethereum mainnet", false)]
    [InlineData("", "Bitcoin mainnet", false)]
    public void ValidatesBitcoinAddressesAndNetwork(
        string address,
        string network,
        bool expected)
    {
        var option = new CryptoDonationConfig
        {
            Currency = "BTC",
            Network = network,
            Address = address,
        };

        Assert.Equal(expected, DonationDestinations.IsValidCrypto(option));
    }

    [Theory]
    [InlineData("ETH", "Ethereum mainnet", "0x52908400098527886E0F7030069857D2E4169EE7", true)]
    [InlineData("USDC", "Ethereum mainnet", "0x52908400098527886E0F7030069857D2E4169EE7", true)]
    [InlineData("USDC", "Base mainnet", "0x52908400098527886E0F7030069857D2E4169EE7", true)]
    [InlineData("USDC", "Bitcoin mainnet", "0x52908400098527886E0F7030069857D2E4169EE7", false)]
    [InlineData("ETH", "Ethereum mainnet", "0x1234", false)]
    [InlineData("ETH", "Ethereum mainnet", "52908400098527886E0F7030069857D2E4169EE7", false)]
    [InlineData("ETH", "Ethereum mainnet", "", false)]
    public void ValidatesEvmAddressesAndExactNetwork(
        string currency,
        string network,
        string address,
        bool expected)
    {
        var option = new CryptoDonationConfig
        {
            Currency = currency,
            Network = network,
            Address = address,
        };

        Assert.Equal(expected, DonationDestinations.IsValidCrypto(option));
    }

    [Fact]
    public void BundledConfigurationOffersOnlyEthOnEthereumMainnet()
    {
        var config = DonationDestinations.Load();

        Assert.Empty(config.BuyMeACoffeeUrl);
        Assert.Empty(config.PaypalUrl);
        Assert.Empty(config.GithubSponsorsUrl);
        Assert.Equal(3, config.Crypto.Length);
        var eth = Assert.Single(config.Crypto, DonationDestinations.IsValidCrypto);
        Assert.Equal("ETH", eth.Currency);
        Assert.Equal("Ethereum mainnet", eth.Network);
        Assert.Equal("0xFac745f39D832BC6A7B6D7F306928aBDC2C6a8ED", eth.Address);
    }

    [Fact]
    public void OpenCodeHookInstallBacksUpManagedPluginAndPreservesUserPlugin()
    {
        var root = CreateTempRoot();

        try
        {
            var user = Path.Combine(root, "user");
            var local = Path.Combine(root, "local");
            var config = Path.Combine(user, ".config", "opencode");
            Directory.CreateDirectory(Path.Combine(config, "plugins"));
            CreateFakePython(local);

            var protection = new OpenCodeProtection(user, local, Path.Combine(root, "roaming"));
            Directory.CreateDirectory(Path.GetDirectoryName(protection.PluginPath)!);
            File.WriteAllText(protection.PluginPath, "// Managed by Axiom\nold plugin");

            Assert.True(protection.EnsureInstalled());
            Assert.Contains("Managed by Axiom", File.ReadAllText(protection.PluginPath));
            Assert.Contains("axiom-blackbox", File.ReadAllText(protection.PluginPath));
            Assert.Single(Directory.GetFiles(Path.GetDirectoryName(protection.PluginPath)!, "*.axiom-backup-*"));

            File.WriteAllText(protection.PluginPath, "// user-authored plugin at Axiom path");
            var userProtection = new OpenCodeProtection(user, local, Path.Combine(root, "roaming"));

            Assert.False(userProtection.EnsureInstalled());
            Assert.Equal("// user-authored plugin at Axiom path", File.ReadAllText(protection.PluginPath));
        }
        finally
        {
            DeleteTempRoot(root);
        }
    }

    [Fact]
    public void CodexHookInstallMergesAndBacksUpExistingHooks()
    {
        var root = CreateTempRoot();

        try
        {
            var user = Path.Combine(root, "user");
            var local = Path.Combine(root, "local");
            var codex = Path.Combine(user, ".codex");
            Directory.CreateDirectory(codex);
            CreateFakePython(local);

            const string original = """
                {
                  "hooks": {
                    "PreToolUse": [
                      { "matcher": "keep", "hooks": [ { "type": "command", "command": "keep.exe" } ] }
                    ]
                  }
                }
                """;
            var hooksPath = Path.Combine(codex, "hooks.json");
            File.WriteAllText(hooksPath, original);

            var protection = new CodexProtection(user, local);
            Assert.True(protection.EnsureInstalled());
            Assert.True(protection.IsInstalled);

            var merged = File.ReadAllText(hooksPath);
            Assert.Contains("keep.exe", merged);
            Assert.Contains("axiom-codex-hook.py", merged);
            Assert.Single(Directory.GetFiles(codex, "*.axiom-backup-*"));
            Assert.Equal(original, File.ReadAllText(Directory.GetFiles(codex, "*.axiom-backup-*").Single()));
        }
        finally
        {
            DeleteTempRoot(root);
        }
    }

    [Fact]
    public void AgentConfigBackupPreservesExistingContent()
    {
        var directory = Path.Combine(Path.GetTempPath(), "axiom-ui-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);

        try
        {
            var original = Path.Combine(directory, "hooks.json");
            File.WriteAllText(original, "{\"hooks\":{\"keep\":true}}");

            var backup = StorageSafety.BackupFile(original);

            Assert.NotNull(backup);
            Assert.True(File.Exists(backup));
            Assert.Equal(File.ReadAllText(original), File.ReadAllText(backup!));
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Fact]
    public void AgentConfigBackupIsNoOpForMissingFile()
    {
        var missing = Path.Combine(Path.GetTempPath(), "axiom-ui-tests", Guid.NewGuid().ToString("N"), "missing.json");

        Assert.Null(StorageSafety.BackupFile(missing));
    }

    [Fact]
    public void SupportPageShowsOnlyConfiguredEthDestination()
    {
        var viewModel = new SupportViewModel();

        Assert.False(viewModel.HasBuyMeACoffee);
        Assert.False(viewModel.HasPayPal);
        Assert.False(viewModel.HasGitHubSponsors);
        Assert.True(viewModel.HasCrypto);
        var eth = Assert.Single(viewModel.CryptoOptions);
        Assert.Equal("ETH", eth.Currency);
        Assert.Equal("Ethereum mainnet", eth.Network);
    }

    private static string CreateTempRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "axiom-ui-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    private static void CreateFakePython(string localAppData)
    {
        var directory = Path.Combine(
            localAppData,
            "Axiom",
            "modules",
            "blackbox",
            "agent-blackbox",
            "venv",
            "Scripts");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "python.exe"), string.Empty);
    }

    private static void DeleteTempRoot(string root)
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
