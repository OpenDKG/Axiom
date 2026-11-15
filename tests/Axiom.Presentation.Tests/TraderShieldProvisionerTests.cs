// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class TraderShieldProvisionerTests
{
    [Fact]
    public void Section_covers_every_supported_wallet()
    {
        var section = TraderShieldProvisioner.BuildSection();

        foreach (var wallet in TraderShieldProvisioner.SupportedWallets)
        {
            Assert.Contains(wallet, section, StringComparison.Ordinal);
        }

        Assert.Contains("enabled: true", section, StringComparison.Ordinal);
        Assert.Contains("addresses: []", section, StringComparison.Ordinal);
    }

    [Fact]
    public void Apply_inserts_the_section_under_the_blackbox_entry()
    {
        const string yaml = """
            plugins:
              entries:
                blackbox:
                  mode: block
                  report: false
            """;

        var updated = TraderShieldProvisioner.Apply(yaml);

        Assert.True(TraderShieldProvisioner.IsEnabled(updated));
        Assert.Contains("mode: block", updated, StringComparison.Ordinal);
        Assert.Contains("report: false", updated, StringComparison.Ordinal);
        Assert.Contains("shields:", updated, StringComparison.Ordinal);
    }

    [Fact]
    public void Apply_is_idempotent_and_replaces_an_existing_section()
    {
        const string yaml = """
            plugins:
              entries:
                blackbox:
                  mode: block
                  shields:
                    trader:
                      enabled: false
                      wallets: [metamask]
                  report: false
            """;

        var once = TraderShieldProvisioner.Apply(yaml);
        var twice = TraderShieldProvisioner.Apply(once);

        Assert.True(TraderShieldProvisioner.IsEnabled(once));
        Assert.Equal(once, twice);
        Assert.Contains("report: false", twice, StringComparison.Ordinal);
        Assert.DoesNotContain("wallets: [metamask]", twice, StringComparison.Ordinal);
    }

    [Fact]
    public void Replacing_shields_keeps_every_key_after_the_block()
    {
        // The real config has a trailing newline and keys after shields. The old regex consumed
        // them, which dropped block mode and the protected paths on the next start.
        const string yaml = """
            plugins:
              entries:
                blackbox:
                  mode: block
                  protected_paths:
                    - ~/.ssh/*
                  shields:
                    trader:
                      enabled: false
                      wallets: [metamask]
                  report: false
                  enabled: true
              enabled:
                - blackbox
              disabled: []
            """;

        var updated = TraderShieldProvisioner.Apply(yaml + "\n");

        Assert.Contains("mode: block", updated, StringComparison.Ordinal);
        Assert.Contains("protected_paths:", updated, StringComparison.Ordinal);
        Assert.Contains("report: false", updated, StringComparison.Ordinal);
        Assert.Contains("enabled:", updated, StringComparison.Ordinal);
        Assert.Contains("- blackbox", updated, StringComparison.Ordinal);
        Assert.True(TraderShieldProvisioner.IsEnabled(updated));
    }

    [Fact]
    public void Apply_keeps_only_valid_wallet_addresses()
    {
        var updated = TraderShieldProvisioner.Apply(
            "plugins:\n  entries:\n    blackbox:\n      mode: block\n",
            addresses: ["0x" + new string('a', 40), "not-an-address", "0x1234"]);

        Assert.Contains("0x" + new string('a', 40), updated, StringComparison.Ordinal);
        Assert.DoesNotContain("not-an-address", updated, StringComparison.Ordinal);
        Assert.DoesNotContain("0x1234\n", updated, StringComparison.Ordinal);
    }

    [Fact]
    public void Address_validation_requires_evm_shape()
    {
        Assert.True(TraderShieldProvisioner.IsWalletAddress("0x" + new string('F', 40)));
        Assert.False(TraderShieldProvisioner.IsWalletAddress("0x" + new string('F', 39)));
        Assert.False(TraderShieldProvisioner.IsWalletAddress("not-an-address"));
        Assert.False(TraderShieldProvisioner.IsWalletAddress(""));
    }

    [Fact]
    public void Build_and_read_roundtrip_selected_wallets_and_addresses()
    {
        var addr = "0x" + new string('b', 40);
        var updated = TraderShieldProvisioner.Apply(
            "plugins:\n  entries:\n    blackbox:\n      mode: block\n      report: false\n",
            enabled: true,
            addresses: [addr.ToUpperInvariant()],
            wallets: ["exodus", "unknown-wallet", "metamask"]);

        var parsed = TraderShieldProvisioner.Read(updated);

        Assert.True(parsed.Enabled);
        Assert.Equal(["metamask", "exodus"], parsed.Wallets);
        Assert.Equal([addr], parsed.Addresses);
        Assert.Contains("report: false", updated, StringComparison.Ordinal);
    }

    [Fact]
    public void Read_handles_yaml_block_lists()
    {
        const string yaml = """
            plugins:
              entries:
                blackbox:
                  mode: block
                  shields:
                    trader:
                      enabled: true
                      wallets:
                        - phantom
                        - rabby
                      addresses:
                        - 0x1111111111111111111111111111111111111111
            """;

        var parsed = TraderShieldProvisioner.Read(yaml);

        Assert.True(parsed.Enabled);
        Assert.Equal(["phantom", "rabby"], parsed.Wallets);
        Assert.Equal(["0x1111111111111111111111111111111111111111"], parsed.Addresses);
    }

    [Fact]
    public void Self_test_checks_include_labelled_seed_write_and_keystore_read()
    {
        var checks = AgentProtectionSelfTest.TraderShieldChecks();

        Assert.Equal(2, checks.Count);
        Assert.All(checks, check => Assert.True(check.ExpectBlock));
        Assert.Contains(checks, check => check.Tool == "write_file" && check.Content.Contains("wallet backup words:", StringComparison.Ordinal));
        Assert.Contains(checks, check => check.Tool == "read_file" && check.Path.Contains("exodus.wallet", StringComparison.OrdinalIgnoreCase));

        var seedPayload = AgentProtectionSelfTest.BuildPayload(checks[0], "test-session");
        Assert.Contains("wallet backup words:", seedPayload, StringComparison.Ordinal);

        Assert.Equal(
            "fileaccess:read_file:crypto-wallet",
            AgentProtectionSelfTest.Identifier("blocked: (fileaccess:read_file:crypto-wallet)"));
        Assert.Equal(
            "secret:seed-phrase",
            AgentProtectionSelfTest.Identifier("blocked: (secret:seed-phrase)"));
    }
}
