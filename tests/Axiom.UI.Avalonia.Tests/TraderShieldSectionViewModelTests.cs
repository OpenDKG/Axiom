// SPDX-License-Identifier: GPL-3.0-or-later
using System.Linq;
using Avalonia.Controls;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Axiom.Presentation;
using Axiom.UI.Avalonia.Views;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

public sealed class TraderShieldSectionViewModelTests
{
    private const string FakeConfigPath = @"C:\lab\hermes\config.yaml";

    [Fact]
    public void Reload_populates_all_supported_wallets_and_addresses()
    {
        var address = "0x" + new string('a', 40);
        var yaml = $"""
            plugins:
              entries:
                blackbox:
                  mode: block
                  shields:
                    trader:
                      enabled: true
                      wallets: [metamask, exodus]
                      addresses:
                        - {address}
            """;

        var vm = new TraderShieldSectionViewModel(
            FakeConfigPath,
            _ => true,
            _ => yaml,
            (_, _) => true,
            () => []);

        Assert.True(vm.IsEnabled);
        Assert.Equal(TraderShieldProvisioner.SupportedWallets.Count, vm.Wallets.Count);
        Assert.Equal(2, vm.Wallets.Count(w => w.IsSelected));
        Assert.True(vm.Wallets.Single(w => w.Id == "metamask").IsSelected);
        Assert.True(vm.Wallets.Single(w => w.Id == "exodus").IsSelected);
        Assert.False(vm.Wallets.Single(w => w.Id == "phantom").IsSelected);
        Assert.Equal([address], vm.Addresses);
        Assert.True(vm.HasAddresses);
    }

    [Fact]
    public void Save_persists_selected_wallets_and_addresses()
    {
        var current = """
            plugins:
              entries:
                blackbox:
                  mode: block
                  report: false
            """;

        var vm = new TraderShieldSectionViewModel(
            FakeConfigPath,
            _ => true,
            _ => current,
            (_, updated) =>
            {
                current = updated;
                return true;
            },
            () => []);

        vm.IsEnabled = true;
        foreach (var wallet in vm.Wallets)
        {
            wallet.IsSelected = wallet.Id is "phantom" or "rabby";
        }

        vm.NewAddressInput = "0x" + new string('C', 40);
        vm.AddAddressCommand.Execute(null);

        Assert.Contains("enabled: true", current, StringComparison.Ordinal);
        Assert.Contains("wallets: [phantom, rabby]", current, StringComparison.Ordinal);
        Assert.Contains("0x" + new string('c', 40), current, StringComparison.Ordinal);
        Assert.Contains("report: false", current, StringComparison.Ordinal);
        Assert.Equal(string.Empty, vm.NewAddressInput);
        Assert.StartsWith("Saved", vm.StatusText, StringComparison.Ordinal);
    }

    [Fact]
    public void Add_address_rejects_invalid_evm_input()
    {
        var saved = false;
        var vm = new TraderShieldSectionViewModel(
            FakeConfigPath,
            _ => true,
            _ => "plugins:\n  entries:\n    blackbox:\n      mode: block\n",
            (_, _) =>
            {
                saved = true;
                return true;
            },
            () => []);

        vm.NewAddressInput = "not-an-evm-address";
        vm.AddAddressCommand.Execute(null);

        Assert.False(saved);
        Assert.Empty(vm.Addresses);
        Assert.Contains("valid EVM address", vm.StatusText, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Self_test_reports_pass_when_seed_write_and_keystore_read_block()
    {
        var vm = new TraderShieldSectionViewModel(
            FakeConfigPath,
            _ => true,
            _ => "plugins:\n  entries:\n    blackbox:\n      mode: block\n",
            (_, _) => true,
            () =>
            [
                new ProtectionCheckResult("seed-phrase write", true, true, "secret:seed-phrase"),
                new ProtectionCheckResult("wallet keystore read", true, true, "fileaccess:read_file:crypto-wallet"),
            ]);

        await vm.RunSelfTestCommand.ExecuteAsync(null);

        Assert.StartsWith("PASS", vm.SelfTestStatusText, StringComparison.Ordinal);
        Assert.Contains("secret:seed-phrase", vm.SelfTestStatusText, StringComparison.Ordinal);
        Assert.Contains("fileaccess:read_file:crypto-wallet", vm.SelfTestStatusText, StringComparison.Ordinal);
    }

    [Fact]
    public void Trader_shield_stays_visible_but_disabled_when_the_platform_cannot_run_it()
    {
        // The default (no explicit config path) is supported on Windows only.
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        TestAppBuilder.RunOnUiThread(() =>
        {
            var securityView = new SecurityView { DataContext = new StubIntegrationsPage() };
            var securityWindow = new Window { Width = 1024, Height = 768, Content = securityView };
            securityWindow.Show();
            Dispatcher.UIThread.RunJobs();

            try
            {
                var section = Assert.Single(securityView.GetVisualDescendants().OfType<TraderShieldSectionView>());
                Assert.True(section.IsVisible);
                Assert.False(section.IsEnabled);
                Assert.Contains(
                    section.GetVisualDescendants().OfType<TextBlock>(),
                    text => text.Text == TraderShieldSectionViewModel.UnsupportedPlatformText);
            }
            finally
            {
                securityWindow.Close();
            }
        });
    }

    [Fact]
    public void Trader_shield_appears_only_on_integrations_and_not_on_agent_protection()
    {
        TestAppBuilder.RunOnUiThread(() =>
        {
            var securityView = new SecurityView();
            var securityWindow = new Window { Width = 1024, Height = 768, Content = securityView };
            securityWindow.Show();
            Dispatcher.UIThread.RunJobs();

            var agentsView = new AgentsView();
            var agentsWindow = new Window { Width = 1024, Height = 768, Content = agentsView };
            agentsWindow.Show();
            Dispatcher.UIThread.RunJobs();

            try
            {
                Assert.Single(securityView.GetVisualDescendants().OfType<TraderShieldSectionView>());
                Assert.Empty(agentsView.GetVisualDescendants().OfType<TraderShieldSectionView>());
            }
            finally
            {
                securityWindow.Close();
                agentsWindow.Close();
            }
        });
    }

    /// <summary>Only the Integrations binding the view needs; the rest of the page is not built.</summary>
    private sealed class StubIntegrationsPage
    {
        public TraderShieldSectionViewModel TraderShield { get; } = new();
    }
}
