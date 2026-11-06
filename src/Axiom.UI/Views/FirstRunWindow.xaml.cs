// SPDX-License-Identifier: GPL-3.0-or-later
using System.Windows;
using Axiom.Contracts;
using Axiom.UI.Services;

namespace Axiom.UI.Views;

public partial class FirstRunWindow : Window
{
    private readonly OptionalModuleInstaller _installer = new();

    public FirstRunWindow()
    {
        InitializeComponent();

        if (DistributionContext.IsStorePackage)
        {
            DkgCheck.IsChecked = false;
            DkgCheck.Visibility = Visibility.Collapsed;
            BlackboxCheck.IsChecked = false;
            BlackboxCheck.Visibility = Visibility.Collapsed;
            ComponentsHeader.Text = "Built-in core components";
            AcceptCheck.Content = "I understand this Store package contains core Axiom only.";
            IntroText.Text =
                "The Microsoft Store package contains Axiom core: local monitoring, history, " +
                "firewall inventory, reputation, community feed and local file scanning. Optional " +
                "third-party installers and agent hooks are not included in this package.";
        }
    }

    private void Accept_Changed(object sender, RoutedEventArgs e) =>
        ApplyButton.IsEnabled = AcceptCheck.IsChecked == true;

    private void Apply_Click(object sender, RoutedEventArgs e)
    {
        if (AcceptCheck.IsChecked != true)
        {
            return;
        }

        var settings = new OnboardingSettings(
            Completed: true,
            Skipped: false,
            Dkg: !DistributionContext.IsStorePackage && DkgCheck.IsChecked == true,
            Blackbox: !DistributionContext.IsStorePackage && BlackboxCheck.IsChecked == true);

        OnboardingStore.Save(settings);

        if (CommunityCheck.IsChecked == true)
        {
            new CommunityFeedSettingsStore().Save(new CommunityFeedSettings(
                Enabled: true,
                Url: CommunityFeedSettingsStore.StarterFeedUrl,
                Token: string.Empty));
        }

        if (settings.Dkg)
        {
            _installer.InstallDkg();
        }

        if (settings.Blackbox)
        {
            _installer.InstallBlackbox();
        }

        DialogResult = true;
    }

    private void Skip_Click(object sender, RoutedEventArgs e)
    {
        OnboardingStore.Save(new OnboardingSettings(
            Completed: true,
            Skipped: true,
            Dkg: false,
            Blackbox: false));

        DialogResult = false;
    }
}
