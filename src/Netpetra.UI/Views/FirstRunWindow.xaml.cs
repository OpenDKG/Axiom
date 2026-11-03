// SPDX-License-Identifier: GPL-3.0-or-later
using System.Windows;
using Netpetra.UI.Services;

namespace Netpetra.UI.Views;

public partial class FirstRunWindow : Window
{
    private readonly OptionalModuleInstaller _installer = new();

    public FirstRunWindow()
    {
        InitializeComponent();
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
            Dkg: DkgCheck.IsChecked == true,
            Blackbox: BlackboxCheck.IsChecked == true);

        OnboardingStore.Save(settings);

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
