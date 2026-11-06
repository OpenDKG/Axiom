// SPDX-License-Identifier: GPL-3.0-or-later
using System.Windows;
using Axiom.UI.Services;

namespace Axiom.UI.Views;

public partial class ReputationSetupWindow : Window
{
    public ReputationSetupWindow(ReputationSettings current)
    {
        InitializeComponent();
        ApiKeyBox.Password = current.ApiKey;
        EnableCheck.IsChecked = current.Enabled;
    }

    public ReputationSettings Settings => new(
        EnableCheck.IsChecked == true,
        ApiKeyBox.Password.Trim());

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        if (EnableCheck.IsChecked == true && string.IsNullOrWhiteSpace(ApiKeyBox.Password))
        {
            MessageBox.Show(
                this,
                "Enter an API key or clear the Enable checkbox.",
                "VirusTotal provider",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
