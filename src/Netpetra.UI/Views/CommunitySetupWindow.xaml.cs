// SPDX-License-Identifier: GPL-3.0-or-later
using System.Windows;
using Netpetra.UI.Services;

namespace Netpetra.UI.Views;

public partial class CommunitySetupWindow : Window
{
    public CommunitySetupWindow(CommunityFeedSettings current)
    {
        InitializeComponent();
        UrlBox.Text = current.Url;
        TokenBox.Password = current.Token;
        EnableCheck.IsChecked = current.Enabled;
    }

    public CommunityFeedSettings Settings => new(
        EnableCheck.IsChecked == true,
        UrlBox.Text.Trim(),
        TokenBox.Password.Trim());

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        if (EnableCheck.IsChecked == true && string.IsNullOrWhiteSpace(UrlBox.Text))
        {
            MessageBox.Show(
                this,
                "Enter an HTTPS feed URL or clear the Enable checkbox.",
                "Community feed",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
