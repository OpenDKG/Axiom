// SPDX-License-Identifier: GPL-3.0-or-later
using System.Windows;
using System.Windows.Controls;
using Axiom.UI.ViewModels;

namespace Axiom.UI.Views;

public partial class SupportView : UserControl
{
    public SupportView() => InitializeComponent();

    private void OnOpenDonationsClicked(object sender, RoutedEventArgs e)
    {
        if (DataContext is not SupportViewModel viewModel)
        {
            return;
        }

        var window = new DonationWindow(viewModel);
        if (Window.GetWindow(this) is { } owner)
        {
            window.Owner = owner;
        }

        window.ShowDialog();
    }
}
