// SPDX-License-Identifier: GPL-3.0-or-later
using System.Windows;
using Netpetra.UI.ViewModels;

namespace Netpetra.UI.Views;

public partial class DonationWindow : Window
{
    public DonationWindow(SupportViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel ?? throw new ArgumentNullException(nameof(viewModel));
    }
}
