// SPDX-License-Identifier: GPL-3.0-or-later
using System.Windows;
using System.Windows.Controls;
using Netpetra.UI.ViewModels;

namespace Netpetra.UI.Views;

public partial class AiAnalystView : UserControl
{
    public AiAnalystView()
    {
        InitializeComponent();
    }

    private void ApiKey_Changed(object sender, RoutedEventArgs e)
    {
        if (DataContext is AiAnalystViewModel viewModel && sender is PasswordBox box)
        {
            viewModel.SetApiKey(box.Password);
        }
    }
}
