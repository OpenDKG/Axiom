// SPDX-License-Identifier: GPL-3.0-or-later
using System.Windows;

namespace Netpetra.UI.Views;

public partial class AgentHookInstallWindow : Window
{
    public AgentHookInstallWindow()
    {
        InitializeComponent();

        // No default action: the user must choose one of the two explicit buttons.
        CompleteInstallation = false;
    }

    public bool CompleteInstallation { get; private set; }

    private void OnPartial(object sender, RoutedEventArgs e)
    {
        CompleteInstallation = false;
        DialogResult = true;
    }

    private void OnComplete(object sender, RoutedEventArgs e)
    {
        CompleteInstallation = true;
        DialogResult = true;
    }
}
