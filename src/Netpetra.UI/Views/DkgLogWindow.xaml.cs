// SPDX-License-Identifier: GPL-3.0-or-later
using System.Windows;

namespace Netpetra.UI.Views;

public partial class DkgLogWindow : Window
{
    public DkgLogWindow(string text)
    {
        InitializeComponent();
        LogText.Text = text;
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
