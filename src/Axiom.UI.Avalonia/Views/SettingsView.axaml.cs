// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Controls;
using Avalonia.Interactivity;

namespace Axiom.UI.Avalonia.Views;

public partial class SettingsView : UserControl
{
    public SettingsView()
    {
        InitializeComponent();
    }

    private async void OnRunOnboardingClick(object? sender, RoutedEventArgs e)
    {
        if (TopLevel.GetTopLevel(this) is Window window &&
            DataContext is ShellViewModel shell)
        {
            await shell.RunOnboardingAsync(window);
        }
    }
}
