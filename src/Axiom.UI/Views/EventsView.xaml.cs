// SPDX-License-Identifier: GPL-3.0-or-later
using System.Windows.Controls;
using System.Windows.Input;
using Axiom.UI.ViewModels;

namespace Axiom.UI.Views;

public partial class EventsView : UserControl
{
    public EventsView() => InitializeComponent();

    private void OnPreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.F && (Keyboard.Modifiers & ModifierKeys.Control) == ModifierKeys.Control)
        {
            SearchBox.Focus();
            SearchBox.SelectAll();
            e.Handled = true;
            return;
        }

        if (DataContext is not EventsViewModel viewModel)
        {
            return;
        }

        if (e.Key == Key.F5)
        {
            viewModel.RefreshCommand.Execute(null);
            e.Handled = true;
        }
        else if (e.Key == Key.Escape)
        {
            viewModel.SearchText = string.Empty;
            e.Handled = true;
        }
    }
}
