// SPDX-License-Identifier: GPL-3.0-or-later
using System.Windows.Controls;
using System.Windows.Input;
using Axiom.UI.ViewModels;

namespace Axiom.UI.Views;

public partial class LiveConnectionsView : UserControl
{
    public LiveConnectionsView() => InitializeComponent();

    private void OnPreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.F && (Keyboard.Modifiers & ModifierKeys.Control) == ModifierKeys.Control)
        {
            SearchBox.Focus();
            SearchBox.SelectAll();
            e.Handled = true;
            return;
        }

        if (e.Key == Key.Escape && DataContext is LiveConnectionsViewModel viewModel)
        {
            viewModel.ResetFiltersCommand.Execute(null);
            e.Handled = true;
        }
    }
}
