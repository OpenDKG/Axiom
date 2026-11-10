// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Controls;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia.Views;

public partial class ConnectionsView : UserControl
{
    public ConnectionsView()
    {
        InitializeComponent();
    }

    // Grouped mode shows one ListBox per application; the toolbar actions (Block outbound, ...)
    // act on SelectedConnection, so a row picked inside any group becomes the selection.
    private void OnGroupRowSelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (DataContext is ConnectionsPageViewModel viewModel &&
            e.AddedItems.Count > 0 &&
            e.AddedItems[0] is ConnectionRow row)
        {
            viewModel.SelectedConnection = row;
        }
    }
}
