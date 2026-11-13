// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Controls;
using Avalonia.Input;

namespace Axiom.UI.Avalonia.Views;

public partial class AgentStatsView : UserControl
{
    public AgentStatsView() => InitializeComponent();

    private void OnRowPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        if (sender is Control row)
        {
            RowSelection.SelectRow(row);
        }
    }
}
