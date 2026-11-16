// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Controls;
using Avalonia.Input;

namespace Axiom.UI.Avalonia.Controls;

/// <summary>
/// Selectable text for read-only pages. Right-clicks are left unhandled so the containing row can
/// still open its context menu (block, end process/app, copy path) instead of starting a text selection,
/// and left-clicks inside a ListBoxItem also select the containing row.
/// </summary>
public sealed class AxiomSelectableTextBlock : SelectableTextBlock
{
    protected override void OnPointerPressed(PointerPressedEventArgs e)
    {
        if (!e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
        {
            return;
        }

        DataListSelection.SelectContainingListItem(this);
        base.OnPointerPressed(e);
    }
}
