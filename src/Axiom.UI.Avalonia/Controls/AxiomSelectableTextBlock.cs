// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Controls;
using Avalonia.Input;

namespace Axiom.UI.Avalonia.Controls;

/// <summary>
/// Selectable text for read-only pages. Right-clicks are left unhandled so the containing row can
/// still open its context menu (block, end task, copy path) instead of starting a text selection.
/// </summary>
public sealed class AxiomSelectableTextBlock : SelectableTextBlock
{
    protected override void OnPointerPressed(PointerPressedEventArgs e)
    {
        if (!e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
        {
            return;
        }

        base.OnPointerPressed(e);
    }
}
