// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.CompilerServices;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.VisualTree;

namespace Axiom.UI.Avalonia.Controls;

/// <summary>
/// Avalonia 12 opens a pointer-triggered <see cref="ContextMenu"/> with the popup's placement target
/// set to the control under the pointer, but leaves <see cref="ContextMenu.PlacementTarget"/> itself
/// null. Axiom's row menus bind their commands through
/// <c>$parent[ContextMenu].PlacementTarget.Tag...</c>, so those bindings resolved to null and every
/// menu item did nothing (issue #296: the menu opened, copying changed nothing).
///
/// This class handler restores the owner control on the menu after the framework has opened it, so
/// the existing <c>PlacementTarget</c> bindings resolve again.
/// </summary>
internal static class ContextMenuPlacement
{
#pragma warning disable CA2255 // The UI assembly must register this before any window is created.
    [ModuleInitializer]
#pragma warning restore CA2255
    internal static void Initialize() =>
        Control.ContextRequestedEvent.AddClassHandler<Control>(
            static (control, _) => ApplyOwner(control),
            RoutingStrategies.Bubble,
            handledEventsToo: true);

    private static void ApplyOwner(Control source)
    {
        for (Control? current = source; current is not null; current = current.GetVisualParent() as Control)
        {
            if (current.ContextMenu is { } menu)
            {
                if (!ReferenceEquals(menu.PlacementTarget, current))
                {
                    menu.PlacementTarget = current;
                }

                return;
            }
        }
    }
}
