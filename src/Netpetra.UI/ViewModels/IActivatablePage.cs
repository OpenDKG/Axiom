// SPDX-License-Identifier: GPL-3.0-or-later
namespace Netpetra.UI.ViewModels;

/// <summary>Optional lifecycle for pages that poll while selected.</summary>
public interface IActivatablePage
{
    void Activate();

    void Deactivate();
}
