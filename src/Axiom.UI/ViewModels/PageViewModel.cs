// SPDX-License-Identifier: GPL-3.0-or-later
using CommunityToolkit.Mvvm.ComponentModel;

namespace Axiom.UI.ViewModels;

/// <summary>Base for the seven navigation destinations.</summary>
public abstract class PageViewModel : ObservableObject
{
    protected PageViewModel(string title, string subtitle, string glyph)
    {
        Title = title;
        Subtitle = subtitle;
        Glyph = glyph;
    }

    public string Title { get; }

    public string Subtitle { get; }

    /// <summary>Segoe MDL2 Assets glyph code used by the navigation rail.</summary>
    public string Glyph { get; }
}
