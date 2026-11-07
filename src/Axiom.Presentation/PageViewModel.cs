// SPDX-License-Identifier: GPL-3.0-or-later
using CommunityToolkit.Mvvm.ComponentModel;

namespace Axiom.Presentation;

/// <summary>Portable base for every navigation destination.</summary>
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

    /// <summary>Portable icon key. Hosts map it to their own icon set.</summary>
    public string Glyph { get; }
}
