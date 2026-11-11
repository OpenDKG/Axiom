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

    /// <summary>
    /// Optional navigation group shown above this page. Only the first page of a group carries it,
    /// so a host can render headers without inventing a second collection.
    /// </summary>
    public string? GroupLabel
    {
        get => _groupLabel;
        set
        {
            if (SetProperty(ref _groupLabel, value))
            {
                OnPropertyChanged(nameof(HasGroupLabel));
            }
        }
    }

    /// <summary>True when this page starts a navigation group.</summary>
    public bool HasGroupLabel => !string.IsNullOrEmpty(_groupLabel);

    private string? _groupLabel;
}
