// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

/// <summary>Theme host that has no renderer: it reports Dark and does not persist a change.</summary>
public sealed class FixedThemeService : IThemeService
{
    public UiTheme Current => UiTheme.Dark;

    public event EventHandler? Changed
    {
        add { }
        remove { }
    }

    public void Apply(UiTheme theme)
    {
    }
}

/// <summary>Host without Windows autostart support. It reports unsupported and changes nothing.</summary>
public sealed class UnsupportedAutostartService : IAutostartService
{
    public bool IsSupported => false;

    public bool IsEnabled => false;

    public string StatusText => "Autostart: unavailable in this host";

    public bool CanRepair => false;

    public bool SetEnabled(bool enabled) => false;

    public bool Repair() => false;
}
