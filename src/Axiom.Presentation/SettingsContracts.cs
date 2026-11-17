// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

/// <summary>Portable palette choice. Hosts map it to their own theme resource.</summary>
public enum UiTheme
{
    Dark,
    Light,
    DarkMidnight,
    LightWarm,
    GlassDark,
    GlassLight,
}

/// <summary>Host theme application and persistence.</summary>
public interface IThemeService
{
    UiTheme Current { get; }

    event EventHandler? Changed;

    void Apply(UiTheme theme);
}

/// <summary>User-facing shell complexity mode.</summary>
public enum UiMode
{
    Mini,
    Simple,
    Advanced,
}

/// <summary>Host shell complexity preference and persistence.</summary>
public interface IUiModeService
{
    UiMode Current { get; }

    event EventHandler? Changed;

    void Apply(UiMode mode);
}

/// <summary>Per-user HKCU Run autostart. Implementations must only touch the Axiom value.</summary>
public interface IAutostartService
{
    bool IsSupported { get; }

    bool IsEnabled { get; }

    string StatusText { get; }

    bool CanRepair { get; }

    bool SetEnabled(bool enabled);

    bool Repair();
}
