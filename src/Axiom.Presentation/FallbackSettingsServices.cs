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

/// <summary>In-memory UI mode service for tests and headless hosts; defaults to Advanced.</summary>
public sealed class FixedUiModeService(UiMode initial = UiMode.Advanced) : IUiModeService
{
    public UiMode Current { get; private set; } = initial;

    public event EventHandler? Changed;

    public void Apply(UiMode mode)
    {
        if (Current == mode)
        {
            return;
        }

        Current = mode;
        Changed?.Invoke(this, EventArgs.Empty);
    }
}

/// <summary>Persists and broadcasts the user's Simple / Mini / Advanced shell mode preference.</summary>
public sealed class PersistentUiModeService : IUiModeService
{
    public PersistentUiModeService()
    {
        Current = UiModeSettingsStore.Load();
    }

    public UiMode Current { get; private set; }

    public event EventHandler? Changed;

    public void Apply(UiMode mode)
    {
        if (Current == mode)
        {
            return;
        }

        Current = mode;
        UiModeSettingsStore.Save(mode);
        Changed?.Invoke(this, EventArgs.Empty);
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
