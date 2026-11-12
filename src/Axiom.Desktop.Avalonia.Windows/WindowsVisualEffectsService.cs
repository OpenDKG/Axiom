// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;

namespace Axiom.Desktop.Avalonia.Windows;

/// <summary>
/// Persists the visual-effects choice and relays the backdrop the window actually achieved. The
/// service never reports a native material until the window confirms it.
/// </summary>
public sealed class WindowsVisualEffectsService : IVisualEffectsService
{
    private VisualEffects _current;
    private string _backdropStatus = "Waiting for the window to report the backdrop";

    public WindowsVisualEffectsService()
    {
        _current = VisualEffectsStore.Load();
    }

    public VisualEffects Current => _current;

    public string BackdropStatus => _backdropStatus;

    public event EventHandler? Changed;

    public void Apply(VisualEffects value)
    {
        _current = value;
        VisualEffectsStore.Save(value);
        Changed?.Invoke(this, EventArgs.Empty);
    }

    public void ReportBackdrop(string status)
    {
        ArgumentNullException.ThrowIfNull(status);
        if (string.Equals(_backdropStatus, status, StringComparison.Ordinal))
        {
            return;
        }

        _backdropStatus = status;
        Changed?.Invoke(this, EventArgs.Empty);
    }
}
