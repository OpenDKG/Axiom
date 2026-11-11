// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;

namespace Axiom.Presentation;

/// <summary>
/// How much visual effect Axiom may request from the host window. Only the host can report what the
/// platform actually granted, so the setting never claims native blur on its own.
/// </summary>
public enum VisualEffects
{
    /// <summary>Use the strongest backdrop the platform confirms, otherwise simulated glass.</summary>
    Auto = 0,

    /// <summary>Request native acrylic or Mica when the theme supports it.</summary>
    Full = 1,

    /// <summary>Prefer a lighter native backdrop, or simulated glass where unsupported.</summary>
    Reduced = 2,

    /// <summary>No native backdrop; glass themes keep their layered surfaces.</summary>
    Off = 3,
}

/// <summary>Host-agnostic access to the visual-effects preference and the confirmed backdrop.</summary>
public interface IVisualEffectsService
{
    /// <summary>User preference. Defaults to <see cref="VisualEffects.Auto"/>.</summary>
    VisualEffects Current { get; }

    /// <summary>
    /// What the host window actually reports, for example "AcrylicBlur (native backdrop active)" or
    /// "Simulated glass (native backdrop unavailable)". Empty until the host reports a value.
    /// </summary>
    string BackdropStatus { get; }

    /// <summary>Stores the preference; the host applies it on its next theme or window update.</summary>
    void Apply(VisualEffects value);

    /// <summary>Called by the host after it observes the real transparency level.</summary>
    void ReportBackdrop(string status);

    event EventHandler? Changed;
}

/// <summary>In-memory implementation used by tests and hosts without native backdrops.</summary>
public sealed class FixedVisualEffectsService : IVisualEffectsService
{
    private VisualEffects _current = VisualEffects.Auto;
    private string _backdropStatus = "Simulated glass (this host reports no native backdrop)";

    public VisualEffects Current => _current;

    public string BackdropStatus => _backdropStatus;

    public event EventHandler? Changed;

    public void Apply(VisualEffects value)
    {
        if (_current == value)
        {
            return;
        }

        _current = value;
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

/// <summary>Persists one word for the user's visual-effects choice; no other data is written.</summary>
public static class VisualEffectsStore
{
    private static string SettingsPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Axiom",
        "visual-effects.txt");

    public static VisualEffects Load()
    {
        try
        {
            if (!File.Exists(SettingsPath))
            {
                return VisualEffects.Auto;
            }

            var value = File.ReadAllText(SettingsPath).Trim();
            return Enum.TryParse<VisualEffects>(value, ignoreCase: true, out var effects)
                ? effects
                : VisualEffects.Auto;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return VisualEffects.Auto;
        }
    }

    public static void Save(VisualEffects effects)
    {
        try
        {
            var directory = Path.GetDirectoryName(SettingsPath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(SettingsPath, effects.ToString());
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A read-only profile must not prevent this session from switching effects.
        }
    }
}

/// <summary>Display labels for the four supported choices.</summary>
public static class VisualEffectsLabels
{
    public static string Label(VisualEffects value) => value switch
    {
        VisualEffects.Full => "Full",
        VisualEffects.Reduced => "Reduced",
        VisualEffects.Off => "Off",
        _ => "Auto",
    };
}
