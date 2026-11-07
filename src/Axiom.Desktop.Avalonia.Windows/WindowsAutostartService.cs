// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Security;
using Axiom.Contracts;
using Axiom.Presentation;
using Microsoft.Win32;

namespace Axiom.Desktop.Avalonia.Windows;

/// <summary>
/// Per-user HKCU Run registration. Only the Axiom value is written or removed; no HKLM, service,
/// scheduled task or machine-wide startup entry is used.
/// </summary>
public sealed class WindowsAutostartService : IAutostartService
{
    public const string ValueName = "Axiom";

    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";

    private readonly string _executablePath;

    public WindowsAutostartService(string? executablePath = null)
    {
        _executablePath = executablePath ?? Environment.ProcessPath ?? string.Empty;
    }

    public bool IsSupported => !DistributionContext.IsStorePackage && _executablePath.Length > 0;

    public bool IsEnabled
    {
        get
        {
            var state = Read();
            return state is AutostartState.Enabled or AutostartState.Stale;
        }
    }

    public bool CanRepair => Read() == AutostartState.Stale;

    public string StatusText => Read() switch
    {
        AutostartState.Enabled => "Autostart: active",
        AutostartState.Stale => "Autostart: path is stale; repair",
        AutostartState.Unavailable => "Autostart: unavailable (permission/policy)",
        _ => "Autostart: off",
    };

    public static string BuildCommand(string executablePath) =>
        $"\"{executablePath}\" --autostart";

    public bool SetEnabled(bool enabled) => enabled ? Enable() : Disable();

    public bool Repair() => Enable();

    private AutostartState Read()
    {
        if (!IsSupported)
        {
            return AutostartState.Unavailable;
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: false);
            var value = key?.GetValue(ValueName) as string;
            if (string.IsNullOrWhiteSpace(value))
            {
                return AutostartState.Disabled;
            }

            return string.Equals(value, BuildCommand(_executablePath), StringComparison.OrdinalIgnoreCase)
                ? AutostartState.Enabled
                : AutostartState.Stale;
        }
        catch (Exception exception) when (exception is
                     SecurityException or UnauthorizedAccessException or IOException)
        {
            return AutostartState.Unavailable;
        }
    }

    private bool Enable()
    {
        if (!IsSupported)
        {
            return false;
        }

        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(RunKeyPath, writable: true);
            if (key is null)
            {
                return false;
            }

            key.SetValue(ValueName, BuildCommand(_executablePath), RegistryValueKind.String);
            return Read() == AutostartState.Enabled;
        }
        catch (Exception exception) when (exception is
                     SecurityException or UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }

    private bool Disable()
    {
        if (DistributionContext.IsStorePackage)
        {
            return true;
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true);
            if (key?.GetValue(ValueName) is not null)
            {
                key.DeleteValue(ValueName, throwOnMissingValue: false);
            }

            return Read() == AutostartState.Disabled;
        }
        catch (Exception exception) when (exception is
                     SecurityException or UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }

    private enum AutostartState
    {
        Disabled,
        Enabled,
        Stale,
        Unavailable,
    }
}
