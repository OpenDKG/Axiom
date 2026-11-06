// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Security;
using Microsoft.Win32;
using Axiom.Contracts;

namespace Axiom.UI.Services;

public enum AutostartState
{
    Disabled,
    Enabled,
    Stale,
    Unavailable,
}

public sealed record AutostartStatus(
    AutostartState State,
    string? RegisteredCommand,
    string Detail);

/// <summary>
/// Per-user HKCU Run registration. Only the Axiom value is written or removed; no HKLM,
/// service, scheduled task or machine-wide startup entry is used.
/// </summary>
public sealed class AutostartRegistration
{
    public const string ValueName = "Axiom";

    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";

    private readonly string _executablePath;

    public AutostartRegistration(string? executablePath = null)
    {
        _executablePath = executablePath ?? Environment.ProcessPath ?? string.Empty;
    }

    public string ExecutablePath => _executablePath;

    public string ExpectedCommand => BuildCommand(_executablePath);

    public AutostartStatus Read()
    {
        if (DistributionContext.IsStorePackage)
        {
            return new AutostartStatus(
                AutostartState.Unavailable,
                null,
                "The Microsoft Store package uses package activation; HKCU Run autostart is disabled.");
        }

        if (string.IsNullOrWhiteSpace(_executablePath))
        {
            return new AutostartStatus(
                AutostartState.Unavailable,
                null,
                "The current executable path is unavailable.");
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: false);
            var value = key?.GetValue(ValueName) as string;
            if (string.IsNullOrWhiteSpace(value))
            {
                return new AutostartStatus(
                    AutostartState.Disabled,
                    null,
                    "No Axiom startup entry is registered.");
            }

            return string.Equals(value, ExpectedCommand, StringComparison.OrdinalIgnoreCase)
                ? new AutostartStatus(
                    AutostartState.Enabled,
                    value,
                    "Autostart points at the current executable.")
                : new AutostartStatus(
                    AutostartState.Stale,
                    value,
                    "The startup entry points at a different or missing executable.");
        }
        catch (Exception exception) when (exception is
                     SecurityException or UnauthorizedAccessException or IOException)
        {
            return new AutostartStatus(
                AutostartState.Unavailable,
                null,
                "Windows policy or permissions block the startup registry entry.");
        }
    }

    public bool Enable()
    {
        if (DistributionContext.IsStorePackage || string.IsNullOrWhiteSpace(_executablePath))
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

            key.SetValue(ValueName, ExpectedCommand, RegistryValueKind.String);
            return Read().State == AutostartState.Enabled;
        }
        catch (Exception exception) when (exception is
                     SecurityException or UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }

    public bool Disable()
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

            return Read().State == AutostartState.Disabled;
        }
        catch (Exception exception) when (exception is
                     SecurityException or UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }

    public static string BuildCommand(string executablePath) =>
        $"\"{executablePath}\" --autostart";
}
