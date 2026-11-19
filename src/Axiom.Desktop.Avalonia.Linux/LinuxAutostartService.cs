// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text;
using Axiom.Presentation;

namespace Axiom.Desktop.Avalonia.Linux;

/// <summary>
/// Per-user login item as an XDG autostart entry:
/// <c>~/.config/autostart/com.axiom.firewall.desktop</c> runs <c>Axiom --autostart</c> when the
/// desktop session starts (GNOME, KDE, XFCE all honour the directory). Only that one file is
/// written or removed; nothing machine-wide is touched (the daemon has its own systemd unit).
/// </summary>
public sealed class LinuxAutostartService : IAutostartService
{
    public const string FileName = LinuxPaths.AppId + ".desktop";

    private readonly string _executablePath;
    private readonly string _entryPath;

    public LinuxAutostartService(string? executablePath = null, string? autostartDirectory = null)
    {
        _executablePath = executablePath ?? Environment.ProcessPath ?? string.Empty;
        _entryPath = Path.Combine(autostartDirectory ?? LinuxPaths.AutostartDirectory, FileName);
    }

    public string EntryPath => _entryPath;

    public bool IsSupported => _executablePath.Length > 0;

    public bool IsEnabled => Read() is AutostartState.Enabled or AutostartState.Stale;

    public bool CanRepair => Read() == AutostartState.Stale;

    public string StatusText => Read() switch
    {
        AutostartState.Enabled => "Autostart: active (~/.config/autostart)",
        AutostartState.Stale => "Autostart: path is stale; repair",
        AutostartState.Unavailable => "Autostart: unavailable",
        _ => "Autostart: off",
    };

    public bool SetEnabled(bool enabled) => enabled ? Enable() : Disable();

    public bool Repair() => Enable();

    /// <summary>The Exec= line this host would write now.</summary>
    public string ExecLine => BuildExec(_executablePath);

    /// <summary>Desktop Entry Exec quoting: double quotes around the path, backslash-escaped specials.</summary>
    internal static string QuoteExecArgument(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var builder = new StringBuilder(value.Length + 2);
        builder.Append('"');
        foreach (var character in value)
        {
            if (character is '"' or '`' or '$' or '\\')
            {
                builder.Append('\\');
            }

            builder.Append(character);
        }

        builder.Append('"');
        return builder.ToString();
    }

    internal static string BuildExec(string executablePath) => QuoteExecArgument(executablePath) + " --autostart";

    public static string BuildEntry(string executablePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        return $"""
            [Desktop Entry]
            Type=Application
            Version=1.5
            Name=Axiom
            Comment=Free open-source network and AI agent security
            Exec={BuildExec(executablePath)}
            Icon={LinuxPaths.AppId}
            Terminal=false
            Categories=Network;Security;
            X-GNOME-Autostart-enabled=true
            X-KDE-autostart-after=panel

            """;
    }

    /// <summary>The Exec= value of an existing entry, or null when unreadable.</summary>
    internal static string? ReadExec(string entryText)
    {
        ArgumentNullException.ThrowIfNull(entryText);
        var inEntry = false;
        foreach (var raw in entryText.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith('['))
            {
                inEntry = line == "[Desktop Entry]";
                continue;
            }

            if (inEntry && line.StartsWith("Exec=", StringComparison.Ordinal))
            {
                return line["Exec=".Length..];
            }
        }

        return null;
    }

    private AutostartState Read()
    {
        if (!IsSupported)
        {
            return AutostartState.Unavailable;
        }

        try
        {
            if (!File.Exists(_entryPath))
            {
                return AutostartState.Disabled;
            }

            var exec = ReadExec(File.ReadAllText(_entryPath));
            return string.Equals(exec, ExecLine, StringComparison.Ordinal)
                ? AutostartState.Enabled
                : AutostartState.Stale;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
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
            Directory.CreateDirectory(Path.GetDirectoryName(_entryPath)!);
            var temporary = _entryPath + ".tmp";
            File.WriteAllText(temporary, BuildEntry(_executablePath));
            File.Move(temporary, _entryPath, overwrite: true);
            return Read() == AutostartState.Enabled;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private bool Disable()
    {
        try
        {
            if (File.Exists(_entryPath))
            {
                File.Delete(_entryPath);
            }

            return Read() == AutostartState.Disabled;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
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
