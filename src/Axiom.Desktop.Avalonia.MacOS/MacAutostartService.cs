// SPDX-License-Identifier: GPL-3.0-or-later
using System.Security;
using System.Xml;
using Axiom.Presentation;

namespace Axiom.Desktop.Avalonia.MacOS;

/// <summary>
/// Per-user login item as a LaunchAgent: <c>~/Library/LaunchAgents/com.axiom.firewall.agent.plist</c>
/// runs <c>Axiom --autostart</c> at login in the GUI (Aqua) session. Only that one file is written
/// or removed; no machine-wide launchd job is touched (the daemon has its own plist).
/// </summary>
public sealed class MacAutostartService : IAutostartService
{
    public const string Label = "com.axiom.firewall.agent";

    private readonly string _executablePath;
    private readonly string _plistPath;

    public MacAutostartService(string? executablePath = null, string? launchAgentsDirectory = null)
    {
        _executablePath = executablePath ?? Environment.ProcessPath ?? string.Empty;
        _plistPath = Path.Combine(
            launchAgentsDirectory ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Library",
                "LaunchAgents"),
            Label + ".plist");
    }

    public string PlistPath => _plistPath;

    public bool IsSupported => _executablePath.Length > 0;

    public bool IsEnabled => Read() is AutostartState.Enabled or AutostartState.Stale;

    public bool CanRepair => Read() == AutostartState.Stale;

    public string StatusText => Read() switch
    {
        AutostartState.Enabled => "Autostart: active (login item)",
        AutostartState.Stale => "Autostart: path is stale; repair",
        AutostartState.Unavailable => "Autostart: unavailable",
        _ => "Autostart: off",
    };

    public bool SetEnabled(bool enabled) => enabled ? Enable() : Disable();

    public bool Repair() => Enable();

    public static string BuildPlist(string executablePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        var path = SecurityElement.Escape(executablePath);
        return $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
                <key>Label</key>
                <string>{Label}</string>
                <key>ProgramArguments</key>
                <array>
                    <string>{path}</string>
                    <string>--autostart</string>
                </array>
                <key>RunAtLoad</key>
                <true/>
                <key>LimitLoadToSessionType</key>
                <string>Aqua</string>
                <key>ProcessType</key>
                <string>Interactive</string>
            </dict>
            </plist>

            """;
    }

    /// <summary>First ProgramArguments entry of an existing plist, or null.</summary>
    internal static string? ReadProgram(string plistXml)
    {
        try
        {
            var document = new XmlDocument { XmlResolver = null };
            using var reader = XmlReader.Create(
                new StringReader(plistXml),
                new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore, XmlResolver = null });
            document.Load(reader);
            var keys = document.SelectNodes("/plist/dict/key");
            if (keys is null)
            {
                return null;
            }

            foreach (XmlNode key in keys)
            {
                if (key.InnerText == "ProgramArguments" &&
                    key.NextSibling is XmlElement { Name: "array" } array &&
                    array.SelectSingleNode("string") is { } first)
                {
                    return first.InnerText;
                }
            }

            return null;
        }
        catch (XmlException)
        {
            return null;
        }
    }

    private AutostartState Read()
    {
        if (!IsSupported)
        {
            return AutostartState.Unavailable;
        }

        try
        {
            if (!File.Exists(_plistPath))
            {
                return AutostartState.Disabled;
            }

            var program = ReadProgram(File.ReadAllText(_plistPath));
            return string.Equals(program, _executablePath, StringComparison.Ordinal)
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
            Directory.CreateDirectory(Path.GetDirectoryName(_plistPath)!);
            var temporary = _plistPath + ".tmp";
            File.WriteAllText(temporary, BuildPlist(_executablePath));
            File.Move(temporary, _plistPath, overwrite: true);
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
            if (File.Exists(_plistPath))
            {
                File.Delete(_plistPath);
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
