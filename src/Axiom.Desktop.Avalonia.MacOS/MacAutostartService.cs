// SPDX-License-Identifier: GPL-3.0-or-later
using System.Security;
using System.Xml;
using Axiom.Presentation;

namespace Axiom.Desktop.Avalonia.MacOS;

/// <summary>
/// Per-user login item as a LaunchAgent: <c>~/Library/LaunchAgents/com.axiom.firewall.agent.plist</c>
/// starts Axiom at login in the GUI (Aqua) session. Only that one file is written or removed; no
/// machine-wide launchd job is touched (the daemon has its own plist).
/// <para>
/// Review #15: a quarantined app runs from an app-translocation path that changes on every launch,
/// so pinning <c>Environment.ProcessPath</c> breaks the login item. When the app runs from a bundle
/// (LaunchServices registered it at launch) the agent runs
/// <c>/usr/bin/open -b com.axiom.firewall --args --autostart</c> instead, which resolves the bundle
/// wherever it lives; the executable path is only pinned when there is no bundle to register.
/// </para>
/// </summary>
public sealed class MacAutostartService : IAutostartService
{
    public const string Label = "com.axiom.firewall.agent";

    public const string BundleId = "com.axiom.firewall";

    public const string OpenPath = "/usr/bin/open";

    private readonly string _executablePath;
    private readonly string _plistPath;
    private readonly bool _bundleRegistered;

    public MacAutostartService(string? executablePath = null, string? launchAgentsDirectory = null, bool? bundleRegistered = null)
    {
        _executablePath = executablePath ?? Environment.ProcessPath ?? string.Empty;
        _bundleRegistered = bundleRegistered ?? MacBundleLayout.Current.IsInsideAppBundle;
        _plistPath = Path.Combine(
            launchAgentsDirectory ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Library",
                "LaunchAgents"),
            Label + ".plist");
    }

    public string PlistPath => _plistPath;

    public bool IsSupported => _executablePath.Length > 0 || _bundleRegistered;

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

    /// <summary>The ProgramArguments this host would write now.</summary>
    public IReadOnlyList<string> ProgramArguments => _bundleRegistered
        ? [OpenPath, "-b", BundleId, "--args", "--autostart"]
        : [_executablePath, "--autostart"];

    /// <summary>Launches the registered bundle by id; the login item survives moves and translocation.</summary>
    public static string BuildPlist() => BuildPlist([OpenPath, "-b", BundleId, "--args", "--autostart"]);

    /// <summary>Pins an executable path (only when no bundle is registered).</summary>
    public static string BuildPlist(string executablePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        return BuildPlist([executablePath, "--autostart"]);
    }

    private static string BuildPlist(IReadOnlyList<string> programArguments)
    {
        var arguments = string.Join('\n', programArguments.Select(argument => $"        <string>{SecurityElement.Escape(argument)}</string>"));
        return $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
                <key>Label</key>
                <string>{Label}</string>
                <key>ProgramArguments</key>
                <array>
            {arguments}
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
    internal static string? ReadProgram(string plistXml) => ReadProgramArguments(plistXml) is { Count: > 0 } arguments ? arguments[0] : null;

    /// <summary>ProgramArguments of an existing plist, or null when unreadable.</summary>
    internal static IReadOnlyList<string>? ReadProgramArguments(string plistXml)
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
                    key.NextSibling is XmlElement { Name: "array" } array)
                {
                    return array.ChildNodes.OfType<XmlElement>()
                        .Where(element => element.Name == "string")
                        .Select(element => element.InnerText)
                        .ToArray();
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

            var arguments = ReadProgramArguments(File.ReadAllText(_plistPath));
            return arguments is not null && arguments.SequenceEqual(ProgramArguments, StringComparer.Ordinal)
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
            File.WriteAllText(temporary, BuildPlist(ProgramArguments));
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
