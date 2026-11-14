// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace Axiom.Presentation;

/// <summary>Opt-out for in-app and tray notifications, independent of the tray icon.</summary>
public static class NotificationSettingsStore
{
    private static readonly string SettingsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Axiom",
        "notifications.txt");

    private static readonly string LegacyPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Axiom",
        "tray-notifications.txt");

    public static bool Enabled { get; private set; } = Load();

    public static event EventHandler? Changed;

    public static void SetEnabled(bool enabled)
    {
        if (Enabled == enabled)
        {
            return;
        }

        Enabled = enabled;
        Write(SettingsPath, enabled ? "enabled" : "disabled");
        Changed?.Invoke(null, EventArgs.Empty);
    }

    private static bool Load()
    {
        try
        {
            if (File.Exists(SettingsPath))
            {
                return !IsDisabled(File.ReadAllText(SettingsPath));
            }

            // Preserve the old "Show tray notifications" opt-out on first run.
            return !File.Exists(LegacyPath) || !IsDisabled(File.ReadAllText(LegacyPath));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return true;
        }
    }

    private static bool IsDisabled(string value) =>
        string.Equals(value.Trim(), "disabled", StringComparison.OrdinalIgnoreCase);

    private static void Write(string path, string value)
    {
        try
        {
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(path, value);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A restricted profile must not crash Settings.
        }
    }
}

/// <summary>Opt-out for hiding console windows of Axiom-launched helper processes.</summary>
public static class BackgroundWindowSettingsStore
{
    private static readonly string SettingsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Axiom",
        "hide-background-windows.txt");

    public static bool Enabled { get; private set; } = Load();

    public static event EventHandler? Changed;

    public static void SetEnabled(bool enabled)
    {
        if (Enabled == enabled)
        {
            return;
        }

        Enabled = enabled;
        try
        {
            var directory = Path.GetDirectoryName(SettingsPath);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(SettingsPath, enabled ? "enabled" : "disabled");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A restricted profile must not crash Settings.
        }

        Changed?.Invoke(null, EventArgs.Empty);
    }

    private static bool Load()
    {
        try
        {
            if (!File.Exists(SettingsPath))
            {
                return true;
            }

            return !string.Equals(File.ReadAllText(SettingsPath).Trim(), "disabled", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return true;
        }
    }
}

/// <summary>
/// Hides console windows of helper processes that descend from the Axiom desktop. It never hides a
/// window of the main Axiom process or an unrelated process that merely shares a name such as
/// node.exe. Windows created by the user's own apps are outside the descendant tree and untouched.
/// </summary>
public static class BackgroundWindowHider
{
    private static readonly HashSet<string> Names = new(StringComparer.OrdinalIgnoreCase)
    {
        "node",
        "cmd",
        "powershell",
        "pwsh",
        "python",
        "pythonw",
        "dkg",
        "opencode",
        "conhost",
        "hermes",
        "git",
        "pip",
        "Axiom.Service",
    };

    private static readonly object Gate = new();
    private static Timer? _timer;
    private static int _rootPid;
    private static DateTimeOffset _until;

    public static void HideDescendants(TimeSpan duration)
    {
        if (!OperatingSystem.IsWindows() || !BackgroundWindowSettingsStore.Enabled)
        {
            return;
        }

        lock (Gate)
        {
            _rootPid = Environment.ProcessId;
            _until = DateTimeOffset.UtcNow + duration;
            _timer?.Dispose();
            _timer = new Timer(
                _ => Sweep(),
                null,
                dueTime: 0,
                period: 500);
        }
    }

    private static void Sweep()
    {
        if (!OperatingSystem.IsWindows() || !BackgroundWindowSettingsStore.Enabled)
        {
            return;
        }

        try
        {
            var parents = ReadParents();
            var descendants = new HashSet<int> { _rootPid };
            var changed = true;
            while (changed)
            {
                changed = false;
                foreach (var pair in parents)
                {
                    if (!descendants.Contains(pair.Key) && descendants.Contains(pair.Value))
                    {
                        descendants.Add(pair.Key);
                        changed = true;
                    }
                }
            }

            foreach (var processId in descendants)
            {
                if (processId == _rootPid)
                {
                    continue;
                }

                try
                {
                    using var process = Process.GetProcessById(processId);
                    if (!Names.Contains(process.ProcessName))
                    {
                        continue;
                    }

                    var handle = process.MainWindowHandle;
                    if (handle != IntPtr.Zero)
                    {
                        _ = ShowWindow(handle, 0); // SW_HIDE
                    }
                }
                catch (Exception exception) when (exception is
                             ArgumentException or InvalidOperationException or
                             System.ComponentModel.Win32Exception)
                {
                }
            }
        }
        catch (Exception exception) when (exception is
                     InvalidOperationException or System.ComponentModel.Win32Exception)
        {
        }
        finally
        {
            if (DateTimeOffset.UtcNow >= _until)
            {
                lock (Gate)
                {
                    _timer?.Dispose();
                    _timer = null;
                }
            }
        }
    }

    private static Dictionary<int, int> ReadParents()
    {
        var parents = new Dictionary<int, int>();
        var snapshot = CreateToolhelp32Snapshot(Th32csSnapProcess, 0);
        if (snapshot == InvalidHandleValue)
        {
            return parents;
        }

        try
        {
            var entry = new ProcessEntry32 { dwSize = (uint)Marshal.SizeOf<ProcessEntry32>() };
            if (!Process32First(snapshot, ref entry))
            {
                return parents;
            }

            do
            {
                var processId = unchecked((int)entry.th32ProcessID);
                var parentId = unchecked((int)entry.th32ParentProcessID);
                if (processId > 4)
                {
                    parents[processId] = parentId;
                }
            }
            while (Process32Next(snapshot, ref entry));
        }
        finally
        {
            _ = CloseHandle(snapshot);
        }

        return parents;
    }

    private const uint Th32csSnapProcess = 0x00000002;
    private static readonly IntPtr InvalidHandleValue = new(-1);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32First(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32Next(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindow(IntPtr window, int command);
}
