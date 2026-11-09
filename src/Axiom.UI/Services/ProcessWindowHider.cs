// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace Axiom.UI.Services;

/// <summary>
/// Keeps child console windows of an optional module hidden after it starts. Some third-party
/// launchers create a new console for their worker process even when the parent was started hidden;
/// this watcher only hides windows owned by the started process tree and by new node/python console
/// hosts. It never terminates a process.
/// </summary>
internal static class ProcessWindowHider
{
    private const int SwHide = 0;
    private const uint Th32CsSnapProcess = 0x00000002;

    public static void Start(int rootProcessId, TimeSpan? duration = null)
    {
        if (rootProcessId <= 0 || !BackgroundWindowSettingsStore.Enabled)
        {
            return;
        }

        var deadline = DateTime.UtcNow + (duration ?? TimeSpan.FromSeconds(30));
        var launchedUtc = DateTime.UtcNow;

        _ = Task.Run(async () =>
        {
            var known = new HashSet<int> { rootProcessId };
            while (DateTime.UtcNow < deadline)
            {
                try
                {
                    ExpandDescendants(known);
                    HideKnownWindows(known);
                    HideNewConsoleHosts(known, launchedUtc);
                }
                catch (Exception exception) when (exception is
                             InvalidOperationException or System.ComponentModel.Win32Exception or
                             NotSupportedException or ArgumentException or IOException)
                {
                    // Best effort only; a hidden console is cosmetic, never a functional dependency.
                }

                await Task.Delay(150).ConfigureAwait(false);
            }
        });
    }

    private static void ExpandDescendants(HashSet<int> known)
    {
        var snapshot = Snapshot();
        var changed = true;
        while (changed)
        {
            changed = false;
            foreach (var (processId, parentId) in snapshot)
            {
                if (known.Contains(parentId) && known.Add(processId))
                {
                    changed = true;
                }
            }
        }
    }

    private static void HideKnownWindows(HashSet<int> known)
    {
        foreach (var processId in known)
        {
            if (processId == Environment.ProcessId)
            {
                continue;
            }

            try
            {
                using var process = Process.GetProcessById(processId);
                var handle = process.MainWindowHandle;
                if (handle != IntPtr.Zero)
                {
                    _ = ShowWindow(handle, SwHide);
                }
            }
            catch (Exception exception) when (exception is
                         ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
            {
            }
        }
    }

    private static void HideNewConsoleHosts(HashSet<int> known, DateTime launchedUtc)
    {
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                if (process.Id == Environment.ProcessId ||
                    process.MainWindowHandle == IntPtr.Zero ||
                    process.StartTime < launchedUtc.AddSeconds(-1) ||
                    (!process.ProcessName.Equals("node", StringComparison.OrdinalIgnoreCase) &&
                     !process.ProcessName.Equals("python", StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                var title = process.MainWindowTitle;
                if (title.Contains("node.exe", StringComparison.OrdinalIgnoreCase) ||
                    title.Contains("python.exe", StringComparison.OrdinalIgnoreCase))
                {
                    known.Add(process.Id);
                    _ = ShowWindow(process.MainWindowHandle, SwHide);
                }
            }
            catch (Exception exception) when (exception is
                         ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
            {
            }
            finally
            {
                process.Dispose();
            }
        }
    }

    private static Dictionary<int, int> Snapshot()
    {
        var result = new Dictionary<int, int>();
        var snapshot = CreateToolhelp32Snapshot(Th32CsSnapProcess, 0);
        if (snapshot == new IntPtr(-1))
        {
            return result;
        }

        try
        {
            var entry = new ProcessEntry32 { Size = (uint)Marshal.SizeOf<ProcessEntry32>() };
            if (!Process32First(snapshot, ref entry))
            {
                return result;
            }

            do
            {
                result[(int)entry.ProcessId] = (int)entry.ParentProcessId;
                entry.Size = (uint)Marshal.SizeOf<ProcessEntry32>();
            }
            while (Process32Next(snapshot, ref entry));
        }
        finally
        {
            _ = CloseHandle(snapshot);
        }

        return result;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint Size;
        public uint Usage;
        public uint ProcessId;
        public IntPtr DefaultHeapId;
        public uint ModuleId;
        public uint Threads;
        public uint ParentProcessId;
        public int PriorityClassBase;
        public uint Flags;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string ExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32First(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32Next(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindow(IntPtr window, int command);
}
