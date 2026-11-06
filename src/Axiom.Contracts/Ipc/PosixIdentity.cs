// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;

namespace Axiom.Contracts.Ipc;

/// <summary>Minimal POSIX identity probe used for endpoint and permission decisions.</summary>
public static partial class PosixIdentity
{
    public static uint EffectiveUserId => OperatingSystem.IsWindows() ? 0 : GetEffectiveUserId();

    public static bool IsSuperUser => !OperatingSystem.IsWindows() && EffectiveUserId == 0;

    /// <summary>
    /// Reads the owning uid of a path with <c>stat(2)</c>. The offset differs between the 64-bit
    /// Linux ABIs Axiom ships for; an unknown ABI fails closed instead of skipping the check.
    /// </summary>
    public static bool TryGetOwnerUserId(string path, out uint uid)
    {
        uid = 0;
        if (OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var offset = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => 28,
            Architecture.Arm64 => 24,
            _ => -1,
        };

        if (offset < 0)
        {
            return false;
        }

        const int StatBufferBytes = 256;
        var buffer = Marshal.AllocHGlobal(StatBufferBytes);
        try
        {
            if (Stat(path, buffer) != 0)
            {
                return false;
            }

            uid = unchecked((uint)Marshal.ReadInt32(buffer, offset));
            return true;
        }
        catch (DllNotFoundException)
        {
            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [DllImport("libc", EntryPoint = "geteuid")]
    private static extern uint GetEffectiveUserId();

    [DllImport("libc", EntryPoint = "stat", SetLastError = true, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    private static extern int Stat([MarshalAs(UnmanagedType.LPUTF8Str)] string path, IntPtr buffer);
}
