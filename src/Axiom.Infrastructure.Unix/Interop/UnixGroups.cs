// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;

namespace Axiom.Infrastructure.Unix.Interop;

/// <summary>
/// Group membership of a uid through libc (<c>getpwuid</c>, <c>getgrnam</c>, <c>getgrouplist</c>).
/// Only the leading fields of <c>struct passwd</c> / <c>struct group</c> are read; they have the
/// same layout on macOS and Linux (name, passwd, uid/gid), so the check is unit-tested on Linux.
/// Any failure answers "not a member".
/// </summary>
public static class UnixGroups
{
    private static readonly object Gate = new();

    public static bool IsMember(uint uid, string groupName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(groupName);
        if (OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            lock (Gate)
            {
                // getpwuid/getgrnam return static storage: serialize and copy out immediately.
                var group = getgrnam(groupName);
                if (group == IntPtr.Zero)
                {
                    return false;
                }

                var groupId = (uint)Marshal.ReadInt32(group, 2 * IntPtr.Size);

                var passwd = getpwuid(uid);
                if (passwd == IntPtr.Zero)
                {
                    return false;
                }

                var name = Marshal.PtrToStringUTF8(Marshal.ReadIntPtr(passwd, 0));
                var primaryGroup = Marshal.ReadInt32(passwd, 2 * IntPtr.Size + sizeof(uint));
                if (name is null)
                {
                    return false;
                }

                if ((uint)primaryGroup == groupId)
                {
                    return true;
                }

                var groups = new int[256];
                var count = groups.Length;
                _ = getgrouplist(name, primaryGroup, groups, ref count);
                count = Math.Clamp(count, 0, groups.Length);
                for (var index = 0; index < count; index++)
                {
                    if ((uint)groups[index] == groupId)
                    {
                        return true;
                    }
                }

                return false;
            }
        }
        catch (Exception exception) when (exception is DllNotFoundException or EntryPointNotFoundException)
        {
            return false;
        }
    }

    [DllImport("libc", SetLastError = true)]
    private static extern IntPtr getpwuid(uint uid);

    [DllImport("libc", SetLastError = true, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    private static extern IntPtr getgrnam([MarshalAs(UnmanagedType.LPUTF8Str)] string name);

    [DllImport("libc", SetLastError = true, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    private static extern int getgrouplist(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string user,
        int group,
        [Out] int[] groups,
        ref int count);
}
