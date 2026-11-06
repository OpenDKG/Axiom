// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;
using System.Text;

namespace Axiom.Infrastructure.Linux.ProcFs;

/// <summary>
/// Reads kernel symlinks under <c>/proc</c> with <c>readlink(2)</c>. Using the syscall directly keeps
/// attribution working inside systemd mount namespaces (<c>PrivateTmp=yes</c>), where the managed
/// <c>FileInfo.LinkTarget</c> helper reported most <c>/proc/&lt;pid&gt;/fd</c> entries as non-links.
/// </summary>
internal static partial class ProcLinkReader
{
    public static string? Read(string path)
    {
        var buffer = new byte[4096];
        var length = readlink(path, buffer, buffer.Length);
        if (length <= 0)
        {
            return null;
        }

        return Encoding.UTF8.GetString(buffer, 0, (int)Math.Min(length, buffer.Length));
    }

    [LibraryImport("libc", EntryPoint = "readlink", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint readlink(string path, byte[] buffer, nint bufferSize);
}
