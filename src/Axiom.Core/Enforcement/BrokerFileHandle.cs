// SPDX-License-Identifier: GPL-3.0-or-later
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Axiom.Core.Enforcement;

/// <summary>Identity and state of an open file, read from its handle rather than its path.</summary>
internal readonly record struct BrokerFileIdentity(
    string FileId,
    long Length,
    long LastWriteStamp,
    bool IsRegularFile,
    bool IsReparsePoint);

internal enum BrokerOpenFailure
{
    None = 0,
    NotFound = 1,
    LinkOrReparse = 2,
    Unsupported = 3,
    Failed = 4,
}

/// <summary>
/// Opens files for <see cref="TrustedFileBroker"/> without following a link in the final path
/// component (<c>FILE_FLAG_OPEN_REPARSE_POINT</c> on Windows, <c>O_NOFOLLOW</c> on Unix), and reads
/// the file identity (volume + file index, or device + inode) and final path from that handle.
/// </summary>
internal static class BrokerFileHandle
{
    public static SafeFileHandle? OpenNoFollow(string path, out BrokerOpenFailure failure)
    {
        if (OperatingSystem.IsWindows())
        {
            var handle = CreateFileW(path, GenericRead, FileShareRead, IntPtr.Zero, OpenExisting, FileFlagOpenReparsePoint, IntPtr.Zero);
            if (!handle.IsInvalid)
            {
                failure = BrokerOpenFailure.None;
                return handle;
            }

            var error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            failure = error is ErrorFileNotFound or ErrorPathNotFound ? BrokerOpenFailure.NotFound : BrokerOpenFailure.Failed;
            return null;
        }

        if (!TryUnixOpenFlags(out var flags))
        {
            failure = BrokerOpenFailure.Unsupported;
            return null;
        }

        var fd = UnixOpen(path, flags);
        if (fd >= 0)
        {
            failure = BrokerOpenFailure.None;
            return new SafeFileHandle(new IntPtr(fd), ownsHandle: true);
        }

        var errno = Marshal.GetLastPInvokeError();
        failure = errno == UnixEnoent
            ? BrokerOpenFailure.NotFound
            : errno == (OperatingSystem.IsMacOS() ? MacEloop : LinuxEloop)
                ? BrokerOpenFailure.LinkOrReparse
                : BrokerOpenFailure.Failed;
        return null;
    }

    public static bool TryGetIdentity(SafeFileHandle handle, out BrokerFileIdentity identity)
    {
        identity = default;
        if (OperatingSystem.IsWindows())
        {
            if (!GetFileInformationByHandle(handle, out var info))
            {
                return false;
            }

            var isDirectory = (info.dwFileAttributes & FileAttributeDirectory) != 0;
            identity = new BrokerFileIdentity(
                string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{info.dwVolumeSerialNumber:x8}:{info.nFileIndexHigh:x8}{info.nFileIndexLow:x8}"),
                ((long)info.nFileSizeHigh << 32) | info.nFileSizeLow,
                ((long)info.ftLastWriteTimeHigh << 32) | info.ftLastWriteTimeLow,
                IsRegularFile: !isDirectory,
                IsReparsePoint: (info.dwFileAttributes & FileAttributeReparsePoint) != 0);
            return true;
        }

        var added = false;
        try
        {
            handle.DangerousAddRef(ref added);
            var fd = handle.DangerousGetHandle().ToInt32();
            return OperatingSystem.IsLinux() ? TryLinuxIdentity(fd, out identity)
                : OperatingSystem.IsMacOS() && TryMacIdentity(fd, out identity);
        }
        finally
        {
            if (added)
            {
                handle.DangerousRelease();
            }
        }
    }

    /// <summary>
    /// Final path of the open file. Windows asks the handle; Unix resolves the opened path and
    /// accepts it only when a no-follow open of the result is the same file as the handle.
    /// </summary>
    public static string? GetFinalPath(SafeFileHandle handle, string openedPath)
    {
        if (OperatingSystem.IsWindows())
        {
            var buffer = new char[32768];
            var length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, 0);
            if (length == 0 || length >= buffer.Length)
            {
                return null;
            }

            var path = new string(buffer, 0, (int)length);
            if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            return path.StartsWith(@"\\?\", StringComparison.Ordinal) ? path[4..] : path;
        }

        var resolved = RealPath(openedPath, IntPtr.Zero);
        if (resolved == IntPtr.Zero)
        {
            return null;
        }

        string? final;
        try
        {
            final = Marshal.PtrToStringUTF8(resolved);
        }
        finally
        {
            Free(resolved);
        }

        if (string.IsNullOrEmpty(final) || !TryGetIdentity(handle, out var opened))
        {
            return null;
        }

        using var check = OpenNoFollow(final, out _);
        return check is not null && TryGetIdentity(check, out var atFinal) &&
               string.Equals(atFinal.FileId, opened.FileId, StringComparison.Ordinal)
            ? final
            : null;
    }

    public static byte[] ReadAll(SafeFileHandle handle)
    {
        using var content = new MemoryStream();
        var chunk = new byte[81920];
        long offset = 0;
        int read;
        while ((read = RandomAccess.Read(handle, chunk, offset)) > 0)
        {
            content.Write(chunk, 0, read);
            offset += read;
        }

        return content.ToArray();
    }

    private static bool TryUnixOpenFlags(out int flags)
    {
        flags = 0;
        if (OperatingSystem.IsMacOS())
        {
            flags = MacONoFollow | MacOCloexec;
            return true;
        }

        if (!OperatingSystem.IsLinux())
        {
            return false;
        }

        var noFollow = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 or Architecture.X86 => 0x20000,
            Architecture.Arm64 or Architecture.Arm => 0x8000,
            _ => 0,
        };
        flags = noFollow | LinuxOCloexec;
        return noFollow != 0;
    }

    private static bool TryLinuxIdentity(int fd, out BrokerFileIdentity identity)
    {
        identity = default;
        var buffer = new byte[256];
        if (Statx(fd, string.Empty, AtEmptyPath, StatxType | StatxMode | StatxMtime | StatxIno | StatxSize, buffer) != 0)
        {
            return false;
        }

        var mode = BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(28, 2));
        var inode = BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(32, 8));
        var size = BinaryPrimitives.ReadInt64LittleEndian(buffer.AsSpan(40, 8));
        var mtimeSeconds = BinaryPrimitives.ReadInt64LittleEndian(buffer.AsSpan(112, 8));
        var mtimeNanos = BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(120, 4));
        var deviceMajor = BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(136, 4));
        var deviceMinor = BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(140, 4));
        identity = new BrokerFileIdentity(
            string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{deviceMajor}:{deviceMinor}:{inode}"),
            size,
            (mtimeSeconds * 1_000_000_000) + mtimeNanos,
            IsRegularFile: (mode & UnixTypeMask) == UnixRegularFile,
            IsReparsePoint: (mode & UnixTypeMask) == UnixSymlink);
        return true;
    }

    private static bool TryMacIdentity(int fd, out BrokerFileIdentity identity)
    {
        identity = default;
        var buffer = new byte[256];
        var result = RuntimeInformation.ProcessArchitecture == Architecture.X64
            ? MacFStatInode64(fd, buffer)
            : MacFStat(fd, buffer);
        if (result != 0)
        {
            return false;
        }

        // 64-bit-inode struct stat: st_dev (int32) @0, st_mode (uint16) @4, st_ino (uint64) @8,
        // st_mtimespec @48, st_size (int64) @96.
        var device = BinaryPrimitives.ReadInt32LittleEndian(buffer.AsSpan(0, 4));
        var mode = BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(4, 2));
        var inode = BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(8, 8));
        var mtimeSeconds = BinaryPrimitives.ReadInt64LittleEndian(buffer.AsSpan(48, 8));
        var mtimeNanos = BinaryPrimitives.ReadInt64LittleEndian(buffer.AsSpan(56, 8));
        var size = BinaryPrimitives.ReadInt64LittleEndian(buffer.AsSpan(96, 8));
        identity = new BrokerFileIdentity(
            string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{device}:{inode}"),
            size,
            (mtimeSeconds * 1_000_000_000) + mtimeNanos,
            IsRegularFile: (mode & UnixTypeMask) == UnixRegularFile,
            IsReparsePoint: (mode & UnixTypeMask) == UnixSymlink);
        return true;
    }

    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x1;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileAttributeDirectory = 0x10;
    private const uint FileAttributeReparsePoint = 0x400;
    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;

    private const int UnixEnoent = 2;
    private const int LinuxEloop = 40;
    private const int MacEloop = 62;
    private const int LinuxOCloexec = 0x80000;
    private const int MacONoFollow = 0x100;
    private const int MacOCloexec = 0x1000000;
    private const int AtEmptyPath = 0x1000;
    private const uint StatxType = 0x1;
    private const uint StatxMode = 0x2;
    private const uint StatxMtime = 0x40;
    private const uint StatxIno = 0x100;
    private const uint StatxSize = 0x200;
    private const int UnixTypeMask = 0xF000;
    private const int UnixRegularFile = 0x8000;
    private const int UnixSymlink = 0xA000;

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint dwFileAttributes;
        public uint ftCreationTimeLow;
        public uint ftCreationTimeHigh;
        public uint ftLastAccessTimeLow;
        public uint ftLastAccessTimeHigh;
        public uint ftLastWriteTimeLow;
        public uint ftLastWriteTimeHigh;
        public uint dwVolumeSerialNumber;
        public uint nFileSizeHigh;
        public uint nFileSizeLow;
        public uint nNumberOfLinks;
        public uint nFileIndexHigh;
        public uint nFileIndexLow;
    }

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle hFile, out ByHandleFileInformation lpFileInformation);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle hFile, [Out] char[] lpszFilePath, uint cchFilePath, uint dwFlags);

    [DllImport("libc", EntryPoint = "open", SetLastError = true, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    private static extern int UnixOpen([MarshalAs(UnmanagedType.LPUTF8Str)] string pathname, int flags);

    [DllImport("libc", EntryPoint = "statx", SetLastError = true, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    private static extern int Statx(int dirfd, [MarshalAs(UnmanagedType.LPUTF8Str)] string pathname, int flags, uint mask, byte[] statxbuf);

    [DllImport("libc", EntryPoint = "fstat", SetLastError = true)]
    private static extern int MacFStat(int fd, byte[] buf);

    [DllImport("libc", EntryPoint = "fstat$INODE64", SetLastError = true)]
    private static extern int MacFStatInode64(int fd, byte[] buf);

    [DllImport("libc", EntryPoint = "realpath", SetLastError = true, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    private static extern IntPtr RealPath([MarshalAs(UnmanagedType.LPUTF8Str)] string path, IntPtr resolvedPath);

    [DllImport("libc", EntryPoint = "free")]
    private static extern void Free(IntPtr pointer);
}
