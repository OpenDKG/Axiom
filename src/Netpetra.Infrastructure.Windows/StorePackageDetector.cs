// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;

namespace Netpetra.Infrastructure.Windows;

/// <summary>
/// Detects MSIX package identity for the current process. A packaged process is subject to package
/// activation and Store certification rules even when it is sideloaded for testing.
/// </summary>
public static class StorePackageDetector
{
    private const int ErrorInsufficientBuffer = 122;

    public static bool IsPackaged
    {
        get
        {
            try
            {
                var length = 0;
                var result = GetCurrentPackageFullName(ref length, IntPtr.Zero);
                return result == ErrorInsufficientBuffer;
            }
            catch (Exception exception) when (exception is
                         DllNotFoundException or EntryPointNotFoundException)
            {
                return false;
            }
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern int GetCurrentPackageFullName(
        ref int packageFullNameLength,
        IntPtr packageFullName);
}
